"""Dashboard HTML pages (GET). State-changing forms post to the existing /app routes in api/human.py, which
answer browsers (Accept: text/html) with a 303 back to the page and JSON clients with JSON."""
import html
import json
import time
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import FileResponse

from ..domain import human_actions as ha, statemachine as sm, tasks as tk
from ..domain.approvals import KINDS
from ..domain.common import audit_head
from ..errors import Problem, not_found
from ..util import canonical_json, sha256_hex
from . import queries as qy
from .render import HERE, redirect, render, safe_next

router = APIRouter(prefix="/app", include_in_schema=False)
RESTORE_BANNER_MS = 7 * 86_400_000
APPROVAL_STATES = ("pending", "approved", "rejected", "expired", "cancelled", "consumed")


def html_session(request: Request):
    from ..api.human import session_dep
    return session_dep(request)


Session = Annotated[object, Depends(html_session)]


def _b(request: Request):
    return request.app.state.bridge


def _opt(v: str | None) -> str | None:
    return v.strip() or None if isinstance(v, str) else None


@router.get("/static/dashboard.css")
def css():
    return FileResponse(HERE / "static" / "dashboard.css", media_type="text/css",
                        headers={"Cache-Control": "public, max-age=86400"})


@router.get("")
def root():
    return redirect("/app/")


@router.get("/login")
def login_page(request: Request):
    return render(request, "login.html")


@router.get("/step-up")
def step_up_page(request: Request, sess: Session, next: str | None = Query(None, max_length=200)):
    return render(request, "step_up.html", next=safe_next(next))


@router.get("/")
def overview(request: Request, sess: Session):
    b = _b(request)
    with b.db.read() as conn:
        active = qy.tasks(conn, scope="active", limit=100)
        counts = qy.state_counts(conn)
        pending = qy.approvals(conn, state="pending", limit=50)
        agents = ha.list_agents(conn)
        restore_at = qy.meta(conn, "last_restore_at")
        totp_fails = qy.totp_failures_last_hour(conn)
        throttled = qy.throttled_accounts(conn)
    banners = []
    if b.storage.degraded():
        banners.append(("bad", "Storage degraded: free disk or inodes below the limit. Agent writes are refused "
                               "(503 storage_degraded) until space is freed; reads still work."))
    if restore_at and int(restore_at) > time.time() * 1000 - RESTORE_BANNER_MS:
        from ..util import iso
        banners.append(("warn", f"The database was restored from a backup at {iso(int(restore_at))}. Open approvals "
                                "were cancelled; agents will re-request them. See the audit log (system.restore)."))
    if totp_fails >= 5:
        banners.append(("warn", f"{totp_fails} wrong TOTP codes after a correct password (logins and step-ups) in the "
                                "last hour. Someone may know a password: change it (bridgectl human reset)."))
    for login in throttled:
        banners.append(("bad", f"Account {login} is temporarily throttled after repeated wrong TOTP codes with the "
                               "correct password. If that was not you, reset it now (bridgectl human reset); "
                               "bridgectl human unlock --login clears the delay."))
    for a in agents:
        if a["paused"]:
            banners.append(("info", f"Agent {a['id']} is paused: its writes are refused (423)."))
    needs_human = [t for t in active if t["state"] == "needs_human"]
    return render(request, "overview.html", active=active, counts=counts, pending=pending, agents=agents,
                  banners=banners, needs_human=needs_human)


@router.get("/tasks")
def task_list(request: Request, sess: Session, scope: str = Query("active", pattern="^(active|history|all)$"),
              state: str | None = Query(None, max_length=30), category: str | None = Query(None, max_length=40),
              priority: str | None = Query(None, max_length=10), agent: str | None = Query(None, max_length=32),
              project: str | None = Query(None, max_length=100), q: str | None = Query(None, max_length=200),
              page: int = Query(1, ge=1, le=1000)):
    f = {"scope": scope, "state": _opt(state), "category": _opt(category), "priority": _opt(priority),
         "agent": _opt(agent), "project": _opt(project), "q": _opt(q)}
    per = 50
    with _b(request).db.read() as conn:
        rows = qy.tasks(conn, **f, limit=per + 1, offset=(page - 1) * per)
        agents = [a["id"] for a in ha.list_agents(conn)]
        projects = qy.projects(conn)
    return render(request, "tasks.html", tasks=rows[:per], has_more=len(rows) > per, page=page, f=f,
                  states=sm.STATES, categories=sorted(tk.CATEGORIES), priorities=tk.PRIORITIES, agents=agents,
                  projects=projects)


TIMELINE_PAGE = 50


@router.get("/tasks/{task_id}")
def task_detail(request: Request, task_id: str, sess: Session, before: int | None = Query(None, ge=1)):
    """Newest TIMELINE_PAGE timeline events, older ones via ?before=<seq>."""
    from ..domain import humans
    actor = humans.actor_for(sess)
    b = _b(request)
    with b.db.read() as conn:
        d = tk.get_detail(conn, actor, task_id, messages=0)
        page = tk.history(conn, actor, task_id, 0, TIMELINE_PAGE, include_bodies=True,
                          max_bytes=2 * b.settings.limits.max_response_bytes, before_seq=before or 2 ** 62)
        names = qy.human_names(conn)
        t = d["task"]

        def permitted(to: str) -> bool:
            try:
                ha.check_authority(conn, actor, t, to, stepped_up=True)
                return True
            except Problem:
                return False
        targets = [s for s in sm.STATES if s != t["state"] and s != "proposed" and t["state"] not in sm.TERMINAL
                   and permitted(s)]
        approve_to = ha.approve_target(t)
        can_approve = approve_to is not None and permitted(approve_to)
        own = qy.agent_parties(conn)
    art_ids = {a["id"] for a in d["artifacts"]}
    older = page["first_seq"] if page["has_more"] and page["first_seq"] else None
    return render(request, "task.html", t=t, timeline=page["events"], older=older, paged=before is not None,
                  artifacts=d["artifacts"], approvals=d["approvals"], art_ids=art_ids, names=names, targets=targets,
                  priorities=tk.PRIORITIES, terminal=t["state"] in sm.TERMINAL, can_approve=can_approve,
                  approve_to=approve_to, agent_party=own)


@router.get("/approvals")
def approval_list(request: Request, sess: Session, state: str | None = Query("pending", max_length=20),
                  party: str | None = Query(None, max_length=32), q: str | None = Query(None, max_length=200)):
    st = _opt(state)
    st = st if st in APPROVAL_STATES else None
    with _b(request).db.read() as conn:
        rows = qy.approvals(conn, state=st, party=_opt(party), q=_opt(q))
        names = qy.human_names(conn)
        parties = list(qy.party_names(conn))
    return render(request, "approvals.html", approvals=rows, names=names, parties=parties,
                  f={"state": st or "all", "party": _opt(party), "q": _opt(q)}, states=APPROVAL_STATES, kinds=KINDS)


@router.get("/approvals/{approval_id}")
def approval_detail(request: Request, approval_id: str, sess: Session):
    from ..domain import humans
    with _b(request).db.read() as conn:
        row = qy.approval_row(conn, approval_id)
        if row is None:
            raise not_found("approval")
        a = ha.get_approval(conn, approval_id)
        task = tk.get_detail(conn, humans.actor_for(sess), a["task_id"], messages=1)["task"]
        names = qy.human_names(conn)
    canonical = row["action"]                     # stored canonical JSON: exactly the bytes the hash covers
    verified = sha256_hex(canonical.encode()) == a["action_sha256"] == sha256_hex(canonical_json(json.loads(canonical)))
    return render(request, "approval.html", a=a, task=task, canonical=canonical, verified=verified, names=names,
                  own_party=a["approver_party"] == sess["party_id"])


@router.get("/agents")
def agents_page(request: Request, sess: Session):
    with _b(request).db.read() as conn:
        agents = ha.list_agents(conn)
        keys = ha.list_keys(conn)
        stats = qy.agent_stats(conn)
    return render(request, "agents.html", agents=agents, keys=keys, stats=stats)


@router.get("/agents/{agent_id}")
def agent_activity(request: Request, agent_id: str, sess: Session):
    with _b(request).db.read() as conn:
        agent = next((a for a in ha.list_agents(conn) if a["id"] == agent_id), None)
        if agent is None:
            raise Problem(404, "agent_not_found", "agent not found")
        stats = qy.agent_stats(conn).get(agent_id, {})
        events = qy.audit(conn, actor=agent_id, limit=100)
        messages = qy.agent_messages(conn, agent_id)
        open_tasks = qy.tasks(conn, scope="active", agent=agent_id, limit=50)
        keys = [k for k in ha.list_keys(conn) if k["agent_id"] == agent_id]
    return render(request, "agent.html", agent=agent, stats=stats, events=events, messages=messages,
                  open_tasks=open_tasks, keys=keys)


@router.get("/audit")
def audit_page(request: Request, sess: Session, action: str | None = Query(None, max_length=60),
               actor: str | None = Query(None, max_length=64), target: str | None = Query(None, max_length=64),
               before_seq: int | None = Query(None, ge=1)):
    f = {"action": _opt(action), "actor": _opt(actor), "target": _opt(target)}
    per = 100
    with _b(request).db.read() as conn:
        rows = qy.audit(conn, **f, before_seq=before_seq, limit=per + 1)
        head_seq, head = audit_head(conn)
    return render(request, "audit.html", rows=rows[:per], has_more=len(rows) > per, f=f,
                  head_seq=head_seq, head=head, older=rows[per - 1]["seq"] if len(rows) > per else None)


MESSAGES_PAGE = 50
ROW_OVERHEAD = 1500      # markup + ids + names per row, generous
PAGE_OVERHEAD = 8192     # layout, tabs, footer


@router.get("/messages")
def messages_page(request: Request, sess: Session, to: str | None = Query(None, pattern="^[A-Za-z0-9_.-]{1,64}$"),
                  before: int | None = Query(None, ge=1, le=2 ** 62)):
    """Read-only: messages delivered to one agent (tab per agent), newest first, keyset-paged by seq and
    bounded by the response byte budget."""
    from .render import has_hidden, preview, reveal
    b = _b(request)
    with b.db.read() as conn:
        agents = ha.list_agents(conn)
        parties = qy.party_names(conn)
        names = qy.human_names(conn)
        if not agents:
            return render(request, "messages.html", agents=[], agent=None, rows=[], parties=parties)
        agent = next((a for a in agents if a["id"] == to), None) if to else agents[0]
        if agent is None:
            raise Problem(404, "agent_not_found", "agent not found")
        rows = qy.messages_to(conn, agent["id"], before_seq=before, limit=MESSAGES_PAGE + 1)
    has_more = len(rows) > MESSAGES_PAGE
    rows = rows[:MESSAGES_PAGE]
    left, shown = b.settings.limits.max_response_bytes - PAGE_OVERHEAD, []
    for r in rows:
        head = r.pop("head")
        r["hidden"] = has_hidden(head)
        r["preview"] = preview(head, r["text_len"])
        r["task_title"] = reveal(r["task_title"][:120])
        size = ROW_OVERHEAD + len(html.escape(r["preview"]).encode()) + len(html.escape(r["task_title"]).encode())
        if shown and size > left:          # the first row is always shown, then stop at the byte budget
            has_more = True
            break
        left -= size
        shown.append(r)
    older = shown[-1]["seq"] if has_more and shown else None
    return render(request, "messages.html", agents=agents, agent=agent, rows=shown, older=older,
                  paged=before is not None, parties=parties, names=names, per=MESSAGES_PAGE)


@router.get("/messages/{message_id}")
def message_detail(request: Request, message_id: str, sess: Session):
    """Read-only: one full message, escaped, hidden characters revealed."""
    from ..domain.common import message_dict
    with _b(request).db.read() as conn:
        row, t = qy.message_with_task(conn, message_id) if _is_msg_id(message_id) else (None, None)
        if row is None:
            raise not_found("message")
        m = message_dict(row)
        names = qy.human_names(conn)
        parties = qy.party_names(conn)
        own = qy.agent_parties(conn)
    recipients = [a for a in dict.fromkeys((t["originator_agent_id"], t["responsible_agent_id"]))
                  if not (m["sender"]["kind"] == "agent" and m["sender"]["id"] == a)]
    return render(request, "message.html", m=m, t={"id": t["id"], "title": t["title"], "state": t["state"]},
                  recipients=recipients, names=names, parties=parties, agent_party=own)


def _is_msg_id(value: str) -> bool:
    from .render import _is_id
    return _is_id(value, "msg_")
