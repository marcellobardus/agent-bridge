"""Task creation, lookup, listing and search, with party ownership boundaries."""
import json

from ..errors import Problem, not_found
from ..util import Budget, canonical_json, dumps, new_id, now_ms, sha256_hex
from .common import Actor, audit, emit, insert_message, load_task, log_task, task_dict, task_summary
from .statemachine import TERMINAL

# category -> owning domain. The responsible agent's party must own the category's domain.
CATEGORIES = {
    # Originator side (business)
    "business_requirements": "business", "strategy_research": "business", "qa": "business",
    "simulation": "business", "product_validation": "business", "business_ops": "business",
    "experiment": "business",
    # Responsible side (engineering)
    "implementation": "engineering", "smart_contract": "engineering", "backend": "engineering",
    "frontend": "engineering", "architecture": "engineering", "infrastructure": "engineering",
    "deployment": "engineering", "bug_fix": "engineering", "engineering_validation": "engineering",
}
PRIORITIES = ("low", "normal", "high", "urgent")


def visible_task(conn, actor: Actor, task_id: str):
    """Agents only see tasks they participate in (404 otherwise); humans see everything."""
    t = load_task(conn, task_id)
    if t is None or (actor.kind == "agent" and actor.id not in (t["originator_agent_id"], t["responsible_agent_id"])):
        raise not_found("task")
    return t


def role_of(task, actor: Actor) -> str:
    if actor.kind == "human":
        return "human"
    return "originator" if actor.id == task["originator_agent_id"] else "responsible"


def writable_task(conn, actor: Actor, task_id: str):
    t = visible_task(conn, actor, task_id)
    if t["state"] in TERMINAL:
        raise Problem(410, "task_closed", f"task is {t['state']}")
    if actor.kind == "agent" and t["paused_at"] is not None:
        raise Problem(409, "task_paused", "a human paused this task; agent writes are blocked until resumed")
    return t


def create(conn, actor: Actor, data: dict, limits) -> dict:
    resp = conn.execute("SELECT a.id, a.disabled_at, p.domain FROM agents a JOIN parties p ON p.id=a.party_id"
                        " WHERE a.id=?", (data["responsible_agent_id"],)).fetchone()
    if resp is None or resp["disabled_at"] is not None:
        raise Problem(422, "unknown_agent", "responsible agent does not exist")
    if resp["id"] == actor.id:
        raise Problem(422, "self_assignment", "a task must be addressed to another agent")
    domain = CATEGORIES[data["category"]]
    if resp["domain"] != domain:
        raise Problem(403, "ownership_violation",
                      f"category {data['category']!r} belongs to the {domain} side; address it to that side's agent")
    for rid in data.get("related_task_ids") or []:
        visible_task(conn, actor, rid)
    hop = 0
    if data.get("parent_task_id"):
        hop = visible_task(conn, actor, data["parent_task_id"])["hop_count"] + 1
        if hop > limits.max_hop_count:
            raise Problem(409, "loop_guard", f"task chain too deep (max {limits.max_hop_count} hops)")
    day_ago = now_ms() - 86_400_000
    n = conn.execute("SELECT count(*) FROM tasks WHERE originator_agent_id=? AND created_at>?", (actor.id, day_ago)).fetchone()[0]
    if n >= limits.tasks_per_agent_per_day:
        raise Problem(429, "daily_limit", "too many new tasks today", headers={"Retry-After": "3600"})
    content = sha256_hex(canonical_json([data["responsible_agent_id"], data["title"].strip().lower(),
                                         data["description"].strip()]))
    dup = conn.execute("SELECT id FROM tasks WHERE originator_agent_id=? AND content_sha256=? AND state NOT IN"
                       " ('closed','rejected') LIMIT 1", (actor.id, content)).fetchone()
    if dup:
        raise Problem(409, "duplicate_task", "an open task with the same title and description exists",
                      extra={"existing_task_id": dup[0]})
    tid, now = new_id("tsk"), now_ms()
    conn.execute(
        "INSERT INTO tasks (id, title, description, originator_agent_id, responsible_agent_id, priority, category,"
        " state, acceptance_criteria, project, component, related_task_ids, parent_task_id, hop_count, content_sha256,"
        " created_at, updated_at) VALUES (?,?,?,?,?,?,?,'proposed',?,?,?,?,?,?,?,?,?)",
        (tid, data["title"], data["description"], actor.id, data["responsible_agent_id"], data["priority"],
         data["category"], dumps(data.get("acceptance_criteria") or []), data.get("project"), data.get("component"),
         dumps(data.get("related_task_ids") or []), data.get("parent_task_id"), hop, content, now, now))
    t = load_task(conn, tid)
    log_task(conn, tid, actor, "created", to_state="proposed")
    audit(conn, actor, "task.create", "task", tid, {"responsible": t["responsible_agent_id"], "category": t["category"]})
    body = {"text": data["description"], "data": {"acceptance_criteria": data.get("acceptance_criteria") or []},
            "refs": data.get("refs") or []}
    m = insert_message(conn, t, actor, "TASK_REQUEST", body, notify=False)
    conn.execute("UPDATE tasks SET message_count=1, agent_streak=1 WHERE id=?", (tid,))
    from .common import message_dict
    emit(conn, t, "task.created", {"task": task_dict(t), "message": message_dict(m)}, actor)
    return {"task": task_dict(load_task(conn, tid)), "message_id": m["id"]}


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def list_tasks(conn, actor: Actor, *, role=None, state=None, category=None, project=None, q=None,
               updated_since=None, limit=50, offset=0, search_messages=False, budget: Budget | None = None,
               scan_tasks: int = 500) -> list[dict]:
    """Newest first. With a budget, stops once the page reaches the byte cap (budget.truncated). Message-text
    search only scans the `scan_tasks` most recently updated tasks (bounded cost)."""
    where, args = [], []
    if actor.kind == "agent":
        if role == "originator":
            where.append("t.originator_agent_id=?"); args.append(actor.id)
        elif role == "responsible":
            where.append("t.responsible_agent_id=?"); args.append(actor.id)
        else:
            where.append("(t.originator_agent_id=? OR t.responsible_agent_id=?)"); args += [actor.id, actor.id]
    for col, val in (("state", state), ("category", category), ("project", project)):
        if val:
            where.append(f"t.{col}=?"); args.append(val)
    if updated_since is not None:
        where.append("t.updated_at>=?"); args.append(updated_since)
    if q:
        clause = "(t.title LIKE ? ESCAPE '\\' OR t.description LIKE ? ESCAPE '\\'"
        args += [_like(q), _like(q)]
        if search_messages:
            clause += (" OR (t.id IN (SELECT id FROM tasks ORDER BY updated_at DESC LIMIT ?) AND EXISTS"
                       " (SELECT 1 FROM messages m WHERE m.task_id=t.id AND m.body LIKE ? ESCAPE '\\'))")
            args += [scan_tasks, _like(q)]
        where.append(clause + ")")
    sql = "SELECT t.* FROM tasks t" + (" WHERE " + " AND ".join(where) if where else "")
    sql += " ORDER BY t.updated_at DESC, t.id DESC LIMIT ? OFFSET ?"
    out = []
    for r in conn.execute(sql, (*args, limit, offset)):
        d = task_dict(r)
        if budget is not None and not budget.admit(d):
            break
        out.append(d)
    return out


def get_detail(conn, actor: Actor, task_id: str, *, messages: int = 50, max_bytes: int | None = None) -> dict:
    """Task + newest `messages` messages (oldest first) + artifacts + approvals. With max_bytes, older messages
    are dropped once the cap is reached (`messages_truncated`; page the rest via /messages)."""
    from .approvals import approval_dict
    from .artifacts import artifact_meta
    from .common import message_dict
    t = visible_task(conn, actor, task_id)
    budget = Budget(max_bytes) if max_bytes else None
    out = {"task": task_dict(t)}
    arts = conn.execute("SELECT id, filename, content_type, size, sha256, uploader_kind, uploader_id, created_at"
                        " FROM artifacts WHERE task_id=? ORDER BY created_at", (task_id,)).fetchall()
    out["artifacts"] = [artifact_meta(a) for a in arts]
    out["approvals"] = [approval_dict(a) for a in
                        conn.execute("SELECT * FROM approvals WHERE task_id=? ORDER BY created_at", (task_id,))]
    if budget is not None:
        budget.admit({k: out[k] for k in ("task", "artifacts", "approvals")})
    msgs = []
    for m in conn.execute("SELECT * FROM messages WHERE task_id=? ORDER BY seq DESC LIMIT ?", (task_id, messages)):
        d = message_dict(m)
        if budget is not None and not budget.admit(d):
            break
        msgs.append(d)
    out["messages"] = msgs[::-1]
    out["messages_truncated"] = bool(budget and budget.truncated)
    return out


def history(conn, actor: Actor, task_id: str, after_seq: int = 0, limit: int = 200, *,
            include_bodies: bool = False, max_bytes: int = 1024 * 1024, before_seq: int | None = None) -> dict:
    """The task timeline: every state change, message, artifact and approval event, oldest first.
    Message bodies only with include_bodies; the page stops at max_bytes (`has_more`, continue from
    `next_after_seq`). before_seq (dashboard) returns the newest `limit` events before that seq instead."""
    from ..util import iso
    from .common import message_dict, message_meta
    visible_task(conn, actor, task_id)
    if before_seq is not None:
        rows = conn.execute("SELECT * FROM (SELECT * FROM task_log WHERE task_id=? AND seq<? ORDER BY seq DESC"
                            " LIMIT ?) ORDER BY seq", (task_id, before_seq, limit + 1))
    else:
        rows = conn.execute("SELECT * FROM task_log WHERE task_id=? AND seq>? ORDER BY seq LIMIT ?",
                            (task_id, after_seq, limit + 1))
    rows = rows.fetchall()          # task_log rows are small; message bodies are loaded one at a time below
    more = len(rows) > limit
    backwards = before_seq is not None          # dashboard: keep the newest events when the budget runs out
    rows = (rows[1:] if more else rows)[::-1] if backwards else rows[:limit]
    budget, out = Budget(max_bytes), []
    for r in rows:
        e = {"seq": r["seq"], "ts": iso(r["ts"]), "actor": {"kind": r["actor_kind"], "id": r["actor_id"]},
             "kind": r["kind"], "from_state": r["from_state"], "to_state": r["to_state"],
             "detail": json.loads(r["detail"])}
        if r["message_id"]:
            m = conn.execute("SELECT * FROM messages WHERE id=?", (r["message_id"],)).fetchone()
            e["message"] = message_dict(m) if include_bodies else message_meta(m)
        if not budget.admit(e):
            more = True
            break
        out.append(e)
    if backwards:
        out.reverse()
        return {"events": out, "has_more": more, "first_seq": out[0]["seq"] if out else None}
    return {"events": out, "next_after_seq": out[-1]["seq"] if out else after_seq, "has_more": more}


def messages_page(conn, actor: Actor, task_id: str, after_seq: int, limit: int, max_bytes: int) -> dict:
    from .common import message_dict
    visible_task(conn, actor, task_id)
    budget, out, more = Budget(max_bytes), [], False
    for m in conn.execute("SELECT * FROM messages WHERE task_id=? AND seq>? ORDER BY seq LIMIT ?",
                          (task_id, after_seq, limit + 1)):
        if len(out) == limit:
            more = True
            break
        d = message_dict(m)
        if not budget.admit(d):
            more = True
            break
        out.append(d)
    return {"messages": out, "next_after_seq": out[-1]["seq"] if out else after_seq, "has_more": more}


__all__ = ["CATEGORIES", "PRIORITIES", "create", "list_tasks", "get_detail", "history", "messages_page", "visible_task",
           "writable_task", "role_of", "task_summary"]
