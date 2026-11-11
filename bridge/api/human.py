"""Human surface `/app`: session login (password + TOTP), CSRF-protected form POSTs, JSON read views.
Browsers (Accept: text/html) get HTML pages / 303 redirects (bridge/web); other clients get JSON.
Not part of the agent OpenAPI contract."""
import asyncio
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from ..domain import artifacts, human_actions as ha, humans, tasks
from ..domain.common import message_dict, task_dict
from ..errors import Problem
from ..util import Budget, now_ms
from .agent import attachment_response
from .deps import Bridge, bridge, client_ip, human_tx
from ..web.render import PRE_COOKIE, done, pre_token_ok, redirect, render, safe_next, wants_html

COOKIE = "__Host-ab_session"
router = APIRouter(prefix="/app", include_in_schema=False)


_HOST_RE = re.compile(r"^(\[::1\]|[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)(:[0-9]{1,5})?$")


def _norm_origin(o: str) -> str:
    """scheme://host[:port] with scheme+host lowercased and no trailing slash (port is compared exactly)."""
    return o.strip().rstrip("/").lower()


def _loopback_host(host: str) -> bool:
    h = host.lower()
    name = h[1:h.index("]")] if h.startswith("[") else h.rsplit(":", 1)[0]
    if name == "localhost":
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def origin_allowed(origin: str | None, sec_fetch_site: str | None, host: str | None, scheme: str,
                   public_origin: str | None, token_ok: bool = False) -> bool:
    """CSRF origin check for dashboard form posts (pure; unit-testable).
    `token_ok`: the request carried a matching pre-session token (login/enroll forms); then an
    `Origin: null` is accepted without Sec-Fetch-Site. Cross-site/same-site fetches are always refused."""
    sfs = (sec_fetch_site or "").strip().lower()
    if sfs in ("cross-site", "same-site"):
        return False
    if origin is None:
        return True
    o = origin.strip()
    if o.lower() == "null":
        return token_ok or sfs == "same-origin"   # browsers set Sec-Fetch-Site; page scripts cannot forge it
    allowed = set()
    if public_origin:
        allowed.add(_norm_origin(public_origin))
    if host and _HOST_RE.match(host.strip()):
        h = host.strip()
        allowed.add(_norm_origin(f"https://{h}"))
        if _loopback_host(h):                     # plain http only for a local caller
            allowed.add(_norm_origin(f"http://{h}"))
    return _norm_origin(o) in allowed


def _check_origin(request: Request, b: Bridge, token_ok: bool = False) -> None:
    if not origin_allowed(request.headers.get("origin"), request.headers.get("sec-fetch-site"),
                          request.headers.get("host"), request.url.scheme, b.settings.public_origin, token_ok):
        raise Problem(403, "bad_origin", "form post refused: open the dashboard link directly in Safari, Chrome or "
                                         "Firefox (not inside a chat app's built-in browser) and retry")


def _check_pre_session(request: Request, b: Bridge, form) -> None:
    """Login and enroll forms carry a pre-session token (random value in the `__Host-ab_pre` cookie and a
    hidden field), compared in constant time. Browsers (Accept: text/html) must present it. Non-browser JSON
    clients (CLI, tests) that send neither cookie nor field keep the header-only check: they carry no ambient
    credential, so there is nothing to forge."""
    supplied = form.get("pre_csrf")
    present = supplied is not None or request.cookies.get(PRE_COOKIE) is not None
    token_ok = False
    if present or wants_html(request):
        if not pre_token_ok(request, supplied if isinstance(supplied, str) else None):
            _check_origin(request, b)      # a cross-site post is reported as such
            raise Problem(403, "csrf_failed", "this form expired or was opened elsewhere; reload the page and retry")
        token_ok = True
    _check_origin(request, b, token_ok)


def session_dep(request: Request):
    b = bridge(request)
    with b.db.read() as conn:
        sess = humans.session(conn, b.settings, request.cookies.get(COOKIE))
    if sess is None:
        raise Problem(401, "not_authenticated", "log in first")
    request.state.principal = sess["human_id"]
    request.state.sess = sess
    if now_ms() - sess["last_seen_at"] > 60_000:
        with b.db.write() as conn:
            humans.touch(conn, sess)
    return sess


class Form:
    def __init__(self, sess, data: dict):
        self.sess, self.data = sess, data
        self.actor = humans.actor_for(sess)
        self.stepped_up = False

    def get(self, k: str, default=None):
        v = self.data.get(k, default)
        return v.strip() if isinstance(v, str) else v


async def form_dep(request: Request, sess=Depends(session_dep)) -> Form:
    """Every state-changing human request: valid session + CSRF token + same Origin."""
    b = bridge(request)
    form = dict(await request.form())
    token_ok = humans.csrf_ok(sess, form.get("csrf_token") or request.headers.get("x-csrf-token"))
    if not token_ok:
        _check_origin(request, b)          # a cross-site post is reported as such
        raise Problem(403, "csrf_failed", "missing or invalid CSRF token")
    _check_origin(request, b, token_ok=True)    # with the session token, Origin: null is fine (cross-site never is)
    return Form(sess, form)


Session = Annotated[object, Depends(session_dep)]
Post = Annotated[Form, Depends(form_dep)]


@router.post("/login")
async def login(request: Request):
    b = bridge(request)
    f = await request.form()
    _check_pre_session(request, b, f)
    ip = client_ip(request)
    res = await _login(b, str(f.get("login", "")), str(f.get("password", "")), str(f.get("totp", "")), ip)
    if wants_html(request):
        resp = redirect("/app/")
    else:
        resp = JSONResponse({"ok": True, "human_id": res["human_id"], "csrf_token": res["csrf_token"]})
    resp.set_cookie(COOKIE, res["token"], max_age=b.settings.session_ttl_s, path="/", secure=True, httponly=True,
                    samesite="strict")
    resp.delete_cookie(PRE_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    return resp


# argon2 (19 MiB, ~0.1-0.5 s) runs on its own single thread, never on the shared worker pool, and only
# after a non-blocking slot was granted (1 per client address, 4 overall) and the per-address bucket charged.
_HASH_POOL = ThreadPoolExecutor(max_workers=1, thread_name_prefix="argon2")


async def _hashing(fn):
    return await asyncio.get_running_loop().run_in_executor(_HASH_POOL, fn)


@asynccontextmanager
async def _hash_slot(b: Bridge, key: str, gate=None):
    """Wait (bounded, asyncio) for a hash slot on `gate` (default: the login/enroll gate), then charge the
    per-key attempts bucket. `key` is an address key (login/enroll) or a session key (step-up)."""
    gate = gate or b.login_gate
    if not await gate.wait_acquire(key):
        raise Problem(429, "login_throttled", "too many password checks in progress; retry in a moment",
                      headers={"Retry-After": "2"})
    try:
        wait = b.limiter.take(("pwcheck", key), b.settings.limits.login_attempts_per_ip_per_min)
        if wait:
            raise Problem(429, "login_throttled", "too many password attempts from your address; wait and retry",
                          headers={"Retry-After": str(wait)})
        yield
    finally:
        gate.release(key)


async def _login(b: Bridge, login_name: str, password: str, code: str, ip: str | None) -> dict:
    """Argon2 runs BEFORE the write transaction; behind the login gate on the dedicated hash thread.
    Failures drain a small global bucket that only turns away logins whose password is wrong."""
    lim = b.settings.limits
    async with _hash_slot(b, humans.throttle_key(ip)):
        h = await _threaded(lambda: _read(b, lambda c: humans.login_precheck(c, login_name, ip)))
        pw_ok = await _hashing(lambda: humans.verify_password(h["password_hash"] if h else None, password))
    if not pw_ok:
        # the global bucket is consulted only once the password is wrong, so a correct login always proceeds
        wait = b.limiter.blocked("loginfail", lim.login_fail_global_per_min)
        if wait:
            raise Problem(429, "login_throttled", "too many failed logins; wait and retry",
                          headers={"Retry-After": str(wait)})
    try:
        res = await _threaded(lambda: human_tx(b, lambda c: humans.login(c, b.settings, h["id"] if h else None,
                                                                         pw_ok, code, ip)))
        b.login_gate.mark_ok(humans.throttle_key(ip))      # this address may use the reserved slot next time
        return res
    except Problem as p:
        if p.status == 401:
            b.limiter.take("loginfail", lim.login_fail_global_per_min)
        raise


def _read(b: Bridge, fn):
    with b.db.read() as conn:
        return fn(conn)


async def _threaded(fn):
    from starlette.concurrency import run_in_threadpool
    return await run_in_threadpool(fn)


@router.post("/logout")
def logout(request: Request, f: Post):
    human_tx(bridge(request), lambda c: humans.logout(c, f.sess))
    resp = redirect("/app/login") if wants_html(request) else JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    return resp


@router.post("/step-up")
async def step_up(request: Request, f: Post):
    """Password + a NEW TOTP code. 5 failures on a session revoke it; wrong codes also count on the
    account. The code used to log in cannot be replayed here (totp_last_step)."""
    b = bridge(request)
    async with _hash_slot(b, "s:" + f.sess["token_hash"].hex(), b.stepup_gate):      # per session
        h = await _threaded(lambda: _read(b, lambda c: humans.step_up_precheck(c, f.sess)))
        pw_ok = await _hashing(lambda: humans.verify_password(h["password_hash"], str(f.get("password", ""))))
    await _threaded(lambda: human_tx(b, lambda c: humans.step_up(c, b.settings, f.sess, pw_ok,
                                                                 str(f.get("totp", "")))))
    return done(request, {"ok": True, "valid_s": b.settings.step_up_window_s}, "stepup",
                safe_next(request.query_params.get("next") or f.get("next")))


# ---- read views ----

@router.get("/api/me")
def me(sess: Session):
    return {"human_id": sess["human_id"], "login": sess["login"], "display_name": sess["display_name"],
            "party_id": sess["party_id"], "csrf_token": sess["csrf_token"]}


@router.get("/api/tasks")
def list_tasks(request: Request, sess: Session, state: str | None = Query(None, max_length=30),
               q: str | None = Query(None, max_length=200), category: str | None = Query(None, max_length=40),
               limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=10000)):
    b = bridge(request)
    budget = Budget(b.settings.limits.max_response_bytes)
    with b.db.read() as conn:
        rows = tasks.list_tasks(conn, humans.actor_for(sess), state=state, q=q, category=category, limit=limit,
                                offset=offset, search_messages=bool(q), budget=budget,
                                scan_tasks=b.settings.limits.search_scan_tasks)
    return {"tasks": rows, "truncated": budget.truncated}


@router.get("/api/tasks/{task_id}")
def get_task(request: Request, task_id: str, sess: Session):
    b = bridge(request)
    with b.db.read() as conn:
        return tasks.get_detail(conn, humans.actor_for(sess), task_id, messages=500,
                                max_bytes=b.settings.limits.max_response_bytes)


@router.get("/api/tasks/{task_id}/history")
def history(request: Request, task_id: str, sess: Session, after_seq: int = Query(0, ge=0),
            include_bodies: bool = False):
    b = bridge(request)
    with b.db.read() as conn:
        return tasks.history(conn, humans.actor_for(sess), task_id, after_seq, 500, include_bodies=include_bodies,
                             max_bytes=b.settings.limits.max_response_bytes)


@router.get("/api/approvals")
def approvals(request: Request, sess: Session, state: str | None = Query(None, max_length=20)):
    b = bridge(request)
    budget = Budget(b.settings.limits.max_response_bytes)
    with b.db.read() as conn:
        return {"approvals": ha.list_approvals(conn, state, budget), "truncated": budget.truncated}


@router.get("/api/approvals/{approval_id}")
def approval(request: Request, approval_id: str, sess: Session):
    with bridge(request).db.read() as conn:
        return {"approval": ha.get_approval(conn, approval_id)}


@router.get("/api/agents")
def agents(request: Request, sess: Session):
    with bridge(request).db.read() as conn:
        return {"agents": ha.list_agents(conn)}


@router.get("/api/audit")
def audit(request: Request, sess: Session, before_seq: int | None = Query(None, ge=1),
          action: str | None = Query(None, max_length=60), target_id: str | None = Query(None, max_length=64),
          limit: int = Query(100, ge=1, le=500)):
    with bridge(request).db.read() as conn:
        return {"audit": ha.list_audit(conn, limit=limit, before_seq=before_seq, action=action, target_id=target_id)}


@router.get("/artifacts/{artifact_id}")
def artifact(request: Request, artifact_id: str, sess: Session):
    with bridge(request).db.read() as conn:
        a = artifacts.download(conn, humans.actor_for(sess), artifact_id)
    return attachment_response(a)


# ---- actions (form POST + csrf_token) ----

def _version(f) -> int | None:
    v = f.get("expected_version")
    if not v:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        raise Problem(422, "validation_error", "expected_version must be an integer") from None


_TASK_ACTIONS = {
    "instruction": lambda c, a, t, f: {"message": message_dict(ha.add_instruction(c, a, t, f.get("text", "")))},
    "priority": lambda c, a, t, f: {"task": task_dict(ha.set_priority(c, a, t, f.get("priority", "")))},
    "pause": lambda c, a, t, f: {"task": task_dict(ha.pause_task(c, a, t, f.get("reason", "")))},
    "resume": lambda c, a, t, f: {"task": task_dict(ha.resume_task(c, a, t))},
    "escalate": lambda c, a, t, f: {"task": task_dict(ha.escalate_task(c, a, t, f.get("reason", "")))},
    "approve": lambda c, a, t, f: {"task": task_dict(ha.approve_task(c, a, t, f.get("reason"), f.stepped_up))},
    "reject": lambda c, a, t, f: {"task": task_dict(ha.reject_task(c, a, t, f.get("reason", ""), f.stepped_up))},
    "transition": lambda c, a, t, f: {"task": task_dict(ha.transition_task(
        c, a, t, f.get("to", ""), f.get("reason"), _version(f), f.stepped_up))},
    "reset_counters": lambda c, a, t, f: {"task": task_dict(ha.reset_counters(c, a, t))},
}


_STEP_UP_TASK_ACTIONS = frozenset({"instruction", "approve", "reject", "transition", "reset_counters"})


@router.post("/tasks/{task_id}/{action}")
def task_action(request: Request, task_id: str, action: str, f: Post):
    if action not in _TASK_ACTIONS:
        raise Problem(404, "unknown_action", "unknown task action")
    if action == "instruction" and not (1 <= len(f.get("text", "")) <= 16000):
        raise Problem(422, "invalid_text", "instruction text must be 1..16000 characters")
    if action in _STEP_UP_TASK_ACTIONS:       # pause/resume/escalate/priority only slow things down: login suffices
        humans.require_step_up(bridge(request).settings, f.sess)
    f.stepped_up = humans.has_step_up(bridge(request).settings, f.sess)
    return done(request, human_tx(bridge(request), lambda c: _TASK_ACTIONS[action](c, f.actor, task_id, f)), action)


@router.post("/approvals/{approval_id}/revoke")
def revoke_approval(request: Request, approval_id: str, f: Post):
    """Withdraw an approved, not yet consumed approval (own party, step-up). The agent's consume then gets 409."""
    b = bridge(request)
    humans.require_step_up(b.settings, f.sess)
    a = human_tx(b, lambda c: ha.revoke_approval(c, f.actor, approval_id, f.get("note")))
    from ..domain.approvals import approval_dict
    return done(request, {"approval": approval_dict(a)}, "approval_revoked")


@router.post("/approvals/{approval_id}/decide")
def decide(request: Request, approval_id: str, f: Post):
    """Needs a fresh step-up (TOTP within the last 5 minutes on this session)."""
    b = bridge(request)
    humans.require_step_up(b.settings, f.sess)
    a = human_tx(b, lambda c: ha.decide_approval(c, f.actor, approval_id, f.get("decision", ""), f.get("note"),
                                                 b.settings.limits))
    from ..domain.approvals import approval_dict
    return done(request, {"approval": approval_dict(a)}, "decided")


def _enrollment(b: Bridge, token: str, ip: str | None):
    """Misses (unknown, used or expired links) are throttled per client address."""
    bucket = ("enrollmiss", humans.throttle_key(ip))
    per_min = b.settings.limits.enroll_miss_per_ip_per_min
    wait = b.limiter.blocked(bucket, per_min)
    if wait:
        raise Problem(429, "rate_limited", "too many invalid enrollment links from your address; wait and retry",
                      headers={"Retry-After": str(wait)})
    try:
        with b.db.read() as conn:
            return humans.enrollment(conn, token)
    except Problem:
        b.limiter.take(bucket, per_min)
        raise


@router.get("/enroll/{token}")
def enroll_info(request: Request, token: str):
    e = _enrollment(bridge(request), token, client_ip(request))
    if wants_html(request):
        return render(request, "enroll.html", token=token, enroll=e)
    return {"login": e["login"], "display_name": e["display_name"], "reset": e["human_id"] is not None}


@router.post("/enroll/{token}")
async def enroll(request: Request, token: str):
    """Form: password, password2. Returns the otpauth URI once (the dashboard renders it as a QR code)."""
    b = bridge(request)
    f = await request.form()
    _check_pre_session(request, b, f)
    if str(f.get("password", "")) != str(f.get("password2", f.get("password", ""))):
        raise Problem(422, "password_mismatch", "passwords differ")
    ip = client_ip(request)
    await _threaded(lambda: _enrollment(b, token, ip))     # invalid links are refused before any argon2 work
    pw = str(f.get("password", ""))
    async with _hash_slot(b, humans.throttle_key(ip)):
        pw_hash = await _hashing(lambda: humans.hash_password(pw))
    res = await _threaded(lambda: human_tx(b, lambda c: humans.enroll(c, token, pw, b.settings.totp_kek, pw_hash)))
    if wants_html(request):
        from ..web.enroll import enrolled_page
        resp = enrolled_page(request, res)
    else:
        resp = JSONResponse(res)
    resp.delete_cookie(PRE_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    return resp


@router.get("/api/keys")
def list_keys(request: Request, sess: Session):
    with bridge(request).db.read() as conn:
        return {"keys": ha.list_keys(conn)}


@router.post("/agents/{agent_id}/keys")
def create_key(request: Request, agent_id: str, f: Post):
    """Own-party agents only, after step-up. The token is in this response only."""
    b = bridge(request)
    humans.require_step_up(b.settings, f.sess)
    key_id, token = human_tx(b, lambda c: ha.create_agent_key(c, f.actor, agent_id, f.get("label", ""), b.settings.pepper))
    if wants_html(request):
        return render(request, "key_minted.html", key_id=key_id, token=token, agent_id=agent_id)
    return {"key_id": key_id, "token": token}


@router.post("/keys/{key_id}/revoke")
def revoke_key(request: Request, key_id: str, f: Post):
    b = bridge(request)
    humans.require_step_up(b.settings, f.sess)
    human_tx(b, lambda c: ha.revoke_agent_key(c, f.actor, key_id))
    return done(request, {"ok": True}, "revoked")


@router.post("/agents/{agent_id}/{action}")
def agent_action(request: Request, agent_id: str, action: str, f: Post):
    b = bridge(request)
    if action not in ("pause", "resume"):
        raise Problem(404, "unknown_action", "unknown agent action")
    humans.require_step_up(b.settings, f.sess)
    human_tx(b, lambda c: (ha.pause_agent if action == "pause" else ha.resume_agent)(c, f.actor, agent_id))
    return done(request, {"ok": True}, f"agent_{action}")
