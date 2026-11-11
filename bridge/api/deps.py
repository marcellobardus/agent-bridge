"""Request plumbing: agent auth, scopes, rate limits, storage guard, idempotent write transactions."""
import dataclasses
import hashlib
import json
import os
import re
import threading
import time

from fastapi import Depends, Request
from fastapi.responses import JSONResponse

from ..config import Settings
from ..db import Database
from ..domain import keys
from ..domain.common import Actor
from ..errors import Problem
from ..util import dumps, now_ms, request_id_var

IDEMPOTENT_STATUSES = (409, 410, 422)   # deterministic refusals are stored and replayed; 429/5xx never are
TRANSIENT_CODES = frozenset({"task_paused"})   # a 409 that a human can lift: never stored, so a retry works
_IDEM_KEY = re.compile(r"[A-Za-z0-9:._-]{8,128}")


class RateLimiter:
    """In-memory token buckets (per minute). Bounded: full (idle) buckets are pruned when the table grows."""

    MAX_ENTRIES = 20_000

    def __init__(self):
        self._b: dict = {}
        self._lock = threading.Lock()

    def _refill(self, key, per_min: int) -> list:
        now = time.monotonic()
        b = self._b.get(key)
        if b is None:
            if len(self._b) >= self.MAX_ENTRIES:
                self._prune(now)
            b = self._b[key] = [float(per_min), now, per_min]
        b[0] = min(per_min, b[0] + (now - b[1]) * per_min / 60.0)
        b[1], b[2] = now, per_min
        return b

    def _prune(self, now: float) -> None:
        full = [k for k, (tok, ts, pm) in self._b.items() if tok + (now - ts) * pm / 60.0 >= pm]
        for k in full:
            del self._b[k]
        if len(self._b) >= self.MAX_ENTRIES:          # still full: drop the least recently used half
            for k, _ in sorted(self._b.items(), key=lambda kv: kv[1][1])[: len(self._b) // 2]:
                del self._b[k]

    def blocked(self, key, per_min: int) -> int:
        with self._lock:
            b = self._refill(key, per_min)
            return 0 if b[0] >= 1 else int((1 - b[0]) * 60 / per_min) + 1

    def take(self, key, per_min: int) -> int:
        """Consume one token; returns 0 if allowed, else seconds to wait."""
        with self._lock:
            b = self._refill(key, per_min)
            if b[0] >= 1:
                b[0] -= 1
                return 0
            return int((1 - b[0]) * 60 / per_min) + 1


class InFlight:
    """Concurrent requests per agent key: bounds the memory one key can pin at once."""

    def __init__(self):
        self._n: dict = {}
        self._lock = threading.Lock()

    def acquire(self, key: str, limit: int) -> bool:
        with self._lock:
            if self._n.get(key, 0) >= limit:
                return False
            self._n[key] = self._n.get(key, 0) + 1
            return True

    def release(self, key: str) -> None:
        with self._lock:
            n = self._n.get(key, 0) - 1
            if n > 0:
                self._n[key] = n
            else:
                self._n.pop(key, None)


class BodyBudget:
    """Global, non-blocking budget for request bodies held in memory at once (bytes, plus a count of
    artifact-size bodies). A request that does not fit is refused (503) before any of its body is read."""

    def __init__(self, max_bytes: int, max_large: int):
        self.max_bytes, self.max_large = max_bytes, max_large
        self.used, self.large = 0, 0
        self._lock = threading.Lock()

    def acquire(self, n: int, large: bool) -> bool:
        with self._lock:
            if self.used + n > self.max_bytes or (large and self.large >= self.max_large):
                return False
            self.used += n
            self.large += int(large)
            return True

    def release(self, n: int, large: bool) -> None:
        with self._lock:
            self.used = max(0, self.used - n)
            self.large = max(0, self.large - int(large))


class _Waiter:
    __slots__ = ("key", "trusted", "fut", "granted")

    def __init__(self, key, trusted, fut):
        self.key, self.trusted, self.fut, self.granted = key, trusted, fut, False


class LoginGate:
    """At most `per_key` password hashes in flight (or waiting) per key and `total` overall, `reserved` of
    which only keys that logged in successfully before may use (bounded in-memory LRU). A caller that finds no
    free slot WAITS (asyncio, never a thread) up to `wait_s` in a queue of at most `queue_max`; over the queue cap,
    or with its key already in flight, it is refused at once. No argon2 work happens before a slot is granted.
    `acquire`/`release` are the non-blocking, synchronous halves (used by tests and by `wait_acquire`)."""

    def __init__(self, per_key: int, total: int, queue_max: int = 0, wait_s: float = 0.0, reserved: int = 0,
                 trusted_max: int = 512):
        self.per_key, self.total, self.queue_max, self.wait_s = per_key, total, queue_max, wait_s
        self.reserved, self.trusted_max = max(0, min(reserved, total - 1)), trusted_max     # never starve everyone
        self._n: dict = {}
        self._all = 0
        self._q: list = []
        self._trusted: dict = {}               # insertion-ordered: oldest first
        self._lock = threading.Lock()

    def mark_ok(self, key: str) -> None:
        """A successful login from this key: it may use the reserved slot from now on (bounded, LRU)."""
        with self._lock:
            self._trusted.pop(key, None)
            self._trusted[key] = True
            while len(self._trusted) > self.trusted_max:
                del self._trusted[next(iter(self._trusted))]

    def _cap(self, trusted: bool) -> int:
        return self.total if trusted else max(0, self.total - self.reserved)

    def acquire(self, key: str) -> bool:
        with self._lock:
            if self._n.get(key, 0) >= self.per_key or self._all >= self._cap(key in self._trusted):
                return False
            self._n[key] = self._n.get(key, 0) + 1
            self._all += 1
            return True

    def _drop_claim(self, key: str) -> None:
        n = self._n.get(key, 0) - 1
        if n > 0:
            self._n[key] = n
        else:
            self._n.pop(key, None)

    def release(self, key: str) -> None:
        with self._lock:
            self._release_locked(key)

    def _release_locked(self, key: str) -> None:
        self._drop_claim(key)
        self._all = max(0, self._all - 1)
        for w in list(self._q):                 # FIFO; a trusted waiter may take the reserved slot
            if self._all < self._cap(w.trusted):
                self._q.remove(w)
                w.granted = True
                self._all += 1
                w.fut.get_loop().call_soon_threadsafe(self._set, w)

    @staticmethod
    def _set(w: _Waiter) -> None:
        if not w.fut.done():
            w.fut.set_result(True)

    async def wait_acquire(self, key: str) -> bool:
        import asyncio
        with self._lock:
            trusted = key in self._trusted
            if self._n.get(key, 0) >= self.per_key:
                return False
            if self._all < self._cap(trusted):
                self._n[key] = self._n.get(key, 0) + 1
                self._all += 1
                return True
            if len(self._q) >= self.queue_max or self.wait_s <= 0:
                return False
            w = _Waiter(key, trusted, asyncio.get_running_loop().create_future())
            self._n[key] = self._n.get(key, 0) + 1          # a waiting key counts as in flight
            self._q.append(w)
        try:
            await asyncio.wait_for(w.fut, self.wait_s)
            return True
        except asyncio.TimeoutError:
            ok = False
        except BaseException:
            self._abandon(w)
            raise
        self._abandon(w)
        return ok

    def _abandon(self, w: _Waiter) -> None:
        with self._lock:
            if w.granted:
                self._release_locked(w.key)     # granted just as the wait ended: hand the slot back
            else:
                if w in self._q:
                    self._q.remove(w)
                self._drop_claim(w.key)


class StorageGuard:
    """Low disk space or inodes -> writes answer 503 storage_degraded. Checked at most every 30 s."""

    def __init__(self, settings: Settings):
        self.s = settings
        self._at, self._degraded = 0.0, False

    def degraded(self) -> bool:
        if time.monotonic() - self._at > 30 or self._at == 0:
            st = os.statvfs(os.path.dirname(os.path.abspath(self.s.db_path)))
            free_bytes = st.f_bavail * st.f_frsize
            inode_pct = 100.0 * st.f_favail / st.f_files if st.f_files else 100.0
            self._degraded = free_bytes < self.s.limits.min_free_bytes or inode_pct < self.s.limits.min_free_inodes_pct
            self._at = time.monotonic()
        return self._degraded


@dataclasses.dataclass
class Bridge:
    settings: Settings
    db: Database
    limiter: RateLimiter
    storage: StorageGuard
    last_used: dict
    inflight: InFlight = dataclasses.field(default_factory=InFlight)
    bodies: BodyBudget | None = None
    login_gate: LoginGate | None = None
    stepup_gate: LoginGate | None = None

    def __post_init__(self):
        lim = self.settings.limits
        if self.bodies is None:
            self.bodies = BodyBudget(lim.max_buffered_bytes, lim.max_large_bodies)
        if self.login_gate is None:
            self.login_gate = LoginGate(lim.login_in_flight_per_ip, lim.login_in_flight_global, lim.login_queue_max,
                                        lim.login_wait_s, lim.login_reserved_slots)
        if self.stepup_gate is None:      # keyed by session; needs a valid session, so outsiders cannot fill it
            self.stepup_gate = LoginGate(1, lim.stepup_in_flight_global, lim.login_queue_max, lim.login_wait_s)


def bridge(request: Request) -> Bridge:
    return request.app.state.bridge


@dataclasses.dataclass
class Principal:
    actor: Actor
    key_id: str
    scopes: frozenset
    paused: bool


def client_ip_from_xff(xff: str | None) -> str | None:
    """Right-most X-Forwarded-For entry: the one the tunnel (ngrok) appended. Left-most entries are
    client-supplied and never trusted. None when there is no header (a local caller)."""
    return xff.split(",")[-1].strip() or None if xff else None


def client_ip(request: Request) -> str | None:
    return client_ip_from_xff(request.headers.get("x-forwarded-for"))


def bearer_token(authorization: str | None) -> str:
    auth = authorization or ""
    return auth[7:].strip() if auth[:7].lower() == "bearer " else ""


def verify_key(b: "Bridge", token: str):
    """The one key check (the body-limit middleware and the route dependency): one indexed read + one constant-time HMAC.
    Returns the joined key/agent row or None. Charges nothing."""
    if not keys.parse(token):
        return None
    with b.db.read() as conn:
        return keys.authenticate(conn, token, b.settings.pepper)


def auth_failure(b: "Bridge", ip: str | None) -> Problem:
    """Charge a failed authentication to the caller's IP bucket and the global backstop. Only failures
    are ever charged or checked, so a flood of bad keys can never lock out a valid key."""
    from ..domain.humans import throttle_key
    lim = b.settings.limits
    ip_bucket = ("authfail", throttle_key(ip))
    wait = b.limiter.blocked(ip_bucket, lim.unauth_per_ip_per_min) or b.limiter.blocked("authfail",
                                                                                        lim.unauth_global_per_min)
    if wait:
        return Problem(429, "rate_limited", "too many failed authentications", headers={"Retry-After": str(wait)})
    b.limiter.take(ip_bucket, lim.unauth_per_ip_per_min)
    b.limiter.take("authfail", lim.unauth_global_per_min)
    return Problem(401, "invalid_key", "missing, malformed, unknown, expired or revoked API key",
                   headers={"WWW-Authenticate": "Bearer"})


def _auth_failed(b: Bridge, request: Request) -> Problem:
    return auth_failure(b, client_ip(request))


INFLIGHT_HELD = "_bridge_inflight_held"   # scope["state"] key: the middleware already holds this key's in-flight slot
PREAUTH = "_bridge_preauth"      # scope["state"] key: (token, row) verified by BridgeMiddleware before the body


def _authenticate(request: Request) -> Principal:
    """Authenticate FIRST (one indexed read + one HMAC); rate buckets are consulted only afterwards.
    A key already verified by the middleware for this very request (body-carrying /v1 calls) is not re-read."""
    b = bridge(request)
    lim = b.settings.limits
    token = bearer_token(request.headers.get("authorization"))
    pre = (request.scope.get("state") or {}).get(PREAUTH)
    if pre is not None and pre[0] == token:
        row = pre[1]
    else:
        row = verify_key(b, token)
    if row is None:
        raise _auth_failed(b, request)
    request.state.principal = row["agent_id"]
    request.state.key_id = row["key_id"]
    wait = b.limiter.take(("key", row["key_id"]), lim.per_key_per_min)
    if wait:
        raise Problem(429, "rate_limited", "per-key request rate exceeded", headers={"Retry-After": str(wait)})
    now = now_ms()
    if now - b.last_used.get(row["key_id"], 0) > 60_000:
        b.last_used[row["key_id"]] = now
        with b.db.write() as conn:
            conn.execute("UPDATE api_keys SET last_used_at=? WHERE id=?", (now, row["key_id"]))
    actor = Actor("agent", row["agent_id"], row["party_id"], row["key_id"])
    paused = row["agent_paused_at"] is not None or row["party_paused_at"] is not None
    return Principal(actor, row["key_id"], frozenset(json.loads(row["scopes"])), paused)


def require(scope: str):
    def dep(request: Request):
        p = _authenticate(request)
        if scope not in p.scopes:
            raise Problem(403, "scope_missing", f"this key lacks the {scope!r} scope")
        b = bridge(request)
        if (request.scope.get("state") or {}).get(INFLIGHT_HELD) == p.key_id:
            yield p                  # taken (and released) by the middleware
            return
        if not b.inflight.acquire(p.key_id, b.settings.limits.max_in_flight_per_key):
            raise Problem(429, "too_many_in_flight", "too many concurrent requests for this key; retry shortly",
                          headers={"Retry-After": "1"})
        try:
            yield p
        finally:
            b.inflight.release(p.key_id)
    dep.__name__ = f"require_{scope.replace(':', '_')}"
    return dep


def problem_response(p: Problem) -> JSONResponse:
    return JSONResponse(p.body(request_id_var.get()), status_code=p.status, headers=p.headers,
                        media_type="application/problem+json")


class WriteCtx:
    def __init__(self, b: Bridge, principal: Principal, key: str, request_hash: str, body: bytes):
        self.b, self.principal, self.key, self.request_hash, self.raw_body = b, principal, key, request_hash, body

    @property
    def actor(self) -> Actor:
        return self.principal.actor

    def run(self, fn, status: int = 200) -> JSONResponse:
        """Run fn(conn) in one write transaction together with the idempotency record.
        fn returns a JSON body, or (body, status, headers)."""
        agent = self.actor.id
        with self.b.db.writer() as conn:
            conn.execute("BEGIN IMMEDIATE")
            prior = conn.execute("SELECT request_sha256, status, response FROM idempotency_keys WHERE agent_id=? AND key=?",
                                 (agent, self.key)).fetchone()
            if prior is not None:
                conn.execute("ROLLBACK")
                if prior["request_sha256"] != self.request_hash:
                    raise Problem(422, "idempotency_key_reuse", "this Idempotency-Key was used with a different request")
                stored = json.loads(prior["response"])
                media = "application/problem+json" if prior["status"] >= 400 else "application/json"
                return JSONResponse(stored["b"], status_code=prior["status"],
                                    headers={**stored["h"], "Idempotent-Replayed": "true"}, media_type=media)
            try:
                out = fn(conn)
                body, code, headers = out if isinstance(out, tuple) else (out, status, {})
            except Problem as p:
                if not p.commit:
                    conn.execute("ROLLBACK")
                    conn.execute("BEGIN IMMEDIATE")
                if p.status not in IDEMPOTENT_STATUSES or p.code in TRANSIENT_CODES:
                    if p.commit:
                        conn.execute("COMMIT")
                    raise
                body, code, headers = p.body(request_id_var.get()), p.status, p.headers
            conn.execute("INSERT INTO idempotency_keys (agent_id, key, request_sha256, status, response, created_at)"
                         " VALUES (?,?,?,?,?,?)", (agent, self.key, self.request_hash, code,
                                                   dumps({"b": body, "h": headers}), now_ms()))
            conn.execute("COMMIT")
        media = "application/problem+json" if code >= 400 else "application/json"
        return JSONResponse(body, status_code=code, headers=headers, media_type=media)


def write_ctx(scope: str):
    async def dep(request: Request, p: Principal = Depends(require(scope))) -> WriteCtx:
        b = bridge(request)
        key = request.headers.get("idempotency-key")
        if not key:
            raise Problem(400, "missing_idempotency_key", "every POST needs an Idempotency-Key header")
        if not _IDEM_KEY.fullmatch(key):
            raise Problem(400, "invalid_idempotency_key", "Idempotency-Key: 8-128 chars of [A-Za-z0-9:._-]")
        if p.paused:
            raise Problem(423, "agent_paused", "your agent or party is paused by a human; reads still work")
        wait = b.limiter.take(("write", p.key_id), b.settings.limits.per_key_writes_per_min)
        if wait:
            raise Problem(429, "rate_limited", "per-key write rate exceeded", headers={"Retry-After": str(wait)})
        if b.storage.degraded():
            raise Problem(503, "storage_degraded", "server storage is low; writes are refused, reads still work",
                          headers={"Retry-After": "300"})
        body = await request.body()
        h = hashlib.sha256()
        for part in (request.method.encode(), request.url.path.encode(), request.url.query.encode(), body):
            h.update(hashlib.sha256(part).digest())
        return WriteCtx(b, p, key, h.hexdigest(), body)
    return dep


def human_tx(b: Bridge, fn):
    """Write transaction for human/CLI actions; a Problem with commit=True keeps its side effects."""
    with b.db.writer() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            out = fn(conn)
        except Problem as p:
            if p.commit:
                conn.execute("COMMIT")
            raise
        conn.execute("COMMIT")
        return out
