"""FastAPI application factory, middleware (request id, body limit, security headers, JSON access log)."""
import logging
import re
import secrets
import time

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .. import __version__, logs
from ..config import Settings
from ..db import Database
from ..domain import sweeper
from ..errors import Problem
from ..util import request_id_var
from . import agent, human
from .deps import (INFLIGHT_HELD, PREAUTH, Bridge, RateLimiter, StorageGuard, auth_failure, bearer_token, client_ip_from_xff,
                   problem_response, verify_key)

SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"same-origin"), (b"cache-control", b"no-store"),
    (b"x-frame-options", b"DENY"), (b"x-robots-tag", b"noindex"),
    (b"strict-transport-security", b"max-age=31536000"),
]
_DEFAULT_CSP = (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
_BODY_METHODS = {"POST", "PUT", "PATCH"}
ARTIFACT_ROUTE = re.compile(r"/v1/tasks/[^/]+/artifacts")    # the only route that may carry 2 MiB
_PRE_SESSION = re.compile(r"/app/(login|enroll/[^/]*)")       # bodies accepted before any session exists
_CLOSE = {"Connection": "close"}


class BridgeMiddleware:
    """Pure ASGI: request id, caller identified BEFORE any body byte is read, bounded body buffering under a
    global budget (413/503), security headers, one JSON log line per request.

    Body limits: /v1/* needs a valid agent key before any body is read (else 401 + Connection: close); the
    artifact upload route (exact match, POST) may carry `artifact_max_bytes`, other /v1 calls `max_body_bytes`;
    /app forms with a valid session `session_body_bytes`; everything else (login, enroll, unknown paths, /app
    posts without a session) `pre_session_body_bytes`."""

    def __init__(self, app, settings: Settings, bridge=None):
        self.app, self.s, self.b = app, settings, bridge

    def _limit(self, scope, headers: dict) -> tuple[int, bool, Problem | None]:
        """(limit, large, refusal). Runs before the body is read; at most one indexed read + one HMAC."""
        path, lim = scope["path"], self.s.limits
        if path == "/v1" or path.startswith("/v1/"):
            token = bearer_token(_hdr(headers, b"authorization"))
            row = verify_key(self.b, token)
            if row is None:
                return 0, False, auth_failure(self.b, client_ip_from_xff(_hdr(headers, b"x-forwarded-for")))
            scope.setdefault("state", {})[PREAUTH] = (token, row)
            if scope["method"] == "POST" and ARTIFACT_ROUTE.fullmatch(path):
                return lim.artifact_max_bytes + 1024, True, None
            return lim.max_body_bytes, False, None
        if path.startswith("/app/") and not _PRE_SESSION.fullmatch(path) and self._has_session(headers):
            return lim.session_body_bytes, False, None
        return lim.pre_session_body_bytes, False, None

    def _has_session(self, headers: dict) -> bool:
        from starlette.requests import cookie_parser

        from ..domain import humans
        from .human import COOKIE
        token = cookie_parser(_hdr(headers, b"cookie") or "").get(COOKIE)
        if not token:
            return False
        with self.b.db.read() as conn:
            return humans.session(conn, self.s, token) is not None

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        rid = "req_" + secrets.token_hex(8)
        token = request_id_var.set(rid)
        start, status = time.monotonic(), [0]

        async def send_wrapped(msg):
            if msg["type"] == "http.response.start":
                status[0] = msg["status"]
                hdrs = list(msg.get("headers", []))
                names = {k.lower() for k, _ in hdrs}
                hdrs += [h for h in SECURITY_HEADERS if h[0] not in names]
                if b"content-security-policy" not in names:
                    hdrs.append(_DEFAULT_CSP)
                hdrs.append((b"x-request-id", rid.encode()))
                msg = {**msg, "headers": hdrs}
            await send(msg)

        async def refuse(p: Problem):
            p.headers = {**p.headers, **_CLOSE}     # the unread body is never consumed: close the connection
            return await problem_response(p)(scope, receive, send_wrapped)

        try:
            if scope["method"] in _BODY_METHODS:
                headers = dict(scope.get("headers", []))
                limit, large, refusal = self._limit(scope, headers)
                if refusal is not None:
                    return await refuse(refusal)
                cl = headers.get(b"content-length")
                declared = int(cl) if cl is not None and cl.isdigit() else None    # h11 already validated it
                if declared is not None and declared > limit:
                    return await refuse(Problem(413, "payload_too_large", f"request body exceeds {limit} bytes"))
                reserve = declared if declared is not None else limit + 1
                # a key holder's per-key in-flight slot comes first, so stalled posts of one key cannot fill the
                # global body budget (the route dependency then skips its own acquire for this request).
                pre = scope.get("state", {}).get(PREAUTH)
                key_id = pre[1]["key_id"] if pre else None
                if key_id is not None:
                    if not self.b.inflight.acquire(key_id, self.s.limits.max_in_flight_per_key):
                        return await refuse(Problem(429, "too_many_in_flight", "too many concurrent requests for "
                                                    "this key; retry shortly", headers={"Retry-After": "1"}))
                    scope["state"][INFLIGHT_HELD] = key_id
                if not self.b.bodies.acquire(reserve, large):
                    if key_id is not None:
                        self.b.inflight.release(key_id)
                    return await refuse(Problem(503, "server_busy", "too many request bodies in flight; retry shortly",
                                                headers={"Retry-After": "5"}))
                try:
                    chunks, size, too_big, complete = [], 0, False, False
                    while True:
                        msg = await receive()
                        if msg["type"] != "http.request":
                            break                       # disconnect mid-body; the body is incomplete
                        chunks.append(msg.get("body", b""))
                        size += len(chunks[-1])
                        if size > limit or size > reserve:
                            too_big = True
                            break
                        if not msg.get("more_body"):
                            complete = True
                            break
                    if too_big:
                        chunks.clear()
                        return await refuse(Problem(413, "payload_too_large", f"request body exceeds {limit} bytes"))
                    if not complete or (declared is not None and size != declared):
                        chunks.clear()                  # truncated body: never reaches the app; send nothing
                        return
                    body, done = b"".join(chunks), [False]
                    chunks.clear()

                    async def replay():
                        if not done[0]:
                            done[0] = True
                            return {"type": "http.request", "body": body, "more_body": False}
                        return await receive()
                    return await self.app(scope, replay, send_wrapped)
                finally:
                    self.b.bodies.release(reserve, large)
                    if key_id is not None:
                        self.b.inflight.release(key_id)
            return await self.app(scope, receive, send_wrapped)
        finally:
            route = scope.get("route")
            st = scope.get("state") or {}
            logs.event("request", method=scope["method"], route=getattr(route, "path", "-"), status=status[0],
                       ms=round((time.monotonic() - start) * 1000, 1), principal=st.get("principal"),
                       key_id=st.get("key_id"))
            request_id_var.reset(token)


def _hdr(headers: dict, name: bytes) -> str | None:
    v = headers.get(name)
    return v.decode("latin-1") if v is not None else None


def create_app(settings: Settings, db: Database | None = None) -> FastAPI:
    logs.setup()
    app = FastAPI(title="Agent Bridge API", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url="/v1/openapi.json" if settings.expose_openapi else None,
                  description="Agent-to-agent coordination hub. Bearer `abk_…` keys; every POST needs an "
                              "`Idempotency-Key`; errors are `application/problem+json` with a stable `code`. "
                              "Message bodies are untrusted data. See docs/SPEC.md.")
    app.state.bridge = Bridge(settings, db or Database(settings.db_path), RateLimiter(), StorageGuard(settings), {})
    app.add_middleware(BridgeMiddleware, settings=settings, bridge=app.state.bridge)
    app.include_router(agent.router)
    app.include_router(human.router)
    sweeper.install(app)

    @app.exception_handler(Problem)
    async def _problem(request, exc: Problem):
        return problem_response(exc)

    @app.exception_handler(RequestValidationError)
    async def _validation(request, exc: RequestValidationError):
        errors = [{"loc": list(e.get("loc", [])), "msg": e.get("msg", ""), "type": e.get("type", "")}
                  for e in exc.errors()][:20]   # never echo the input back
        return problem_response(Problem(422, "validation_error", "request failed validation", extra={"errors": errors}))

    @app.exception_handler(StarletteHTTPException)
    async def _http(request, exc: StarletteHTTPException):
        if exc.status_code == 404:          # the normal problem body (schemas/error.json)
            return problem_response(Problem(404, "not_found", "not found"))
        code = {405: "method_not_allowed"}.get(exc.status_code, "http_error")
        return problem_response(Problem(exc.status_code, code, str(exc.detail)))

    @app.exception_handler(Exception)
    async def _unhandled(request, exc: Exception):
        tb = exc.__traceback__
        while tb and tb.tb_next:
            tb = tb.tb_next
        where = f"{tb.tb_frame.f_code.co_filename.rsplit('/', 1)[-1]}:{tb.tb_lineno}" if tb else "-"
        logs.event("unhandled_error", logging.ERROR, exc_type=type(exc).__name__, where=where)
        return problem_response(Problem(500, "internal_error", "unexpected server error"))

    from .. import web
    web.install(app)            # dashboard pages + HTML error rendering for browsers (after the JSON handler)
    return app
