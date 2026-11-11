"""Hardening regressions: pre-auth body buffering, OpenAPI/404, login gate, step-up, pre-session CSRF token,
account oracle, audit noise, enrollment TTL + throttle, approvals query."""
import asyncio
import logging
import re
import threading
import time

import pytest
from fastapi.testclient import TestClient

from bridge import ops
from bridge.api.app import create_app
from bridge.domain import humans, keys
from bridge.web import queries as qy

from conftest import make_settings

PW = "correct horse battery"
HTML = {"Accept": "text/html"}


def fresh(env):
    return TestClient(env.app, base_url="https://testserver")


def asgi(app, method, path, headers=None, body=b""):
    """Call the ASGI app directly and record every call of `receive` (to prove the body was never read)."""
    calls, sent = [], []

    async def receive():
        calls.append(1)
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(m):
        sent.append(m)
    hdrs = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method, "scheme": "https",
             "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "", "headers": hdrs,
             "client": ("127.0.0.1", 40000), "server": ("testserver", 443), "state": {}}
    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    return start["status"], {k.decode(): v.decode() for k, v in start["headers"]}, calls


@pytest.fixture
def henv(env):
    env.add_human("alice", "alice")
    env.add_human("bob", "bob")
    return env


def upload(agent, path, n, ctype="text/plain"):
    return agent.post(path, content=b"a" * n, headers={"Content-Type": ctype})


# ---------------------------------------------------------------- pre-auth body buffering

@pytest.mark.parametrize("path", ["/v1/tasks/x/artifacts", "/v1/tasks", "/v1/inbox/ack", "/v1/nonexistent"])
def test_unauthenticated_post_is_refused_before_the_body_is_read(env, path):
    big = str(2 * 1024 * 1024)
    for hdrs in ({}, {"Authorization": "Bearer abk_aaaaaaaaaaaa_" + "b" * 43}, {"Authorization": "Basic x"}):
        status, out, calls = asgi(env.app, "POST", path, {"Content-Length": big, **hdrs}, b"x" * 10)
        assert status == 401 and calls == [], (path, hdrs)
        assert out["connection"] == "close"
    assert env.app.state.bridge.bodies.used == 0


def test_auth_failures_in_the_middleware_are_still_rate_limited(make_env):
    e = make_env(unauth_per_ip_per_min=3)
    codes = [asgi(e.app, "POST", "/v1/tasks", {"Content-Length": "10", "X-Forwarded-For": "198.51.100.1"})[0]
             for _ in range(5)]
    assert codes[:3] == [401] * 3 and codes[3:] == [429, 429]
    assert e.agent_a.create_task()["id"]                         # a valid key is never charged


def test_valid_key_is_verified_once_and_large_upload_still_works(env, monkeypatch):
    t = env.agent_a.create_task()
    real, n = keys.authenticate, []

    def spy(*a, **kw):
        n.append(1)
        return real(*a, **kw)
    monkeypatch.setattr(keys, "authenticate", spy)
    r = upload(env.agent_a, f"/v1/tasks/{t['id']}/artifacts?filename=big.txt", 1024 * 1024)
    assert r.status_code == 201, r.text
    assert len(n) == 1                                            # middleware verified; the dependency reused it
    assert env.app.state.bridge.bodies.used == 0 and env.app.state.bridge.bodies.large == 0


def test_large_limit_only_on_the_exact_artifact_route(env):
    t = env.agent_a.create_task()
    for path in (f"/v1/tasks/{t['id']}/x/artifacts", "/v1/artifacts", f"/v1/tasks/{t['id']}/artifacts/",
                 "/v1/x/artifacts", f"/v1/tasks/{t['id']}/messages?a=/artifacts"):
        r = upload(env.agent_a, path, 300 * 1024)
        assert r.status_code == 413 and r.json()["code"] == "payload_too_large", path
    status, _, calls = asgi(env.app, "GET", f"/v1/tasks/{t['id']}/artifacts",
                            {"Content-Length": str(300 * 1024), "Authorization": f"Bearer {env.agent_a.token}"})
    assert status != 413                                          # GET is not a body method


def test_pre_session_bodies_get_the_small_limit(henv):
    big = {"login": "alice", "password": "x" * 9000, "totp": "000000"}
    r = fresh(henv).post("/app/login", data=big)
    assert r.status_code == 413
    with henv.db.write() as c:
        token = humans.invite(c, ops.CLI, "newbie", "bob", "Newbie")
    assert fresh(henv).post(f"/app/enroll/{token}", data={"password": "x" * 9000}).status_code == 413
    assert fresh(henv).post("/app/logout", data={"pad": "x" * 9000}).status_code == 413     # no session
    assert fresh(henv).post("/nowhere", content=b"x" * 9000).status_code == 413
    status, _, calls = asgi(henv.app, "POST", "/app/login", {"Content-Length": "100000"})
    assert status == 413 and calls == []                          # declared size: refused before reading


def test_session_forms_allow_a_full_instruction(henv):
    t = henv.agent_a.create_task()
    m = henv.login("alice")
    text = "é" * 16000                                            # 2-byte chars, %-encoded: ~96 KB form
    r = m.post(f"/app/tasks/{t['id']}/instruction", text=text)
    assert r.status_code == 200, r.text[:200]
    r = m.post(f"/app/tasks/{t['id']}/instruction", text="x", pad="y" * (210 * 1024))
    assert r.status_code == 413


def test_global_budget_answers_503_before_reading(env):
    b = env.app.state.bridge
    t = env.agent_a.create_task()
    auth = {"Authorization": f"Bearer {env.agent_a.token}"}
    assert b.bodies.acquire(b.bodies.max_bytes - 100, False)
    try:
        status, out, calls = asgi(env.app, "POST", "/v1/tasks", {"Content-Length": "1000", **auth})
        assert status == 503 and out["retry-after"] == "5" and out["connection"] == "close" and calls == []
        assert env.agent_a.get("/v1/me").status_code == 200       # reads are unaffected
    finally:
        b.bodies.release(b.bodies.max_bytes - 100, False)
    for _ in range(b.bodies.max_large):                           # all artifact slots taken
        assert b.bodies.acquire(1, True)
    try:
        status, out, calls = asgi(env.app, "POST", f"/v1/tasks/{t['id']}/artifacts",
                                  {"Content-Length": "1000", **auth})
        assert status == 503 and calls == []
        assert env.agent_a.post(f"/v1/tasks/{t['id']}/messages",
                                {"type": "NOTE", "text": "small bodies still pass"}).status_code != 503
    finally:
        for _ in range(b.bodies.max_large):
            b.bodies.release(1, True)
    assert b.bodies.used == 0 and b.bodies.large == 0


def test_budget_defaults_and_config():
    from bridge.config import Limits
    lim = Limits()
    assert lim.max_large_bodies == 4 and lim.max_buffered_bytes == 16 * 1024 * 1024
    assert lim.pre_session_body_bytes == 8 * 1024
    assert lim.max_large_bodies * (lim.artifact_max_bytes + 1024) <= lim.max_buffered_bytes


def test_concurrent_unauthenticated_uploads_never_buffer(env):
    """N parked unauthenticated 2 MiB uploads: each is answered 401 without one body byte being read."""
    results = []

    def one():
        results.append(asgi(env.app, "POST", "/v1/tasks/x/artifacts", {"Content-Length": str(2 * 1024 * 1024)},
                            b"x" * (2 * 1024 * 1024)))
    th = [threading.Thread(target=one) for _ in range(20)]
    for x in th:
        x.start()
    for x in th:
        x.join()
    assert all(s in (401, 429) and calls == [] for s, _, calls in results)


# ---------------------------------------------------------------- OpenAPI / 404

def test_openapi_not_served_by_default_and_small_404(env, tmp_path):
    r = env.client.get("/v1/openapi.json")
    assert r.status_code == 404 and r.json()["code"] == "not_found"
    assert env.client.get("/docs").status_code == 404 and env.client.get("/redoc").status_code == 404
    r = env.client.get("/some/random/path")
    assert r.status_code == 404 and r.json()["code"] == "not_found" and {"title", "status", "detail", "request_id"} <= set(r.json())
    s = make_settings(tmp_path / "o")
    (tmp_path / "o").mkdir()
    s.db_path = str(tmp_path / "o" / "b.db")
    s.expose_openapi = True
    ops.init_db(s.db_path)
    assert "paths" in TestClient(create_app(s), base_url="https://testserver").get("/v1/openapi.json").json()
    assert "/v1/tasks" in env.app.openapi()["paths"]              # scripts/export_openapi.py still works


# ---------------------------------------------------------------- login gate

def test_login_gate_skips_the_hash_when_refused(henv, monkeypatch):
    hashed = []
    real = humans.verify_password

    def spy(phc, pw):
        hashed.append(threading.current_thread().name)
        return real(phc, pw)
    monkeypatch.setattr(humans, "verify_password", spy)
    gate = henv.app.state.bridge.login_gate
    gate.wait_s = 0.2
    assert gate.acquire(humans.throttle_key("203.0.113.5"))       # a login from this address is in flight
    try:
        r = fresh(henv).post("/app/login", data={"login": "alice", "password": PW, "totp": henv.code("alice")},
                             headers={"X-Forwarded-For": "203.0.113.5"})
        assert r.status_code == 429 and r.headers["retry-after"] and not hashed     # 1 per address: refused at once
        r = fresh(henv).post("/app/login", data={"login": "alice", "password": PW, "totp": henv.code("alice")},
                             headers={"X-Forwarded-For": "203.0.113.6"})
        assert r.status_code == 200 and hashed                    # another address is not affected
    finally:
        gate.release(humans.throttle_key("203.0.113.5"))
    assert all(n.startswith("argon2") for n in hashed)            # dedicated hash thread, not the shared pool
    held = [f"x{i}" for i in range(gate.total - gate.reserved)]
    for k in held:
        assert gate.acquire(k)
    try:
        hashed.clear()
        t0 = time.time()
        r = fresh(henv).post("/app/login", data={"login": "alice", "password": "y", "totp": "1"},
                             headers={"X-Forwarded-For": "203.0.113.7"})
        assert r.status_code == 429 and not hashed and time.time() - t0 >= 0.15     # waited, then gave up
    finally:
        for k in held:
            gate.release(k)
    assert gate._all == 0 and not gate._n and not gate._q


def test_per_ip_bucket_is_charged_before_the_hash(make_env, monkeypatch):
    e = make_env(login_attempts_per_ip_per_min=2)
    e.add_human("alice", "alice")
    hashed = []
    real = humans.verify_password
    monkeypatch.setattr(humans, "verify_password", lambda phc, pw: hashed.append(1) or real(phc, pw))
    xff = {"X-Forwarded-For": "192.0.2.50"}
    for _ in range(2):
        assert fresh(e).post("/app/login", data={"login": "nobody", "password": "y", "totp": "1"},
                             headers=xff).status_code == 401
    r = fresh(e).post("/app/login", data={"login": "nobody", "password": "y", "totp": "1"}, headers=xff)
    assert r.status_code == 429 and len(hashed) == 2


def test_step_up_and_enroll_use_the_gates(henv):
    m = henv.login("alice", step_up=False)
    b = henv.app.state.bridge
    with henv.db.read() as c:
        sess_key = "s:" + c.execute("SELECT token_hash FROM sessions").fetchone()[0].hex()
    assert b.stepup_gate.acquire(sess_key)                         # this session's step-up is in flight
    try:
        r = m.post("/app/step-up", password=PW, totp=henv.code("alice", time.time() + 30))
        assert r.status_code == 429
    finally:
        b.stepup_gate.release(sess_key)
    assert b.login_gate.acquire(humans.throttle_key(None))
    try:
        with henv.db.write() as c:
            token = humans.invite(c, ops.CLI, "newbie", "bob", "Newbie")
        assert fresh(henv).post(f"/app/enroll/{token}", data={"password": "a-long-enough-pw"}).status_code == 429
    finally:
        b.login_gate.release(humans.throttle_key(None))


# ---------------------------------------------------------------- step-up

def _approval(env):
    t = env.agent_a.create_task(responsible_agent_id="agent-b")
    env.agent_b.post(f"/v1/tasks/{t['id']}/accept")
    r = env.agent_b.post(f"/v1/tasks/{t['id']}/approvals", {"kind": "prod_deploy", "summary": "deploy",
                                                           "action": {"x": 1}})
    assert r.status_code == 201, r.text
    return r.json()["approval"]


def test_login_is_not_a_step_up(henv):
    apr = _approval(henv)
    party = apr["approver_party"]
    b = henv.login(party, step_up=False)
    with henv.db.read() as c:
        assert c.execute("SELECT step_up_at FROM sessions").fetchone()[0] is None
    r = b.post(f"/app/approvals/{apr['id']}/decide", decision="approve")
    assert r.status_code == 403 and r.json()["code"] == "step_up_required"
    for path, data in ((f"/app/agents/{'agent-b' if party == 'bob' else 'agent-a'}/keys", {"label": "x"}),
                       (f"/app/agents/{'agent-b' if party == 'bob' else 'agent-a'}/pause", {}),
                       (f"/app/keys/{keys.parse(henv.agent_a.token)[0]}/revoke", {})):
        assert b.post(path, **data).json()["code"] == "step_up_required", path
    login_code = henv.code(party)                                 # the code that was just used to log in
    r = b.post("/app/step-up", password=PW, totp=login_code)
    assert r.status_code == 401 and r.json()["code"] == "step_up_failed"       # replay refused
    assert b.post(f"/app/approvals/{apr['id']}/decide", decision="approve").json()["code"] == "step_up_required"
    r = b.post("/app/step-up", password=PW, totp=henv.code(party, time.time() + 30))
    assert r.status_code == 200, r.text
    r = b.post(f"/app/approvals/{apr['id']}/decide", decision="approve")
    assert r.status_code == 200 and r.json()["approval"]["state"] == "approved"


def test_html_flow_shows_step_up_form(henv):
    apr = _approval(henv)
    b = henv.login(apr["approver_party"], step_up=False)
    r = b.c.post(f"/app/approvals/{apr['id']}/decide", data={"csrf_token": b.csrf, "decision": "approve"},
                 headers=HTML)
    assert r.status_code == 403 and 'action="/app/step-up?next=' in r.text


# ---------------------------------------------------------------- pre-session CSRF token

def _pre(r):
    return re.search(r'name="pre_csrf" value="([^"]+)"', r.text).group(1)


def test_login_page_sets_pre_session_cookie(henv):
    c = fresh(henv)
    r = c.get("/app/login", headers=HTML)
    sc = r.headers["set-cookie"]
    assert sc.startswith("__Host-ab_pre=") and "Secure" in sc and "HttpOnly" in sc and "samesite=strict" in sc.lower()
    assert "Path=/" in sc and "Domain" not in sc
    tok = _pre(r)
    assert c.cookies.get("__Host-ab_pre") == tok
    assert _pre(c.get("/app/login", headers=HTML)) == tok         # stable across tabs


def test_browser_post_needs_matching_token(henv):
    c = fresh(henv)
    tok = _pre(c.get("/app/login", headers=HTML))
    data = {"login": "alice", "password": PW, "totp": henv.code("alice")}
    for extra in ({}, {"pre_csrf": "x" * 43}, {"pre_csrf": tok[:-1] + ("A" if tok[-1] != "A" else "B")}):
        r = c.post("/app/login", data={**data, **extra}, headers=HTML)
        assert r.status_code == 403 and "Safari, Chrome or Firefox" in r.text, extra
    r = fresh(henv).post("/app/login", data={**data, "pre_csrf": tok})          # field without cookie
    assert r.status_code == 403 and r.json()["code"] == "csrf_failed"
    r = c.post("/app/login", data={**data, "pre_csrf": tok}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403 and r.json()["code"] == "bad_origin"           # token never overrides a foreign Origin
    r = c.post("/app/login", data={**data, "pre_csrf": tok}, headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403 and r.json()["code"] == "bad_origin"
    r = c.post("/app/login", data={**data, "pre_csrf": tok}, headers={**HTML, "Origin": "null"},
               follow_redirects=False)
    assert r.status_code == 303                                   # null Origin, no Sec-Fetch-Site, token ok


def test_enroll_with_token_accepts_null_origin(henv):
    with henv.db.write() as c:
        token = humans.invite(c, ops.CLI, "newbie", "bob", "Newbie")
    c = fresh(henv)
    tok = _pre(c.get(f"/app/enroll/{token}", headers=HTML))
    r = c.post(f"/app/enroll/{token}", data={"password": "a-long-enough-pw", "password2": "a-long-enough-pw"},
               headers={"Origin": "null"})
    assert r.status_code == 403                                   # cookie present, field missing
    r = c.post(f"/app/enroll/{token}", data={"password": "a-long-enough-pw", "password2": "a-long-enough-pw",
                                             "pre_csrf": tok}, headers={"Origin": "null"})
    assert r.status_code == 200 and "otpauth_uri" in r.json()


def test_json_clients_without_token_keep_header_check(henv):
    data = {"login": "alice", "password": PW, "totp": henv.code("alice")}
    assert fresh(henv).post("/app/login", data=data).status_code == 200          # no Origin, no cookie: CLI/tests
    r = fresh(henv).post("/app/login", data=data, headers={"Origin": "http://testserver"})
    assert r.status_code == 403 and r.json()["code"] == "bad_origin"            # http only for loopback hosts


def test_bad_origin_page_explains(henv):
    m = henv.login("alice")
    r = m.c.post("/app/logout", data={"csrf_token": m.csrf}, headers={**HTML, "Origin": "https://evil.example"})
    assert r.status_code == 403 and "Safari, Chrome or Firefox" in r.text and "chat app" in r.text


# ---------------------------------------------------------------- account oracle / audit noise

def test_account_delay_only_after_correct_password(henv):
    with henv.db.write() as c:
        c.execute("UPDATE humans SET totp_next_allowed_at=? WHERE login='alice'", (int(time.time() * 1000) + 60_000,))
    r = fresh(henv).post("/app/login", data={"login": "alice", "password": "wrong password!!", "totp": "000000"},
                         headers={"X-Forwarded-For": "192.0.2.1"})
    assert r.status_code == 401 and r.json()["code"] == "login_failed"         # no account-state oracle
    r = fresh(henv).post("/app/login", data={"login": "alice", "password": PW, "totp": henv.code("alice")},
                         headers={"X-Forwarded-For": "192.0.2.2"})
    assert r.status_code == 429


def test_unknown_login_failures_go_to_journald_only(henv, caplog):
    caplog.set_level(logging.INFO, logger="bridge")
    with henv.db.read() as c:
        before = c.execute("SELECT count(*) FROM audit_log").fetchone()[0]
    r = fresh(henv).post("/app/login", data={"login": "nobody", "password": "secret-typed-here", "totp": "1"})
    assert r.status_code == 401
    with henv.db.read() as c:
        assert c.execute("SELECT count(*) FROM audit_log").fetchone()[0] == before
    recs = [x for x in caplog.records if x.getMessage() == "login.fail"]
    assert recs and recs[0].fields["reason"] == "unknown_login"
    assert all("secret-typed-here" not in str(getattr(x, "fields", "")) for x in caplog.records)
    fresh(henv).post("/app/login", data={"login": "alice", "password": "wrong password!!", "totp": "1"})
    with henv.db.read() as c:
        assert c.execute("SELECT count(*) FROM audit_log WHERE action='login.fail'").fetchone()[0] == 1


# ---------------------------------------------------------------- enrollment TTL + throttle

def test_enrollment_ttl_configurable_default_24h(henv):
    from bridge.config import Settings
    assert Settings().enroll_ttl_s == 24 * 3600
    with henv.db.write() as c:
        humans.invite(c, ops.CLI, "a1", "bob", "A1")
        humans.invite(c, ops.CLI, "a2", "bob", "A2", ttl_ms=3600_000)
    with henv.db.read() as c:
        rows = {r["login"]: r["expires_at"] - r["created_at"] for r in c.execute("SELECT * FROM enrollments")}
    assert rows == {"a1": 24 * 3600_000, "a2": 3600_000}
    with henv.db.write() as c, pytest.raises(Exception):
        humans.invite(c, ops.CLI, "a3", "bob", "A3", ttl_ms=1)


def test_enroll_misses_are_throttled_per_ip(make_env):
    e = make_env(enroll_miss_per_ip_per_min=2)
    xff = {"X-Forwarded-For": "198.51.100.9"}
    for _ in range(2):
        assert fresh(e).get("/app/enroll/" + "x" * 43, headers=xff).status_code == 404
    r = fresh(e).get("/app/enroll/" + "y" * 43, headers=xff)
    assert r.status_code == 429 and r.headers["retry-after"]
    assert fresh(e).post("/app/enroll/" + "y" * 43, data={"password": "a-long-enough-pw"},
                         headers=xff).status_code == 429
    assert fresh(e).get("/app/enroll/" + "x" * 43, headers={"X-Forwarded-For": "198.51.100.10"}).status_code == 404


# ---------------------------------------------------------------- approvals query

def test_approvals_list_never_loads_payloads(henv):
    _approval(henv)
    seen = []
    with henv.db.read() as c:
        c.set_trace_callback(seen.append)
        try:
            rows = qy.approvals(c, state=None)
        finally:
            c.set_trace_callback(None)
    assert rows and rows[0]["action"] is None
    sql = [s for s in seen if "FROM approvals" in s]
    assert sql and all("a.*" not in s and "a.action," not in s and "LIMIT 200" in s for s in sql)
