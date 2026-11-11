import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def henv(env):
    env.add_human("alice", "alice")
    env.add_human("bob", "bob")
    return env


def fresh(env):
    return TestClient(env.app, base_url="https://testserver")


def test_login_sets_secure_cookie(henv):
    c = fresh(henv)
    r = c.post("/app/login", data={"login": "alice", "password": "correct horse battery", "totp": henv.code("alice")})
    assert r.status_code == 200
    sc = r.headers["set-cookie"]
    assert sc.startswith("__Host-ab_session=") and "Secure" in sc and "HttpOnly" in sc and "samesite=strict" in sc.lower()
    assert c.get("/app/api/me").json()["party_id"] == "alice"
    assert fresh(henv).get("/app/api/me").status_code == 401


def test_login_failures_generic(henv):
    c = fresh(henv)
    for data in ({"login": "alice", "password": "wrong password!!", "totp": henv.code("alice")},
                 {"login": "alice", "password": "correct horse battery", "totp": "000000"},
                 {"login": "nobody", "password": "x", "totp": "1"}):
        r = c.post("/app/login", data=data, headers={"X-Forwarded-For": "203.0.113.9"})
        assert r.status_code == 401 and r.json()["code"] == "login_failed"
    with henv.db.read() as conn:
        acts = [r[0] for r in conn.execute("SELECT action FROM audit_log WHERE action LIKE 'login.%'")]
    assert "login.totp_fail" in acts and acts.count("login.fail") == 1    # unknown login -> journald only


def test_throttle_per_ip_not_per_login(henv):
    c = fresh(henv)
    bad = {"login": "alice", "password": "wrong password!!", "totp": "000000"}
    for _ in range(3):
        assert c.post("/app/login", data=bad, headers={"X-Forwarded-For": "198.51.100.7"}).status_code == 401
    r = c.post("/app/login", data=bad, headers={"X-Forwarded-For": "198.51.100.7"})
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    # a client-supplied left-most entry is ignored: the right-most (tunnel-appended) one counts
    r = c.post("/app/login", data=bad, headers={"X-Forwarded-For": "1.2.3.4, 198.51.100.7"})
    assert r.status_code == 429
    # the same login from another IP is not delayed
    r = c.post("/app/login", data={"login": "alice", "password": "correct horse battery",
                                   "totp": henv.code("alice")}, headers={"X-Forwarded-For": "192.0.2.1"})
    assert r.status_code == 200
    from bridge import ops
    from bridge.domain import humans
    with henv.db.write() as conn:
        assert humans.unlock(conn, ops.CLI, "198.51.100.7") == 1


def test_csrf_and_origin(henv):
    t = henv.agent_a.create_task()
    m = henv.login("alice")
    r = m.c.post(f"/app/tasks/{t['id']}/pause", data={})
    assert r.status_code == 403 and r.json()["code"] == "csrf_failed"
    r = m.c.post(f"/app/tasks/{t['id']}/pause", data={"csrf_token": "wrong"})
    assert r.json()["code"] == "csrf_failed"
    r = m.c.post(f"/app/tasks/{t['id']}/pause", data={"csrf_token": m.csrf}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403 and r.json()["code"] == "bad_origin"
    r = m.c.post(f"/app/tasks/{t['id']}/pause", data={"csrf_token": m.csrf}, headers={"Origin": "https://testserver"})
    assert r.status_code == 200


def test_human_task_actions(henv):
    g, h = henv.agent_a, henv.agent_b
    t = g.create_task()
    m = henv.login("alice")
    b = henv.login("bob")
    # instruction -> both agents, resets streak
    r = b.post(f"/app/tasks/{t['id']}/instruction", text="Focus on the liquidation path first")
    assert r.status_code == 200 and r.json()["message"]["type"] == "HUMAN_INSTRUCTION"
    for a in (g, h):
        assert any(e.get("message", {}).get("type") == "HUMAN_INSTRUCTION" for e in a.get("/v1/inbox").json()["events"])
    assert m.post(f"/app/tasks/{t['id']}/priority", priority="urgent").json()["task"]["priority"] == "urgent"
    assert m.post(f"/app/tasks/{t['id']}/priority", priority="mega").json()["code"] == "invalid_priority"
    # pause blocks agent writes; resume restores them
    assert m.post(f"/app/tasks/{t['id']}/pause", reason="hold").json()["task"]["paused"] is True
    r = h.post(f"/v1/tasks/{t['id']}/accept", {})
    assert r.status_code == 409 and r.json()["code"] == "task_paused"
    assert m.post(f"/app/tasks/{t['id']}/resume").json()["task"]["paused"] is False
    assert h.post(f"/v1/tasks/{t['id']}/accept", {}).status_code == 201
    # escalate -> needs_human; approve -> back to the previous state
    assert m.post(f"/app/tasks/{t['id']}/escalate", reason="check scope").json()["task"]["state"] == "needs_human"
    assert b.post(f"/app/tasks/{t['id']}/approve").json()["task"]["state"] == "accepted"
    assert b.post(f"/app/tasks/{t['id']}/transition", to="ready_for_validation", reason="x").json()["task"]["state"] \
        == "ready_for_validation"
    assert m.post(f"/app/tasks/{t['id']}/approve").json()["task"]["state"] == "verified"
    assert m.post(f"/app/tasks/{t['id']}/reject", reason="superseded").json()["task"]["state"] == "rejected"
    assert m.post(f"/app/tasks/{t['id']}/resume").json()["code"] == "task_closed"
    # read views
    assert m.get(f"/app/api/tasks/{t['id']}").json()["task"]["state"] == "rejected"
    assert len(m.get(f"/app/api/tasks/{t['id']}/history").json()["events"]) > 5
    assert m.get("/app/api/audit?limit=5").json()["audit"][0]["hash"]
    assert {a["id"] for a in m.get("/app/api/agents").json()["agents"]} == {"agent-a", "agent-b"}


def test_agent_pause_own_party_only(henv):
    m = henv.login("alice")
    assert m.post("/app/agents/agent-b/pause").json()["code"] == "wrong_party"
    assert m.post("/app/agents/agent-a/pause").status_code == 200
    assert henv.agent_a.post("/v1/tasks", {}).json()["code"] == "agent_paused"
    assert m.post("/app/agents/agent-a/resume").status_code == 200


def test_step_up_and_logout(henv, monkeypatch):
    import time as _t
    m = henv.login("alice")
    later = _t.time() + 60
    monkeypatch.setattr("bridge.domain.totp.time.time", lambda: later)
    assert m.post("/app/step-up", password="correct horse battery", totp="000000").json()["code"] == "step_up_failed"
    r = m.post("/app/step-up", password="correct horse battery", totp=henv.code("alice", later))
    assert r.status_code == 200
    assert m.post("/app/step-up", password="correct horse battery", totp=henv.code("alice", later)).status_code == 401   # replay refused
    assert m.post("/app/logout").status_code == 200
    assert m.get("/app/api/me").status_code == 401


def test_invite_enroll_login_and_reset(env):
    from bridge import ops
    from bridge.domain import humans
    import base64, urllib.parse
    with env.db.write() as c:
        token = humans.invite(c, ops.CLI, "bob", "bob", "Bob")
    c = fresh(env)
    assert c.get(f"/app/enroll/{token}").json()["login"] == "bob"
    assert c.post(f"/app/enroll/{token}", data={"password": "short", "password2": "short"}).json()["code"] == "weak_password"
    r = c.post(f"/app/enroll/{token}", data={"password": "a-long-enough-pw", "password2": "a-long-enough-pw"})
    assert r.status_code == 200
    q = urllib.parse.parse_qs(urllib.parse.urlparse(r.json()["otpauth_uri"]).query)["secret"][0]
    env.totp_secrets["bob"] = base64.b32decode(q + "=" * (-len(q) % 8))
    assert c.post(f"/app/enroll/{token}", data={"password": "a-long-enough-pw"}).json()["code"] == "enrollment_invalid"
    b = env.login("bob", "a-long-enough-pw")
    assert b.get("/app/api/me").json()["party_id"] == "bob"
    # reset: account disabled and sessions revoked immediately
    with env.db.write() as conn:
        token2 = humans.reset_link(conn, ops.CLI, "bob")
    assert b.get("/app/api/me").status_code == 401
    r = fresh(env).post("/app/login", data={"login": "bob", "password": "a-long-enough-pw",
                                            "totp": env.code("bob")}, headers={"X-Forwarded-For": "192.0.2.50"})
    assert r.status_code == 401
    assert fresh(env).post(f"/app/enroll/{token2}", data={"password": "another-long-pw"}).status_code == 200


def test_dashboard_key_minting_own_party(henv):
    b = henv.login("bob")
    assert b.post("/app/agents/agent-a/keys", label="x").json()["code"] == "wrong_party"
    r = b.post("/app/agents/agent-b/keys", label="agent-b-main")
    assert r.status_code == 200 and r.json()["token"].startswith("abk_")
    from conftest import Agent
    agent_b2 = Agent(henv.client, r.json()["token"], "agent-b")
    assert agent_b2.get("/v1/me").json()["agent_id"] == "agent-b"
    keys = b.get("/app/api/keys").json()["keys"]
    assert all("secret" not in str(k) for k in keys)
    gk = next(k["id"] for k in keys if k["agent_id"] == "agent-a")
    assert b.post(f"/app/keys/{gk}/revoke").json()["code"] == "wrong_party"
    assert b.post(f"/app/keys/{r.json()['key_id']}/revoke").status_code == 200
    assert agent_b2.get("/v1/me").status_code == 401
