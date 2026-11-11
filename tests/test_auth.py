from bridge.domain import keys
from bridge import ops


def test_health_needs_no_auth(env):
    r = env.client.get("/v1/health")
    assert r.status_code == 200 and r.json() == {"ok": True}
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-request-id"].startswith("req_")


def test_me(env):
    r = env.agent_a.get("/v1/me")
    assert r.status_code == 200
    assert r.json()["agent_id"] == "agent-a" and r.json()["party_id"] == "alice"
    assert r.json()["poll_after_s"] == 900


def test_missing_malformed_wrong_key(env):
    for hdr in ({}, {"Authorization": "Bearer nope"}, {"Authorization": "Basic abc"},
                {"Authorization": "Bearer abk_aaaaaaaaaaaa_" + "A" * 43},
                {"Authorization": env.agent_a.h()["Authorization"][:-2] + "zz"}):
        r = env.client.get("/v1/me", headers=hdr)
        assert r.status_code == 401
        assert r.headers["content-type"].startswith("application/problem+json")
        assert r.json()["code"] == "invalid_key"


def test_secret_not_stored_in_db(env):
    secret = env.agent_a.token.split("_", 2)[2]
    with env.db.read() as c:
        rows = c.execute("SELECT secret_hash FROM api_keys").fetchall()
    assert all(secret.encode() not in bytes(r[0]) and len(r[0]) == 32 for r in rows)


def test_revocation(env):
    assert env.agent_a.get("/v1/me").status_code == 200
    key_id = env.agent_a.token.split("_")[1]
    with env.db.write() as c:
        keys.revoke(c, ops.CLI, key_id)
    r = env.agent_a.get("/v1/me")
    assert r.status_code == 401 and r.json()["code"] == "invalid_key"


def test_expired_key(env):
    key_id = env.agent_b.token.split("_")[1]
    with env.db.write() as c:
        c.execute("UPDATE api_keys SET expires_at=1 WHERE id=?", (key_id,))
    assert env.agent_b.get("/v1/me").status_code == 401


def test_scope_missing(env):
    ro = env.agent("agent-a", scopes=("tasks:read",))
    assert ro.get("/v1/tasks").status_code == 200
    r = ro.post("/v1/tasks", {"title": "x"})
    assert r.status_code == 403 and r.json()["code"] == "scope_missing"
    assert ro.get("/v1/inbox").json()["code"] == "scope_missing"


def test_max_two_active_keys(env):
    import pytest
    from bridge.errors import Problem
    env.agent("agent-a")  # second key
    with env.db.write() as c, pytest.raises(Problem) as e:
        keys.create(c, ops.CLI, "agent-a", "third", env.settings.pepper)
    assert e.value.code == "too_many_keys"


def test_no_decide_route_for_agents(env):
    t = env.agent_b.create_task()
    a = env.agent_b.post(f"/v1/tasks/{t['id']}/approvals",
                        {"kind": "prod_deploy", "summary": "deploy", "action": {"x": 1}}).json()["approval"]
    for path in (f"/v1/approvals/{a['id']}/decide", f"/v1/approvals/{a['id']}/approve"):
        assert env.agent_b.post(path, {"decision": "approve"}).status_code in (404, 405)
    # bearer keys do not authenticate the human surface
    r = env.client.post(f"/app/approvals/{a['id']}/decide", data={"decision": "approve"}, headers=env.agent_b.h())
    assert r.status_code == 401
