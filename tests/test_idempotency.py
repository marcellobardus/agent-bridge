BODY = {"title": "Idem task", "description": "d", "responsible_agent_id": "agent-b", "category": "bug_fix"}


def test_missing_key_400(env):
    r = env.client.post("/v1/tasks", json=BODY, headers=env.agent_a.h())
    assert r.status_code == 400 and r.json()["code"] == "missing_idempotency_key"
    r = env.client.post("/v1/tasks", json=BODY, headers=env.agent_a.h({"Idempotency-Key": "short"}))
    assert r.json()["code"] == "invalid_idempotency_key"


def test_same_key_same_body_replays_identically(env):
    r1 = env.agent_a.post("/v1/tasks", BODY, key="evt_1:0-abcdef")
    r2 = env.agent_a.post("/v1/tasks", BODY, key="evt_1:0-abcdef")
    assert r1.status_code == r2.status_code == 201
    assert r1.json() == r2.json()
    assert r2.headers["idempotent-replayed"] == "true" and "idempotent-replayed" not in r1.headers
    with env.db.read() as c:
        assert c.execute("SELECT count(*) FROM tasks").fetchone()[0] == 1


def test_same_key_different_body_422(env):
    env.agent_a.post("/v1/tasks", BODY, key="reuse-key-123")
    r = env.agent_a.post("/v1/tasks", {**BODY, "title": "Other"}, key="reuse-key-123")
    assert r.status_code == 422 and r.json()["code"] == "idempotency_key_reuse"
    r = env.agent_a.post("/v1/tasks/x/transition", {"to": "closed"}, key="reuse-key-123")  # different path
    assert r.status_code == 422 and r.json()["code"] == "idempotency_key_reuse"


def test_keys_are_scoped_per_agent(env):
    t = env.agent_a.create_task()
    r1 = env.agent_b.post(f"/v1/tasks/{t['id']}/accept", {}, key="shared-key-1")
    assert r1.status_code == 201
    r2 = env.agent_a.post("/v1/tasks", {**BODY, "title": "per-agent"}, key="shared-key-1")
    assert r2.status_code == 201


def test_deterministic_409_is_replayed(env):
    env.agent_a.post("/v1/tasks", BODY)
    r1 = env.agent_a.post("/v1/tasks", BODY, key="dupe-key-0001")
    assert r1.status_code == 409 and r1.json()["code"] == "duplicate_task"
    r2 = env.agent_a.post("/v1/tasks", BODY, key="dupe-key-0001")
    assert r2.json() == r1.json() and r2.headers["idempotent-replayed"] == "true"


def test_429_not_stored(make_env):
    e = make_env(per_key_writes_per_min=1)
    assert e.agent_a.post("/v1/tasks", BODY, key="k-rate-0001").status_code == 201
    r = e.agent_a.post("/v1/tasks", {**BODY, "title": "B"}, key="k-rate-0002")
    assert r.status_code == 429
    with e.db.read() as c:
        assert c.execute("SELECT count(*) FROM idempotency_keys WHERE key='k-rate-0002'").fetchone()[0] == 0
