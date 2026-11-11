"""Retention sweeper: what is deleted, what is kept, storage guard refresh, thread lifecycle."""
import time

from fastapi.testclient import TestClient

from bridge.domain import sweeper as sw
from bridge.util import now_ms

DAY = 86_400_000


def _count(env, sql, *args):
    with env.db.read() as c:
        return c.execute(sql, args).fetchone()[0]


def test_idempotency_keys_expire_after_7_days(env):
    t = env.agent_a.create_task()
    r1 = env.agent_b.post(f"/v1/tasks/{t['id']}/accept", key="old-key-0001")
    assert r1.status_code in (200, 201)
    with env.db.write() as c:
        c.execute("UPDATE idempotency_keys SET created_at=? WHERE key='old-key-0001'", (now_ms() - 7 * DAY - 1000,))
    n = _count(env, "SELECT count(*) FROM idempotency_keys")
    with env.db.write() as c:
        out = sw.sweep(c, env.settings.session_idle_s)
    assert out["idempotency_keys"] == 1
    assert _count(env, "SELECT count(*) FROM idempotency_keys") == n - 1
    assert _count(env, "SELECT count(*) FROM idempotency_keys WHERE key='old-key-0001'") == 0


def test_events_deleted_only_when_acked_and_old(env):
    for _ in range(3):
        env.agent_a.create_task()
    ev = env.agent_b.get("/v1/inbox").json()["events"]
    assert len(ev) == 3
    with env.db.write() as c:
        c.execute("UPDATE events SET created_at=?", (now_ms() - 31 * DAY,))
    with env.db.write() as c:                 # nothing acked yet: old events are kept for the offline agent
        assert sw.sweep(c, env.settings.session_idle_s)["events"] == 0
    assert env.agent_b.post("/v1/inbox/ack", {"cursor": ev[1]["seq"]}).status_code == 200
    with env.db.write() as c:
        assert sw.sweep(c, env.settings.session_idle_s)["events"] == 2
    left = env.agent_b.get("/v1/inbox").json()["events"]
    assert [e["id"] for e in left] == [ev[2]["id"]]      # the unacked one survives; the cursor still works
    # recent acked events are kept for 30 days
    env.agent_a.create_task()
    new = env.agent_b.get("/v1/inbox").json()
    env.agent_b.post("/v1/inbox/ack", {"cursor": new["next_cursor"]})
    with env.db.write() as c:
        assert sw.sweep(c, env.settings.session_idle_s)["events"] == 1   # only the old one acked now
    assert _count(env, "SELECT count(*) FROM events WHERE recipient_agent_id='agent-b'") == 1


def test_sessions_throttle_enrollments(env):
    from bridge import ops
    from bridge.domain import humans
    env.add_human("alice", "alice")
    env.login("alice")                                 # live session: kept
    now = now_ms()
    with env.db.write() as c:
        for i, (exp, seen, rev) in enumerate([(now - 2 * DAY, now - 3 * DAY, None),     # expired > 1 day: gone
                                              (now + DAY, now, now - 2 * DAY),           # revoked > 1 day: gone
                                              (now + DAY, now - 2 * DAY, None),          # idle long ago: gone
                                              (now - 3600_000, now - 3600_000, None)]):  # expired < 1 day: kept
            c.execute("INSERT INTO sessions (token_hash, human_id, csrf_token, created_at, last_seen_at, expires_at,"
                      " revoked_at) SELECT ?, id, 'x', ?, ?, ?, ? FROM humans", (bytes([i]) * 32, now, seen, exp, rev))
        c.execute("INSERT INTO login_throttle VALUES ('198.51.100.1', 5, ?, ?)", (now - 7200_000, now - 7200_000))
        c.execute("INSERT INTO login_throttle VALUES ('198.51.100.2', 9, ?, ?)", (now + 60_000, now - 7200_000))
        c.execute("INSERT INTO login_throttle VALUES ('198.51.100.3', 1, ?, ?)", (now, now))
        tok = humans.invite(c, ops.CLI, "bob", "bob", "Bob")
        c.execute("UPDATE enrollments SET expires_at=?", (now - 8 * DAY,))
        humans.invite(c, ops.CLI, "other", "bob", "Other")
        out = sw.sweep(c, env.settings.session_idle_s)
    assert out["sessions"] == 3 and _count(env, "SELECT count(*) FROM sessions") == 2
    assert out["login_throttle"] == 1                     # an active delay is never dropped early
    assert _count(env, "SELECT count(*) FROM login_throttle") == 2
    assert out["enrollments"] == 1 and _count(env, "SELECT count(*) FROM enrollments") == 1
    assert tok


def test_throttle_table_capped(env, monkeypatch):
    monkeypatch.setattr(sw, "THROTTLE_MAX_ROWS", 5)
    now = now_ms()
    with env.db.write() as c:
        for i in range(8):
            c.execute("INSERT INTO login_throttle VALUES (?, 1, ?, ?)", (f"203.0.113.{i}", now + 60_000, now + i))
        assert sw.sweep(c, 1800)["login_throttle"] == 3
        kept = sorted(r[0] for r in c.execute("SELECT ip FROM login_throttle"))
    assert kept == [f"203.0.113.{i}" for i in range(3, 8)]  # the newest rows stay


def test_due_approvals_persisted_as_expired(env):
    env.add_human("bob", "bob")
    t = env.agent_a.create_task()
    r = env.agent_b.post(f"/v1/tasks/{t['id']}/approvals", {"kind": "prod_deploy", "summary": "s", "action": {"a": 1}})
    aid = r.json()["approval"]["id"]
    with env.db.write() as c:
        assert sw.sweep(c, 1800)["approvals_expired"] == 0
        c.execute("UPDATE approvals SET expires_at=? WHERE id=?", (now_ms() - 1, aid))
        assert sw.sweep(c, 1800)["approvals_expired"] == 1
        assert c.execute("SELECT state FROM approvals WHERE id=?", (aid,)).fetchone()[0] == "expired"
        assert c.execute("SELECT count(*) FROM audit_log WHERE action='approval.expire' AND target_id=?",
                         (aid,)).fetchone()[0] == 1
    with env.db.read() as c:
        from bridge.domain.common import audit_verify
        assert audit_verify(c)[0]


def test_tasks_messages_audit_never_swept(env):
    t = env.agent_a.create_task()
    with env.db.write() as c:
        c.execute("UPDATE tasks SET created_at=0, updated_at=0")
        c.execute("UPDATE messages SET created_at=0")
        before = [c.execute(f"SELECT count(*) FROM {tb}").fetchone()[0] for tb in ("tasks", "messages", "audit_log")]
        sw.sweep(c, 1800, now=now_ms() + 3650 * DAY)
        after = [c.execute(f"SELECT count(*) FROM {tb}").fetchone()[0] for tb in ("tasks", "messages", "audit_log")]
    assert before == after and t


def test_run_once_refreshes_storage_guard_and_skips_when_degraded(env, monkeypatch):
    b = env.app.state.bridge
    s = sw.Sweeper(b)
    calls = []
    monkeypatch.setattr(b.storage, "degraded", lambda: calls.append(1) or True)
    monkeypatch.setattr(sw, "sweep", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not sweep")))
    assert s.run_once() == {} and calls == [1]
    monkeypatch.undo()
    assert isinstance(s.run_once(), dict)


def test_thread_runs_with_app_lifespan(env, monkeypatch):
    ticks = []
    real = sw.Sweeper.run_once
    monkeypatch.setattr(sw.Sweeper, "run_once", lambda self: ticks.append(1) or real(self))
    with TestClient(env.app, base_url="https://testserver") as c:   # runs the lifespan (startup/shutdown)
        assert c.get("/v1/health").status_code == 200
        deadline = time.time() + 5
        while not ticks and time.time() < deadline:
            time.sleep(0.02)
        thread = env.app.state.sweeper._thread
        assert ticks and thread is not None and thread.is_alive() and thread.daemon
    assert env.app.state.sweeper._thread is None                    # stopped on shutdown


def test_loop_survives_errors(env, monkeypatch):
    s = sw.Sweeper(env.app.state.bridge, interval_s=0.01)
    n = []

    def boom(self):
        n.append(1)
        raise RuntimeError("disk on fire")
    monkeypatch.setattr(sw.Sweeper, "run_once", boom)
    s.start()
    deadline = time.time() + 5
    while len(n) < 3 and time.time() < deadline:
        time.sleep(0.01)
    s.stop()
    assert len(n) >= 3
