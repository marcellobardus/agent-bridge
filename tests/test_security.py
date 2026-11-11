"""Security regression tests (see SECURITY.md).
Each test reproduces the reviewer's exploit, scaled down, and asserts the fixed behaviour."""
import importlib.util
import json
import os
import sys
import sqlite3
import threading
import time

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from starlette.routing import Route

from bridge import ops
from bridge.domain import humans, keys
from bridge.util import now_ms

HTML = {"Accept": "text/html,application/xhtml+xml"}
PW = "correct horse battery"
MARKER = "SECRET-MARKER-7f3a"


def fresh(env):
    return TestClient(env.app, base_url="https://testserver")


def key_id(agent):
    return keys.parse(agent.token)[0]


@pytest.fixture
def senv(env):
    env.add_human("alice", "alice")
    env.add_human("bob", "bob")
    return env


def login(env, who):
    """A fresh session (resets the TOTP replay counter so a test can log in twice within one 30 s step)."""
    with env.db.write() as c:
        c.execute("UPDATE humans SET totp_last_step=0 WHERE login=?", (who,))
    return env.login(who)


def stale_step_up(env):
    with env.db.write() as c:
        c.execute("UPDATE sessions SET step_up_at=?", (now_ms() - 10 * 60_000,))


# ---------------------------------------------------------------- pre-auth lockout


def bad(env, ip=None, extra_xff=None):
    h = {"Authorization": "Bearer nope"}
    if ip:
        h["X-Forwarded-For"] = f"{extra_xff}, {ip}" if extra_xff else ip
    return env.client.get("/v1/me", headers=h)


def test_flood_from_one_ip_does_not_lock_out_valid_keys(make_env):
    e = make_env(unauth_per_ip_per_min=5, unauth_global_per_min=1000)
    codes = [bad(e, "203.0.113.5").status_code for _ in range(40)]
    assert codes[:5] == [401] * 5 and set(codes[5:]) == {429}
    # valid keys keep working, even when they arrive through the same address as the attacker
    assert e.agent_a.get("/v1/me", headers={"X-Forwarded-For": "203.0.113.5"}).status_code == 200
    assert e.agent_b.post("/v1/inbox/ack", {"cursor": 0}).status_code == 200
    # another address is not affected by the first one's bucket
    assert bad(e, "198.51.100.9").status_code == 401


def test_client_supplied_left_most_xff_is_ignored(make_env):
    e = make_env(unauth_per_ip_per_min=3, unauth_global_per_min=1000)
    codes = [bad(e, "203.0.113.5", extra_xff=f"10.0.0.{i}").status_code for i in range(6)]
    assert codes == [401] * 3 + [429] * 3        # rotating the client-supplied left-most entry does not help


def test_flood_from_many_ips_hits_backstop_but_never_valid_keys(make_env):
    e = make_env(unauth_per_ip_per_min=5, unauth_global_per_min=20)
    codes = [bad(e, f"2001:db8:{i:x}::1").status_code for i in range(60)]   # 60 distinct /64s
    assert codes[:20] == [401] * 20 and set(codes[20:]) == {429}
    for _ in range(5):
        assert e.agent_a.get("/v1/me").status_code == 200
        assert e.agent_b.get("/v1/inbox").status_code == 200


def test_reviewer_exploit_with_defaults(env):
    """900 bad requests used to answer 574x429 and lock out both agents; now only the attacker's IP is slowed."""
    codes = [bad(env, "203.0.113.77").status_code for _ in range(60)]
    assert 429 in codes
    assert env.agent_a.get("/v1/me").status_code == 200
    assert env.agent_b.post("/v1/inbox/ack", {"cursor": 0}).status_code == 200


def test_limiter_table_is_bounded():
    from bridge.api.deps import RateLimiter
    rl = RateLimiter()
    rl.MAX_ENTRIES = 100
    for i in range(1000):
        rl.take(("authfail", str(i)), 30)
    assert len(rl._b) <= 100


# ---------------------------------------------------------------- owner: auth if the URL leaks

PUBLIC = {("GET", "/v1/health"), ("GET", "/app/login"), ("POST", "/app/login"),
          ("GET", "/app/static/dashboard.css"), ("GET", "/app"), ("GET", "/app/enroll/{token}"),
          ("POST", "/app/enroll/{token}")}


def _routes(routes):
    """Every registered route, descending into included routers (FastAPI keeps them as _IncludedRouter)."""
    out = []
    for r in routes:
        if hasattr(r, "original_router"):
            out += _routes(r.original_router.routes)
        elif isinstance(r, (APIRoute, Route)):
            for m in sorted(r.methods or ()):
                if m != "HEAD":
                    out.append((m, r.path))
    return out


def _fill(path, ids):
    for name, value in ids.items():
        path = path.replace("{" + name + "}", value)
    return path


def test_no_unauthenticated_route_returns_data(senv):
    """Every registered route, hit without credentials (JSON and browser), refuses or redirects to login and
    never returns data; the only exceptions are health (minimal body) and the login/enroll/CSS pages, which hold
    no data (the OpenAPI document is not served unless `expose_openapi`)."""
    g, h = senv.agent_a, senv.agent_b
    senv.settings.limits.unauth_per_ip_per_min = 10 ** 6     # this test is about 401s, not the failed-auth limiter
    t = g.create_task(title=f"{MARKER} title", description=f"{MARKER} description")
    h.post(f"/v1/tasks/{t['id']}/accept")
    art = g.post(f"/v1/tasks/{t['id']}/artifacts?filename=a.txt", content=MARKER.encode(),
                 headers={"Content-Type": "text/plain"}).json()["artifact"]
    apr = h.post(f"/v1/tasks/{t['id']}/approvals", {"kind": "prod_deploy", "summary": MARKER,
                                                     "action": {"x": MARKER}}).json()["approval"]
    with senv.db.read() as c:
        msg_id = c.execute("SELECT id FROM messages WHERE task_id=? LIMIT 1", (t["id"],)).fetchone()[0]
    ids = {"task_id": t["id"], "artifact_id": art["id"], "approval_id": apr["id"], "message_id": msg_id,
           "agent_id": "agent-a",
           "key_id": key_id(g), "action": "pause", "token": "x" * 43}
    routes = _routes(senv.app.routes)
    assert len(routes) > 40                             # really enumerating everything
    seen = set()
    cookie = next(iter(login(senv, "alice").c.cookies.jar)).value          # a VALID human session
    base = [{"Accept": "application/json"}, HTML, {"Authorization": "Bearer abk_aaaaaaaaaaaa_" + "b" * 43},
            {"Cookie": "__Host-ab_session=forged"}]
    for method, path in routes + [("HEAD", p) for m, p in routes if m == "GET"]:       # HEAD too
        seen.add((method, path))
        url = _fill(path, ids)
        assert "{" not in url, (method, path)                       # every placeholder must be filled
        variants = list(base)
        if path.startswith("/app"):
            variants.append({"Authorization": f"Bearer {g.token}"})           # valid agent key on the human surface
        if path.startswith("/v1"):
            variants.append({"Cookie": f"__Host-ab_session={cookie}"})        # valid human cookie on the agent API
        for hdrs in variants:
            r = fresh(senv).request(method, url, headers=hdrs, follow_redirects=False)
            assert MARKER not in r.text, (method, path)
            assert key_id(g) not in r.text or path == "/app/keys/{key_id}/revoke", (method, path)
            if (method.replace("HEAD", "GET"), path) in PUBLIC:
                continue
            ok = r.status_code in (401, 403) or (r.status_code == 303 and r.headers["location"] == "/app/login") \
                or (method == "HEAD" and r.status_code == 405 and not r.content)
            assert ok, (method, path, hdrs, r.status_code, r.text[:200])
    assert PUBLIC <= seen
    r = fresh(senv).get("/v1/health")
    assert r.status_code == 200 and r.json() == {"ok": True}
    assert fresh(senv).get("/v1/openapi.json").status_code == 404           # not served in production
    assert fresh(senv).get("/app/enroll/" + "x" * 43).status_code == 404


def test_revoked_key_is_refused_on_the_very_next_request(senv):
    assert senv.agent_b.get("/v1/me").status_code == 200
    b = login(senv, "bob")
    assert b.post(f"/app/keys/{key_id(senv.agent_b)}/revoke").status_code == 200
    r = senv.agent_b.get("/v1/me")
    assert r.status_code == 401 and r.json()["code"] == "invalid_key"
    other = senv.agent("agent-a")
    with senv.db.write() as c:                          # bridgectl key revoke path
        keys.revoke(c, ops.CLI, key_id(other))
    assert other.get("/v1/me").status_code == 401


# ---------------------------------------------------------------- memory exhaustion

def _filled_task(env, n, text_kb=15):
    t = env.agent_a.create_task()
    assert env.agent_b.post(f"/v1/tasks/{t['id']}/accept").status_code == 201
    for i in range(n):
        r = env.agent_b.post(f"/v1/tasks/{t['id']}/messages",
                            {"type": "PROGRESS_UPDATE", "body": {"text": f"{i:04d}" + "x" * (text_kb * 1024)}})
        assert r.status_code == 201, r.text
    return t


def test_history_omits_bodies_unless_asked_and_pages_by_bytes(make_env):
    e = make_env(max_response_bytes=60_000)
    t = _filled_task(e, 12)
    r = e.agent_a.get(f"/v1/tasks/{t['id']}/history?limit=500")
    page = r.json()
    msgs = [ev["message"] for ev in page["events"] if "message" in ev]
    assert len(msgs) == 14 and all("body" not in m and m["body_bytes"] > 0 for m in msgs[2:])
    assert len(r.content) < 60_000 and page["has_more"] is False
    seen, after, pages = [], 0, 0
    while True:
        r = e.agent_a.get(f"/v1/tasks/{t['id']}/history?include_bodies=true&after_seq={after}")
        assert len(r.content) <= 60_000 + 20_000          # cap + at most the one item that crossed it
        page = r.json()
        seen += page["events"]
        after, pages = page["next_after_seq"], pages + 1
        if not page["has_more"]:
            break
    assert pages >= 3 and len({ev["seq"] for ev in seen}) == len(seen)
    assert sum(1 for ev in seen if ev.get("message", {}).get("type") == "PROGRESS_UPDATE") == 12


def test_messages_inbox_detail_and_lists_are_byte_capped(make_env):
    e = make_env(max_response_bytes=60_000)
    t = _filled_task(e, 12)
    got, after = [], 0
    while True:
        r = e.agent_a.get(f"/v1/tasks/{t['id']}/messages?after_seq={after}&limit=200")
        assert len(r.content) <= 80_000
        p = r.json()
        got += p["messages"]
        after = p["next_after_seq"]
        if not p["has_more"]:
            break
    assert len(got) == 14
    r = e.agent_a.get("/v1/inbox?limit=100")
    assert len(r.content) <= 80_000 and r.json()["has_more"] is True and r.json()["poll_after_s"] == 0
    d = e.agent_a.get(f"/v1/tasks/{t['id']}")
    assert len(d.content) <= 80_000 and d.json()["messages_truncated"] is True
    assert d.json()["messages"][-1]["body"]["text"].startswith("0011")     # newest kept
    for i in range(6):
        e.agent_a.create_task(title=f"long {i}", description="d" * 15000)
    r = e.agent_a.get("/v1/tasks?limit=100")
    assert len(r.content) <= 80_000 and r.json()["truncated"] is True and r.json()["next_offset"] >= 1


def test_data_cap_and_depth(env):
    t = env.agent_a.create_task()
    env.agent_b.post(f"/v1/tasks/{t['id']}/accept")

    def post(data):
        return env.agent_b.post(f"/v1/tasks/{t['id']}/messages", {"type": "PROGRESS_UPDATE", "body": {"data": data}})

    r = post({"blob": "x" * (16 * 1024 + 1)})
    assert r.status_code == 413 and r.json()["code"] == "data_too_large"
    deep = {}
    cur = deep
    for _ in range(8):
        cur["a"] = {}
        cur = cur["a"]
    r = post(deep)                                       # 9 levels including data itself
    assert r.status_code == 422 and r.json()["code"] == "data_too_deep"
    assert post({"a": {"b": {"c": [1, [2, [3]]]}}}).status_code == 201
    r = env.agent_b.post(f"/v1/tasks/{t['id']}/approvals", {"kind": "prod_deploy", "summary": "s", "action": deep})
    assert r.status_code == 422 and r.json()["code"] == "action_too_deep"


def test_in_flight_limit_per_key(env):
    inflight = env.app.state.bridge.inflight
    kid = key_id(env.agent_a)
    assert inflight.acquire(kid, 2) and inflight.acquire(kid, 2)
    r = env.agent_a.get("/v1/me")
    assert r.status_code == 429 and r.json()["code"] == "too_many_in_flight" and r.headers["retry-after"] == "1"
    assert env.agent_b.get("/v1/me").status_code == 200                 # per key
    inflight.release(kid)
    assert env.agent_a.get("/v1/me").status_code == 200
    inflight.release(kid)
    assert env.agent_a.get("/v1/tasks/tsk_00000000000000000000000000").status_code == 404
    assert inflight._n == {}                                          # slots released after errors too


def test_in_flight_limit_with_real_concurrency(env, monkeypatch):
    from bridge.domain import inbox
    gate, entered = threading.Event(), threading.Semaphore(0)
    real = inbox.fetch

    def slow(*a, **kw):
        entered.release()
        gate.wait(10)
        return real(*a, **kw)
    monkeypatch.setattr(inbox, "fetch", slow)
    results = []
    threads = [threading.Thread(target=lambda: results.append(env.agent_a.get("/v1/inbox").status_code))
               for _ in range(2)]
    for th in threads:
        th.start()
    assert entered.acquire(timeout=10) and entered.acquire(timeout=10)
    r = env.agent_a.get("/v1/me")
    assert r.status_code == 429 and r.json()["code"] == "too_many_in_flight"
    gate.set()
    for th in threads:
        th.join(10)
    assert results == [200, 200]
    assert env.agent_a.get("/v1/me").status_code == 200


def test_dashboard_timeline_is_paginated(senv):
    from bridge.web.pages import TIMELINE_PAGE
    senv.settings.limits.per_key_writes_per_min = 10_000
    senv.settings.limits.max_agent_streak = 10_000
    t = _filled_task(senv, 60, text_kb=1)
    m = login(senv, "alice")
    p = m.c.get(f"/app/tasks/{t['id']}", headers=HTML)
    assert p.status_code == 200
    assert p.text.count('class="msg ') <= TIMELINE_PAGE and "0059x" in p.text and "0000x" not in p.text
    import re
    older = re.search(r'href="/app/tasks/[^"?]+\?before=(\d+)"', p.text).group(1)
    p2 = m.c.get(f"/app/tasks/{t['id']}?before={older}", headers=HTML)
    assert "0000x" in p2.text and "0059x" not in p2.text and "newest events" in p2.text


# ---------------------------------------------------------------- TOTP brute force

def test_step_up_needs_password_and_revokes_session_after_5_failures(senv):
    m = login(senv, "alice")
    later = time.time() + 30
    assert m.post("/app/step-up", password="wrong password!", totp=senv.code("alice", later)).status_code == 401
    for i in range(3):
        r = m.post("/app/step-up", password=PW, totp="000000")
        assert r.status_code == 401 and r.json()["code"] == "step_up_failed"
    r = m.post("/app/step-up", password=PW, totp="000001")
    assert r.status_code == 401 and r.json().get("session_revoked") is True
    assert m.get("/app/api/me").status_code == 401                       # session gone
    with senv.db.read() as c:
        acts = [r[0] for r in c.execute("SELECT action FROM audit_log WHERE action LIKE 'stepup.%' OR"
                                        " action='session.revoke'")]
    assert acts.count("stepup.fail") == 5 and "session.revoke" in acts


def test_account_delay_is_ip_independent_and_unlockable(senv):
    c = fresh(senv)
    for i in range(5):                                    # correct password, wrong code, 5 different addresses
        r = c.post("/app/login", data={"login": "alice", "password": PW, "totp": "000000"},
                   headers={"X-Forwarded-For": f"2001:db8:{i}::1"})
        assert r.status_code == 401
    r = c.post("/app/login", data={"login": "alice", "password": PW, "totp": senv.code("alice")},
               headers={"X-Forwarded-For": "2001:db8:99::1"})
    assert r.status_code == 429 and r.json()["code"] == "login_throttled" and int(r.headers["retry-after"]) >= 1
    # the other human is unaffected; the dashboard shows a banner
    b = login(senv, "bob")
    assert "temporarily throttled" in b.c.get("/app/", headers=HTML).text
    # no permanent lockout: the delay expires, and `bridgectl human unlock --login` clears it at once
    with senv.db.write() as conn:
        assert humans.unlock(conn, ops.CLI, login="alice") == 1
    assert login(senv, "alice")


def test_wrong_passwords_cannot_lock_the_account(senv):
    c = fresh(senv)
    for i in range(10):
        c.post("/app/login", data={"login": "alice", "password": "not the password", "totp": "000000"},
               headers={"X-Forwarded-For": f"192.0.2.{i}"})
    with senv.db.read() as conn:
        assert conn.execute("SELECT totp_failures FROM humans WHERE login='alice'").fetchone()[0] == 0
    assert login(senv, "alice")


def test_delays_grow_exponentially(senv):
    hid = senv.add_human("eve", "alice")
    delays = []
    for _ in range(4):
        with senv.db.write() as conn:
            humans._account_totp_fail(conn, hid)
    for _ in range(4):
        with senv.db.write() as conn:
            humans._account_totp_fail(conn, hid)
            delays.append(conn.execute("SELECT totp_next_allowed_at FROM humans WHERE id=?", (hid,)).fetchone()[0]
                          - now_ms())
    assert all(b > a * 1.5 for a, b in zip(delays, delays[1:]))
    assert delays[0] >= 1000 and max(delays) <= humans.ACCOUNT_MAX_DELAY_MS


# ---------------------------------------------------------------- slot exhaustion (real server: tests/e2e)

def test_server_settings():
    from bridge.config import Settings
    s = Settings()
    assert s.limit_concurrency >= 200 and 0 < s.header_timeout_s <= 30 and s.body_timeout_s >= s.header_timeout_s


# ---------------------------------------------------------------- restore re-arms credentials

def _snapshot(env, tmp_path):
    snap = str(tmp_path / f"snap-{time.time_ns()}.db")
    ops.backup(env.settings.db_path, snap)
    return snap


def _restore(env, snap, **kw):
    env.db.close()
    out = ops.restore(env.settings.db_path, snap, **kw)
    env.db.close()
    return out


def test_restore_keeps_revocations_and_kills_sessions(senv, tmp_path):
    m = login(senv, "alice")
    with senv.db.write() as c:
        token = humans.invite(c, ops.CLI, "newbie", "bob", "Newbie")
    snap = _snapshot(senv, tmp_path)
    with senv.db.write() as c:
        keys.revoke(c, ops.CLI, key_id(senv.agent_b))
        c.execute("UPDATE humans SET disabled_at=? WHERE login='bob'", (now_ms(),))
    later_key = senv.agent("agent-a")                  # minted after the snapshot: gone after restore
    out = _restore(senv, snap)
    assert out["credentials_verified"] and key_id(senv.agent_b) in out["keys_revoked"]
    assert "bob" in out["humans_disabled"] and out["sessions_revoked"] >= 1 and out["enrollments_closed"] == 1
    assert senv.agent_b.get("/v1/me").status_code == 401            # was 200 before the fix
    assert later_key.get("/v1/me").status_code == 401
    assert senv.agent_a.get("/v1/me").status_code == 200           # untouched credentials keep working
    assert m.get("/app/api/me").status_code == 401                  # logged-out by the restore
    r = fresh(senv).post("/app/login", data={"login": "bob", "password": PW, "totp": senv.code("bob")})
    assert r.status_code == 401
    assert fresh(senv).get(f"/app/enroll/{token}").status_code == 404
    assert login(senv, "alice")


def test_restore_disables_humans_whose_credentials_changed(senv, tmp_path):
    snap = _snapshot(senv, tmp_path)
    with senv.db.write() as c:
        humans.reset(c, ops.CLI, "alice", "a brand new password", senv.settings.totp_kek)
    out = _restore(senv, snap)
    assert out["humans_disabled"] == ["alice"]       # the old (maybe leaked) password is not re-armed


def test_restore_without_readable_db_needs_confirmation(senv, tmp_path):
    snap = _snapshot(senv, tmp_path)
    senv.db.close()
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(senv.settings.db_path + suffix):
            os.remove(senv.settings.db_path + suffix)
    with pytest.raises(ops.CredentialsUnverified) as ei:
        ops.restore(senv.settings.db_path, snap)
    assert key_id(senv.agent_b) in ei.value.active["keys"] and "alice" in ei.value.active["humans"]
    assert not os.path.exists(senv.settings.db_path)              # nothing was swapped in
    out = _restore(senv, snap, confirm_credentials=True)
    assert out["credentials_verified"] is False and out["sessions_revoked"] >= 0


def test_info_snapshot_schema_must_match_migrations(senv, tmp_path):
    for evil in ("CREATE TRIGGER t AFTER INSERT ON messages BEGIN UPDATE api_keys SET revoked_at=NULL; END",
                 "CREATE VIEW v AS SELECT 1", "CREATE TABLE extra (x)", "DROP INDEX messages_dedupe"):
        snap = _snapshot(senv, tmp_path)
        c = sqlite3.connect(snap)
        c.execute(evil)
        c.commit()
        c.close()
        with pytest.raises(ValueError, match="schema"):
            ops.check_snapshot(snap)


# ---------------------------------------------------------------- cross-party authority

def _rfv_task(env):
    t = env.agent_a.create_task()                         # agent-a (alice) -> agent-b (bob)
    for s in ("accepted", "in_progress", "ready_for_validation"):
        assert env.agent_b.to(t["id"], s).status_code == 200
    return t


def test_events_carry_sender_party(senv):
    t = senv.agent_a.create_task()
    senv.agent_b.post(f"/v1/tasks/{t['id']}/accept")
    login(senv, "bob").post(f"/app/tasks/{t['id']}/instruction", text="do it")
    evs = senv.agent_a.get("/v1/inbox").json()["events"]
    msgs = {e["message"]["type"]: e["message"]["sender"] for e in evs if e["type"] == "message.created"}
    assert msgs["TASK_ACCEPTED"] == {"kind": "agent", "id": "agent-b", "party_id": "bob"}
    assert msgs["HUMAN_INSTRUCTION"]["kind"] == "human" and msgs["HUMAN_INSTRUCTION"]["party_id"] == "bob"
    assert all(e["actor"].get("party_id") for e in evs)


def test_only_originator_party_human_verifies(senv):
    t = _rfv_task(senv)
    b = login(senv, "bob")
    r = b.post(f"/app/tasks/{t['id']}/approve")           # reviewer exploit: 200 before the fix
    assert r.status_code == 403 and r.json()["code"] == "wrong_party"
    r = b.post(f"/app/tasks/{t['id']}/transition", to="verified")
    assert r.status_code == 403 and r.json()["code"] == "wrong_party"
    assert "mark verified" not in b.c.get(f"/app/tasks/{t['id']}", headers=HTML).text
    m = login(senv, "alice")
    assert m.post(f"/app/tasks/{t['id']}/approve").json()["task"]["state"] == "verified"


def test_only_responsible_party_human_accepts_on_its_behalf(senv):
    t = senv.agent_a.create_task()
    r = login(senv, "alice").post(f"/app/tasks/{t['id']}/approve")
    assert r.status_code == 403 and r.json()["code"] == "wrong_party"
    assert login(senv, "bob").post(f"/app/tasks/{t['id']}/approve").json()["task"]["state"] == "accepted"


def test_cross_party_override_needs_step_up_but_visibility_stays(senv):
    t = senv.agent_a.create_task()
    senv.agent_b.post(f"/v1/tasks/{t['id']}/accept")
    m = login(senv, "alice")
    stale_step_up(senv)
    r = m.post(f"/app/tasks/{t['id']}/transition", to="in_progress")   # the responsible side's move
    assert r.status_code == 403 and r.json()["code"] == "step_up_required"
    # both humans still see everything and may pause/resume/escalate/re-prioritise without step-up (instructing
    # needs one)
    assert m.get(f"/app/api/tasks/{t['id']}").status_code == 200
    assert m.post(f"/app/tasks/{t['id']}/instruction", text="context").json()["code"] == "step_up_required"
    assert m.post(f"/app/tasks/{t['id']}/pause").status_code == 200
    assert m.post(f"/app/tasks/{t['id']}/resume").status_code == 200
    assert m.post(f"/app/tasks/{t['id']}/priority", priority="high").status_code == 200
    b = login(senv, "bob")                                             # own side: no CROSS-PARTY step-up needed
    assert b.post(f"/app/tasks/{t['id']}/transition", to="in_progress").status_code == 200
    m2 = login(senv, "alice")                                          # fresh login = fresh step-up
    assert m2.post(f"/app/tasks/{t['id']}/transition", to="blocked", reason="override").status_code == 200
    assert m2.post(f"/app/tasks/{t['id']}/instruction", text="context").status_code == 200


# ---------------------------------------------------------------- bidi/invisible characters

def test_approval_payload_is_shown_ascii_escaped_with_warning(senv):
    t = senv.agent_a.create_task()
    action = {"to": "0x1234‮5678", "amount": "1​000", "note": "pay\x7f"}
    apr = senv.agent_a.post(f"/v1/tasks/{t['id']}/approvals", {"kind": "fund_move", "summary": "pay ‮evil",
                                                               "action": action}).json()["approval"]
    p = login(senv, "alice").c.get(f"/app/approvals/{apr['id']}", headers=HTML).text
    for ch in ("‮", "​", "\x7f"):
        assert ch not in p
    assert "\\u202e" in p and "\\u200b" in p and "\\u007f" in p
    assert "WARNING: non-ASCII or control characters" in p and "non-ASCII / invisible characters in the summary" in p
    clean = senv.agent_a.post(f"/v1/tasks/{senv.agent_a.create_task()['id']}/approvals",
                              {"kind": "fund_move", "summary": "plain", "action": {"to": "0xabc"}}).json()["approval"]
    assert "WARNING: non-ASCII" not in login(senv, "alice").c.get(f"/app/approvals/{clean['id']}", headers=HTML).text


def test_agent_text_is_stripped_of_invisible_characters(senv):
    t = senv.agent_a.create_task(title="Fix ‮margin", description="desc​ with⁦ isolate")
    senv.agent_b.post(f"/v1/tasks/{t['id']}/accept", {"body": {"text": "ok‮ reversed"}})
    p = login(senv, "bob").c.get(f"/app/tasks/{t['id']}", headers=HTML).text
    for ch in ("‮", "​", "⁦"):
        assert ch not in p
    assert "ok reversed" in p


# ---------------------------------------------------------------- pause vs consume, revoke

def _approved(env):
    t = env.agent_a.create_task()
    env.agent_b.post(f"/v1/tasks/{t['id']}/accept")
    apr = env.agent_b.post(f"/v1/tasks/{t['id']}/approvals", {"kind": "prod_deploy", "summary": "deploy",
                                                              "action": {"v": "1.2"}}).json()["approval"]
    b = login(env, "bob")
    assert b.post(f"/app/approvals/{apr['id']}/decide", decision="approve").status_code == 200
    return t, apr, b


def test_paused_task_blocks_consume(senv):
    t, apr, b = _approved(senv)
    assert login(senv, "alice").post(f"/app/tasks/{t['id']}/pause", reason="stop").status_code == 200
    body = {"action_sha256": apr["action_sha256"]}
    r = senv.agent_b.post(f"/v1/approvals/{apr['id']}/consume", body, key="consume-0001")
    assert r.status_code == 409 and r.json()["code"] == "task_paused"            # was 200 before the fix
    assert b.post(f"/app/tasks/{t['id']}/resume").status_code == 200
    r = senv.agent_b.post(f"/v1/approvals/{apr['id']}/consume", body, key="consume-0001")   # same key works
    assert r.status_code == 200 and r.json()["approval"]["state"] == "consumed"


def test_human_can_revoke_an_approved_approval(senv):
    t, apr, b = _approved(senv)
    assert login(senv, "alice").post(f"/app/approvals/{apr['id']}/revoke").json()["code"] == "wrong_party"
    stale_step_up(senv)
    assert b.post(f"/app/approvals/{apr['id']}/revoke").json()["code"] == "step_up_required"
    b2 = login(senv, "bob")
    page = b2.c.get(f"/app/approvals/{apr['id']}", headers=HTML).text
    assert "Revoke approval" in page
    r = b2.post(f"/app/approvals/{apr['id']}/revoke", note="changed my mind")
    assert r.status_code == 200 and r.json()["approval"]["state"] == "cancelled"
    r = senv.agent_b.post(f"/v1/approvals/{apr['id']}/consume", {"action_sha256": apr["action_sha256"]})
    assert r.status_code == 409 and r.json()["code"] == "not_approved"
    evs = [e for e in senv.agent_b.get("/v1/inbox").json()["events"] if e["type"] == "approval.decided"]
    assert evs[-1]["approval"]["state"] == "cancelled"
    assert b2.post(f"/app/approvals/{apr['id']}/revoke").json()["code"] == "not_approved"


# ---------------------------------------------------------------- login outside the write lock

def test_password_is_verified_outside_the_write_lock(senv, monkeypatch):
    lock = senv.db._lock
    held = []
    real = humans.verify_password

    def spy(phc, pw):
        held.append(lock.locked())
        return real(phc, pw)
    monkeypatch.setattr(humans, "verify_password", spy)
    login(senv, "alice")
    fresh(senv).post("/app/login", data={"login": "nobody", "password": "x" * 12, "totp": "1"})
    m = login(senv, "bob")
    m.post("/app/step-up", password=PW, totp="000000")
    assert held and not any(held)


def test_global_login_failure_bucket(make_env):
    e = make_env(login_fail_global_per_min=3)
    e.add_human("alice", "alice")
    c = fresh(e)
    for i in range(3):
        assert c.post("/app/login", data={"login": "x", "password": "y", "totp": "1"},
                      headers={"X-Forwarded-For": f"192.0.2.{i}"}).status_code == 401
    r = c.post("/app/login", data={"login": "x", "password": "y", "totp": "1"},
               headers={"X-Forwarded-For": "192.0.2.200"})
    assert r.status_code == 429 and r.json()["code"] == "login_throttled"


# ---------------------------------------------------------------- Low

def test_refused_upload_stores_no_blob(make_env):
    e = make_env(max_messages_per_task=2)
    t = e.agent_a.create_task()
    e.agent_b.post(f"/v1/tasks/{t['id']}/accept")
    e.agent_b.post(f"/v1/tasks/{t['id']}/messages", {"type": "PROGRESS_UPDATE", "body": {"text": "1"}})
    for i in range(3):
        r = e.agent_b.post(f"/v1/tasks/{t['id']}/artifacts?filename=f{i}.txt", content=b"data",
                          headers={"Content-Type": "text/plain"})
        assert r.status_code == 409 and r.json()["code"] == "loop_guard"
    with e.db.read() as c:
        assert c.execute("SELECT count(*) FROM artifacts").fetchone()[0] == 0


def test_per_agent_artifact_quota(make_env):
    e = make_env(artifact_agent_quota_bytes=100)
    t = e.agent_a.create_task()
    e.agent_b.post(f"/v1/tasks/{t['id']}/accept")

    def up(agent, n):
        return agent.post(f"/v1/tasks/{t['id']}/artifacts?filename=a.txt", content=b"x" * n,
                          headers={"Content-Type": "text/plain"})
    assert up(e.agent_b, 80).status_code == 201
    r = up(e.agent_b, 30)
    assert r.status_code == 413 and r.json()["code"] == "artifact_quota_exceeded"
    assert up(e.agent_a, 80).status_code == 201          # the other side is not starved


def test_message_cap_is_per_sender_and_resettable(make_env):
    e = make_env(max_messages_per_task=3)
    e.add_human("bob", "bob")
    t = e.agent_a.create_task()
    e.agent_b.post(f"/v1/tasks/{t['id']}/accept")
    for i in range(2):
        assert e.agent_b.post(f"/v1/tasks/{t['id']}/messages",
                             {"type": "PROGRESS_UPDATE", "body": {"text": str(i)}}).status_code == 201
    r = e.agent_b.post(f"/v1/tasks/{t['id']}/messages", {"type": "PROGRESS_UPDATE", "body": {"text": "x"}})
    assert r.status_code == 409 and r.json()["code"] == "loop_guard"
    r = e.agent_a.post(f"/v1/tasks/{t['id']}/messages", {"type": "CLARIFICATION_REQUEST", "body": {"text": "?"}})
    assert r.status_code == 201                          # agent-b's spam did not use up agent-a's share
    b = login(e, "bob")
    assert b.post(f"/app/tasks/{t['id']}/reset_counters").status_code == 200
    assert e.agent_b.post(f"/v1/tasks/{t['id']}/messages",
                         {"type": "PROGRESS_UPDATE", "body": {"text": "again"}}).status_code == 201


def test_search_offset_ceiling_and_scan_cap(make_env):
    e = make_env(search_scan_tasks=1)
    old = e.agent_a.create_task(title="old one")
    e.agent_b.post(f"/v1/tasks/{old['id']}/accept", {"body": {"text": "needle in a message"}})
    e.agent_a.create_task(title="newer one")
    assert e.agent_a.get("/v1/tasks/search?q=needle").json()["tasks"] == []      # outside the scanned window
    assert len(e.agent_a.get("/v1/tasks/search?q=old one").json()["tasks"]) == 1  # titles always searched
    assert e.agent_a.get("/v1/tasks/search?q=needle&offset=1001").status_code == 422


def test_l6_integration_example_client_checks_the_hostname():
    path = os.path.join(os.path.dirname(__file__), "..", "integration-kit", "examples", "client.py")
    spec = importlib.util.spec_from_file_location("integration_example_client", path)
    mod = importlib.util.module_from_spec(spec)
    old, sys.dont_write_bytecode = sys.dont_write_bytecode, True     # never leave .pyc in the Agent B package
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = old
    mod.Bridge("https://bridge.example.com", "k")                    # any https custom domain
    for url in ("http://127.0.0.1.evil.example", "http://127.0.0.1@evil.example", "http://evil.example",
                "ftp://x", "https://"):
        with pytest.raises(SystemExit):
            mod.Bridge(url, "k")
    mod.Bridge("https://x.ngrok-free.app", "k")
    mod.Bridge("http://127.0.0.1:8787", "k")
    with open(os.path.join(os.path.dirname(path), "curl.sh")) as f:
        sh = f.read()
    assert sh.count('--proto "$PROTO"') >= 4 and 'PROTO="=https"' in sh


def test_bad_expected_version_is_422(senv):
    t = senv.agent_a.create_task()
    r = login(senv, "bob").post(f"/app/tasks/{t['id']}/transition", to="accepted", expected_version="abc")
    assert r.status_code == 422 and r.json()["code"] == "validation_error"


def test_l9_responsible_self_check_is_labelled(senv):
    t = _rfv_task(senv)
    senv.agent_b.post(f"/v1/tasks/{t['id']}/messages", {"type": "VALIDATION_RESULT",
                                                       "body": {"text": "green", "data": {"outcome": "pass"}}})
    p = login(senv, "alice").c.get(f"/app/tasks/{t['id']}", headers=HTML).text
    assert "self-check by the responsible agent" in p and "Validation outcome" not in p


def test_task_paused_refusal_is_not_stored_under_idempotency_key(senv):
    t = senv.agent_a.create_task()
    m = login(senv, "alice")
    m.post(f"/app/tasks/{t['id']}/pause")
    r = senv.agent_b.post(f"/v1/tasks/{t['id']}/accept", key="accept-key-0001")
    assert r.status_code == 409 and r.json()["code"] == "task_paused"
    m.post(f"/app/tasks/{t['id']}/resume")
    r = senv.agent_b.post(f"/v1/tasks/{t['id']}/accept", key="accept-key-0001")
    assert r.status_code == 201 and "idempotent-replayed" not in r.headers


def test_openapi_documents_new_fields():
    with open(os.path.join(os.path.dirname(__file__), "..", "docs", "openapi.json")) as f:
        spec = json.load(f)
    s = spec["components"]["schemas"]
    assert "party_id" in s["Sender"]["properties"] and "has_more" in s["HistoryOut"]["properties"]
    assert "include_bodies" in json.dumps(spec["paths"]["/v1/tasks/{task_id}/history"])
