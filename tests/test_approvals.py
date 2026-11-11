import sqlite3

import pytest

from bridge.domain import approvals as apr
from bridge.util import canonical_json, sha256_hex

ACTION = {"tool": "deploy", "service": "margin-engine", "version": "1.4.2", "env": "prod"}


@pytest.fixture
def setup(env):
    env.add_human("alice", "alice")
    env.add_human("bob", "bob")
    t = env.agent_a.create_task()
    r = env.agent_b.post(f"/v1/tasks/{t['id']}/approvals", {"kind": "prod_deploy", "summary": "Deploy fix", "action": ACTION})
    assert r.status_code == 201, r.text
    return env, t, r.json()["approval"]


def test_request_binds_hash(setup):
    env, t, a = setup
    assert a["state"] == "pending" and a["approver_party"] == "bob"
    assert a["action_sha256"] == sha256_hex(canonical_json(ACTION))
    assert a["dashboard_url"] == f"https://testserver/app/approvals/{a['id']}"
    assert env.agent_b.get("/v1/inbox").json()["pending_approvals"] == 1
    # agent-a cannot see agent-b's approval
    assert env.agent_a.get(f"/v1/approvals/{a['id']}").status_code == 404
    r = env.agent_b.post(f"/v1/tasks/{t['id']}/approvals", {"kind": "prod_deploy", "summary": "again", "action": {}})
    assert r.status_code == 409 and r.json()["code"] == "approval_pending"
    # the other side may hold its own pending approval on the same task
    r = env.agent_a.post(f"/v1/tasks/{t['id']}/approvals", {"kind": "fund_move", "summary": "pay", "action": {"usd": 1}})
    assert r.status_code == 201
    r = env.agent_b.post(f"/v1/tasks/{t['id']}/approvals", {"kind": "shell", "summary": "x", "action": {}})
    assert r.status_code == 422


def test_wrong_party_cannot_decide(setup):
    env, t, a = setup
    m = env.login("alice")
    r = m.post(f"/app/approvals/{a['id']}/decide", decision="approve")
    assert r.status_code == 403 and r.json()["code"] == "wrong_party"
    # also enforced by the DB trigger
    with env.db.read() as c:
        mid = c.execute("SELECT id FROM humans WHERE login='alice'").fetchone()[0]
    with pytest.raises(sqlite3.IntegrityError):
        with env.db.write() as c:
            c.execute("UPDATE approvals SET state='approved', decided_by_human_id=? WHERE id=?", (mid, a["id"]))


def test_pending_cannot_be_consumed(setup):
    env, t, a = setup
    r = env.agent_b.post(f"/v1/approvals/{a['id']}/consume", {"action_sha256": a["action_sha256"]})
    assert r.status_code == 409 and r.json()["code"] == "not_approved"


def test_approve_consume_once(setup):
    env, t, a = setup
    b = env.login("bob")
    r = b.post(f"/app/approvals/{a['id']}/decide", decision="approve", note="go")
    assert r.status_code == 200 and r.json()["approval"]["state"] == "approved"
    ev = env.agent_b.get("/v1/inbox").json()["events"]
    assert ev[-1]["type"] == "approval.decided" and ev[-1]["approval"]["state"] == "approved"
    r = env.agent_b.post(f"/v1/approvals/{a['id']}/consume", {"action_sha256": "0" * 64})
    assert r.status_code == 409 and r.json()["code"] == "hash_mismatch"
    r = env.agent_b.post(f"/v1/approvals/{a['id']}/consume", {"action_sha256": a["action_sha256"]})
    assert r.status_code == 200 and r.json()["approval"]["state"] == "consumed"
    r = env.agent_b.post(f"/v1/approvals/{a['id']}/consume", {"action_sha256": a["action_sha256"]})
    assert r.status_code == 409 and r.json()["code"] == "already_consumed"
    # decided approvals cannot be re-decided
    assert b.post(f"/app/approvals/{a['id']}/decide", decision="reject").json()["code"] == "not_pending"


def test_reject_and_cancel(setup):
    env, t, a = setup
    b = env.login("bob")
    assert b.post(f"/app/approvals/{a['id']}/decide", decision="reject").json()["approval"]["state"] == "rejected"
    r = env.agent_b.post(f"/v1/approvals/{a['id']}/consume", {"action_sha256": a["action_sha256"]})
    assert r.json()["code"] == "not_approved"
    a2 = env.agent_b.post(f"/v1/tasks/{t['id']}/approvals", {"kind": "prod_deploy", "summary": "v2",
                                                            "action": ACTION}).json()["approval"]
    assert env.agent_b.post(f"/v1/approvals/{a2['id']}/cancel").json()["approval"]["state"] == "cancelled"


def test_step_up_required(setup):
    env, t, a = setup
    b = env.login("bob")
    with env.db.write() as c:
        c.execute("UPDATE sessions SET step_up_at=1")
    r = b.post(f"/app/approvals/{a['id']}/decide", decision="approve")
    assert r.status_code == 403 and r.json()["code"] == "step_up_required"


def test_expiry(setup):
    env, t, a = setup
    with env.db.write() as c:
        c.execute("UPDATE approvals SET expires_at=1 WHERE id=?", (a["id"],))
    assert env.agent_b.get(f"/v1/approvals/{a['id']}").json()["approval"]["state"] == "expired"
    b = env.login("bob")
    assert b.post(f"/app/approvals/{a['id']}/decide", decision="approve").json()["code"] == "not_pending"


def test_task_close_cancels_open_approvals(setup):
    env, t, a = setup
    env.agent_a.to(t["id"], "closed")
    got = env.agent_b.get(f"/v1/approvals/{a['id']}").json()["approval"]
    assert got["state"] == "cancelled" and got["decided_by"] is None


def test_human_decide_function_rejects_agents(setup):
    env, t, a = setup
    from bridge.domain.common import Actor
    from bridge.errors import Problem
    with pytest.raises(Problem) as e, env.db.write() as c:
        apr.decide(c, Actor("agent", "agent-b", "bob"), a["id"], "approve", None, env.settings.limits)
    assert e.value.code == "humans_only"
