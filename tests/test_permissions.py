"""Every (from_state, to_state, role) triple against the permission table in docs/SPEC.md §4."""
import itertools

import pytest

from bridge.domain import human_actions, statemachine as sm
from bridge.domain.common import Actor
from bridge.errors import Problem

STATES = ["proposed", "accepted", "in_progress", "ready_for_validation", "verified", "closed", "blocked",
          "rejected", "needs_human"]
NH = "needs_human"
# Written independently of the implementation: from -> role -> allowed targets
AGENT_TABLE = {
    "proposed": {"responsible": {"accepted", "rejected", NH}, "originator": {"closed", NH}},
    "accepted": {"responsible": {"in_progress", "blocked", "rejected", NH}, "originator": {"closed", NH}},
    "in_progress": {"responsible": {"ready_for_validation", "blocked", NH}, "originator": {"closed", NH}},
    "ready_for_validation": {"originator": {"verified", "in_progress", "closed", NH}, "responsible": {"in_progress", NH}},
    "verified": {"originator": {"closed", NH}, "responsible": {NH}},
    "blocked": {"responsible": {"in_progress", "rejected", NH}, "originator": {"closed", NH}},
    "needs_human": {}, "closed": {}, "rejected": {},
}
TERMINAL = {"closed", "rejected"}


def expected(frm, to, role):
    if frm in TERMINAL or frm == to:
        return False
    if role == "human":
        return to != "proposed"
    if role == "system":
        return to == NH
    return to in AGENT_TABLE[frm].get(role, set())


TRIPLES = list(itertools.product(STATES, STATES, ["originator", "responsible", "human", "system"]))


@pytest.mark.parametrize("frm,to,role", TRIPLES)
def test_table_matches_spec(frm, to, role):
    assert sm.allowed(frm, to, role) == expected(frm, to, role)


@pytest.fixture(scope="module")
def big_env(tmp_path_factory):
    from conftest import Env
    e = Env(tmp_path_factory.mktemp("perm"), per_key_per_min=10**6, per_key_writes_per_min=10**6,
            tasks_per_agent_per_day=10**6, messages_per_agent_per_day=10**6)
    e.add_human("alice", "alice")
    yield e
    e.db.close()


@pytest.mark.parametrize("frm,to,role", [t for t in TRIPLES if t[2] != "system"])
def test_transition_via_api(big_env, frm, to, role):
    e = big_env
    t = e.agent_a.create_task()   # agent-a = originator, agent-b = responsible
    with e.db.write() as c:
        c.execute("UPDATE tasks SET state=? WHERE id=?", (frm, t["id"]))
    ok = expected(frm, to, role)
    if role == "human":
        # alice = the originator's party. With a step-up he may override the responsible side, except
        # accepting a proposal on its behalf (party rules are tested in test_security.py).
        ok = ok and not (frm == "proposed" and to in sm.ACTIVE)          # leaving proposed = responsible party
        hum = Actor("human", _human_id(e), "alice")
        try:
            with e.db.write() as c:
                new = human_actions.transition_task(c, hum, t["id"], to, "because", stepped_up=True)
            assert ok and new["state"] == to
        except Problem as p:
            assert not ok, p.code
            assert p.status in (403, 410, 422)
        return
    agent = e.agent_a if role == "originator" else e.agent_b
    r = agent.to(t["id"], to, "because")
    if ok:
        assert r.status_code == 200, r.text
        assert r.json()["task"]["state"] == to
    else:
        assert r.status_code in (403, 410, 422), r.text
        if frm in TERMINAL:
            assert r.json()["code"] == "task_closed"


def _human_id(e):
    with e.db.read() as c:
        return c.execute("SELECT id FROM humans WHERE login='alice'").fetchone()[0]


def test_responsible_cannot_verify(env):
    t = env.agent_a.create_task()
    for s in ("accepted", "in_progress", "ready_for_validation"):
        assert env.agent_b.to(t["id"], s).status_code == 200
    r = env.agent_b.to(t["id"], "verified")
    assert r.status_code == 403 and r.json()["code"] == "transition_forbidden"
    # nor via a VALIDATION_RESULT message: the responsible side's result is a report only
    r = env.agent_b.post(f"/v1/tasks/{t['id']}/messages",
                        {"type": "VALIDATION_RESULT", "body": {"text": "all green", "data": {"outcome": "pass"}}})
    assert r.status_code == 201 and r.json()["task"]["state"] == "ready_for_validation"


def test_reason_required_and_version_conflict(env):
    t = env.agent_a.create_task()
    r = env.agent_b.post(f"/v1/tasks/{t['id']}/transition", {"to": "rejected"})
    assert r.status_code == 422 and r.json()["code"] == "reason_required"
    r = env.agent_b.post(f"/v1/tasks/{t['id']}/transition", {"to": "accepted", "expected_version": 99})
    assert r.status_code == 409 and r.json()["code"] == "version_conflict"


def test_terminal_trigger_in_db(env):
    import sqlite3
    t = env.agent_a.create_task()
    env.agent_a.to(t["id"], "closed")
    with pytest.raises(sqlite3.IntegrityError):
        with env.db.write() as c:
            c.execute("UPDATE tasks SET state='in_progress' WHERE id=?", (t["id"],))
