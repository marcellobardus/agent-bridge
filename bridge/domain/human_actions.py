"""Human oversight actions (dashboard backend). Both humans see every task and may instruct, pause, escalate and
re-prioritise it (full visibility). A transition that only one side's agent could make belongs to
that side: `verified` only by a human of the originator's party, accepting a proposal only by the responsible
party's human, and any other transition owned by the other side needs a fresh step-up ("cross-party override").
Approval decisions, agent pause and keys are limited to the human's own party."""
import json

from ..errors import Problem, not_found
from ..util import iso, now_ms
from . import approvals, statemachine as sm
from .common import Actor, audit, emit, insert_message, load_task, log_task, task_summary
from .tasks import PRIORITIES, visible_task


def _task(conn, human: Actor, task_id: str):
    if human.kind != "human":
        raise Problem(403, "humans_only", "human action")
    t = visible_task(conn, human, task_id)
    if t["state"] in sm.TERMINAL:
        raise Problem(410, "task_closed", f"task is {t['state']}")
    return t


def add_instruction(conn, human: Actor, task_id: str, text: str, refs: list | None = None):
    """HUMAN_INSTRUCTION message to both agents; resets the agent streak (loop guard)."""
    t = _task(conn, human, task_id)
    m = insert_message(conn, t, human, "HUMAN_INSTRUCTION", {"text": text, "data": {}, "refs": refs or []})
    conn.execute("UPDATE tasks SET agent_streak=0, message_count=message_count+1, updated_at=? WHERE id=?",
                 (now_ms(), task_id))
    return m


def set_priority(conn, human: Actor, task_id: str, priority: str):
    t = _task(conn, human, task_id)
    if priority not in PRIORITIES:
        raise Problem(422, "invalid_priority", f"priority must be one of {PRIORITIES}")
    conn.execute("UPDATE tasks SET priority=?, version=version+1, updated_at=? WHERE id=?", (priority, now_ms(), task_id))
    new = load_task(conn, task_id)
    log_task(conn, task_id, human, "priority_changed", detail={"from": t["priority"], "to": priority})
    emit(conn, new, "task.priority_changed", {"task": task_summary(new), "from": t["priority"], "to": priority}, human)
    audit(conn, human, "task.priority", "task", task_id, {"from": t["priority"], "to": priority})
    return new


def pause_task(conn, human: Actor, task_id: str, reason: str = ""):
    """Blocks all agent writes on the task (409 task_paused) until a human resumes it."""
    t = _task(conn, human, task_id)
    if t["paused_at"] is not None:
        return t
    conn.execute("UPDATE tasks SET paused_at=?, paused_by=?, version=version+1, updated_at=? WHERE id=?",
                 (now_ms(), human.id, now_ms(), task_id))
    new = load_task(conn, task_id)
    log_task(conn, task_id, human, "paused", detail={"reason": reason[:500]})
    emit(conn, new, "task.paused", {"task": task_summary(new), "reason": reason}, human)
    audit(conn, human, "task.pause", "task", task_id, {})
    return new


def resume_task(conn, human: Actor, task_id: str):
    t = _task(conn, human, task_id)
    if t["paused_at"] is None:
        return t
    conn.execute("UPDATE tasks SET paused_at=NULL, paused_by=NULL, agent_streak=0, version=version+1, updated_at=?"
                 " WHERE id=?", (now_ms(), task_id))
    new = load_task(conn, task_id)
    log_task(conn, task_id, human, "resumed")
    emit(conn, new, "task.resumed", {"task": task_summary(new)}, human)
    audit(conn, human, "task.resume", "task", task_id, {})
    return new


def _party_of(conn, agent_id: str) -> str | None:
    r = conn.execute("SELECT party_id FROM agents WHERE id=?", (agent_id,)).fetchone()
    return r[0] if r else None


def check_authority(conn, human: Actor, t, to: str, stepped_up: bool) -> None:
    """Which human may make this transition (see module docstring)."""
    orig, resp = _party_of(conn, t["originator_agent_id"]), _party_of(conn, t["responsible_agent_id"])
    # a task in needs_human is judged by the state it was escalated from, so parking it there is no way around
    # the table; resuming to that state is the plain "approve" and needs nothing more.
    frm = t["resume_state"] if t["state"] == "needs_human" and t["resume_state"] else t["state"]
    if to == "verified" and human.party_id != orig:
        raise Problem(403, "wrong_party", "only a human of the originator's party can mark this task verified")
    accepting = to == "accepted" and frm == "proposed"
    if accepting and human.party_id != resp:
        raise Problem(403, "wrong_party", "only a human of the responsible party can accept this task on its behalf")
    if frm == "proposed" and to in sm.ACTIVE and human.party_id != resp:
        raise Problem(403, "wrong_party", "only a human of the responsible party can move a proposed task to an"
                                          " active state")
    if t["state"] == "needs_human" and to == frm:
        return
    parties = {sm.ORIGINATOR: orig, sm.RESPONSIBLE: resp}
    own_side = any(parties[r] == human.party_id for r in sm.agent_roles(frm, to))
    if not own_side and not stepped_up:
        owner = sm.agent_owner(frm, to) or "agents'"
        raise Problem(403, "step_up_required", f"{frm} -> {to} is not on your side of the permission table ({owner}"
                                                " decision); a cross-party override needs password + TOTP step-up")


def transition_task(conn, human: Actor, task_id: str, to: str, reason: str | None = None,
                    expected_version: int | None = None, stepped_up: bool = False):
    t = _task(conn, human, task_id)
    if to in sm.STATES:
        check_authority(conn, human, t, to, stepped_up)
    return sm.apply(conn, human, t, to, sm.HUMAN, reason, expected_version)


def escalate_task(conn, human: Actor, task_id: str, reason: str):
    return transition_task(conn, human, task_id, "needs_human", reason)


def reset_counters(conn, human: Actor, task_id: str):
    """Restart the per-sender message caps (and the agent streak) after a human has looked at the task."""
    t = _task(conn, human, task_id)
    top = conn.execute("SELECT coalesce(max(seq),0) FROM messages WHERE task_id=?", (task_id,)).fetchone()[0]
    conn.execute("UPDATE tasks SET counter_reset_seq=?, agent_streak=0, updated_at=? WHERE id=?", (top, now_ms(), task_id))
    log_task(conn, task_id, human, "counters_reset", detail={"after_seq": top})
    audit(conn, human, "task.reset_counters", "task", task_id, {"after_seq": top})
    return load_task(conn, t["id"])


def approve_task(conn, human: Actor, task_id: str, reason: str | None = None, stepped_up: bool = False):
    """Human 'approve': needs_human -> the state it was escalated from (proposed -> accepted);
    proposed -> accepted; ready_for_validation -> verified."""
    t = _task(conn, human, task_id)
    if t["state"] == "needs_human":
        to = t["resume_state"] or "in_progress"
        to = "accepted" if to == "proposed" else to
    else:
        to = {"proposed": "accepted", "ready_for_validation": "verified"}.get(t["state"])
        if to is None:
            raise Problem(409, "nothing_to_approve", f"approve is not meaningful in state {t['state']}")
    check_authority(conn, human, t, to, stepped_up)
    return sm.apply(conn, human, t, to, sm.HUMAN, reason)


def approve_target(t) -> str | None:
    """What the dashboard 'Approve' button would do (for labels and visibility)."""
    if t["state"] == "needs_human":
        to = t["resume_state"] or "in_progress"
        return "accepted" if to == "proposed" else to
    return {"proposed": "accepted", "ready_for_validation": "verified"}.get(t["state"])


def reject_task(conn, human: Actor, task_id: str, reason: str, stepped_up: bool = False):
    return transition_task(conn, human, task_id, "rejected", reason, stepped_up=stepped_up)


def revoke_approval(conn, human: Actor, approval_id: str, note: str | None):
    """Withdraw an approved, not yet consumed approval (caller enforces step-up)."""
    return approvals.revoke(conn, human, approval_id, note)


def decide_approval(conn, human: Actor, approval_id: str, decision: str, note: str | None, limits):
    """Caller (HTTP layer) must enforce a fresh step-up before calling this."""
    return approvals.decide(conn, human, approval_id, decision, note, limits)


def _set_agent_pause(conn, human: Actor, agent_id: str, paused: bool):
    _own_agent(conn, human, agent_id)
    conn.execute("UPDATE agents SET paused_at=? WHERE id=?", (now_ms() if paused else None, agent_id))
    audit(conn, human, "agent.pause" if paused else "agent.resume", "agent", agent_id, {})


def pause_agent(conn, human: Actor, agent_id: str):
    _set_agent_pause(conn, human, agent_id, True)


def resume_agent(conn, human: Actor, agent_id: str):
    _set_agent_pause(conn, human, agent_id, False)


def _own_agent(conn, human: Actor, agent_id: str):
    a = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
    if a is None:
        raise not_found("agent")
    if a["party_id"] != human.party_id:
        raise Problem(403, "wrong_party", "you can only manage your own party's agents")
    return a


def create_agent_key(conn, human: Actor, agent_id: str, label: str, pepper: bytes) -> tuple[str, str]:
    """Mint a key for an own-party agent (caller enforces step-up). Returns (key_id, token) — show once."""
    from . import keys
    _own_agent(conn, human, agent_id)
    return keys.create(conn, human, agent_id, label or "dashboard", pepper)


def revoke_agent_key(conn, human: Actor, key_id: str) -> None:
    from . import keys
    k = conn.execute("SELECT agent_id FROM api_keys WHERE id=?", (key_id,)).fetchone()
    if k is None:
        raise Problem(404, "key_not_found", "no such key")
    _own_agent(conn, human, k["agent_id"])
    keys.revoke(conn, human, key_id)


def list_keys(conn) -> list[dict]:
    rows = conn.execute("SELECT id, agent_id, label, scopes, created_at, expires_at, revoked_at, last_used_at"
                        " FROM api_keys ORDER BY agent_id, created_at").fetchall()
    return [{"id": r["id"], "agent_id": r["agent_id"], "label": r["label"], "scopes": json.loads(r["scopes"]),
             "created_at": iso(r["created_at"]), "expires_at": iso(r["expires_at"]),
             "revoked_at": iso(r["revoked_at"]), "last_used_at": iso(r["last_used_at"])} for r in rows]


# ---- read views for the dashboard ----

def list_approvals(conn, state: str | None = None, budget=None) -> list[dict]:
    out = []
    for r in conn.execute("SELECT * FROM approvals ORDER BY created_at DESC LIMIT 200"):
        a = approvals.approval_dict(r)
        if state is not None and a["state"] != state:
            continue
        if budget is not None and not budget.admit(a):
            break
        out.append(a)
    return out


def get_approval(conn, approval_id: str) -> dict:
    a = conn.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
    if a is None:
        raise not_found("approval")
    return approvals.approval_dict(a)


def list_agents(conn) -> list[dict]:
    rows = conn.execute("SELECT a.*, c.last_poll_at, c.acked_seq FROM agents a"
                        " LEFT JOIN agent_cursors c ON c.agent_id=a.id ORDER BY a.id").fetchall()
    return [{"id": r["id"], "party_id": r["party_id"], "display_name": r["display_name"],
             "paused": r["paused_at"] is not None, "disabled": r["disabled_at"] is not None,
             "last_poll_at": iso(r["last_poll_at"]), "acked_seq": r["acked_seq"]} for r in rows]


def list_audit(conn, *, limit: int = 100, before_seq: int | None = None, action: str | None = None,
               target_id: str | None = None) -> list[dict]:
    rows = conn.execute("SELECT * FROM audit_log WHERE (? IS NULL OR seq<?) AND (? IS NULL OR action=?)"
                        " AND (? IS NULL OR target_id=?) ORDER BY seq DESC LIMIT ?",
                        (before_seq, before_seq, action, action, target_id, target_id, limit)).fetchall()
    return [{"seq": r["seq"], "ts": iso(r["ts"]), "actor": {"kind": r["actor_kind"], "id": r["actor_id"]},
             "action": r["action"], "target_kind": r["target_kind"], "target_id": r["target_id"],
             "detail": json.loads(r["detail"]), "hash": r["hash"]} for r in rows]
