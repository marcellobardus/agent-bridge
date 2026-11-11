"""Task states and the role-based transition permission table (docs/SPEC.md §4)."""
from ..errors import Problem
from ..util import now_ms
from .common import SYSTEM, Actor, audit, emit, load_task, log_task, task_summary

STATES = ("proposed", "accepted", "in_progress", "ready_for_validation", "verified", "closed",
          "blocked", "rejected", "needs_human")
TERMINAL = frozenset({"closed", "rejected"})

ORIGINATOR, RESPONSIBLE, HUMAN, SYS = "originator", "responsible", "human", "system"
ROLES = (ORIGINATOR, RESPONSIBLE, HUMAN, SYS)
O, R = ORIGINATOR, RESPONSIBLE

# (from, to) -> agent roles allowed. Humans and the system are handled below.
_AGENT_RULES: dict[tuple[str, str], frozenset] = {
    ("proposed", "accepted"): frozenset({R}),
    ("proposed", "rejected"): frozenset({R}),
    ("proposed", "closed"): frozenset({O}),                 # originator withdraws
    ("accepted", "in_progress"): frozenset({R}),
    ("accepted", "blocked"): frozenset({R}),
    ("accepted", "rejected"): frozenset({R}),
    ("accepted", "closed"): frozenset({O}),
    ("in_progress", "ready_for_validation"): frozenset({R}),  # e.g. the responsible agent declares engineering work done
    ("in_progress", "blocked"): frozenset({R}),
    ("in_progress", "closed"): frozenset({O}),
    ("ready_for_validation", "verified"): frozenset({O}),    # only the originator side validates
    ("ready_for_validation", "in_progress"): frozenset({O, R}),  # validation failed / responsible withdraws claim
    ("ready_for_validation", "closed"): frozenset({O}),
    ("verified", "closed"): frozenset({O}),
    ("blocked", "in_progress"): frozenset({R}),
    ("blocked", "rejected"): frozenset({R}),
    ("blocked", "closed"): frozenset({O}),
}
for _s in STATES:  # any participant (or the server's loop guards) may escalate an active task
    if _s not in TERMINAL and _s != "needs_human":
        _AGENT_RULES[(_s, "needs_human")] = frozenset({O, R})

REASON_REQUIRED = frozenset({"rejected", "blocked", "needs_human"})


def agent_owner(frm: str, to: str) -> str | None:
    """The agent role a transition belongs to (O or R) if only one side's agent may make it, else None."""
    roles = _AGENT_RULES.get((frm, to), frozenset())
    return next(iter(roles)) if len(roles) == 1 else None


def agent_roles(frm: str, to: str) -> frozenset:
    """Agent roles that may make (frm, to); empty when no agent may (the pair exists only as a human override)."""
    return _AGENT_RULES.get((frm, to), frozenset())


ACTIVE = frozenset({"accepted", "in_progress", "ready_for_validation", "verified", "blocked"})


def allowed(frm: str, to: str, role: str) -> bool:
    if frm in TERMINAL or frm == to or to not in STATES:
        return False
    if role == HUMAN:          # humans may override any non-terminal task, except back to proposed
        return to != "proposed"
    if role == SYS:            # the server only escalates (loop guards)
        return to == "needs_human" and frm != "needs_human"
    return role in _AGENT_RULES.get((frm, to), ())


def check(task, to: str, role: str, reason: str | None, expected_version: int | None = None) -> None:
    frm = task["state"]
    if frm in TERMINAL:
        raise Problem(410, "task_closed", f"task is {frm}")
    if expected_version is not None and expected_version != task["version"]:
        raise Problem(409, "version_conflict", "task changed since you read it",
                      extra={"current_version": task["version"], "current_state": frm})
    if to not in STATES or to == frm:
        raise Problem(422, "invalid_transition", f"{frm} -> {to} is not a valid transition")
    if not allowed(frm, to, role):
        if any(allowed(frm, to, r) for r in ROLES):
            raise Problem(403, "transition_forbidden", f"{role} may not move a task from {frm} to {to}")
        raise Problem(422, "invalid_transition", f"{frm} -> {to} is not a valid transition")
    if to in REASON_REQUIRED and not (reason or "").strip():
        raise Problem(422, "reason_required", f"a reason is required to move a task to {to}")


def apply(conn, actor: Actor, task, to: str, role: str, reason: str | None = None,
          expected_version: int | None = None):
    """Check and perform a transition atomically (caller owns the transaction). Returns the new row."""
    check(task, to, role, reason, expected_version)
    frm, now = task["state"], now_ms()
    resume = frm if to == "needs_human" else None
    reset = frm == "needs_human"  # a human resolved the escalation: reset loop counters
    conn.execute(
        "UPDATE tasks SET state=?, resume_state=?, version=version+1, updated_at=?,"
        " closed_at=CASE WHEN ? THEN ? ELSE closed_at END,"
        " clarification_rounds=CASE WHEN ? THEN 0 ELSE clarification_rounds END,"
        " agent_streak=CASE WHEN ? THEN 0 ELSE agent_streak END WHERE id=?",
        (to, resume, now, to in TERMINAL, now, reset, reset, task["id"]))
    if to in TERMINAL:
        from .approvals import cancel_open_for_task
        cancel_open_for_task(conn, task["id"], f"task {to}")
    new = load_task(conn, task["id"])
    detail = {"reason": (reason or "")[:500]} if reason else {}
    log_task(conn, task["id"], actor, "state_changed", from_state=frm, to_state=to, detail=detail)
    emit(conn, new, "task.state_changed", {"task": task_summary(new), "from": frm, "to": to,
                                           "reason": reason, "role": role}, actor)
    audit(conn, actor, "task.transition", "task", task["id"], {"from": frm, "to": to, "role": role})
    return new


def escalate_by_system(conn, task, reason: str):
    """Loop guard tripped: move to needs_human (if not already) and answer 409 loop_guard, keeping the change."""
    if task["state"] not in TERMINAL and task["state"] != "needs_human":
        apply(conn, SYSTEM, task, "needs_human", SYS, reason)
    raise Problem(409, "loop_guard", reason, extra={"task_state": "needs_human"}, commit=True)
