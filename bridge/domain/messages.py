"""Agent messages within a task with loop guards and duplicate detection."""
from ..errors import Problem
from ..util import canonical_json, json_depth_exceeds, now_ms, sha256_hex
from . import statemachine as sm
from .common import Actor, insert_message, load_task
from .tasks import role_of, writable_task

MESSAGE_TYPES = ("TASK_REQUEST", "TASK_ACCEPTED", "TASK_REJECTED", "CLARIFICATION_REQUEST", "CLARIFICATION_RESPONSE",
                 "PROGRESS_UPDATE", "ARTIFACT_SUBMITTED", "VALIDATION_RESULT", "DECISION_REQUEST", "HUMAN_INSTRUCTION")
AGENT_POSTABLE = MESSAGE_TYPES[1:-1]           # TASK_REQUEST only via task creation; HUMAN_INSTRUCTION only by humans
DEDUPE_EXEMPT = frozenset({"PROGRESS_UPDATE"})  # identical progress reports are legitimate

# message type -> roles that may send it
SENDERS = {
    "TASK_ACCEPTED": {"responsible"}, "TASK_REJECTED": {"responsible"}, "PROGRESS_UPDATE": {"responsible"},
    "CLARIFICATION_REQUEST": {"originator", "responsible"}, "CLARIFICATION_RESPONSE": {"originator", "responsible"},
    "ARTIFACT_SUBMITTED": {"originator", "responsible"}, "VALIDATION_RESULT": {"originator", "responsible"},
    "DECISION_REQUEST": {"originator", "responsible"},
}


def _transition_for(mtype: str, role: str, task, body: dict) -> tuple[str | None, str | None]:
    """The state change implied by a message, as (to_state, reason)."""
    text = body.get("text") or ""
    if mtype == "TASK_ACCEPTED":
        return "accepted", None
    if mtype == "TASK_REJECTED":
        return "rejected", text
    if mtype == "DECISION_REQUEST":
        return "needs_human", text or "decision requested"
    if mtype == "VALIDATION_RESULT" and role == "originator":
        if task["state"] != "ready_for_validation":
            raise Problem(409, "not_ready_for_validation", "the originator validates only in ready_for_validation")
        return ("verified" if body["data"]["outcome"] == "pass" else "in_progress"), None
    return None, None


def check_body(body: dict, limits) -> None:
    """A small, shallow `data` (the bulk of a message is plain `text`)."""
    data = body.get("data") or {}
    if len(canonical_json(data)) > limits.max_data_bytes:
        raise Problem(413, "data_too_large", f"body.data exceeds {limits.max_data_bytes} bytes")
    if json_depth_exceeds(data, limits.max_json_depth):
        raise Problem(422, "data_too_deep", f"body.data nests deeper than {limits.max_json_depth} levels")


def post_message(conn, actor: Actor, task_id: str, mtype: str, body: dict, in_reply_to: str | None, limits) -> dict:
    """Returns {"message": row, "task": row, "deduplicated": bool}."""
    prep = prepare(conn, actor, task_id, mtype, body, in_reply_to, limits)
    if "deduplicated" in prep:
        return prep
    return finish(conn, actor, prep, body)


def prepare(conn, actor: Actor, task_id: str, mtype: str, body: dict, in_reply_to: str | None, limits,
            *, pending_artifact: bool = False) -> dict:
    """Every check and loop guard of a message, before anything is stored (an artifact upload runs this
    before inserting its blob, with pending_artifact=True). Returns the context for finish(), or a
    deduplicated result."""
    if mtype not in AGENT_POSTABLE:
        raise Problem(422, "message_type_not_allowed", f"{mtype} cannot be posted by an agent here")
    task = writable_task(conn, actor, task_id)
    role = role_of(task, actor)
    if role not in SENDERS[mtype]:
        raise Problem(403, "sender_not_allowed", f"the {role} may not send {mtype}")
    check_body(body, limits)
    if mtype == "VALIDATION_RESULT" and (body.get("data") or {}).get("outcome") not in ("pass", "fail"):
        raise Problem(422, "invalid_body", "VALIDATION_RESULT needs data.outcome = 'pass' | 'fail'")
    if mtype == "ARTIFACT_SUBMITTED" and not pending_artifact:
        ids = (body.get("data") or {}).get("artifact_ids") or []
        if not ids and not body.get("refs"):
            raise Problem(422, "invalid_body", "ARTIFACT_SUBMITTED needs data.artifact_ids or refs")
        for aid in ids:
            if not isinstance(aid, str) or not conn.execute("SELECT 1 FROM artifacts WHERE id=? AND task_id=?",
                                                            (aid, task_id)).fetchone():
                raise Problem(422, "unknown_artifact", "artifact_ids must reference artifacts of this task")
    if mtype == "TASK_REJECTED" and not (body.get("text") or "").strip():
        raise Problem(422, "reason_required", "TASK_REJECTED needs a reason in text")

    # duplicate detection (same sender, task, type and body within the window)
    if mtype not in DEDUPE_EXEMPT and not pending_artifact:
        body_sha = sha256_hex(canonical_json(body))
        dup = conn.execute("SELECT * FROM messages WHERE task_id=? AND sender_id=? AND body_sha256=? AND type=?"
                           " AND created_at>? ORDER BY seq DESC LIMIT 1",
                           (task_id, actor.id, body_sha, mtype, now_ms() - limits.dedupe_window_s * 1000)).fetchone()
        if dup:
            return {"message": dup, "task": task, "deduplicated": True}

    depth = 0
    if in_reply_to:
        parent = conn.execute("SELECT * FROM messages WHERE id=? AND task_id=?", (in_reply_to, task_id)).fetchone()
        if parent is None:
            raise Problem(422, "unknown_parent", "in_reply_to must reference a message of this task")
        depth = parent["depth"] + 1
    if mtype == "CLARIFICATION_RESPONSE":
        if not in_reply_to or parent["type"] != "CLARIFICATION_REQUEST" or parent["sender_id"] == actor.id:
            raise Problem(422, "invalid_parent", "CLARIFICATION_RESPONSE must reply to the other side's CLARIFICATION_REQUEST")
        if conn.execute("SELECT 1 FROM messages WHERE in_reply_to=? AND type='CLARIFICATION_RESPONSE'",
                        (in_reply_to,)).fetchone():
            raise Problem(409, "already_responded", "this clarification request already has a response")

    to, reason = _transition_for(mtype, role, task, body)
    if to:
        sm.check(task, to, role, reason)

    # loop guards: escalate to needs_human and refuse (the escalation is committed)
    if mtype == "CLARIFICATION_REQUEST" and task["clarification_rounds"] >= limits.max_clarification_rounds:
        sm.escalate_by_system(conn, task, f"clarification rounds exceeded ({limits.max_clarification_rounds})")
    if depth > limits.max_reply_depth:
        sm.escalate_by_system(conn, task, f"reply chain too deep ({limits.max_reply_depth})")
    if task["agent_streak"] >= limits.max_agent_streak:
        sm.escalate_by_system(conn, task, f"{limits.max_agent_streak} agent messages without human involvement")
    # counted per sender since the last human reset, so one agent cannot use up the other's share
    sent = conn.execute("SELECT count(*) FROM messages WHERE task_id=? AND sender_id=? AND seq>?",
                        (task_id, actor.id, task["counter_reset_seq"])).fetchone()[0]
    if sent >= limits.max_messages_per_task:
        sm.escalate_by_system(conn, task, f"message limit per sender reached ({limits.max_messages_per_task});"
                                          " a human can reset the counters")
    n = conn.execute("SELECT count(*) FROM messages WHERE sender_id=? AND sender_kind='agent' AND created_at>?",
                     (actor.id, now_ms() - 86_400_000)).fetchone()[0]
    if n >= limits.messages_per_agent_per_day:
        raise Problem(429, "daily_limit", "too many messages today", headers={"Retry-After": "3600"})
    return {"task": task, "role": role, "mtype": mtype, "in_reply_to": in_reply_to, "depth": depth,
            "to": to, "reason": reason}


def finish(conn, actor: Actor, prep: dict, body: dict) -> dict:
    task, task_id = prep["task"], prep["task"]["id"]
    m = insert_message(conn, task, actor, prep["mtype"], body, prep["in_reply_to"], prep["depth"])
    conn.execute("UPDATE tasks SET message_count=message_count+1, agent_streak=agent_streak+1,"
                 " clarification_rounds=clarification_rounds+?, updated_at=? WHERE id=?",
                 (1 if prep["mtype"] == "CLARIFICATION_REQUEST" else 0, now_ms(), task_id))
    task = load_task(conn, task_id)
    if prep["to"]:
        task = sm.apply(conn, actor, task, prep["to"], prep["role"], prep["reason"])
    return {"message": m, "task": task, "deduplicated": False}
