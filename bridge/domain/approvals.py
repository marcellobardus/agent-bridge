"""Human approvals for consequential actions: bound to SHA-256 of the canonical action JSON, single-use.
Agents may request, read, cancel and consume; only a human of the requesting agent's party may decide."""
import json

from ..errors import Problem, not_found
from ..util import Budget, canonical_json, iso, json_depth_exceeds, new_id, now_ms, sha256_hex
from .common import SYSTEM, Actor, audit, emit_to, log_task
from .tasks import writable_task

KINDS = ("prod_deploy", "fund_move", "mainnet_upgrade", "live_trading", "credential_change")
OPEN = ("pending", "approved")


def action_hash(action) -> str:
    return sha256_hex(canonical_json(action))


def effective_state(a, now: int | None = None) -> str:
    now = now or now_ms()
    if a["state"] == "pending" and now >= a["expires_at"]:
        return "expired"
    if a["state"] == "approved" and a["valid_until"] is not None and now >= a["valid_until"]:
        return "expired"
    return a["state"]


def approval_dict(a, origin: str | None = None, with_action: bool = True) -> dict:
    d = {"id": a["id"], "task_id": a["task_id"], "kind": a["kind"], "state": effective_state(a),
         "requested_by": a["requested_by_agent_id"], "approver_party": a["approver_party_id"],
         "summary": a["summary"], "action": json.loads(a["action"]) if with_action else None, "action_sha256": a["action_sha256"],
         "decided_by": a["decided_by_human_id"], "decided_at": iso(a["decided_at"]), "decision_note": a["decision_note"],
         "created_at": iso(a["created_at"]), "expires_at": iso(a["expires_at"]), "valid_until": iso(a["valid_until"]),
         "consumed_at": iso(a["consumed_at"])}
    if origin:
        d["dashboard_url"] = f"{origin.rstrip('/')}/app/approvals/{a['id']}"
    return d


def _load(conn, approval_id: str):
    a = conn.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
    if a is None:
        raise not_found("approval")
    return a


def _own(conn, actor: Actor, approval_id: str):
    a = _load(conn, approval_id)
    if a["requested_by_agent_id"] != actor.id:
        raise not_found("approval")
    return a


def _expire_if_due(conn, a):
    """Persist lazy expiry (inside a write transaction)."""
    if a["state"] in OPEN and effective_state(a) == "expired":
        conn.execute("UPDATE approvals SET state='expired' WHERE id=?", (a["id"],))
        audit(conn, SYSTEM, "approval.expire", "approval", a["id"], {})
        return _load(conn, a["id"])
    return a


def request(conn, actor: Actor, task_id: str, kind: str, summary: str, action, expires_in_s: int | None, limits) -> dict:
    task = writable_task(conn, actor, task_id)
    n = conn.execute("SELECT count(*) FROM approvals WHERE requested_by_agent_id=? AND created_at>?",
                     (actor.id, now_ms() - 86_400_000)).fetchone()[0]
    if n >= limits.approvals_per_agent_per_day:
        raise Problem(429, "daily_limit", "too many approval requests today", headers={"Retry-After": "3600"})
    pend = conn.execute("SELECT * FROM approvals WHERE task_id=? AND requested_by_agent_id=? AND state='pending'",
                        (task_id, actor.id)).fetchone()
    if pend is not None:
        pend = _expire_if_due(conn, pend)
        if pend["state"] == "pending":
            raise Problem(409, "approval_pending", "you already have a pending approval on this task",
                          extra={"approval_id": pend["id"]})
    if json_depth_exceeds(action, limits.max_json_depth):
        raise Problem(422, "action_too_deep", f"action nests deeper than {limits.max_json_depth} levels")
    raw = canonical_json(action)
    if len(raw) > 32768:
        raise Problem(413, "action_too_large", "action payload exceeds 32 KiB")
    ttl = min(expires_in_s or limits.approval_ttl_s, limits.approval_max_ttl_s)
    aid, now = new_id("apr"), now_ms()
    conn.execute("INSERT INTO approvals (id, task_id, requested_by_agent_id, approver_party_id, kind, summary, action,"
                 " action_sha256, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                 (aid, task["id"], actor.id, actor.party_id, kind, summary, raw.decode(), sha256_hex(raw), now,
                  now + ttl * 1000))
    log_task(conn, task_id, actor, "approval_requested", detail={"approval_id": aid, "kind": kind})
    audit(conn, actor, "approval.request", "approval", aid, {"task_id": task_id, "kind": kind,
                                                             "action_sha256": sha256_hex(raw)})
    return _load(conn, aid)


def get_own(conn, actor: Actor, approval_id: str):
    return _own(conn, actor, approval_id)


def list_own(conn, actor: Actor, state: str | None = None, task_id: str | None = None,
             budget: Budget | None = None, origin: str | None = None) -> list[dict]:
    """Newest first, at most 200, and at most ~budget bytes (each action may be 32 KiB)."""
    out = []
    for a in conn.execute("SELECT * FROM approvals WHERE requested_by_agent_id=? AND (? IS NULL OR task_id=?)"
                          " ORDER BY created_at DESC LIMIT 200", (actor.id, task_id, task_id)):
        if state is not None and effective_state(a) != state:
            continue
        d = approval_dict(a, origin)
        if budget is not None and not budget.admit(d):
            break
        out.append(d)
    return out


def pending_count(conn, agent_id: str) -> int:
    return conn.execute("SELECT count(*) FROM approvals WHERE requested_by_agent_id=? AND state='pending' AND expires_at>?",
                        (agent_id, now_ms())).fetchone()[0]


def consume(conn, actor: Actor, approval_id: str, sha: str):
    a = _expire_if_due(conn, _own(conn, actor, approval_id))
    writable_task(conn, actor, a["task_id"])   # a paused (409 task_paused) or closed (410) task stops consumption
    if a["state"] == "consumed":
        raise Problem(409, "already_consumed", "approval was already consumed")
    if a["state"] == "expired":
        raise Problem(409, "approval_expired", "approval expired")
    if a["state"] != "approved":
        raise Problem(409, "not_approved", f"approval is {a['state']}")
    if sha != a["action_sha256"]:
        raise Problem(409, "hash_mismatch", "action_sha256 does not match the approved payload")
    conn.execute("UPDATE approvals SET state='consumed', consumed_at=? WHERE id=?", (now_ms(), approval_id))
    log_task(conn, a["task_id"], actor, "approval_consumed", detail={"approval_id": approval_id})
    audit(conn, actor, "approval.consume", "approval", approval_id, {"action_sha256": sha})
    return _load(conn, approval_id)


def cancel(conn, actor: Actor, approval_id: str):
    a = _expire_if_due(conn, _own(conn, actor, approval_id))
    if a["state"] != "pending":
        raise Problem(409, "not_pending", f"approval is {a['state']}")
    conn.execute("UPDATE approvals SET state='cancelled', decision_note='withdrawn by agent' WHERE id=?", (approval_id,))
    log_task(conn, a["task_id"], actor, "approval_cancelled", detail={"approval_id": approval_id})
    audit(conn, actor, "approval.cancel", "approval", approval_id, {})
    return _load(conn, approval_id)


def decide(conn, human: Actor, approval_id: str, decision: str, note: str | None, limits):
    """Human decision. Caller must have verified a fresh step-up (password + TOTP)."""
    if human.kind != "human":
        raise Problem(403, "humans_only", "only a human can decide an approval")
    a = _expire_if_due(conn, _load(conn, approval_id))
    if a["approver_party_id"] != human.party_id:
        raise Problem(403, "wrong_party", "only a human of the requesting agent's party can decide this approval")
    if a["state"] != "pending":
        raise Problem(409, "not_pending", f"approval is {a['state']}")
    if decision not in ("approve", "reject"):
        raise Problem(422, "invalid_decision", "decision must be approve or reject")
    now = now_ms()
    state = "approved" if decision == "approve" else "rejected"
    conn.execute("UPDATE approvals SET state=?, decided_by_human_id=?, decided_at=?, decision_note=?, valid_until=?"
                 " WHERE id=?", (state, human.id, now, (note or "")[:1000] or None,
                                 now + limits.approval_consume_window_s * 1000 if state == "approved" else None, approval_id))
    a = _load(conn, approval_id)
    log_task(conn, a["task_id"], human, "approval_decided", detail={"approval_id": approval_id, "state": state})
    audit(conn, human, "approval.decide", "approval", approval_id, {"state": state, "action_sha256": a["action_sha256"]})
    emit_to(conn, a["requested_by_agent_id"], "approval.decided", a["task_id"],
            {"approval": approval_dict(a), "actor": {"kind": "human", "id": human.id, "party_id": human.party_id}})
    return a


def revoke(conn, human: Actor, approval_id: str, note: str | None):
    """A human of the approver party withdraws an approved-but-not-consumed approval (caller enforces
    step-up). The agent is told via approval.decided (state cancelled); a later consume answers 409."""
    if human.kind != "human":
        raise Problem(403, "humans_only", "only a human can revoke an approval")
    a = _expire_if_due(conn, _load(conn, approval_id))
    if a["approver_party_id"] != human.party_id:
        raise Problem(403, "wrong_party", "only a human of the requesting agent's party can revoke this approval")
    if a["state"] != "approved":
        raise Problem(409, "not_approved", f"approval is {a['state']}; only approved, unconsumed approvals can be revoked")
    text = "revoked by human" + (f": {note[:900]}" if note else "")
    conn.execute("UPDATE approvals SET state='cancelled', decision_note=? WHERE id=?", (text, approval_id))
    a = _load(conn, approval_id)
    log_task(conn, a["task_id"], human, "approval_revoked", detail={"approval_id": approval_id})
    audit(conn, human, "approval.revoke", "approval", approval_id, {"action_sha256": a["action_sha256"]})
    emit_to(conn, a["requested_by_agent_id"], "approval.decided", a["task_id"],
            {"approval": approval_dict(a), "actor": {"kind": "human", "id": human.id, "party_id": human.party_id}})
    return a


def cancel_open_for_task(conn, task_id: str | None, note: str) -> int:
    """Server-side termination (task closed/rejected, or restore when task_id is None): cancel every open
    approval and tell the requesting agent. Never 'rejected' — that is reserved for a human decision."""
    rows = conn.execute("SELECT * FROM approvals WHERE state IN ('pending','approved') AND (? IS NULL OR task_id=?)",
                        (task_id, task_id)).fetchall()
    for a in rows:
        conn.execute("UPDATE approvals SET state='cancelled', decision_note=? WHERE id=?", (note, a["id"]))
        b = _load(conn, a["id"])
        audit(conn, SYSTEM, "approval.cancel", "approval", a["id"], {"reason": note})
        emit_to(conn, a["requested_by_agent_id"], "approval.decided", a["task_id"],
                {"approval": approval_dict(b), "actor": {"kind": "system", "id": "bridge"}})
    return len(rows)
