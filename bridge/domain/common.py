"""Shared domain pieces: actor, audit hash chain, outbox events, task timeline, message insert."""
import dataclasses
import hashlib
import json
import sqlite3

from ..util import canonical_json, dumps, iso, new_id, now_ms, request_id_var, sha256_hex

GENESIS = "0" * 64


@dataclasses.dataclass(frozen=True)
class Actor:
    kind: str                      # agent | human | system | cli
    id: str
    party_id: str | None = None
    credential_id: str | None = None


SYSTEM = Actor("system", "bridge")


# ---- audit log (append-only, hash-chained) ----

def _audit_hash(prev_hash: str, row: dict) -> str:
    return hashlib.sha256(prev_hash.encode() + canonical_json(row)).hexdigest()


_AUDIT_FIELDS = ("ts", "actor_kind", "actor_id", "credential_id", "action", "target_kind", "target_id",
                 "request_id", "detail")


def audit(conn: sqlite3.Connection, actor: Actor, action: str, target_kind: str | None = None,
          target_id: str | None = None, detail: dict | None = None) -> str:
    """Append one audit row. `detail` holds ids/states/hashes only — never bodies or secrets."""
    head = conn.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    prev = head[0] if head else GENESIS
    row = {"ts": now_ms(), "actor_kind": actor.kind, "actor_id": actor.id, "credential_id": actor.credential_id,
           "action": action, "target_kind": target_kind, "target_id": target_id,
           "request_id": request_id_var.get(), "detail": canonical_json(detail or {}).decode()}
    h = _audit_hash(prev, row)
    conn.execute(f"INSERT INTO audit_log ({','.join(_AUDIT_FIELDS)}, prev_hash, hash) VALUES "
                 f"({','.join('?' * len(_AUDIT_FIELDS))}, ?, ?)", (*[row[k] for k in _AUDIT_FIELDS], prev, h))
    return h


def audit_head(conn: sqlite3.Connection) -> tuple[int, str]:
    r = conn.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    return (r[0], r[1]) if r else (0, GENESIS)


def audit_verify(conn: sqlite3.Connection) -> tuple[bool, int, int | None]:
    """Re-walk the chain. Returns (ok, rows_checked, first_bad_seq)."""
    prev, n = GENESIS, 0
    for r in conn.execute(f"SELECT seq, {','.join(_AUDIT_FIELDS)}, prev_hash, hash FROM audit_log ORDER BY seq"):
        row = {k: r[k] for k in _AUDIT_FIELDS}
        if r["prev_hash"] != prev or _audit_hash(prev, row) != r["hash"]:
            return False, n, r["seq"]
        prev, n = r["hash"], n + 1
    return True, n, None


# ---- presentation helpers ----

def task_summary(t) -> dict:
    return {"id": t["id"], "title": t["title"], "state": t["state"], "version": t["version"],
            "priority": t["priority"], "category": t["category"],
            "originator_agent_id": t["originator_agent_id"], "responsible_agent_id": t["responsible_agent_id"],
            "paused": t["paused_at"] is not None}


def task_dict(t) -> dict:
    return {**task_summary(t), "description": t["description"], "resume_state": t["resume_state"],
            "acceptance_criteria": json.loads(t["acceptance_criteria"]), "project": t["project"],
            "component": t["component"], "related_task_ids": json.loads(t["related_task_ids"]),
            "parent_task_id": t["parent_task_id"], "hop_count": t["hop_count"],
            "clarification_rounds": t["clarification_rounds"], "message_count": t["message_count"],
            "created_at": iso(t["created_at"]), "updated_at": iso(t["updated_at"]), "closed_at": iso(t["closed_at"])}


def message_dict(m) -> dict:
    return {"id": m["id"], "seq": m["seq"], "task_id": m["task_id"], "type": m["type"],
            "sender": _sender(m), "in_reply_to": m["in_reply_to"],
            "depth": m["depth"], "body": json.loads(m["body"]), "created_at": iso(m["created_at"])}


def _sender(m) -> dict:
    """The sender's party travels with the message, so an agent can tell its own party's human
    (instructions) from the other party's (context only)."""
    party = m["sender_party_id"] if "sender_party_id" in m.keys() else None
    return {"kind": m["sender_kind"], "id": m["sender_id"], "party_id": party}


def message_meta(m) -> dict:
    """A message without its body (history default): `body_bytes` tells the reader what it would cost."""
    d = message_dict_nobody(m)
    d["body_bytes"] = len(m["body"].encode()) if isinstance(m["body"], str) else 0
    return d


def message_dict_nobody(m) -> dict:
    return {"id": m["id"], "seq": m["seq"], "task_id": m["task_id"], "type": m["type"], "sender": _sender(m),
            "in_reply_to": m["in_reply_to"], "depth": m["depth"], "created_at": iso(m["created_at"])}


def load_task(conn: sqlite3.Connection, task_id: str):
    return conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()


# ---- outbox + timeline ----

def emit(conn: sqlite3.Connection, task, etype: str, payload: dict, actor: Actor) -> None:
    """Queue an inbox event for each participant agent except the acting agent itself."""
    recipients = {task["originator_agent_id"], task["responsible_agent_id"]}
    if actor.kind == "agent":
        recipients.discard(actor.id)
    ts = now_ms()
    body = dumps({"actor": {"kind": actor.kind, "id": actor.id, "party_id": actor.party_id}, **payload})
    for agent_id in sorted(recipients):
        conn.execute("INSERT INTO events (id, recipient_agent_id, type, task_id, payload, created_at) "
                     "VALUES (?,?,?,?,?,?)", (new_id("evt"), agent_id, etype, task["id"], body, ts))


def emit_to(conn: sqlite3.Connection, agent_id: str, etype: str, task_id: str | None, payload: dict) -> None:
    conn.execute("INSERT INTO events (id, recipient_agent_id, type, task_id, payload, created_at) VALUES (?,?,?,?,?,?)",
                 (new_id("evt"), agent_id, etype, task_id, dumps(payload), now_ms()))


def log_task(conn: sqlite3.Connection, task_id: str, actor: Actor, kind: str, *, from_state=None, to_state=None,
             message_id=None, detail: dict | None = None) -> None:
    conn.execute("INSERT INTO task_log (task_id, ts, actor_kind, actor_id, kind, from_state, to_state, message_id, detail)"
                 " VALUES (?,?,?,?,?,?,?,?,?)", (task_id, now_ms(), actor.kind, actor.id, kind, from_state, to_state,
                                                 message_id, dumps(detail or {})))


def insert_message(conn: sqlite3.Connection, task, actor: Actor, mtype: str, body: dict,
                   in_reply_to: str | None = None, depth: int = 0, notify: bool = True):
    """Store a message, log it on the task timeline, deliver it to the other participant(s), audit it."""
    raw = canonical_json(body)
    if len(raw) > 65536:
        from ..errors import Problem
        raise Problem(413, "message_too_large", "message body exceeds 64 KiB")
    mid = new_id("msg")
    conn.execute("INSERT INTO messages (id, task_id, type, sender_kind, sender_id, sender_party_id, in_reply_to, depth,"
                 " body, body_sha256, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                 (mid, task["id"], mtype, actor.kind, actor.id, actor.party_id, in_reply_to, depth, raw.decode(),
                  sha256_hex(raw), now_ms()))
    m = conn.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
    log_task(conn, task["id"], actor, "message", message_id=mid, detail={"type": mtype})
    if notify:
        emit(conn, task, "message.created", {"task": task_summary(task), "message": message_dict(m)}, actor)
    audit(conn, actor, "message.create", "message", mid, {"task_id": task["id"], "type": mtype, "body_sha256": sha256_hex(raw)})
    return m
