"""Per-agent inbox over the outbox table: cursor = events.seq (single writer => commit order, no skips)."""
import json

from ..util import Budget, iso, now_ms
from .approvals import pending_count


def fetch(conn, agent_id: str, cursor: int | None, limit: int, poll_after_s: int,
          max_bytes: int = 1024 * 1024) -> dict:
    """One page of events after `cursor`. The page also stops at ~max_bytes: `has_more` then says
    "fetch again now" exactly as for a full page."""
    if cursor is None:
        r = conn.execute("SELECT acked_seq FROM agent_cursors WHERE agent_id=?", (agent_id,)).fetchone()
        cursor = r[0] if r else 0
    budget, events, has_more = Budget(max_bytes), [], False
    for r in conn.execute("SELECT * FROM events WHERE recipient_agent_id=? AND seq>? ORDER BY seq LIMIT ?",
                          (agent_id, cursor, limit + 1)):
        if len(events) == limit:
            has_more = True
            break
        e = {"seq": r["seq"], "id": r["id"], "type": r["type"], "task_id": r["task_id"],
             "created_at": iso(r["created_at"]), **json.loads(r["payload"])}
        if not budget.admit(e):
            has_more = True
            break
        events.append(e)
    return {"events": events, "next_cursor": events[-1]["seq"] if events else cursor, "has_more": has_more,
            "poll_after_s": 0 if has_more else poll_after_s, "pending_approvals": pending_count(conn, agent_id),
            "server_time": iso(now_ms())}


def record_poll(conn, agent_id: str) -> None:
    conn.execute("INSERT INTO agent_cursors (agent_id, last_poll_at) VALUES (?,?) ON CONFLICT(agent_id) DO UPDATE"
                 " SET last_poll_at=excluded.last_poll_at", (agent_id, now_ms()))


def ack(conn, agent_id: str, cursor: int) -> int:
    """Monotonic: acked_seq = max(old, min(cursor, highest seq)). Returns the stored cursor."""
    top = conn.execute("SELECT coalesce(max(seq),0) FROM events").fetchone()[0]
    conn.execute("INSERT INTO agent_cursors (agent_id, acked_seq, acked_at) VALUES (?,?,?) ON CONFLICT(agent_id)"
                 " DO UPDATE SET acked_seq=max(acked_seq, excluded.acked_seq), acked_at=excluded.acked_at",
                 (agent_id, min(max(cursor, 0), top), now_ms()))
    return conn.execute("SELECT acked_seq FROM agent_cursors WHERE agent_id=?", (agent_id,)).fetchone()[0]
