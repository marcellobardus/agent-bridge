"""Read-only queries for dashboard pages that the JSON read views do not cover (filters, counts, activity)."""
import json

from ..domain import approvals as apr
from ..domain.common import task_dict
from ..util import iso, now_ms

TERMINAL = ("closed", "rejected")
SEARCH_SCAN_TASKS = 500        # message-text search covers the newest N tasks only
_PRIO = "CASE t.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END"


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def tasks(conn, *, scope: str = "active", state=None, category=None, priority=None, agent=None, project=None,
          q=None, limit: int = 50, offset: int = 0) -> list[dict]:
    """scope: active (non-terminal), history (closed/rejected), all. q searches title, description, messages."""
    where, args = [], []
    if scope == "active":
        where.append("t.state NOT IN ('closed','rejected')")
    elif scope == "history":
        where.append("t.state IN ('closed','rejected')")
    for col, val in (("state", state), ("category", category), ("priority", priority), ("project", project)):
        if val:
            where.append(f"t.{col}=?")
            args.append(val)
    if agent:
        where.append("(t.originator_agent_id=? OR t.responsible_agent_id=?)")
        args += [agent, agent]
    if q:
        where.append("(t.id=? OR t.title LIKE ? ESCAPE '\\' OR t.description LIKE ? ESCAPE '\\' OR"
                     " (t.id IN (SELECT id FROM tasks ORDER BY updated_at DESC LIMIT ?) AND EXISTS"
                     " (SELECT 1 FROM messages m WHERE m.task_id=t.id AND m.body LIKE ? ESCAPE '\\')))")
        args += [q, _like(q), _like(q), SEARCH_SCAN_TASKS, _like(q)]
    sql = "SELECT t.* FROM tasks t" + (" WHERE " + " AND ".join(where) if where else "")
    order = f"{_PRIO}, t.updated_at DESC" if scope == "active" else "t.updated_at DESC"
    sql += f" ORDER BY {order}, t.id DESC LIMIT ? OFFSET ?"
    return [task_dict(r) for r in conn.execute(sql, (*args, limit, offset))]


def state_counts(conn) -> dict:
    return {r[0]: r[1] for r in conn.execute("SELECT state, count(*) FROM tasks GROUP BY state")}


def projects(conn) -> list[str]:
    return [r[0] for r in conn.execute("SELECT DISTINCT project FROM tasks WHERE project IS NOT NULL"
                                       " ORDER BY project LIMIT 100")]


def agent_parties(conn) -> dict:
    return {r[0]: r[1] for r in conn.execute("SELECT id, party_id FROM agents")}


def human_names(conn) -> dict:
    return {r["id"]: r["login"] for r in conn.execute("SELECT id, login FROM humans")}


APPROVALS_SCAN = 200
_APPROVAL_LIST_COLS = ", ".join("a." + c for c in (
    "id", "task_id", "kind", "state", "requested_by_agent_id", "approver_party_id", "summary", "action_sha256",
    "decided_by_human_id", "decided_at", "decision_note", "created_at", "expires_at", "valid_until", "consumed_at"))


def approvals(conn, *, state=None, party=None, q=None, limit: int = 200) -> list[dict]:
    """All approvals (both parties see everything), newest first; `state` is the effective state."""
    where, args = [], []
    if party:
        where.append("a.approver_party_id=?")
        args.append(party)
    if q:
        where.append("(a.id=? OR a.task_id=? OR a.kind=? OR a.summary LIKE ? ESCAPE '\\' OR t.title LIKE ? ESCAPE '\\'"
                     " OR a.decision_note LIKE ? ESCAPE '\\')")
        args += [q, q, q, _like(q), _like(q), _like(q)]
    # list columns only (never the up-to-32-KiB `action` payload), at most APPROVALS_SCAN rows per view
    sql = ("SELECT " + _APPROVAL_LIST_COLS + ", t.title AS task_title FROM approvals a JOIN tasks t ON t.id=a.task_id"
           + (" WHERE " + " AND ".join(where) if where else "") + f" ORDER BY a.created_at DESC LIMIT {APPROVALS_SCAN}")
    out = []
    for r in conn.execute(sql, args):
        d = {**apr.approval_dict(r, with_action=False), "task_title": r["task_title"]}   # lists never need payloads
        if state is None or d["state"] == state:
            out.append(d)
        if len(out) >= limit:
            break
    return out


def approval_row(conn, approval_id: str):
    return conn.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()


def audit(conn, *, action=None, actor=None, target=None, before_seq=None, limit: int = 100) -> list[dict]:
    """`action` matches exactly or as a prefix ending in '.', e.g. 'approval.' or 'login.fail'."""
    where, args = [], []
    if action and action.endswith("."):
        where.append("action LIKE ? ESCAPE '\\'")
        args.append(action.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    elif action:
        where.append("action=?")
        args.append(action)
    if actor:
        where.append("actor_id=?")
        args.append(actor)
    if target:
        where.append("target_id=?")
        args.append(target)
    if before_seq:
        where.append("seq<?")
        args.append(before_seq)
    sql = "SELECT * FROM audit_log" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY seq DESC LIMIT ?"
    return [{"seq": r["seq"], "ts": iso(r["ts"]), "actor_kind": r["actor_kind"], "actor_id": r["actor_id"],
             "credential_id": r["credential_id"], "action": r["action"], "target_kind": r["target_kind"],
             "target_id": r["target_id"], "detail": json.loads(r["detail"]), "hash": r["hash"]}
            for r in conn.execute(sql, (*args, limit))]


def agent_stats(conn) -> dict:
    """Per agent: unacked inbox events, active keys, messages sent in the last 24 h, open tasks."""
    day = now_ms() - 86_400_000
    out: dict = {}
    for r in conn.execute("SELECT a.id, (SELECT count(*) FROM events e WHERE e.recipient_agent_id=a.id AND"
                          " e.seq > coalesce((SELECT acked_seq FROM agent_cursors c WHERE c.agent_id=a.id),0)) AS unacked,"
                          " (SELECT count(*) FROM api_keys k WHERE k.agent_id=a.id AND k.revoked_at IS NULL AND"
                          "  (k.expires_at IS NULL OR k.expires_at>?)) AS active_keys,"
                          " (SELECT count(*) FROM messages m WHERE m.sender_kind='agent' AND m.sender_id=a.id AND"
                          "  m.created_at>?) AS messages_24h,"
                          " (SELECT count(*) FROM tasks t WHERE (t.originator_agent_id=a.id OR t.responsible_agent_id=a.id)"
                          "  AND t.state NOT IN ('closed','rejected')) AS open_tasks FROM agents a", (now_ms(), day)):
        out[r["id"]] = dict(r)
    return out


def agent_messages(conn, agent_id: str, limit: int = 30) -> list[dict]:
    rows = conn.execute("SELECT m.id, m.task_id, m.type, m.body, m.created_at, t.title FROM messages m JOIN tasks t"
                        " ON t.id=m.task_id WHERE m.sender_kind='agent' AND m.sender_id=? ORDER BY m.seq DESC LIMIT ?",
                        (agent_id, limit)).fetchall()
    out = []
    for r in rows:
        text = (json.loads(r["body"]).get("text") or "")
        out.append({"id": r["id"], "task_id": r["task_id"], "task_title": r["title"], "type": r["type"],
                    "text": text[:300] + ("…" if len(text) > 300 else ""), "created_at": iso(r["created_at"])})
    return out


def meta(conn, key: str) -> str | None:
    r = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return r[0] if r else None


def totp_failures_last_hour(conn) -> int:
    """Wrong TOTP codes with a correct password (login) plus failed step-ups in the last hour (dashboard banner)."""
    return conn.execute("SELECT count(*) FROM audit_log WHERE action IN ('login.totp_fail','stepup.fail') AND ts>?",
                        (now_ms() - 3_600_000,)).fetchone()[0]


def throttled_accounts(conn) -> list[str]:
    return [r[0] for r in conn.execute("SELECT login FROM humans WHERE totp_next_allowed_at>?", (now_ms(),))]


# ---- Messages page: messages addressed to one agent ----
# Recipient semantics follow common.emit: a message on a task is delivered to every participant agent
# (originator, responsible) except the agent that sent it, so a HUMAN_INSTRUCTION reaches both agents and an
# agent's message reaches the other participant. TASK_REQUEST (notify=False) reaches the responsible agent through
# task.created, which is the same "other participant" rule.
_TO_AGENT = ("(t.originator_agent_id=:agent OR t.responsible_agent_id=:agent)"
             " AND NOT (m.sender_kind='agent' AND m.sender_id=:agent)")
PREVIEW_HEAD = 400             # characters of message text read per row (the page shows ~160)


def messages_to(conn, agent_id: str, *, before_seq: int | None = None, limit: int = 50) -> list[dict]:
    """Newest first, keyset-paged by messages.seq. Only the head of the text is read (bounded rows)."""
    rows = conn.execute(
        "SELECT m.seq, m.id, m.task_id, m.type, m.sender_kind, m.sender_id, m.sender_party_id, m.created_at,"
        " substr(json_extract(m.body,'$.text'),1,:head) AS head, length(json_extract(m.body,'$.text')) AS text_len,"
        " length(m.body) AS body_len, t.title FROM messages m JOIN tasks t ON t.id=m.task_id"
        f" WHERE {_TO_AGENT} AND m.seq<:before ORDER BY m.seq DESC LIMIT :limit",
        {"agent": agent_id, "head": PREVIEW_HEAD, "before": before_seq or 2 ** 62, "limit": limit}).fetchall()
    return [{"seq": r["seq"], "id": r["id"], "task_id": r["task_id"], "task_title": r["title"], "type": r["type"],
             "sender": {"kind": r["sender_kind"], "id": r["sender_id"], "party_id": r["sender_party_id"]},
             "created_at": iso(r["created_at"]), "head": r["head"] if isinstance(r["head"], str) else "",
             "text_len": r["text_len"] or 0, "body_bytes": r["body_len"]} for r in rows]


def message_with_task(conn, message_id: str):
    """(message row, task row) or (None, None)."""
    m = conn.execute("SELECT * FROM messages WHERE id=?", (message_id,)).fetchone()
    if m is None:
        return None, None
    return m, conn.execute("SELECT * FROM tasks WHERE id=?", (m["task_id"],)).fetchone()


def party_names(conn) -> dict:
    """party_id -> display name, e.g. {'alice': 'Alice'}."""
    return {r["id"]: r["display_name"] for r in conn.execute("SELECT id, display_name FROM parties")}
