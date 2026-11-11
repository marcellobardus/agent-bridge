"""Agent API keys: `abk_<keyid:12>_<secret:43>`, stored as HMAC-SHA256(pepper, secret), scoped, revocable."""
import hashlib
import hmac
import json
import re
import secrets

from ..errors import Problem
from ..util import now_ms
from .common import Actor, audit

SCOPES = ("inbox:read", "tasks:read", "tasks:write", "approvals:request")
MAX_ACTIVE_KEYS = 2
_TOKEN = re.compile(r"abk_([a-z0-9]{12})_([A-Za-z0-9_-]{43})")
_KEYID_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


def _hash(pepper: bytes, secret: str) -> bytes:
    return hmac.new(pepper, secret.encode(), hashlib.sha256).digest()


def parse(token: str) -> tuple[str, str] | None:
    m = _TOKEN.fullmatch(token or "")
    return (m.group(1), m.group(2)) if m else None


def create(conn, actor: Actor, agent_id: str, label: str, pepper: bytes, scopes=SCOPES,
           expires_at: int | None = None) -> tuple[str, str]:
    """Returns (key_id, full_token). The token is shown once and never stored."""
    agent = conn.execute("SELECT id FROM agents WHERE id=? AND disabled_at IS NULL", (agent_id,)).fetchone()
    if agent is None:
        raise Problem(404, "agent_not_found", "agent not found")
    bad = [s for s in scopes if s not in SCOPES]
    if bad or not scopes:
        raise Problem(422, "invalid_scopes", f"scopes must be a non-empty subset of {SCOPES}")
    now = now_ms()
    active = conn.execute("SELECT count(*) FROM api_keys WHERE agent_id=? AND revoked_at IS NULL"
                          " AND (expires_at IS NULL OR expires_at>?)", (agent_id, now)).fetchone()[0]
    if active >= MAX_ACTIVE_KEYS:
        raise Problem(409, "too_many_keys", f"at most {MAX_ACTIVE_KEYS} active keys per agent; revoke one first")
    key_id = "".join(secrets.choice(_KEYID_ALPHABET) for _ in range(12))
    secret = secrets.token_urlsafe(32)
    conn.execute("INSERT INTO api_keys (id, agent_id, secret_hash, scopes, label, created_at, expires_at)"
                 " VALUES (?,?,?,?,?,?,?)", (key_id, agent_id, _hash(pepper, secret), json.dumps(list(scopes)),
                                             label, now, expires_at))
    audit(conn, actor, "key.create", "api_key", key_id, {"agent_id": agent_id, "scopes": list(scopes)})
    return key_id, f"abk_{key_id}_{secret}"


def revoke(conn, actor: Actor, key_id: str) -> None:
    cur = conn.execute("UPDATE api_keys SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (now_ms(), key_id))
    if cur.rowcount == 0:
        raise Problem(404, "key_not_found", "no active key with that id")
    audit(conn, actor, "key.revoke", "api_key", key_id, {})


def authenticate(conn, token: str, pepper: bytes):
    """Returns the joined key/agent row or None. Constant-time compare; unknown ids still pay for an HMAC."""
    parsed = parse(token)
    if parsed is None:
        return None
    key_id, secret = parsed
    row = conn.execute("SELECT k.id AS key_id, k.secret_hash, k.scopes, k.expires_at, k.revoked_at, k.last_used_at,"
                       " a.id AS agent_id, a.party_id, a.paused_at AS agent_paused_at, a.disabled_at,"
                       " p.paused_at AS party_paused_at FROM api_keys k JOIN agents a ON a.id=k.agent_id"
                       " JOIN parties p ON p.id=a.party_id WHERE k.id=?", (key_id,)).fetchone()
    digest = _hash(pepper, secret)
    expected = row["secret_hash"] if row else b"\0" * 32
    if not hmac.compare_digest(digest, expected) or row is None:
        return None
    if row["revoked_at"] is not None or row["disabled_at"] is not None:
        return None
    if row["expires_at"] is not None and row["expires_at"] <= now_ms():
        return None
    return row
