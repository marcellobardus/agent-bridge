"""Settings: a TOML file (non-secret) plus credential files (pepper, totp_kek) via systemd LoadCredential."""
import dataclasses
import os
import tomllib
from pathlib import Path


@dataclasses.dataclass
class Limits:
    max_body_bytes: int = 256 * 1024
    artifact_max_bytes: int = 2 * 1024 * 1024
    artifact_task_quota_bytes: int = 20 * 1024 * 1024
    artifact_global_quota_bytes: int = 512 * 1024 * 1024
    per_key_per_min: int = 120
    per_key_writes_per_min: int = 30
    unauth_per_ip_per_min: int = 30          # failed authentications per client IP; valid keys never charged
    unauth_global_per_min: int = 3000        # backstop for failed auths from all IPs; never blocks a valid key
    login_fail_global_per_min: int = 60      # failed dashboard logins from all IPs, on top of per-IP throttling
    max_in_flight_per_key: int = 2           # concurrent requests per agent key
    max_response_bytes: int = 1024 * 1024    # list/history/inbox pages stop growing past this
    max_data_bytes: int = 16 * 1024          # message body `data` (canonical JSON)
    max_json_depth: int = 8                  # nesting depth of `data` and approval `action`
    artifact_agent_quota_bytes: int = 256 * 1024 * 1024   # per uploading agent, ~half the global quota
    search_scan_tasks: int = 500             # message-text search scans only the newest N tasks
    tasks_per_agent_per_day: int = 100
    messages_per_agent_per_day: int = 500
    approvals_per_agent_per_day: int = 20
    max_clarification_rounds: int = 3
    max_reply_depth: int = 6
    max_agent_streak: int = 40
    max_messages_per_task: int = 300         # per sender per task since the last human counter reset
    max_hop_count: int = 3
    dedupe_window_s: int = 600
    approval_ttl_s: int = 24 * 3600
    approval_max_ttl_s: int = 7 * 24 * 3600
    approval_consume_window_s: int = 24 * 3600
    min_free_bytes: int = 500 * 1024 * 1024
    min_free_inodes_pct: float = 5.0
    # request bodies are buffered only after the caller is identified, under a global budget
    pre_session_body_bytes: int = 8 * 1024   # /app/login, /app/enroll/*, any POST without a key or session
    session_body_bytes: int = 200 * 1024     # session-bound /app forms (16000-char instruction, worst-case %-encoding)
    max_buffered_bytes: int = 16 * 1024 * 1024    # all request bodies buffered at once, all callers
    max_large_bodies: int = 4                # concurrent artifact-size bodies (> max_body_bytes)
    # argon2 is gated before any hashing (non-blocking; over -> 429 at once)
    login_in_flight_per_ip: int = 1
    login_in_flight_global: int = 4
    login_queue_max: int = 16                # logins/enrollments that may wait for a slot ...
    login_wait_s: float = 5.0                # ... for at most this long (asyncio wait, no thread)
    login_reserved_slots: int = 1            # of the global slots, usable only by addresses that logged in before
    stepup_in_flight_global: int = 8         # step-up has its own gate, 1 per session
    login_attempts_per_ip_per_min: int = 10  # in memory, charged before the hash
    enroll_miss_per_ip_per_min: int = 10     # GET/POST /app/enroll/<unknown token>


@dataclasses.dataclass
class Settings:
    db_path: str = "/var/lib/agent-bridge/bridge.db"
    host: str = "127.0.0.1"
    port: int = 8787
    public_origin: str | None = None          # e.g. https://example.ngrok.app (dashboard links, Origin check)
    poll_after_s: int = 900                   # default agent poll interval hint (15 min)
    session_ttl_s: int = 12 * 3600
    session_idle_s: int = 30 * 60
    step_up_window_s: int = 5 * 60
    header_timeout_s: int = 10                # close connections that do not finish request headers in time
    body_timeout_s: int = 30                  # ... or the request body (artifact uploads)
    small_body_timeout_s: int = 10            # header + body deadline for every non-artifact request
    enroll_ttl_s: int = 24 * 3600             # lifetime of new enrollment links (existing links keep theirs)
    expose_openapi: bool = False              # serve /v1/openapi.json (agents use docs/openapi.json instead)
    limit_concurrency: int = 200              # uvicorn connection/task ceiling (idle sockets are cheap)
    pepper: bytes = b""
    totp_kek: bytes = b""
    limits: Limits = dataclasses.field(default_factory=Limits)


def _read_credential(name: str, cred_dir: str | None) -> bytes:
    if not cred_dir:
        raise RuntimeError(f"credential {name!r}: no credentials directory (set CREDENTIALS_DIRECTORY or credentials_dir)")
    raw = Path(cred_dir, name).read_bytes().strip()
    if len(raw) == 64 and all(c in b"0123456789abcdefABCDEF" for c in raw):
        return bytes.fromhex(raw.decode())
    return raw


def load_settings(path: str | None = None) -> Settings:
    data: dict = {}
    path = path or os.environ.get("BRIDGE_CONFIG")
    if path:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    for section in ("server", "storage"):          # sectioned layout written by deploy/install.sh
        data.update(data.pop(section, {}))
    data.pop("backup_dir", None)                  # used by deploy/backup.sh, not by the service
    limits = Limits(**data.pop("limits", {}))
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY") or data.pop("credentials_dir", None)
    data.pop("credentials_dir", None)
    s = Settings(limits=limits, **data)
    s.pepper = _read_credential("pepper", cred_dir)
    s.totp_kek = _read_credential("totp_kek", cred_dir)
    if len(s.pepper) < 32 or len(s.totp_kek) != 32:
        raise RuntimeError("pepper must be >= 32 bytes and totp_kek exactly 32 bytes")
    return s
