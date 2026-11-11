"""Operational functions used by bridgectl: init, backup, restore, doctor."""
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import tomllib
import urllib.parse

from .db import connect, migrate, migrations
from .domain import approvals
from .domain.common import Actor, audit, audit_head, audit_verify
from .util import now_ms

CLI = Actor("cli", "bridgectl")
DEFAULT_PARTIES = [("alice", "Alice", "business"), ("bob", "Bob", "engineering")]
DEFAULT_AGENTS = [("agent-a", "alice", "Agent A"), ("agent-b", "bob", "Agent B")]
EVENT_SEQ_BUMP = 1_000_000


def init_db(path: str, seed: bool = True) -> int:
    conn = connect(path)
    try:
        version = migrate(conn)
        if seed:
            conn.execute("BEGIN IMMEDIATE")
            now = now_ms()
            for pid, name, domain in DEFAULT_PARTIES:
                if conn.execute("INSERT OR IGNORE INTO parties (id, display_name, domain, created_at) VALUES (?,?,?,?)",
                                (pid, name, domain, now)).rowcount:
                    audit(conn, CLI, "party.create", "party", pid, {"domain": domain})
            for aid, pid, name in DEFAULT_AGENTS:
                if conn.execute("INSERT OR IGNORE INTO agents (id, party_id, display_name, created_at) VALUES (?,?,?,?)",
                                (aid, pid, name, now)).rowcount:
                    audit(conn, CLI, "agent.create", "agent", aid, {"party_id": pid})
            conn.execute("COMMIT")
        return version
    finally:
        conn.close()


class CredentialsUnverified(ValueError):
    """Restore refused: the replaced DB is missing or unreadable, so revocations made after the snapshot cannot be
    carried forward. Re-run with --confirm-credentials after reading `active` (then rotate what may have leaked)."""

    def __init__(self, active: dict):
        self.active = active
        super().__init__("the current database is missing or unreadable, so key revocations and account changes "
                         "made after the snapshot cannot be carried forward. The snapshot would re-activate: "
                         f"keys {active['keys']} and humans {active['humans']}. Re-run with --confirm-credentials, "
                         "then rotate keys (bridgectl key rotate) and reset humans (bridgectl human reset) that "
                         "may have changed since the snapshot")


def check_snapshot(path: str) -> dict:
    """Integrity, foreign keys, schema and audit chain of a DB file. Raises ValueError on failure."""
    try:
        return _check_snapshot(path)
    except sqlite3.DatabaseError as e:
        raise ValueError(f"not a valid bridge database ({type(e).__name__})") from None


def _schema(conn) -> set:
    return {(r[0], r[1], r[2]) for r in conn.execute(
        "SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name")}


def expected_schema(version: int) -> set:
    """sqlite_master as produced by the migrations up to `version` (an in-memory reference database)."""
    ref = sqlite3.connect(":memory:")
    try:
        for v, sql in migrations():
            if v <= version:
                ref.executescript(sql)
        return _schema(ref)
    finally:
        ref.close()


def _check_snapshot(path: str) -> dict:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA trusted_schema=OFF")     # no functions/virtual tables invoked from a planted schema
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("integrity_check failed")
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        known = max(v for v, _ in migrations())
        if not 1 <= version <= known:
            raise ValueError(f"unknown schema version {version}")
        got, want = _schema(conn), expected_schema(version)
        if got != want:
            extra = sorted(f"{t} {n}" for t, n, _ in got - want)
            missing = sorted(f"{t} {n}" for t, n, _ in want - got)
            raise ValueError(f"schema differs from migration {version} (unexpected: {extra[:5]}, "
                             f"missing/changed: {missing[:5]})")
        if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ValueError("foreign_key_check failed")
        ok, n, bad = audit_verify(conn)
        if not ok:
            raise ValueError(f"audit chain broken at seq {bad}")
        seq, h = audit_head(conn)
        r = conn.execute("SELECT value FROM meta WHERE key='backup_taken_at'").fetchone()
        return {"audit_rows": n, "head_seq": seq, "head_hash": h, "backup_taken_at": int(r[0]) if r else None,
                "schema_version": version}
    finally:
        conn.close()


def _credential_state(path: str) -> dict | None:
    """Keys, humans and agents of an existing DB (the one about to be replaced), or None if unreadable."""
    if not os.path.exists(path):
        return None
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA trusted_schema=OFF")
            if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                return None
            return {
                "keys": {r["id"]: r["revoked_at"] for r in conn.execute("SELECT id, revoked_at FROM api_keys")},
                "humans": {r["id"]: dict(r) for r in conn.execute(
                    "SELECT id, login, disabled_at, password_hash, totp_secret_enc FROM humans")},
                "agents": {r["id"]: r["disabled_at"] for r in conn.execute("SELECT id, disabled_at FROM agents")},
                "agent_paused": {r["id"]: r["paused_at"] for r in conn.execute("SELECT id, paused_at FROM agents")},
                "party_paused": {r["id"]: r["paused_at"] for r in conn.execute("SELECT id, paused_at FROM parties")},
            }
        finally:
            conn.close()
    except sqlite3.Error:
        return None


def active_credentials(path: str) -> dict:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return {"keys": [r[0] for r in conn.execute("SELECT id FROM api_keys WHERE revoked_at IS NULL ORDER BY id")],
                "humans": [r[0] for r in conn.execute("SELECT login FROM humans WHERE disabled_at IS NULL ORDER BY login")]}
    finally:
        conn.close()


def _carry_forward(conn, prior: dict | None, now: int) -> dict:
    """A restore must never re-arm a credential. Every session is revoked and every enrollment link used.
    From the replaced DB (when readable) revocations carry forward: keys revoked there, or unknown there, stay
    revoked; humans disabled there, unknown there, or whose password/TOTP changed after the snapshot are disabled
    (re-enroll with `bridgectl human reset`). Credential VALUES are never copied from the replaced DB: it may be
    the compromised one."""
    out = {"sessions_revoked": conn.execute("UPDATE sessions SET revoked_at=? WHERE revoked_at IS NULL",
                                            (now,)).rowcount,
           "enrollments_closed": conn.execute("UPDATE enrollments SET used_at=? WHERE used_at IS NULL",
                                              (now,)).rowcount,
           "credentials_verified": prior is not None, "keys_revoked": [], "humans_disabled": []}
    if prior is None:
        return out
    for key_id, revoked in conn.execute("SELECT id, revoked_at FROM api_keys WHERE revoked_at IS NULL").fetchall():
        if key_id not in prior["keys"] or prior["keys"][key_id] is not None:
            conn.execute("UPDATE api_keys SET revoked_at=? WHERE id=?", (prior["keys"].get(key_id) or now, key_id))
            out["keys_revoked"].append(key_id)
    for h in conn.execute("SELECT id, login, password_hash, totp_secret_enc FROM humans WHERE disabled_at IS NULL"
                          ).fetchall():
        p = prior["humans"].get(h["id"])
        if (p is None or p["disabled_at"] is not None or p["password_hash"] != h["password_hash"]
                or p["totp_secret_enc"] != h["totp_secret_enc"]):
            conn.execute("UPDATE humans SET disabled_at=? WHERE id=?", ((p or {}).get("disabled_at") or now, h["id"]))
            out["humans_disabled"].append(h["login"])
    for agent_id, disabled in prior["agents"].items():
        if disabled is not None:
            conn.execute("UPDATE agents SET disabled_at=? WHERE id=? AND disabled_at IS NULL", (disabled, agent_id))
    for agent_id, paused in prior.get("agent_paused", {}).items():       # a pause survives a restore
        if paused is not None:
            conn.execute("UPDATE agents SET paused_at=? WHERE id=? AND paused_at IS NULL", (paused, agent_id))
    for party_id, paused in prior.get("party_paused", {}).items():
        if paused is not None:
            conn.execute("UPDATE parties SET paused_at=? WHERE id=? AND paused_at IS NULL", (paused, party_id))
    return out


def backup(db_path: str, out_path: str) -> dict:
    """Online backup (sqlite3 backup API) to a new file, stamped with the snapshot time, then verified."""
    if os.path.exists(out_path):
        raise FileExistsError(out_path)
    src = connect(db_path, readonly=True)
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    dst = sqlite3.connect(out_path)
    try:
        taken = now_ms()
        src.backup(dst)
        dst.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('backup_taken_at', ?)", (str(taken),))
        dst.commit()
        dst.execute("PRAGMA journal_mode=DELETE")
    finally:
        dst.close()
        src.close()
    return check_snapshot(out_path)


def restore(db_path: str, snapshot_path: str, confirm_credentials: bool = False) -> dict:
    """Replace the live DB (service must be stopped) with a verified snapshot, then in one transaction:
    cancel every open approval, carry credential revocations forward (see _carry_forward), drop
    idempotency rows at/after the snapshot time, bump the event sequence, and append a system.restore audit row
    recording the replaced head. Refuses (CredentialsUnverified) when the replaced DB cannot be read, unless
    confirm_credentials."""
    snap = check_snapshot(snapshot_path)
    prior = _credential_state(db_path)
    if prior is None and not confirm_credentials:
        raise CredentialsUnverified(active_credentials(snapshot_path))
    replaced = {"head_seq": None, "head_hash": None}
    if os.path.exists(db_path):
        try:
            old = connect(db_path, readonly=True)
            replaced["head_seq"], replaced["head_hash"] = audit_head(old)
            old.close()
        except sqlite3.Error:
            pass
        shutil.copyfile(db_path, db_path + ".replaced")
        os.chmod(db_path + ".replaced", 0o600)
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(db_path + suffix):
            os.remove(db_path + suffix)
    src = sqlite3.connect(f"file:{snapshot_path}?mode=ro", uri=True)
    fd = os.open(db_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    dst = sqlite3.connect(db_path)
    src.backup(dst)
    src.close()
    dst.close()
    conn = connect(db_path)
    try:
        migrate(conn)
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT OR IGNORE INTO sqlite_sequence (name, seq) VALUES ('events', 0)")
        conn.execute("UPDATE sqlite_sequence SET seq=seq+? WHERE name='events'", (EVENT_SEQ_BUMP,))
        cancelled = approvals.cancel_open_for_task(conn, None, "restore")
        cutoff = snap["backup_taken_at"]
        if cutoff is None:
            dropped = conn.execute("DELETE FROM idempotency_keys").rowcount
        else:
            dropped = conn.execute("DELETE FROM idempotency_keys WHERE created_at>=?", (cutoff,)).rowcount
        creds = _carry_forward(conn, prior, now_ms())
        conn.execute("DELETE FROM meta WHERE key='backup_taken_at'")
        conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('last_restore_at', ?)", (str(now_ms()),))
        detail = {"replaced_head_seq": replaced["head_seq"], "replaced_head_hash": replaced["head_hash"],
                  "snapshot_head_seq": snap["head_seq"], "snapshot_head_hash": snap["head_hash"],
                  "snapshot_taken_at": cutoff, "cancelled_approvals": cancelled, "dropped_idempotency_keys": dropped,
                  **creds}
        audit(conn, Actor("system", "restore"), "system.restore", "database", None, detail)
        conn.execute("COMMIT")
        return detail
    finally:
        conn.close()


def doctor(settings) -> list[tuple[str, bool, str]]:
    checks = []
    st = os.statvfs(os.path.dirname(os.path.abspath(settings.db_path)))
    free, inode_pct = st.f_bavail * st.f_frsize, 100.0 * st.f_favail / max(st.f_files, 1)
    checks.append(("disk_free", free >= settings.limits.min_free_bytes, f"{free // 2**20} MiB free"))
    checks.append(("inodes_free", inode_pct >= settings.limits.min_free_inodes_pct, f"{inode_pct:.1f}% free"))
    try:
        conn = connect(settings.db_path, readonly=True)
        checks.append(("integrity", conn.execute("PRAGMA quick_check").fetchone()[0] == "ok", "quick_check"))
        checks.append(("journal_mode", conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal", "wal"))
        ok, n, bad = audit_verify(conn)
        checks.append(("audit_chain", ok, f"{n} rows" + ("" if ok else f", broken at {bad}")))
        fails = conn.execute("SELECT count(*) FROM audit_log WHERE action='login.totp_fail' AND ts>?",
                             (now_ms() - 3_600_000,)).fetchone()[0]
        checks.append(("totp_failures_1h", fails < 5, f"{fails} wrong-TOTP logins in the last hour"))
        keys = conn.execute("SELECT agent_id, count(*) FROM api_keys WHERE revoked_at IS NULL GROUP BY agent_id").fetchall()
        checks.append(("agent_keys", True, ", ".join(f"{a}:{c}" for a, c in keys) or "none"))
        conn.close()
    except sqlite3.Error as e:
        checks.append(("database", False, type(e).__name__))
    import stat
    mode = stat.S_IMODE(os.stat(settings.db_path).st_mode) if os.path.exists(settings.db_path) else 0
    checks.append(("db_permissions", mode & 0o077 == 0, oct(mode)))
    return checks


# ---- tunnel checks -------------------------------------------------------------------------------------
# Run by `bridgectl doctor` as root, outside the CLI sandbox (that one has IPAddressDeny=any and cannot read the
# journal). They never open the DB and need no credentials.
NGROK_UNIT = "agent-bridge-ngrok.service"
RENDERED_NGROK_CONFIG = "/run/agent-bridge-ngrok/ngrok.yml"   # exists only while the pinned-domain unit runs
NGROK_INSPECTOR = ("127.0.0.1", 4040)
_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_JOURNAL_URL_RE = re.compile(r'"url":"(https://[^"]*)"')
_RENDERED_URL_RE = re.compile(r"^\s*url:\s*[\"']?(https://[^\"'\s]+)[\"']?\s*$", re.M)
_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def valid_hostname(h: str) -> bool:
    """Same rules as deploy/ngrok/render-config.sh: lowercase LDH labels of 1-63 chars without edge hyphens, at
    least one dot, <= 253 chars, last label not starting with a digit. No scheme, port, path, userinfo or whitespace."""
    if not isinstance(h, str) or not 0 < len(h) <= 253 or "." not in h or not h.isascii():
        return False
    labels = h.split(".")
    return all(_LABEL_RE.match(x) for x in labels) and not labels[-1][0].isdigit()


def origin_host(url: str | None) -> str | None:
    """Hostname of a bare `https://<hostname>` (one trailing slash tolerated), else None."""
    if not url or not url.startswith("https://"):
        return None
    host = url[len("https://"):]
    host = host[:-1] if host.endswith("/") else host
    return host if valid_hostname(host) else None


def _run(run, argv: list[str], timeout: float) -> str | None:
    try:
        r = run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def running_tunnel_url(run=subprocess.run, rendered: str = RENDERED_NGROK_CONFIG) -> tuple[str | None, str]:
    """URL of the running tunnel: the last bare https://<host> `"url"` in the journal of the CURRENT invocation of
    the ngrok unit (same logic as deploy/ngrok/sync-origin.sh); failing that, the endpoint url of the rendered
    pinned-domain config. Returns (url or None, where it came from / why it is unknown)."""
    inv = (_run(run, ["systemctl", "show", "-p", "InvocationID", "--value", NGROK_UNIT], 5) or "").strip()
    if not re.fullmatch(r"[0-9a-f]{32}", inv):
        return None, f"{NGROK_UNIT} not running or systemctl unavailable"
    out = _run(run, ["journalctl", f"_SYSTEMD_INVOCATION_ID={inv}", "-o", "cat", "--no-pager"], 15)
    url = None
    for m in _JOURNAL_URL_RE.finditer(out or ""):
        if origin_host(m.group(1)) and not m.group(1).endswith("/"):
            url = m.group(1)
    if url:
        return url, "journal"
    try:
        with open(rendered, encoding="utf-8") as f:
            for m in _RENDERED_URL_RE.finditer(f.read(65536)):
                if origin_host(m.group(1)):
                    return m.group(1).rstrip("/"), "rendered config"
    except OSError:
        pass
    if out is None:
        return None, "journal unavailable (run as root via bridgectl)"
    return None, "no tunnel URL in this invocation's journal"


def inspector_check(addr: tuple[str, int] = NGROK_INSPECTOR, timeout: float = 0.5) -> tuple[str, str]:
    """FAIL if anything accepts a TCP connection on 127.0.0.1:4040 (ngrok inspector/API: it would hand captured
    requests, bearer keys included, to any local process)."""
    try:
        with socket.create_connection(addr, timeout=timeout):
            return "FAIL", f"something listens on {addr[0]}:{addr[1]} (ngrok inspector? keep web_addr: false)"
    except ConnectionRefusedError:
        return "OK", f"nothing on {addr[0]}:{addr[1]}"
    except OSError as e:
        return "WARN", f"could not check {addr[0]}:{addr[1]} ({type(e).__name__})"


def tunnel_checks(public_origin: str | None, *, run=subprocess.run, rendered: str = RENDERED_NGROK_CONFIG,
                  inspector: tuple[str, int] = NGROK_INSPECTOR) -> list[tuple[str, str, str]]:
    """[(name, "OK"|"WARN"|"FAIL", info)]. A missing journal or a public_origin that differs from the running
    tunnel is a WARN; a listener on the inspector port or a plain-http public origin is a FAIL."""
    checks = [("ngrok_inspector", *inspector_check(inspector))]
    po = (public_origin or "").strip()
    u = urllib.parse.urlsplit(po) if po else None
    if not po:
        checks.append(("public_origin", "WARN", "not set (enrollment links and the Origin check need it)"))
        return checks
    if "CHANGE-ME" in po:
        checks.append(("public_origin", "WARN", f"still the placeholder {po}"))
        return checks
    if u.scheme == "http" and u.hostname in _LOOPBACK:
        checks.append(("public_origin", "OK", f"{po} (loopback: no tunnel to compare)"))
        return checks
    if u.scheme != "https":
        checks.append(("public_origin", "FAIL", f"{po}: must be https (plain http only for loopback)"))
        return checks
    if origin_host(po) is None:
        checks.append(("public_origin", "WARN", f"{po}: expected https://<lowercase hostname> without port or path"))
        return checks
    checks.append(("public_origin", "OK", po))
    url, src = running_tunnel_url(run, rendered)
    if url is None:
        checks.append(("public_origin_tunnel", "WARN", f"cannot compare with the running tunnel: {src}"))
    elif url != po.rstrip("/"):
        checks.append(("public_origin_tunnel", "WARN", f"public_origin {po} != running tunnel {url} ({src}); "
                       "agents and links point at the wrong host: fix public_origin and restart agent-bridge"))
    else:
        checks.append(("public_origin_tunnel", "OK", f"matches the running tunnel ({src})"))
    return checks


def read_public_origin(config_path: str | None) -> str | None:
    """public_origin from config.toml ([server] section or flat), without loading credentials."""
    path = config_path or os.environ.get("BRIDGE_CONFIG")
    if not path:
        return None
    with open(path, "rb") as f:
        data = tomllib.load(f)
    return (data.get("server") or {}).get("public_origin", data.get("public_origin"))
