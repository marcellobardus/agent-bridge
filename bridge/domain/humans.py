"""Human accounts: argon2id password + TOTP, per-IP login throttling plus per-account TOTP delays (no permanent
lockout), sessions with CSRF + step-up (password + TOTP)."""
import hashlib
import hmac
import ipaddress
import os
import secrets
import threading
import time

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .. import logs
from ..errors import Problem
from ..util import new_id, now_ms
from . import totp
from .common import Actor, audit

_ph = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)   # m=19 MiB, t=2, p=1
_hash_sem = threading.Semaphore(1)                                     # one hash at a time: bounded memory
_DUMMY = _ph.hash("dummy-password-for-timing")
MIN_PASSWORD = 12
THROTTLE_FREE_FAILURES = 3
THROTTLE_MAX_DELAY_MS = 300_000
ACCOUNT_FREE_TOTP_FAILURES = 5          # wrong TOTP codes (with a correct password) before per-account delays
ACCOUNT_MAX_DELAY_MS = 15 * 60_000
STEPUP_MAX_FAILURES = 5                 # wrong step-ups on one session before it is revoked


def hash_password(pw: str) -> str:
    if len(pw) < MIN_PASSWORD:
        raise Problem(422, "weak_password", f"password must be at least {MIN_PASSWORD} characters")
    with _hash_sem:
        return _ph.hash(pw)


def verify_password(phc: str | None, pw: str) -> bool:
    with _hash_sem:
        try:
            return _ph.verify(phc or _DUMMY, pw) and phc is not None
        except (VerificationError, InvalidHashError):
            return False


def seal_totp(kek: bytes, human_id: str, secret: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(kek).encrypt(nonce, secret, human_id.encode())


def open_totp(kek: bytes, human_id: str, blob: bytes) -> bytes:
    return AESGCM(kek).decrypt(blob[:12], blob[12:], human_id.encode())


def create(conn, actor: Actor, party_id: str, login: str, display_name: str, password: str, kek: bytes) -> tuple[str, str]:
    """Returns (human_id, otpauth_uri). The URI carries the TOTP secret: show once, never log."""
    if conn.execute("SELECT 1 FROM parties WHERE id=?", (party_id,)).fetchone() is None:
        raise Problem(404, "party_not_found", "party not found")
    hid, secret = new_id("hum"), totp.new_secret()
    conn.execute("INSERT INTO humans (id, party_id, login, display_name, password_hash, totp_secret_enc, created_at)"
                 " VALUES (?,?,?,?,?,?,?)", (hid, party_id, login, display_name, hash_password(password),
                                             seal_totp(kek, hid, secret), now_ms()))
    audit(conn, actor, "human.create", "human", hid, {"party_id": party_id, "login": login})
    return hid, totp.otpauth_uri(secret, login)


def reset(conn, actor: Actor, login: str, password: str, kek: bytes) -> str:
    """New password and new TOTP secret; revokes all sessions. Returns the new otpauth URI."""
    h = conn.execute("SELECT id FROM humans WHERE login=?", (login,)).fetchone()
    if h is None:
        raise Problem(404, "human_not_found", "no such login")
    secret = totp.new_secret()
    conn.execute("UPDATE humans SET password_hash=?, totp_secret_enc=?, totp_last_step=0, disabled_at=NULL,"
                 " totp_failures=0, totp_next_allowed_at=0 WHERE id=?",
                 (hash_password(password), seal_totp(kek, h["id"], secret), h["id"]))
    conn.execute("UPDATE sessions SET revoked_at=? WHERE human_id=? AND revoked_at IS NULL", (now_ms(), h["id"]))
    audit(conn, actor, "human.reset", "human", h["id"], {})
    return totp.otpauth_uri(secret, login)


ENROLL_TTL_MS = 24 * 3600 * 1000


def invite(conn, actor: Actor, login: str, party_id: str, display_name: str, ttl_ms: int = ENROLL_TTL_MS) -> str:
    """One-time enrollment link token (default 24 h, `enroll_ttl_s`) for a new account. Returns the token
    (shown once). The TTL is fixed when the link is made: changing the setting never touches existing links."""
    if conn.execute("SELECT 1 FROM parties WHERE id=?", (party_id,)).fetchone() is None:
        raise Problem(404, "party_not_found", "party not found")
    if conn.execute("SELECT 1 FROM humans WHERE login=?", (login,)).fetchone():
        raise Problem(409, "login_taken", "login exists; use `human reset`")
    return _enrollment(conn, actor, login, party_id, display_name, None, ttl_ms)


def reset_link(conn, actor: Actor, login: str, ttl_ms: int = ENROLL_TTL_MS) -> str:
    """Lost password/TOTP: disable the account and revoke its sessions now; the link sets new credentials."""
    h = conn.execute("SELECT * FROM humans WHERE login=?", (login,)).fetchone()
    if h is None:
        raise Problem(404, "human_not_found", "no such login")
    conn.execute("UPDATE humans SET disabled_at=? WHERE id=?", (now_ms(), h["id"]))
    conn.execute("UPDATE sessions SET revoked_at=? WHERE human_id=? AND revoked_at IS NULL", (now_ms(), h["id"]))
    return _enrollment(conn, actor, h["login"], h["party_id"], h["display_name"], h["id"], ttl_ms)


def _enrollment(conn, actor, login, party_id, display_name, human_id, ttl_ms: int = ENROLL_TTL_MS) -> str:
    if not 60_000 <= ttl_ms <= 7 * 86_400_000:
        raise Problem(422, "invalid_ttl", "enrollment link lifetime must be between 1 minute and 7 days")
    token, now = secrets.token_urlsafe(32), now_ms()
    conn.execute("UPDATE enrollments SET used_at=? WHERE login=? AND used_at IS NULL", (now, login))  # one live link
    conn.execute("INSERT INTO enrollments (token_hash, login, party_id, display_name, human_id, created_at, expires_at)"
                 " VALUES (?,?,?,?,?,?,?)", (_token_hash(token), login, party_id, display_name, human_id, now,
                                             now + ttl_ms))
    audit(conn, actor, "human.reset_link" if human_id else "human.invite", "human", human_id or login, {})
    return token


def enrollment(conn, token: str):
    r = conn.execute("SELECT * FROM enrollments WHERE token_hash=?", (_token_hash(token or ""),)).fetchone()
    if r is None or r["used_at"] is not None or r["expires_at"] <= now_ms():
        raise Problem(404, "enrollment_invalid", "link is invalid, used or expired")
    return r


def enroll(conn, token: str, password: str, kek: bytes, pw_hash: str | None = None) -> dict:
    """Consume a link: set the password and a fresh TOTP secret. Returns {"human_id","otpauth_uri"} (shown once).
    The first login (password + TOTP) proves the authenticator was set up. Pass pw_hash (hashed before the write
    transaction) to keep argon2 out of the DB write lock."""
    e = enrollment(conn, token)
    pw_hash, secret = pw_hash or hash_password(password), totp.new_secret()
    hid = e["human_id"] or new_id("hum")
    if e["human_id"]:
        conn.execute("UPDATE humans SET password_hash=?, totp_secret_enc=?, totp_last_step=0, disabled_at=NULL,"
                     " totp_failures=0, totp_next_allowed_at=0 WHERE id=?", (pw_hash, seal_totp(kek, hid, secret), hid))
    else:
        conn.execute("INSERT INTO humans (id, party_id, login, display_name, password_hash, totp_secret_enc, created_at)"
                     " VALUES (?,?,?,?,?,?,?)", (hid, e["party_id"], e["login"], e["display_name"], pw_hash,
                                                 seal_totp(kek, hid, secret), now_ms()))
    conn.execute("UPDATE enrollments SET used_at=? WHERE token_hash=?", (now_ms(), e["token_hash"]))
    audit(conn, Actor("human", hid, e["party_id"]), "human.enroll", "human", hid, {})
    return {"human_id": hid, "otpauth_uri": totp.otpauth_uri(secret, e["login"])}


def unlock(conn, actor: Actor, ip: str | None = None, login: str | None = None) -> int:
    """Clear login throttling: one IP (`ip`), one account's TOTP delay (`login`), or everything (neither)."""
    n = 0
    if login is None:
        n += conn.execute("DELETE FROM login_throttle WHERE ? IS NULL OR ip=?", (ip, ip)).rowcount
    if ip is None:
        n += conn.execute("UPDATE humans SET totp_failures=0, totp_next_allowed_at=0 WHERE (? IS NULL OR login=?)"
                          " AND (totp_failures>0 OR totp_next_allowed_at>0)", (login, login)).rowcount
    audit(conn, actor, "human.unlock", "login_throttle", login or ip or "*", {"rows": n})
    return n


def throttle_key(ip: str | None) -> str:
    """IPv4 address or IPv6 /64; one shared bucket when the tunnel supplied no address."""
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return "unknown"
    if addr.version == 6:
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


def throttle_check(conn, key: str) -> None:
    r = conn.execute("SELECT next_allowed_at FROM login_throttle WHERE ip=?", (key,)).fetchone()
    now = now_ms()
    if r and r[0] > now:
        raise Problem(429, "login_throttled", "too many failed logins from your address; wait and retry",
                      headers={"Retry-After": str(max(1, (r[0] - now + 999) // 1000))})


def _throttle_fail(conn, key: str) -> None:
    now = now_ms()
    r = conn.execute("SELECT failures, updated_at FROM login_throttle WHERE ip=?", (key,)).fetchone()
    failures = 1 if (r is None or now - r["updated_at"] > 3_600_000) else r["failures"] + 1
    delay = 0 if failures < THROTTLE_FREE_FAILURES else min(2000 * 2 ** (failures - THROTTLE_FREE_FAILURES),
                                                            THROTTLE_MAX_DELAY_MS)
    conn.execute("INSERT INTO login_throttle (ip, failures, next_allowed_at, updated_at) VALUES (?,?,?,?)"
                 " ON CONFLICT(ip) DO UPDATE SET failures=excluded.failures, next_allowed_at=excluded.next_allowed_at,"
                 " updated_at=excluded.updated_at", (key, failures, now + delay, now))


def _check_totp(conn, h, code: str, kek: bytes) -> bool:
    step = totp.verify(open_totp(kek, h["id"], h["totp_secret_enc"]), code, h["totp_last_step"])
    if step is None:
        return False
    conn.execute("UPDATE humans SET totp_last_step=? WHERE id=?", (step, h["id"]))
    return True


def account_check(h) -> None:
    """Per-account delay after repeated wrong TOTP codes with a correct password (independent of IP)."""
    now = now_ms()
    if h is not None and h["totp_next_allowed_at"] > now:
        raise Problem(429, "login_throttled", "too many wrong codes for this account; wait and retry",
                      headers={"Retry-After": str(max(1, (h["totp_next_allowed_at"] - now + 999) // 1000))})


def _account_totp_fail(conn, human_id: str) -> int:
    conn.execute("UPDATE humans SET totp_failures=totp_failures+1 WHERE id=?", (human_id,))
    n = conn.execute("SELECT totp_failures FROM humans WHERE id=?", (human_id,)).fetchone()[0]
    if n >= ACCOUNT_FREE_TOTP_FAILURES:
        delay = min(2000 * 2 ** min(n - ACCOUNT_FREE_TOTP_FAILURES, 20), ACCOUNT_MAX_DELAY_MS)
        conn.execute("UPDATE humans SET totp_next_allowed_at=? WHERE id=?", (now_ms() + delay, human_id))
    return n


def _account_totp_ok(conn, human_id: str) -> None:
    conn.execute("UPDATE humans SET totp_failures=0, totp_next_allowed_at=0 WHERE id=?", (human_id,))


def _token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


_FAIL_WINDOW_S = 3600
_FAIL_MAX_KEYS = 4096
_wrong_pw: dict = {}                     # (human_id, address key) -> [window start (monotonic), count]
_wrong_pw_lock = threading.Lock()


def _count_wrong_password(human_id: str, key: str) -> int:
    """In-memory, bounded count of wrong passwords per login + address key in the current hour (1 = first)."""
    now = time.monotonic()
    with _wrong_pw_lock:
        e = _wrong_pw.get((human_id, key))
        if e is None or now - e[0] >= _FAIL_WINDOW_S:
            if len(_wrong_pw) >= _FAIL_MAX_KEYS:
                for k in [k for k, v in _wrong_pw.items() if now - v[0] >= _FAIL_WINDOW_S]:
                    del _wrong_pw[k]
                if len(_wrong_pw) >= _FAIL_MAX_KEYS:
                    _wrong_pw.pop(next(iter(_wrong_pw)))
            e = _wrong_pw[(human_id, key)] = [now, 0]
        e[1] += 1
        return e[1]


def login_precheck(conn, login_name: str, ip: str | None):
    """Read-only part of a login, before any argon2 work: the per-IP throttle only. The per-account TOTP delay
    is checked only once the password verified (no account-state oracle), inside `login`.
    Returns the (enabled) human row or None."""
    throttle_check(conn, throttle_key(ip))
    return conn.execute("SELECT * FROM humans WHERE login=? AND disabled_at IS NULL", (login_name,)).fetchone()


def login(conn, settings, human_id: str | None, pw_ok: bool, code: str, ip: str | None) -> dict:
    """Write part of a login (the password was verified before this transaction). Generic failure message.
    Returns {"token","csrf_token","human_id"}."""
    key = throttle_key(ip)
    h = conn.execute("SELECT * FROM humans WHERE id=? AND disabled_at IS NULL", (human_id,)).fetchone() if human_id else None
    pw_ok = pw_ok and h is not None
    sys = Actor("system", "login", credential_id=key)
    if pw_ok:
        account_check(h)                       # re-checked inside the transaction (parallel attempts)
    if not pw_ok or not _check_totp(conn, h, code, settings.totp_kek):
        _throttle_fail(conn, key)
        detail = {}
        if pw_ok:
            detail["account_failures"] = _account_totp_fail(conn, h["id"])
        if h is None:       # unknown/disabled login -> journald only, never the permanent audit chain
            logs.event("login.fail", reason="unknown_login", ip_key=key)
        elif pw_ok:
            audit(conn, sys, "login.totp_fail", "human", h["id"], detail)
        else:               # wrong password for a known login: one audit row per login+address per hour
            n = _count_wrong_password(h["id"], key)
            if n == 1:
                audit(conn, sys, "login.fail", "human", h["id"], {"count": n})
            else:
                logs.event("login.fail", reason="wrong_password", ip_key=key, count=n)
        raise Problem(401, "login_failed", "invalid login, password or code", commit=True)
    conn.execute("DELETE FROM login_throttle WHERE ip=?", (key,))
    _account_totp_ok(conn, h["id"])
    token, csrf, now = secrets.token_urlsafe(32), secrets.token_urlsafe(32), now_ms()
    # a login is never a step-up. Consequential actions need a second, later TOTP code (replay protection
    # via totp_last_step means the login code cannot be reused), so one relayed code is not enough.
    conn.execute("INSERT INTO sessions (token_hash, human_id, csrf_token, created_at, last_seen_at, expires_at, step_up_at)"
                 " VALUES (?,?,?,?,?,?,NULL)", (_token_hash(token), h["id"], csrf, now, now,
                                                now + settings.session_ttl_s * 1000))
    audit(conn, Actor("human", h["id"], h["party_id"], _token_hash(token).hex()[:12]), "login.ok", "human", h["id"], {})
    return {"token": token, "csrf_token": csrf, "human_id": h["id"]}


def session(conn, settings, token: str | None):
    """Returns the joined session/human row if valid, else None. Read-only."""
    if not token:
        return None
    r = conn.execute("SELECT s.*, h.party_id, h.login, h.display_name, h.disabled_at FROM sessions s"
                     " JOIN humans h ON h.id=s.human_id WHERE s.token_hash=?", (_token_hash(token),)).fetchone()
    now = now_ms()
    if (r is None or r["revoked_at"] is not None or r["disabled_at"] is not None or r["expires_at"] <= now
            or now - r["last_seen_at"] > settings.session_idle_s * 1000):
        return None
    return r


def actor_for(sess) -> Actor:
    return Actor("human", sess["human_id"], sess["party_id"], sess["token_hash"].hex()[:12])


def touch(conn, sess) -> None:
    if now_ms() - sess["last_seen_at"] > 60_000:
        conn.execute("UPDATE sessions SET last_seen_at=? WHERE token_hash=?", (now_ms(), sess["token_hash"]))


def step_up_precheck(conn, sess):
    h = conn.execute("SELECT * FROM humans WHERE id=?", (sess["human_id"],)).fetchone()
    account_check(h)
    return h


def step_up(conn, settings, sess, pw_ok: bool, code: str) -> None:
    """Password + TOTP (the password was verified before this transaction). Every failure counts on the
    session (5 -> the session is revoked); a wrong code with the right password also counts on the account."""
    h = conn.execute("SELECT * FROM humans WHERE id=?", (sess["human_id"],)).fetchone()
    if pw_ok:
        account_check(h)
    if not pw_ok or not _check_totp(conn, h, code, settings.totp_kek):
        conn.execute("UPDATE sessions SET stepup_failures=stepup_failures+1 WHERE token_hash=?", (sess["token_hash"],))
        n = conn.execute("SELECT stepup_failures FROM sessions WHERE token_hash=?", (sess["token_hash"],)).fetchone()[0]
        detail = {"session_failures": n, "password_ok": pw_ok}
        if pw_ok:
            detail["account_failures"] = _account_totp_fail(conn, h["id"])
        audit(conn, actor_for(sess), "stepup.fail", "human", h["id"], detail)
        if n >= STEPUP_MAX_FAILURES:
            conn.execute("UPDATE sessions SET revoked_at=? WHERE token_hash=?", (now_ms(), sess["token_hash"]))
            audit(conn, actor_for(sess), "session.revoke", "human", h["id"], {"reason": "step-up failures"})
            raise Problem(401, "step_up_failed", "too many failed step-ups: this session was revoked; log in again",
                          extra={"session_revoked": True}, commit=True)
        raise Problem(401, "step_up_failed", "invalid password or code", commit=True)
    _account_totp_ok(conn, h["id"])
    conn.execute("UPDATE sessions SET step_up_at=?, stepup_failures=0 WHERE token_hash=?", (now_ms(), sess["token_hash"]))
    audit(conn, actor_for(sess), "stepup.ok", "human", h["id"], {})


def has_step_up(settings, sess) -> bool:
    return sess["step_up_at"] is not None and now_ms() - sess["step_up_at"] <= settings.step_up_window_s * 1000


def require_step_up(settings, sess) -> None:
    if not has_step_up(settings, sess):
        raise Problem(403, "step_up_required", "confirm with password + a fresh TOTP code (POST /app/step-up) and retry")


def logout(conn, sess) -> None:
    conn.execute("UPDATE sessions SET revoked_at=? WHERE token_hash=?", (now_ms(), sess["token_hash"]))
    audit(conn, actor_for(sess), "logout", "human", sess["human_id"], {})


def csrf_ok(sess, supplied: str | None) -> bool:
    return bool(supplied) and hmac.compare_digest(sess["csrf_token"], supplied)
