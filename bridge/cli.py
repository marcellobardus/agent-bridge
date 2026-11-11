"""bridgectl backend (on-box admin only; there is no admin over HTTP).
Run via the systemd-run wrapper as the agent-bridge user; refuses to run as root."""
import argparse
import getpass
import json
import os
import secrets
import shutil
import sys
import tempfile

from . import ops
from .config import load_settings
from .db import connect
from .domain import humans, keys
from .domain.common import audit, audit_verify
from .errors import Problem
from .util import now_ms


def _tx(settings, fn):
    conn = connect(settings.db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        out = fn(conn)
        conn.execute("COMMIT")
        return out
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def _password(args) -> str:
    if args.password_stdin:
        return sys.stdin.readline().rstrip("\n")
    pw = getpass.getpass("New password (>= 12 chars): ")
    if pw != getpass.getpass("Repeat: "):
        raise SystemExit("passwords differ")
    return pw


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="bridgectl")
    ap.add_argument("--config", help="config.toml (default: $BRIDGE_CONFIG)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("gen-credentials", help="write random pepper and totp_kek files (0400) into DIR")
    p.add_argument("dir")
    for name in ("init-db", "migrate"):
        p = sub.add_parser(name, help="create/migrate the schema and seed parties + agents (idempotent)")
        p.add_argument("--no-seed", action="store_true")
    hp = sub.add_parser("human").add_subparsers(dest="sub", required=True)
    p = hp.add_parser("invite", help="print a one-time enrollment link (enroll_ttl_s, default 24 h; the human sets password + TOTP)")
    p.add_argument("login"); p.add_argument("--party", help="default: same as login")
    p.add_argument("--display-name")
    p = hp.add_parser("reset", help="disable the account, revoke sessions, print a one-time re-enrollment link")
    p.add_argument("login")
    p = hp.add_parser("create", help="dev/test: create an account with a password from stdin or prompt")
    p.add_argument("--login", required=True); p.add_argument("--party", required=True)
    p.add_argument("--display-name", required=True); p.add_argument("--password-stdin", action="store_true")
    p = hp.add_parser("unlock", help="clear login throttling (per IP) and per-account TOTP delays")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--ip"); g.add_argument("--login"); g.add_argument("--all", action="store_true")
    p = hp.add_parser("disable"); p.add_argument("login")
    kp = sub.add_parser("key").add_subparsers(dest="sub", required=True)
    p = kp.add_parser("create", help="prints ONLY the token on stdout (pipe it to a 0600 file)")
    p.add_argument("--agent", required=True); p.add_argument("--label", default="default")
    p.add_argument("--scopes", default=",".join(keys.SCOPES)); p.add_argument("--expires-days", type=int)
    p = kp.add_parser("revoke"); p.add_argument("key_id")
    p = kp.add_parser("rotate", help="create a new key, then revoke OLD; prints the new token")
    p.add_argument("--agent", required=True); p.add_argument("--old", required=True)
    p.add_argument("--label", default="rotated")
    kp.add_parser("list")
    ap_ = sub.add_parser("audit").add_subparsers(dest="sub", required=True)
    p = ap_.add_parser("verify"); p.add_argument("--db", help="verify another DB file (e.g. bridge.db.replaced)")
    p.add_argument("--contains", help="also check that this head hash appears in the chain")
    bp = sub.add_parser("backup").add_subparsers(dest="sub", required=True)
    p = bp.add_parser("snapshot", help="online backup to a new file (used by deploy/backup.sh)")
    p.add_argument("--out", required=True)
    p = sub.add_parser("restore", help="restore from a snapshot (file argument or stdin); stop the service first")
    p.add_argument("snapshot", nargs="?", help="default: read the snapshot from stdin")
    p.add_argument("--check-only", action="store_true"); p.add_argument("--purge-replaced", action="store_true")
    p.add_argument("--confirm-credentials", action="store_true",
                   help="restore even though the current DB is missing/unreadable (revocations cannot be carried "
                        "forward); then rotate keys and reset humans")
    p = sub.add_parser("doctor")
    p.add_argument("--tunnel", action="store_true",
                   help="only the tunnel checks (inspector port, public_origin vs running ngrok URL); no DB, no "
                        "credentials; bridgectl runs this part as root")
    return ap


def _restore(args, db_path: str) -> int:
    if args.purge_replaced:
        path = db_path + ".replaced"
        if os.path.exists(path):
            os.remove(path)
        print(f"removed {path}" if not os.path.exists(path) else "nothing to remove", file=sys.stderr)
        return 0
    snap, tmp = args.snapshot, None
    if snap is None:   # snapshot on stdin: spool next to the DB (same filesystem, 0600)
        fd, tmp = tempfile.mkstemp(prefix=".restore-", dir=os.path.dirname(os.path.abspath(db_path)))
        with os.fdopen(fd, "wb") as f:
            shutil.copyfileobj(sys.stdin.buffer, f)
        snap = tmp
    try:
        out = ops.check_snapshot(snap) if args.check_only else ops.restore(db_path, snap, args.confirm_credentials)
        print(json.dumps(out))
        if not args.check_only:
            print(f"restore: revoked {out['sessions_revoked']} sessions; keys kept revoked: {out['keys_revoked']}; "
                  f"humans disabled (re-enroll with `bridgectl human reset <login>`): {out['humans_disabled']}",
                  file=sys.stderr)
            if not out["credentials_verified"]:
                print("restore: WARNING credentials were NOT verified against the replaced DB: rotate every agent "
                      "key and reset every human that may have changed since the snapshot", file=sys.stderr)
        return 0
    except ValueError as e:
        print(f"snapshot rejected: {e}", file=sys.stderr)
        return 1
    finally:
        if tmp:
            os.remove(tmp)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "doctor" and args.tunnel:   # touches no DB file, so root is fine (needs the journal)
        return _doctor_tunnel(args.config)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print("bridgectl must not run as root (it would create root-owned DB files); use the wrapper", file=sys.stderr)
        return 2
    if args.cmd == "gen-credentials":
        os.makedirs(args.dir, mode=0o700, exist_ok=True)
        for name in ("pepper", "totp_kek"):
            path = os.path.join(args.dir, name)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
            with os.fdopen(fd, "w") as f:
                f.write(secrets.token_hex(32) + "\n")
        print(f"wrote {args.dir}/pepper and {args.dir}/totp_kek (0400)")
        return 0
    s = load_settings(args.config)
    if args.cmd == "restore":
        return _restore(args, s.db_path)
    try:
        return _dispatch(args, s)
    except Problem as p:
        print(f"error: {p.code}: {p.detail}", file=sys.stderr)
        return 1


def _doctor_tunnel(config_path: str | None) -> int:
    try:
        origin = ops.read_public_origin(config_path)
    except (OSError, ValueError) as e:
        print(f"FAIL config: cannot read public_origin ({type(e).__name__})")
        return 1
    bad = 0
    for name, level, info in ops.tunnel_checks(origin):
        bad += level == "FAIL"
        print(f"{level:<4} {name}: {info}")
    return 1 if bad else 0


def _hours(s) -> str:
    return f"{s.enroll_ttl_s / 3600:g} h"


def _link(s, token: str) -> str:
    base = (s.public_origin or "https://<public-origin>").rstrip("/")
    return f"{base}/app/enroll/{token}"


def _dispatch(args, s) -> int:
    cli = ops.CLI
    if args.cmd in ("init-db", "migrate"):
        print(f"schema version {ops.init_db(s.db_path, seed=not args.no_seed)}")
    elif args.cmd == "human":
        if args.sub == "invite":
            token = _tx(s, lambda c: humans.invite(c, cli, args.login, args.party or args.login,
                                                   args.display_name or args.login.title(), s.enroll_ttl_s * 1000))
            print(f"one-time enrollment link ({_hours(s)}; a secret: share only over a private channel):",
                  file=sys.stderr)
            print(_link(s, token))
        elif args.sub == "reset":
            token = _tx(s, lambda c: humans.reset_link(c, cli, args.login, s.enroll_ttl_s * 1000))
            print(f"account disabled and sessions revoked; re-enrollment link ({_hours(s)}):", file=sys.stderr)
            print(_link(s, token))
        elif args.sub == "create":
            pw = _password(args)
            hid, uri = _tx(s, lambda c: humans.create(c, cli, args.party, args.login, args.display_name, pw, s.totp_kek))
            print(f"created {hid}. TOTP secret (shown once; add it to an authenticator app):", file=sys.stderr)
            print(uri)
        elif args.sub == "unlock":
            n = _tx(s, lambda c: humans.unlock(c, cli, args.ip, args.login))
            print(f"cleared {n} throttle rows")
        elif args.sub == "disable":
            def fn(c):
                n = c.execute("UPDATE humans SET disabled_at=? WHERE login=?", (now_ms(), args.login)).rowcount
                c.execute("UPDATE sessions SET revoked_at=? WHERE human_id IN (SELECT id FROM humans WHERE login=?)"
                          " AND revoked_at IS NULL", (now_ms(), args.login))
                audit(c, cli, "human.disable", "human", args.login, {})
                return n
            print(f"disabled {_tx(s, fn)} account(s)")
    elif args.cmd == "key":
        if args.sub in ("create", "rotate"):
            scopes = tuple(x for x in getattr(args, "scopes", ",".join(keys.SCOPES)).split(",") if x)
            exp = now_ms() + args.expires_days * 86_400_000 if getattr(args, "expires_days", None) else None

            def fn(c):
                out = keys.create(c, cli, args.agent, args.label, s.pepper, scopes, exp)
                if args.sub == "rotate":   # MAX_ACTIVE_KEYS=2 allows the overlap
                    keys.revoke(c, cli, args.old)
                return out
            key_id, token = _tx(s, fn)
            print(f"key id {key_id} for agent {args.agent}; token on stdout, shown once", file=sys.stderr)
            print(token)
        elif args.sub == "revoke":
            _tx(s, lambda c: keys.revoke(c, cli, args.key_id))
            print(f"revoked {args.key_id}")
        else:
            conn = connect(s.db_path, readonly=True)
            for r in conn.execute("SELECT id, agent_id, label, scopes, created_at, expires_at, revoked_at, last_used_at"
                                  " FROM api_keys ORDER BY agent_id, created_at"):
                print(json.dumps(dict(r)))
            conn.close()
    elif args.cmd == "audit":
        conn = connect(args.db or s.db_path, readonly=True)
        ok, n, bad = audit_verify(conn)
        found = None
        if args.contains:
            found = conn.execute("SELECT seq FROM audit_log WHERE hash=?", (args.contains,)).fetchone()
        conn.close()
        print(f"audit chain {'OK' if ok else 'BROKEN at seq ' + str(bad)} ({n} rows verified)")
        if args.contains:
            print(f"hash {'found at seq ' + str(found[0]) if found else 'NOT FOUND'}")
        return 0 if ok and (not args.contains or found) else 1
    elif args.cmd == "backup":
        print(json.dumps(ops.backup(s.db_path, args.out)))
    elif args.cmd == "doctor":
        bad = 0
        for name, ok, info in ops.doctor(s):
            bad += not ok
            print(f"{'OK  ' if ok else 'FAIL'} {name}: {info}")
        return 1 if bad else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
