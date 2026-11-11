#!/bin/bash
# Agent Bridge installer / upgrader. Idempotent. Run as root from the extracted release tarball:
#   sudo ./deploy/install.sh [--with-ngrok]
# Never touches: other services, firewall rules, sshd config, other services. Never prints secrets.
set -euo pipefail

# Strict hostname check for NGROK_DOMAIN (interpolated into sed/config). Same rules as deploy/ngrok/render-config.sh,
# deploy/ngrok/sync-origin.sh and bridge/ops.py valid_hostname: lowercase LDH labels 1-63 chars, no edge hyphens,
# >= 1 dot, <= 253 chars, last label not starting with a digit; no scheme, port, path or userinfo.
valid_hostname() {
  local h=$1 l
  [ -n "$h" ] && [ "${#h}" -le 253 ] || return 1
  case $h in
    *[!abcdefghijklmnopqrstuvwxyz0123456789.-]*|.*|*.|*..*) return 1 ;;
    *.*) ;;
    *) return 1 ;;
  esac
  case ${h##*.} in [0123456789]*) return 1 ;; esac
  while :; do
    l=${h%%.*}
    case $l in ""|-*|*-) return 1 ;; esac
    [ "${#l}" -le 63 ] || return 1
    [ "$h" = "$l" ] && return 0
    h=${h#*.}
  done
}

WITH_NGROK=0
while [ $# -gt 0 ]; do
  case $1 in
    --with-ngrok) WITH_NGROK=1 ;;
    --check-host) valid_hostname "${2:-}" && exit 0; exit 1 ;;   # test hook (no root needed)
    -h|--help) sed -n '2,4p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
[ -f "$SRC/requirements.lock" ] && [ -d "$SRC/bridge" ] && [ -d "$SRC/deploy" ] || { echo "run from an extracted release tarball (needs bridge/, deploy/, requirements.lock)" >&2; exit 1; }
VER=$(tr -d '[:space:]' < "$SRC/VERSION" 2>/dev/null || true)
[[ $VER =~ ^[A-Za-z0-9._+-]+$ ]] || { echo "missing/invalid VERSION file" >&2; exit 1; }

OPT=/opt/agent-bridge
ETC=/etc/agent-bridge
STATE=/var/lib/agent-bridge
BACKUPS=/var/backups/agent-bridge
REL=$OPT/releases/$VER
UNITDIR=/etc/systemd/system
say() { echo "[install] $*"; }
warn() { echo "[install] WARN: $*" >&2; }

# ---- preflight --------------------------------------------------------------------------------
command -v systemctl >/dev/null && command -v systemd-run >/dev/null || { echo "systemd required" >&2; exit 1; }
PY=${PYTHON:-python3}
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 13) else 1)' || { echo "python >= 3.13 required" >&2; exit 1; }
"$PY" -c 'import venv, ensurepip' 2>/dev/null || { echo "python venv/ensurepip missing (apt install python3-venv)" >&2; exit 1; }

snap_listeners() { ss -ltnH 2>/dev/null | awk '{print $4}' | sort -u || true; }
snap_fw() { { iptables-save 2>/dev/null || true; ip6tables-save 2>/dev/null || true; nft list ruleset 2>/dev/null || true; } | sha256sum | cut -d' ' -f1; }
L_BEFORE=$(snap_listeners)
FW_BEFORE=$(snap_fw)

# ---- users, groups, dirs ----------------------------------------------------------------------
mkuser() { # name home shell
  if ! getent passwd "$1" >/dev/null; then
    useradd --system --user-group --no-create-home --home-dir "$2" --shell "$3" --comment "Agent Bridge $1" "$1"
    say "created user $1"
  fi
}
mkuser agent-bridge /var/lib/agent-bridge /usr/sbin/nologin
mkuser ngrok /var/lib/agent-bridge-ngrok /usr/sbin/nologin
# bridge-backup: sshd runs forced commands through the login shell, so nologin would break the
# off-box pull. The account has a locked password and is only usable via a `restrict,command=` key.
mkuser bridge-backup /var/lib/bridge-backup /bin/sh

install -d -m 0755 -o root -g root "$OPT" "$OPT/releases" "$ETC"
install -d -m 0700 -o root -g root "$ETC/credentials"
install -d -m 0700 -o agent-bridge -g agent-bridge "$STATE"
install -d -m 2750 -o agent-bridge -g bridge-backup "$BACKUPS"
chmod 2750 "$BACKUPS"
# bridge-backup home: root-owned so sshd StrictModes is satisfied and the account cannot alter its own key
install -d -m 0755 -o root -g root /var/lib/bridge-backup /var/lib/bridge-backup/.ssh
[ -e /var/lib/bridge-backup/.ssh/authorized_keys ] || install -m 0644 -o root -g root /dev/null /var/lib/bridge-backup/.ssh/authorized_keys

# ---- credentials (only if missing; never printed) ---------------------------------------------
for c in pepper totp_kek; do
  f=$ETC/credentials/$c
  if [ ! -s "$f" ]; then
    ( umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$f.tmp" && mv "$f.tmp" "$f" )
    say "generated credential $c (64 hex chars, not shown)"
  fi
  chown root:root "$f"; chmod 0400 "$f"
done

# ---- config (only if missing) -----------------------------------------------------------------
if [ ! -e "$ETC/config.toml" ]; then
  if [ -f "$SRC/config.example.toml" ]; then
    install -m 0644 -o root -g root "$SRC/config.example.toml" "$ETC/config.toml"
  else
    cat > "$ETC/config.toml" <<'CFG'
# Agent Bridge config (non-secret). Secrets are systemd credentials: pepper, totp_kek.
[server]
host = "127.0.0.1"   # loopback only; the service refuses anything else
port = 8787
public_origin = "https://CHANGE-ME.ngrok-free.app"   # enrollment links + dashboard Origin check
poll_after_s = 900

[storage]
db_path = "/var/lib/agent-bridge/bridge.db"
backup_dir = "/var/backups/agent-bridge"
CFG
    chmod 0644 "$ETC/config.toml"
  fi
  say "wrote default $ETC/config.toml (review it)"
fi

# ---- public_origin (enrollment links + dashboard Origin check) ---------------------------------
# Set from NGROK_DOMAIN in ngrok.env when the placeholder is still there. The file is parsed, never sourced.
# NGROK_DOMAIN may be any hostname reserved on the ngrok account (x.ngrok-free.app, x.ngrok.app, bridge.example.com).
dom=""
if [ -r "$ETC/ngrok.env" ]; then
  dom=$(sed -n 's/^NGROK_DOMAIN=//p' "$ETC/ngrok.env" | head -n1 | tr -d '[:space:]"'"'")
  if [ -n "$dom" ] && ! valid_hostname "$dom"; then
    warn "NGROK_DOMAIN in $ETC/ngrok.env is not a valid lowercase hostname (no scheme, port or path); not using it"
    dom=""
  fi
fi
if [ -n "$dom" ] && grep -q 'CHANGE-ME' "$ETC/config.toml"; then
  sed -i "s|https://CHANGE-ME\.ngrok-free\.app|https://$dom|" "$ETC/config.toml"
  say "set public_origin to https://$dom in $ETC/config.toml"
fi
cur_origin=$(sed -n 's/^public_origin[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$ETC/config.toml" | head -n1)
if [ -n "$dom" ] && [ "${cur_origin%/}" != "https://$dom" ] && [ ! -e "$UNITDIR/agent-bridge-ngrok.service.d/ephemeral.conf" ]; then
  warn "public_origin ($cur_origin) differs from https://$dom (NGROK_DOMAIN): edit $ETC/config.toml and restart agent-bridge (docs/OPS.md, 'Pin a domain')"
fi
if grep -q 'CHANGE-ME' "$ETC/config.toml"; then
  warn "public_origin in $ETC/config.toml is still a placeholder: set it to https://<NGROK_DOMAIN> and restart agent-bridge (enrollment links and dashboard logins depend on it)"
fi

# ---- build release ----------------------------------------------------------------------------
if [ -e "$REL/.complete" ]; then
  say "release $VER already built"
else
  PART=$OPT/releases/.partial-$VER
  rm -rf "$PART"; mkdir -p "$PART"
  cp -a "$SRC/bridge" "$SRC/deploy" "$SRC/requirements.lock" "$SRC/VERSION" "$PART/"
  [ -f "$SRC/pyproject.toml" ] && cp -a "$SRC/pyproject.toml" "$PART/"
  [ -f "$SRC/config.example.toml" ] && cp -a "$SRC/config.example.toml" "$PART/"
  "$PY" -m venv "$PART/venv"
  # hashes only, wheels only: nothing is compiled on the host; no pip cache (inodes)
  "$PART/venv/bin/python" -m pip install --quiet --disable-pip-version-check --no-cache-dir \
    --require-hashes --only-binary=:all: -r "$PART/requirements.lock"
  # run bridge from the release dir (python -I ignores cwd/PYTHONPATH, so use a .pth in the venv)
  site=$("$PART/venv/bin/python" -c 'import sysconfig; print(sysconfig.get_path("purelib"))')
  echo "$REL" > "$site/agent-bridge-release.pth"
  chmod +x "$PART"/deploy/{bridgectl,backup.sh,serve-latest-backup,install.sh,uninstall.sh} 2>/dev/null || true
  chown -R root:root "$PART"; chmod -R go-w,a+rX "$PART"
  touch "$PART/.complete"
  rm -rf "$REL"; mv "$PART" "$REL"
  say "built release $VER"
fi

# ---- units + wrapper --------------------------------------------------------------------------
install -m 0750 -o root -g root "$REL/deploy/bridgectl" /usr/local/sbin/bridgectl
[ ! -f "$REL/deploy/ngrok/sync-origin.sh" ] || \
  install -m 0750 -o root -g root "$REL/deploy/ngrok/sync-origin.sh" /usr/local/sbin/agent-bridge-sync-origin
for u in agent-bridge.service agent-bridge-backup.service agent-bridge-backup.timer; do
  install -m 0644 -o root -g root "$REL/deploy/systemd/$u" "$UNITDIR/$u"
done
[ "$WITH_NGROK" -eq 1 ] || [ ! -e "$UNITDIR/agent-bridge-ngrok.service" ] || \
  install -m 0644 -o root -g root "$REL/deploy/systemd/agent-bridge-ngrok.service" "$UNITDIR/agent-bridge-ngrok.service"

# ---- flip current -----------------------------------------------------------------------------
PREV=$(readlink -e "$OPT/current" 2>/dev/null || true)
if systemctl is-active --quiet agent-bridge.service; then systemctl stop agent-bridge.service; fi
ln -sfn "$REL" "$OPT/current.new"; mv -T "$OPT/current.new" "$OPT/current"
say "current -> $REL (previous: ${PREV:-none})"

systemctl daemon-reload
/usr/local/sbin/bridgectl migrate
systemctl enable agent-bridge.service >/dev/null
systemctl restart agent-bridge.service

ok=0
for _ in $(seq 1 30); do
  if "$PY" -I -c 'import urllib.request,sys; sys.exit(0 if urllib.request.urlopen("http://127.0.0.1:8787/v1/health",timeout=2).status==200 else 1)' 2>/dev/null; then ok=1; break; fi
  sleep 1
done
if [ "$ok" -ne 1 ]; then
  echo "[install] ERROR: /v1/health not OK after restart. Recent log:" >&2
  journalctl -u agent-bridge -n 20 --no-pager -o cat >&2 || true
  if [ -n "$PREV" ] && [ -d "$PREV" ] && [ "$PREV" != "$REL" ]; then
    warn "rolling back to $PREV (DB migrations are forward-only; see docs/OPS.md)"
    ln -sfn "$PREV" "$OPT/current.new"; mv -T "$OPT/current.new" "$OPT/current"
    systemctl restart agent-bridge.service || true
  fi
  exit 1
fi
say "health OK"

# ---- prune releases (keep current + the one before it) ----------------------------------------
CURR=$(readlink -f "$OPT/current")
keep=("$CURR")
[ -n "$PREV" ] && [ "$PREV" != "$CURR" ] && [ -d "$PREV" ] && keep+=("$PREV")
while IFS= read -r d; do   # newest first; fill up to 2 kept releases
  d=$(readlink -f "$d")
  case " ${keep[*]} " in *" $d "*) continue ;; esac
  if [ "${#keep[@]}" -lt 2 ]; then keep+=("$d"); continue; fi
  say "removing old release ${d##*/}"; rm -rf -- "$d"
done < <(ls -1dt "$OPT"/releases/*/ 2>/dev/null | sed 's|/$||')

# ---- backup timer -----------------------------------------------------------------------------
if [ -s "$ETC/backup-recipients.txt" ] && command -v age >/dev/null; then
  systemctl enable --now agent-bridge-backup.timer >/dev/null
  say "backup timer enabled"
else
  warn "backup timer NOT enabled: need 'age' installed (apt install age) and $ETC/backup-recipients.txt (public recipients). See docs/OPS.md"
fi

# ---- ngrok (opt-in) ---------------------------------------------------------------------------
if [ "$WITH_NGROK" -eq 1 ]; then
  if ! command -v ngrok >/dev/null; then
    command -v curl >/dev/null || { echo "curl required for --with-ngrok" >&2; exit 1; }
    install -d -m 0755 /etc/apt/keyrings
    curl -fsSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc -o /etc/apt/keyrings/ngrok.asc
    chmod 0644 /etc/apt/keyrings/ngrok.asc
    echo "deb [signed-by=/etc/apt/keyrings/ngrok.asc] https://ngrok-agent.s3.amazonaws.com bookworm main" > /etc/apt/sources.list.d/ngrok.list
    # refresh only the ngrok source, leave every other apt source alone
    apt-get update -o Dir::Etc::sourcelist=sources.list.d/ngrok.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
    apt-get install -y ngrok
  fi
  install -m 0644 -o root -g root "$REL/deploy/systemd/agent-bridge-ngrok.service" "$UNITDIR/agent-bridge-ngrok.service"
  systemctl daemon-reload
  if [ -e "$ETC/ngrok.env" ]; then
    st=$(stat -c '%a %U' "$ETC/ngrok.env")
    [ "$st" = "600 root" ] || { echo "$ETC/ngrok.env must be root 0600 (is: $st)" >&2; exit 1; }
    systemctl enable agent-bridge-ngrok.service >/dev/null
    systemctl restart agent-bridge-ngrok.service
    say "ngrok unit enabled and started"
  else
    warn "$ETC/ngrok.env missing: ngrok unit installed but not enabled (docs/OPS.md, 'ngrok')"
  fi
fi

# ---- verification -----------------------------------------------------------------------------
/usr/local/sbin/bridgectl doctor || warn "bridgectl doctor reported problems"

L_AFTER=$(snap_listeners)
NEW=$(comm -13 <(echo "$L_BEFORE") <(echo "$L_AFTER") | sed '/^$/d' || true)
if [ -n "$NEW" ] && [ "$NEW" != "127.0.0.1:8787" ]; then
  echo "[install] ERROR: unexpected new listening sockets:" >&2; echo "$NEW" >&2; exit 1
fi
if ss -ltnH | awk '{print $4}' | grep -E ':8787$' | grep -vxq '127.0.0.1:8787'; then
  echo "[install] ERROR: something listens on :8787 outside 127.0.0.1" >&2; exit 1
fi
ss -ltnH | awk '{print $4}' | grep -qx '127.0.0.1:8787' || { echo "[install] ERROR: bridge not listening on 127.0.0.1:8787" >&2; exit 1; }
[ "$(snap_fw)" = "$FW_BEFORE" ] || warn "firewall ruleset hash changed during install (installer does not touch it; investigate)"
say "listeners OK: new sockets = ${NEW:-none (127.0.0.1:8787 already present)}"
say "done. version $VER"
