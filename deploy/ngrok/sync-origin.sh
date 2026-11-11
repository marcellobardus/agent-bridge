#!/usr/bin/env bash
# Sync public_origin in /etc/agent-bridge/config.toml with the current ngrok tunnel URL (ephemeral URLs change on
# restart; see deploy/systemd/agent-bridge-ngrok-ephemeral.conf.example). Installed as
# /usr/local/sbin/agent-bridge-sync-origin. No-op when unchanged. Prints no secrets.
# Test hook (no root): agent-bridge-sync-origin --check-url URL  -> exit 0 if URL is https://<valid hostname>.
set -euo pipefail
CFG=${BRIDGE_CONFIG:-${AGENT_BRIDGE_CONFIG:-/etc/agent-bridge/config.toml}}

# Strict hostname check (same rules as deploy/ngrok/render-config.sh and bridge/ops.py valid_hostname): the value
# is interpolated into sed. Lowercase LDH labels 1-63 chars, no edge hyphens, >= 1 dot, <= 253 chars, last label
# not starting with a digit.
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
# https://<hostname> exactly: no port, path, query, userinfo, trailing slash
valid_url() { [[ $1 == https://* ]] && valid_hostname "${1#https://}"; }

if [ "${1:-}" = "--check-url" ]; then
  valid_url "${2:-}" && exit 0
  exit 1
fi

url=""
for _ in $(seq 1 20); do
  # only the current run of the unit, so a stale URL from a previous session is never picked up
  inv=$(systemctl show -p InvocationID --value agent-bridge-ngrok.service 2>/dev/null || true)
  [[ $inv =~ ^[0-9a-f]{32}$ ]] || { sleep 1; continue; }
  # last "url":"https://..." value in this invocation's log that is a bare https://<hostname>
  # (other url fields, e.g. error links with paths, are skipped)
  while IFS= read -r cand; do
    cand=${cand#\"url\":\"}; cand=${cand%\"}
    if valid_url "$cand"; then url=$cand; fi
  done < <(journalctl _SYSTEMD_INVOCATION_ID="$inv" -o cat --no-pager 2>/dev/null | grep -o '"url":"https://[^"]*"' || true)
  [ -n "$url" ] && break
  sleep 1
done
[ -n "$url" ] || { echo "no valid ngrok url found in journal" >&2; exit 1; }

cur=$(sed -n 's/^public_origin[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$CFG" | head -n1)
if [ "${cur%/}" = "$url" ]; then
  echo "public_origin already $url"
  exit 0
fi
tmp=$(mktemp "$CFG.XXXXXX")
trap 'rm -f "$tmp"' EXIT
if grep -q '^public_origin[[:space:]]*=' "$CFG"; then
  sed "s|^public_origin[[:space:]]*=.*|public_origin = \"$url\"|" "$CFG" > "$tmp"
else
  echo "no public_origin line in $CFG (it belongs under [server]); not editing" >&2; exit 1
fi
chmod --reference="$CFG" "$tmp"; chown --reference="$CFG" "$tmp" 2>/dev/null || true
mv "$tmp" "$CFG"
echo "public_origin -> $url; restarting agent-bridge"
systemctl restart agent-bridge.service
