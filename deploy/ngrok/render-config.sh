#!/bin/sh
# Render ngrok.yml from the secret-free template. Usage: render-config.sh TEMPLATE OUT
# Needs NGROK_DOMAIN and NGROK_AUTHTOKEN in the environment (from ngrok.env). Never prints either.
# NGROK_DOMAIN is any hostname you own on ngrok (x.ngrok-free.app, x.ngrok.app, bridge.example.com, ...).
# Test hook (no root, no env needed): render-config.sh --check-host NAME  -> exit 0 if NAME is a valid hostname.
set -eu

# Strict hostname check: the value is interpolated into sed and the YAML config.
# Lowercase LDH labels of 1-63 chars, no leading/trailing hyphen, at least one dot, <= 253 chars,
# last label not starting with a digit (no IPv4 literals). Rejects scheme, port, path, userinfo, whitespace, uppercase.
# Keep in sync with deploy/install.sh, deploy/ngrok/sync-origin.sh and bridge/ops.py valid_hostname.
valid_hostname() {
  _vh=$1
  [ -n "$_vh" ] && [ "${#_vh}" -le 253 ] || return 1
  case $_vh in
    *[!abcdefghijklmnopqrstuvwxyz0123456789.-]*|.*|*.|*..*) return 1 ;;
    *.*) ;;
    *) return 1 ;;
  esac
  case ${_vh##*.} in [0123456789]*) return 1 ;; esac
  while :; do
    _vl=${_vh%%.*}
    case $_vl in ""|-*|*-) return 1 ;; esac
    [ "${#_vl}" -le 63 ] || return 1
    [ "$_vh" = "$_vl" ] && return 0
    _vh=${_vh#*.}
  done
}

if [ "${1:-}" = "--check-host" ]; then
  valid_hostname "${2:-}"
  exit $?
fi

tmpl=$1 out=$2
valid_hostname "${NGROK_DOMAIN:-}" || {
  echo "NGROK_DOMAIN missing or invalid (want a bare lowercase hostname like bridge.example.com: no scheme, port or path)" >&2
  exit 1
}
[ -n "${NGROK_AUTHTOKEN:-}" ] || { echo "NGROK_AUTHTOKEN missing" >&2; exit 1; }
umask 077
sed "s|@NGROK_DOMAIN@|$NGROK_DOMAIN|g" "$tmpl" > "$out"
