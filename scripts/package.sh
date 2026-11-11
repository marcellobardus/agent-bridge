#!/bin/bash
# Build $DIST_DIR (default: ../dist, i.e. next to the repo)/agent-bridge-<ver>.tar.gz (+ .sha256): source + requirements.lock, no venv/caches/tests/secrets.
# Usage: scripts/package.sh [version]   (default: contents of VERSION, else git describe, else date)
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f requirements.lock ] || { echo "requirements.lock missing: run scripts/lock.sh" >&2; exit 1; }
VER=${1:-$(cat VERSION 2>/dev/null || git describe --tags --always --dirty 2>/dev/null || date -u +%Y%m%d%H%M%S)}
VER=$(echo "$VER" | tr -d '[:space:]')
[[ $VER =~ ^[A-Za-z0-9._+-]+$ ]] || { echo "bad version '$VER'" >&2; exit 1; }
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
P=$W/agent-bridge-$VER
DIST=${DIST_DIR:-$(cd .. && pwd)/dist}   # outside the repo by default (not in git)
mkdir -p "$P" "$DIST"
for p in bridge deploy docs LICENSE requirements.lock pyproject.toml config.example.toml README.md; do
  [ -e "$p" ] && cp -a "$p" "$P/"
done
echo "$VER" > "$P/VERSION"
find "$P" \( -name __pycache__ -o -name '*.pyc' -o -name '.git*' -o -name '.venv' -o -name '*.db' -o -name '*.db-*' -o -name '.env*' -o -name '.pytest_cache' \) -prune -exec rm -rf {} +
if grep -rIlE 'abk_[A-Za-z0-9_-]{12}_[A-Za-z0-9_-]{43}|NGROK_AUTHTOKEN=[A-Za-z0-9_]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY|AGE-SECRET-KEY-' "$P"; then
  echo "secret-looking content found, refusing to package" >&2; exit 1
fi
OUT=$DIST/agent-bridge-$VER.tar.gz
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='UTC 2020-01-01' -C "$W" -czf "$OUT" "agent-bridge-$VER"
( cd "$DIST" && sha256sum "agent-bridge-$VER.tar.gz" > "agent-bridge-$VER.tar.gz.sha256" )
echo "$OUT"; cat "$OUT.sha256"
