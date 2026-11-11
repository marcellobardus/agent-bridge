#!/bin/bash
# Static checks for deploy/: bash -n, shellcheck (if present), systemd-analyze verify (if present).
set -uo pipefail
cd "$(dirname "$0")"
rc=0
scripts=(install.sh uninstall.sh bridgectl backup.sh serve-latest-backup check.sh ngrok/render-config.sh ngrok/sync-origin.sh ../scripts/lock.sh ../scripts/package.sh)
for s in "${scripts[@]}"; do bash -n "$s" || { echo "FAIL bash -n $s"; rc=1; }; done
if command -v shellcheck >/dev/null; then
  shellcheck -x "${scripts[@]}" || rc=1
else echo "shellcheck not installed: skipped"; fi
if command -v systemd-analyze >/dev/null; then
  t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
  # verify resolves ExecStart paths; stage stubs so a missing /opt/... path is not an error
  for u in systemd/*.service systemd/*.timer; do cp "$u" "$t/"; done
  sed -i 's|^ConditionPathExists=.*||' "$t/agent-bridge-ngrok.service"
  for u in "$t"/*.service "$t"/*.timer; do
    out=$(systemd-analyze verify "$u" 2>&1 | grep -v -E 'is not executable|Command .* not found|No such file or directory|ExecStart|ExecStartPre|Failed to prepare filename|Failed to create directory|^$')
    [ -z "$out" ] || { echo "FAIL verify $(basename "$u"):"; echo "$out"; rc=1; }
  done
else echo "systemd-analyze not installed: skipped"; fi
# the template must hold no secrets
grep -Eqi 'authtoken *: *[A-Za-z0-9_]{10,}' ngrok/ngrok.yml.tmpl && { echo "FAIL: authtoken in template"; rc=1; }
[ $rc -eq 0 ] && echo "deploy/check.sh OK"
exit $rc
