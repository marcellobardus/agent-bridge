#!/bin/bash
# Remove Agent Bridge. Keeps data (DB, backups, credentials, config) unless --purge --yes.
# Never touches other services, firewall or sshd. Does not remove the ngrok apt package or age.
set -euo pipefail
PURGE=0 YES=0
for a in "$@"; do case $a in --purge) PURGE=1;; --yes) YES=1;; *) echo "usage: $0 [--purge --yes]" >&2; exit 2;; esac; done
[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
if [ "$PURGE" -eq 1 ] && [ "$YES" -ne 1 ]; then echo "--purge deletes the DB, backups, credentials and config: add --yes to confirm" >&2; exit 1; fi

for u in agent-bridge-ngrok.service agent-bridge-backup.timer agent-bridge-backup.service agent-bridge.service; do
  systemctl disable --now "$u" 2>/dev/null || true
  rm -f "/etc/systemd/system/$u"
done
rm -rf /etc/systemd/system/agent-bridge-ngrok.service.d   # ephemeral drop-in, if any
systemctl daemon-reload
rm -f /usr/local/sbin/bridgectl /usr/local/sbin/agent-bridge-sync-origin
rm -rf /opt/agent-bridge
echo "[uninstall] service, units, wrapper and releases removed; data kept"
if [ "$PURGE" -eq 1 ]; then
  rm -rf /var/lib/agent-bridge /var/lib/agent-bridge-ngrok /var/backups/agent-bridge /etc/agent-bridge /var/lib/bridge-backup
  for u in agent-bridge ngrok bridge-backup; do userdel "$u" 2>/dev/null || true; done
  echo "[uninstall] data, credentials and users purged"
fi
