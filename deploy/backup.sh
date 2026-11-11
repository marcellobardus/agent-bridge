#!/bin/sh
# Encrypted DB backup. Run by agent-bridge-backup.service as user agent-bridge (UMask 0027, setgid dir
# => files are agent-bridge:bridge-backup 0640). Needs: bridge.cli `backup snapshot --out FILE`
# (online sqlite backup + integrity/audit checks, writes an uncompressed .db), gzip, age.
# bridge.cli loads pepper/totp_kek from $CREDENTIALS_DIRECTORY for every subcommand, so the unit has LoadCredential=.
# The age PRIVATE key is never on this box; only public recipients in backup-recipients.txt.
set -eu
umask 0027
DEST=${BACKUP_DIR:-/var/backups/agent-bridge}
RECIP=${BACKUP_RECIPIENTS:-/etc/agent-bridge/backup-recipients.txt}
KEEP=${BACKUP_KEEP:-28}
CUR=${BRIDGE_CURRENT:-/opt/agent-bridge/current}
CONF=${BRIDGE_CONFIG:-/etc/agent-bridge/config.toml}

[ -s "$RECIP" ] || { echo "backup: $RECIP missing or empty (age public recipients)" >&2; exit 1; }
command -v age >/dev/null || { echo "backup: age not installed (apt install age)" >&2; exit 1; }

ts=$(date -u +%Y%m%dT%H%M%SZ)
tmp=$(mktemp -d "$DEST/.tmp.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

"$CUR/venv/bin/python" -I -B -m bridge.cli --config "$CONF" backup snapshot --out "$tmp/db"
[ -s "$tmp/db" ] || { echo "backup: empty snapshot" >&2; exit 1; }
gzip -9 -n < "$tmp/db" | age -R "$RECIP" -o "$tmp/out.age"
rm -f "$tmp/db"
[ -s "$tmp/out.age" ] || { echo "backup: encryption produced no output" >&2; exit 1; }

final="$DEST/bridge-$ts.db.gz.age"
mv "$tmp/out.age" "$final"
sum=$(sha256sum "$final" | cut -d' ' -f1)
size=$(wc -c < "$final")
printf '{"file":"%s","sha256":"%s","bytes":%s,"created":"%s"}\n' "$(basename "$final")" "$sum" "$size" "$ts" > "$DEST/MANIFEST.json.new"
mv "$DEST/MANIFEST.json.new" "$DEST/MANIFEST.json"

# prune: keep the KEEP newest snapshots
ls -1 "$DEST"/bridge-*.db.gz.age 2>/dev/null | sort -r | tail -n +"$((KEEP + 1))" | while IFS= read -r f; do rm -f -- "$f"; done
echo "backup ok: $(basename "$final") $size bytes sha256=$sum"
