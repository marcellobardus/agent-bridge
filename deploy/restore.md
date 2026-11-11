# Restore procedure (RPO <= 6 h, RTO ~15 min)

The age **private key never lives on the host**. Decryption happens on the operator's own machine.
Snapshots are `/var/backups/agent-bridge/bridge-<UTC>.db.gz.age` (age-encrypted, gzip inside a plain SQLite copy).

## 0. Get a snapshot off the host (or use the off-box copy)

Off-box pull over the existing SSH (run from a trusted off-box machine; see "Pull setup" below):

```sh
umask 077
ssh -i ~/.ssh/bridge_backup_ro -o IdentitiesOnly=yes bridge-backup@HOST > bridge-latest.db.gz.age
test -s bridge-latest.db.gz.age   # non-zero exit or empty file = alert
```

## 1. Decrypt off-box (operator's machine holding the age identity)

```sh
age -d -i ~/secure/agent-bridge-backup.key bridge-latest.db.gz.age | gunzip > bridge-restore.db
sha256sum bridge-latest.db.gz.age     # compare with MANIFEST.json "sha256" if available
```

## 2. Dry check on the host (nothing is stopped or changed)

Pipe the decrypted file straight into `bridgectl`; never stage it in `/tmp` on the host (it holds every message,
artifact, password hash and sealed TOTP secret; the wrapper spools stdin into a 0600 file next to the DB itself):

```sh
ssh admin@HOST 'sudo bridgectl restore --check-only' < bridge-restore.db
```

This verifies SQLite integrity, foreign keys, the audit hash chain, and that the schema (`sqlite_master`) is
exactly what the migrations produce for the snapshot's version (no extra triggers, views or tables); the file is
opened with `trusted_schema=OFF`. age encryption does not authenticate who made the snapshot, so these checks are
the defence against a planted file.

## 3. Restore

```sh
ssh admin@HOST 'sudo bridgectl restore' < bridge-restore.db
```

**Credentials are never re-armed by a restore**. In the same transaction the restore
revokes every dashboard session (everyone logs in again), closes every open enrollment link, and compares the
snapshot with the database it replaces:

- API keys revoked in the replaced DB, or unknown to it, stay revoked. Keys minted after the snapshot are gone:
  re-mint them (`bridgectl key create`) for the affected agent.
- Humans disabled in the replaced DB, unknown to it, or whose password or TOTP changed after the snapshot are
  **disabled**: run `sudo bridgectl human reset <login>` for each (listed on stderr as `humans disabled`).
- Credential values are never copied from the replaced DB (it might be the compromised one); only revocations flow
  forward.

If the current DB is missing or unreadable (disk loss, corruption), nothing can be compared: the restore refuses
and prints the keys and humans the snapshot would re-activate. Re-run with
`ssh admin@HOST 'sudo bridgectl restore --confirm-credentials' < bridge-restore.db`, then rotate every agent
key (`bridgectl key rotate`) and reset every human (`bridgectl human reset`) that may have changed since the
snapshot was taken.

`bridgectl` stops `agent-bridge`, then runs `bridge.cli restore` as user `agent-bridge`, which:
keeps the old DB as `bridge.db.replaced` (0600, one copy), removes stale `-wal/-shm`, swaps the snapshot in,
runs migrations, **cancels every open approval** (pending *and* approved, so nothing can be consumed twice),
revokes sessions and carries credential revocations forward (above), deletes idempotency keys newer than the snapshot, appends a `system.restore` audit row recording the replaced
head, bumps the event sequence by 1,000,000. On success the wrapper starts the service again; on failure it
leaves the service **stopped** and says so.

## 4. Verify

```sh
sudo bridgectl audit verify                      # chain intact, includes the system.restore row
systemctl status agent-bridge --no-pager
curl -fsS http://127.0.0.1:8787/v1/health
journalctl -u agent-bridge -n 30 -o cat
```

Log in to the dashboard: both humans see a restore banner for 7 days (snapshot age, old/new head, number of
cancelled approvals). Agents re-request cancelled approvals and re-receive unacked events (dedupe by event id).
Write down the new audit head (dashboard footer).

To check that a head you recorded before the incident was in the lost window:
`sudo bridgectl audit verify --db bridge.db.replaced --contains <hash>`. When done:
`sudo bridgectl restore --purge-replaced`.

Then securely delete the decrypted `bridge-restore.db` on your machine (`shred -u bridge-restore.db`). Nothing was
written to the host outside the bridge's own state directory.

## Pull setup (read-only, forced command)

On the puller (the trusted off-box machine): `ssh-keygen -t ed25519 -f ~/.ssh/bridge_backup_ro -N ''`.
On the host, as root, append one line to `/var/lib/bridge-backup/.ssh/authorized_keys` (root-owned file; the
`bridge-backup` account cannot change it). Do not edit sshd_config:

```
restrict,command="/opt/agent-bridge/current/deploy/serve-latest-backup" ssh-ed25519 AAAA...pubkey... backup-pull
```

`restrict` disables pty, forwarding, agent and X11; the forced command only `cat`s the newest ciphertext
(exit 1 if none). The `bridge-backup` shell is `/bin/sh` only because sshd runs forced commands through the
login shell; the password is locked.

Daily cron on the puller (ciphertext only is stored; keep 30 daily + 12 monthly):

```sh
0 3 * * * umask 077; f=$HOME/bridge-backups/bridge-$(date -u +\%F).db.gz.age; \
  ssh -i ~/.ssh/bridge_backup_ro -o IdentitiesOnly=yes -o BatchMode=yes bridge-backup@HOST > "$f" \
  && test -s "$f" || { rm -f "$f"; echo "BRIDGE BACKUP PULL FAILED" >&2; }
```

Alert if the pull fails, the file is empty, or the newest copy is older than 36 h.

## Restore drill (quarterly)

Steps 0–2 on the latest off-box copy (`--check-only`). Do a full step 3 drill only on a scratch machine
(never practise on production).
