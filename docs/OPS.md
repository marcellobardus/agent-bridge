# Agent Bridge: operations guide

Single process (`bridge.serve`, 127.0.0.1:8787) + SQLite + optional outbound-only ngrok. Admin = on-box `sudo bridgectl ...` only.

| Path | What |
|---|---|
| `/opt/agent-bridge/releases/<ver>`, `current` -> | code + venv, root-owned, max 2 kept |
| `/etc/agent-bridge/config.toml` | non-secret config; `public_origin = "https://<NGROK_DOMAIN>"` is required (set by install.sh from `ngrok.env`, else edit by hand) |
| `/etc/agent-bridge/credentials/{pepper,totp_kek}` | root 0400, loaded via systemd `LoadCredential` |
| `/etc/agent-bridge/ngrok.env` | root 0600: `NGROK_AUTHTOKEN`, `NGROK_DOMAIN` (bare hostname, any domain reserved on the ngrok account) |
| `/etc/agent-bridge/backup-recipients.txt` | age **public** recipient(s) |
| `/var/lib/agent-bridge/bridge.db` | the database (agent-bridge 0600) |
| `/var/backups/agent-bridge/` | encrypted snapshots (agent-bridge:bridge-backup, setgid, 0640) |
| `/usr/local/sbin/bridgectl` | root-only wrapper (runs the CLI as `agent-bridge`) |

In this guide `alice`/`bob` are the ids of your two parties and `agent-a`/`agent-b` the ids of their agents
(`bridgectl init-db` seeds the ids in `bridge/ops.py`; use the ids that exist in your database).

## First deploy (checklist)

1. A Linux host with systemd, Python 3.13+ (the installer builds a hash-pinned venv), `age` for backups and, for the
   public tunnel, an ngrok account (authtoken + domain, see "ngrok" below).
2. Build a tarball on a build machine: `scripts/package.sh [version]` (writes `agent-bridge-<ver>.tar.gz` and its
   `.sha256` next to the repo; refuses to package anything that looks like a secret). Copy it to the host, verify the
   checksum and extract it.
3. Optionally create `/etc/agent-bridge/ngrok.env` first (see "ngrok"), so the installer writes `public_origin`.
4. Run the installer (next section), then `sudo bridgectl doctor`.
5. Create the first human: `sudo bridgectl human invite alice` (see `docs/DASHBOARD.md`), mint agent keys, set up
   backups and test a restore (`deploy/restore.md`).

## Install / upgrade / rollback

```sh
# on the host, as root, in the extracted tarball
sudo ./deploy/install.sh [--with-ngrok]
```
Idempotent: creates users/dirs, generates credentials only if missing, builds `releases/<ver>` with a hash-pinned
venv (`--require-hashes --only-binary=:all: --no-cache-dir`), stops the service, flips `current`, runs
`bridgectl migrate`, restarts, waits for `/v1/health`, runs `bridgectl doctor`, and checks that the only new
listener is `127.0.0.1:8787` and the firewall ruleset hash is unchanged. If health fails after an upgrade it flips
`current` back to the previous release automatically.

Manual rollback (previous release still on disk):
```sh
ls /opt/agent-bridge/releases
sudo ln -sfn /opt/agent-bridge/releases/<old> /opt/agent-bridge/current.new && sudo mv -T /opt/agent-bridge/current.new /opt/agent-bridge/current
sudo systemctl restart agent-bridge
```
Migrations are forward-only. If the new release changed the schema, roll back *code* only if the old code
tolerates it; otherwise restore a pre-upgrade snapshot (`deploy/restore.md`). Run `sudo bridgectl backup now`
before every upgrade.

Uninstall: `sudo ./deploy/uninstall.sh` keeps data; `--purge --yes` deletes DB, backups, credentials, users.

## Restart and health

```sh
sudo systemctl restart agent-bridge
systemctl status agent-bridge --no-pager
journalctl -u agent-bridge -o cat -n 100 -f        # JSON logs, no secrets/bodies
curl -fsS http://127.0.0.1:8787/v1/health          # {"ok":true}
curl -fsS https://<NGROK_DOMAIN>/v1/health -H 'ngrok-skip-browser-warning: 1'
sudo bridgectl doctor
ss -ltnp | grep -E "8787|4040"                     # must show 127.0.0.1:8787 only (nothing on 4040: ngrok inspector off; doctor FAILs otherwise)
```
The unit restarts on failure (`Restart=on-failure`) and at boot. Logs are journald only (no files, no inodes).

## Keys, accounts

Run via `sudo bridgectl` (never run the CLI as root directly: root-owned `-wal` files would break the service).
```sh
sudo bridgectl key create --agent agent-a     # prints ONLY the abk_... token on stdout, once; max 2 active per agent
sudo bridgectl key create --agent agent-b --label prod --expires-days 180   # optional --scopes a,b
sudo bridgectl key list                       # JSON lines: id, agent, label, scopes, last_used_at, ...
sudo bridgectl key revoke <keyid>             # immediate
sudo bridgectl key rotate --agent agent-a --old <keyid>   # new key (printed once) + revokes OLD in one step
sudo bridgectl human invite alice          # one-time 24 h enrollment link <public_origin>/app/enroll/<token> (password + TOTP)
sudo bridgectl human invite bob --party bob --display-name Bob
sudo bridgectl human reset alice           # lost password/TOTP: disables account, revokes sessions, prints a new link
sudo bridgectl human disable alice         # disable + revoke sessions
sudo bridgectl human unlock --all             # clear login throttles: per IP and per account (or --ip <addr> | --login <name>)
sudo bridgectl audit verify                   # re-walk the audit hash chain (--db FILE, --contains HASH)
sudo bridgectl doctor                         # disk/inodes, integrity, audit chain, TOTP failures, db perms, tunnel (below)
```
`bridgectl doctor` also runs `bridge.cli doctor --tunnel` as root (no DB, no credentials): **FAIL** if anything
accepts a connection on `127.0.0.1:4040` (ngrok inspector/API) or `public_origin` is plain `http` to a non-loopback
host; **WARN** if `public_origin` differs from the running tunnel URL (taken, like `agent-bridge-sync-origin`, from
the journal of the current `agent-bridge-ngrok` invocation, else from the rendered pinned config in
`/run/agent-bridge-ngrok/ngrok.yml`), or if that URL cannot be determined (unit stopped, journal unreadable).
There are no recovery codes; the fallback for a locked-out human is `human reset` by someone with root on the box.
After 5 wrong TOTP codes with the correct password an account gets an exponential delay (2 s doubling to 15 min,
from any IP; the dashboard shows a red banner). That means someone has the password: `human reset` that login.
`human unlock --login <name>` clears the delay without a reset (only if you caused it yourself).
A zero-downtime rotation: `key rotate` (both keys work until the old one is revoked, which happens in the same
command, so deploy the new key promptly) or create -> deploy to the agent -> `key revoke`.
Capture a key into a root-only file, never into a terminal log or chat:
`sudo bridgectl key create --agent agent-b | sudo tee /root/agent-b.key >/dev/null` (then hand over via a password
manager / one-time secret, and `shred -u` it). The dashboard can also mint/revoke keys for one's own party's agent after step-up.

## Backups

Timer `agent-bridge-backup.timer` runs every 6 h as user `agent-bridge` (the unit loads `pepper` and `totp_kek` via `LoadCredential`, because `bridge.cli backup snapshot` reads them like every subcommand; the snapshot itself is just the DB) (`00/6:17`): online SQLite snapshot -> gzip -> `age -R backup-recipients.txt`
-> `/var/backups/agent-bridge/bridge-<UTC>.db.gz.age`, keeps 28 (7 days). Needs `apt install age` and the owner's
**public** recipient in `/etc/agent-bridge/backup-recipients.txt` (`age-keygen` on the operator's machine; keep the private
key offline; paste the `age1...` public line only).
```sh
sudo install -m 0644 /dev/stdin /etc/agent-bridge/backup-recipients.txt   # paste age1... line, Ctrl-D
sudo systemctl enable --now agent-bridge-backup.timer
sudo bridgectl backup now
ls -l /var/backups/agent-bridge
```
Off-box pull and the full restore steps (and the quarterly drill) are in `deploy/restore.md`.

## ngrok (one reserved domain)

1. In the ngrok dashboard (dashboard.ngrok.com): **Getting Started -> Your Authtoken** shows the authtoken
   (or Your Authtoken in the left menu). **Domains -> New Domain** reserves the domain: the free static
   `something.ngrok-free.app` (one per free account), or on a paid plan a `*.ngrok.app` / `*.ngrok.dev` name or your
   own hostname (e.g. `bridge.example.com`; add the CNAME record ngrok shows at your DNS provider and wait until the
   dashboard shows it as verified/certificate issued). Copy the authtoken and the hostname.
2. On the host, create the secrets file without echoing into shell history or logs:
   ```sh
   sudo bash -c 'umask 077; read -r -s -p "authtoken: " t; echo; read -r -p "domain (e.g. bridge.example.com): " d; printf "NGROK_AUTHTOKEN=%s\nNGROK_DOMAIN=%s\n" "$t" "$d" > /etc/agent-bridge/ngrok.env; chmod 600 /etc/agent-bridge/ngrok.env; chown root:root /etc/agent-bridge/ngrok.env'
   ```
   (`read -s` keeps the token out of history and the screen; do not pass it as an argument.) `NGROK_DOMAIN` is a
   bare lowercase hostname: no `https://`, port, path or trailing dot. `render-config.sh` and `install.sh` refuse
   anything else (LDH labels of 1-63 chars, at least one dot, at most 253 chars), because the value is put into the
   ngrok config and `config.toml` with `sed`.
3. `sudo ./deploy/install.sh --with-ngrok` (installs ngrok from ngrok's apt repo, see below; enables the unit because the env file exists),
   or `sudo systemctl enable --now agent-bridge-ngrok` if already installed.
4. Check: `systemctl status agent-bridge-ngrok`, `curl -fsS https://<domain>/v1/health -H 'ngrok-skip-browser-warning: 1'`.

Apt source (official, from https://ngrok.com/download/linux): key `https://ngrok-agent.s3.amazonaws.com/ngrok.asc`,
line `deb https://ngrok-agent.s3.amazonaws.com bookworm main` (ngrok publishes one suite for all releases), package `ngrok`.
The installer stores the key under `/etc/apt/keyrings/ngrok.asc` with `signed-by=` (narrower than the page's
`trusted.gpg.d`) and refreshes only that source.

The unit runs as user `ngrok`, outbound only (no listening socket: `web_addr: false`, no request capture:
`inspect_db_size: -1`), `MemoryMax=96M`, `GOMEMLIMIT=72MiB`, forwarding to `http://127.0.0.1:8787`. The token is
read from `$NGROK_AUTHTOKEN`; the rendered config in `/run/agent-bridge-ngrok/ngrok.yml` holds only the domain.

**Tradeoff:** ngrok's edge terminates TLS. ngrok can in principle read bearer keys, session cookies and bodies in
transit. Keys are revocable, approvals need password + TOTP step-up in the dashboard and are bound to a payload
hash, but treat the free tunnel as a compromise vs. end-to-end TLS. Rotate keys if you ever suspect the ngrok account.
Protect that account (2FA).

### Free-plan limits and request budget

Free plan as designed: ~20,000 HTTP requests/month, ~1 GB data out, 1 static domain, browser interstitial on HTML
(agents send `ngrok-skip-browser-warning: 1`; humans click through once). Re-check on ngrok.com/pricing; the
numbers below are the budget, not a measurement.

Rules that keep it low (all already in the service/clients, no code change needed): `poll_after_s = 900` (15 min) for
both agents; clients persist `next_poll_at` so an early cron run makes zero requests; one batched `GET /v1/inbox`
returns events **and** the pending-approval count; `POST /v1/inbox/ack` only for non-empty pages; `/v1/approvals`
only when that count or an `approval.*` event changed; `has_more` drains immediately; `Retry-After` is honoured.

| Source (30-day month) | Calc | Requests |
|---|---|---|
| Agent A idle poll, 15 min | 96/day x 30 | 2,880 |
| Agent B idle poll, 15 min | 96/day x 30 | 2,880 |
| Acks + task/message/artifact/approval writes | ~40 tasks x ~25 requests | 1,000-2,000 |
| Dashboard, 2 humans | ~30 page loads/day incl. assets x 30 | ~1,800 |
| Health pings, smoke tests | est. | ~100 |
| **Typical total** | | **~8.7-9.7k (about 45 % of 20k)** |

Worst realistic month (double the writes, dashboard used heavily at ~60 loads/day): ~13-14k, still under the cap.
Check actual usage in the ngrok dashboard (Usage) after the first week; **act at ~70 % (14k)**.

If it approaches the cap (config/ops only, no code changes):
1. Raise `poll_after_s` in `/etc/agent-bridge/config.toml` (e.g. 1800 saves ~2.9k/month across both agents) and
   `sudo systemctl restart agent-bridge`; clients pick the hint up on their next poll.
2. Or move to a paid ngrok plan (about $10/month at time of writing) which lifts the request cap.

Does **not** fit free: any agent polling at 5 min (8,640/month each, ~15-17k total, tight) or 60 s (43,200/month).

### If ngrok is down or the quota is hit
Agents get errors/429 and back off; nothing is lost (durable inbox, cursors, idempotent retries). The bridge and
humans on-box are unaffected: `ssh -L 8787:127.0.0.1:8787 admin@HOST` and browse `http://127.0.0.1:8787/app` for
the dashboard. Quota hit: wait for the monthly reset, or raise polling intervals, or upgrade the ngrok plan. Do
**not** add a second public tunnel or open a port. Restart: `sudo systemctl restart agent-bridge-ngrok`.

### Limitation: a free tunnel's quota can be exhausted by anyone who knows the URL
Every request that reaches the tunnel edge counts against its quota, including 401s and 429s, so the service cannot
prevent quota exhaustion (see SECURITY.md, Limitations). Mitigation and recovery:
- Keep the hostname out of anything public (screenshots, issues, chats with third parties, public repos).
- Watch for it: agents that see repeated edge errors (ngrok `ERR_NGROK_*` pages, 429 from the edge rather than
  problem+json from the bridge) should report it to their human; check ngrok **Usage** weekly.
- Recovery: (1) humans use the SSH tunnel above, the dashboard keeps working; (2) wait for the reset, upgrade the
  plan, or release the static domain, claim a new one, put it in `/etc/agent-bridge/ngrok.env` and `public_origin`,
  restart both units and give the new URL to both agents privately; (3) if the old hostname leaked together with a
  key, rotate keys too (`bridgectl key rotate`).

## Local processes on the host
The service listens on 127.0.0.1:8787 only. Local processes can reach it directly over plain HTTP and can set
`X-Forwarded-For`, which the service takes (right-most entry) as the client address for login throttling and the
failed-auth limiter, so local processes are trusted not to spoof the client address (see SECURITY.md, Limitations).
They still need a key or a password + TOTP to do anything. If the host runs untrusted local code, the hardening
option is a Unix socket in a directory only the tunnel user can enter (uvicorn `--uds`, ngrok `addr: unix:...`);
it is not wired in because it has not been validated against the ngrok agent.

## Memory

The units cap memory: `agent-bridge` `MemoryMax=192M`, `MemorySwapMax=0`, `OOMScoreAdjust=500` (it is killed before
sshd or other services), ngrok `MemoryMax=96M`, `GOMEMLIMIT=72MiB`, transient backup/CLI runs 96M each. Typical use is
well below the caps. An OOM-kill hits the bridge first and systemd restarts it. Swap is the operator's call (the
installer does not create it); if added, the units keep `MemorySwapMax=0` so the bridge never swaps.

## Inode / storage guard
One DB file, backups pruned to 28, pip runs with `--no-cache-dir`, logs in journald. The service checks free space/inodes every minute and
goes read-only (`503 storage_degraded` on writes) below 500 MB or 5 % inodes free; `bridgectl doctor` shows it. Check: `df -h /; df -i /`.

### No reserved domain yet (fallback)
The Debian package installs the agent at `/usr/local/bin/ngrok` (the unit uses that path). If the account has no
reserved domain, pinning a URL fails with `ERR_NGROK_313`. Stop-gap (use it only until a domain is
pinned): the drop-in `deploy/systemd/agent-bridge-ngrok-ephemeral.conf.example`, installed as
`/etc/systemd/system/agent-bridge-ngrok.service.d/ephemeral.conf`, starts the endpoint without a `url` from the
reviewed `deploy/ngrok/ngrok-ephemeral.yml` in the current release (`web_addr: false`, `inspect_db_size: -1`,
`log_level: info` so the tunnel-started line reaches the journal) and
an `ExecStartPost` that runs `/usr/local/sbin/agent-bridge-sync-origin` (after a short delay) copies the random URL into `public_origin`:
```sh
sudo install -d -m 0755 /etc/systemd/system/agent-bridge-ngrok.service.d
sudo install -m 0644 /opt/agent-bridge/current/deploy/systemd/agent-bridge-ngrok-ephemeral.conf.example \
  /etc/systemd/system/agent-bridge-ngrok.service.d/ephemeral.conf
sudo rm -f /etc/agent-bridge/ngrok-ephemeral.yml          # the old hand-made copy, if present
sudo systemctl daemon-reload && sudo systemctl restart agent-bridge-ngrok
sudo bridgectl doctor                                      # public_origin_tunnel OK, ngrok_inspector OK
```
The URL then changes on every ngrok restart. `deploy/ngrok/sync-origin.sh` (installed as `agent-bridge-sync-origin`) reads the current URL from the ngrok
journal, rewrites `public_origin` and restarts agent-bridge only if it changed. The dashboard Origin check also accepts
the request's own Host, so a changed tunnel URL no longer breaks logins; links printed by `bridgectl` use `public_origin`,
which the sync script keeps current. Fix: pin a domain (next section).

### Pin a domain (free static, paid `*.ngrok.app`/`*.ngrok.dev`, or your own hostname)
1. Pick the domain. No API key or dashboard step is needed for the first two options (only the authtoken):
   - every account has one assigned **dev domain** (e.g. `<words>.ngrok-free.dev`); an endpoint started without a
     `url` uses it, and it does not change across restarts;
   - on a paid plan (Hobbyist and up) an ngrok-branded name such as `<name>.ngrok.app` works by just putting it in
     `NGROK_DOMAIN`: the agent claims it on first start (up to 10 on Hobbyist; a name taken by someone else fails);
   - your own hostname needs the ngrok dashboard (Domains -> New Domain, then the CNAME ngrok shows, wait until verified).
   `ERR_NGROK_313` means the account is still on Free; `ERR_NGROK_18021` means another endpoint (e.g. the running
   unit) already uses the account's endpoint slot: stop `agent-bridge-ngrok` before testing by hand.
2. Set `NGROK_DOMAIN` (bare hostname) in `/etc/agent-bridge/ngrok.env`, keeping it root 0600:
   ```sh
   sudo bash -c 'umask 077; read -r -p "domain (e.g. bridge.example.com): " d; sed -i "/^NGROK_DOMAIN=/d" /etc/agent-bridge/ngrok.env; printf "NGROK_DOMAIN=%s\n" "$d" >> /etc/agent-bridge/ngrok.env'
   sudo stat -c '%a %U' /etc/agent-bridge/ngrok.env      # 600 root
   /opt/agent-bridge/current/deploy/ngrok/render-config.sh --check-host bridge.example.com && echo valid
   ```
3. Remove the ephemeral drop-in (and the old hand-made ephemeral file, if any):
   `sudo rm -f /etc/systemd/system/agent-bridge-ngrok.service.d/ephemeral.conf /etc/agent-bridge/ngrok-ephemeral.yml`
   (and `sudo rmdir /etc/systemd/system/agent-bridge-ngrok.service.d` if empty).
4. Set `public_origin = "https://<NGROK_DOMAIN>"` under `[server]` in `/etc/agent-bridge/config.toml`
   (`sudo sed -i 's|^public_origin[[:space:]]*=.*|public_origin = "https://bridge.example.com"|' /etc/agent-bridge/config.toml`).
5. `sudo systemctl daemon-reload && sudo systemctl restart agent-bridge agent-bridge-ngrok`
6. Check: `systemctl show -p DropInPaths agent-bridge-ngrok` is empty, `sudo bridgectl doctor` shows
   `public_origin_tunnel` OK (from the rendered config) and `ngrok_inspector` OK,
   `curl -fsS https://<NGROK_DOMAIN>/v1/health -H 'ngrok-skip-browser-warning: 1'`.
7. Give the new URL (`AGENT_BRIDGE_URL=https://<NGROK_DOMAIN>`) to both agents privately; an enrollment link that is still open is not tied to a hostname:
   replace the host in the existing link with the new domain. Re-issue it (`bridgectl human invite/reset`, which closes the old link) only if the link itself may have leaked.
