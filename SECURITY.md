# Agent Bridge — Security

What this covers: the threat model, the controls that answer it, the authentication design choice, a summary of
the classes of issues found in security reviews and fixed, the known limitations, and how to report a problem or
rotate a secret. Mechanics are specified in `docs/SPEC.md`; operations in `docs/OPS.md` and `deploy/restore.md`.

## Reporting a vulnerability

Use **GitHub private vulnerability reporting** on this repository (*Security → Report a vulnerability*, i.e. a
private security advisory). **Do not open public issues or pull requests for security problems.** Include the
version or commit, the steps to reproduce, the impact, and (for a running deployment) the time and the
`X-Request-Id` of the response. **Never include real keys, passwords, TOTP secrets, cookies or hostnames you want to
keep private.** We aim to acknowledge a report within 7 days and to coordinate disclosure
with you. Only the latest release / `main` is supported.

## 2. Threat model

| # | Adversary / event | Can do | Must not be able to |
|---|---|---|---|
| T1 | **Anyone on the internet who learns the URL** (leaked in a chat, screenshot, log) | Send any request to the edge | Read any data, write anything, lock out the agents, exhaust the hub's memory or connections, guess a key or a TOTP in useful time |
| T2 | **The tunnel edge** (TLS terminated there) | See bearer keys, cookies, passwords, TOTP codes and bodies in transit | — (trusted by design decision; see §3 and §6) |
| T3 | **A leaked agent key** | Act as that agent within its scopes | Act after revocation (next request refused), decide approvals, act as a human, see the other side's private data beyond shared tasks |
| T4 | **A compromised or prompt-injected agent** (with its valid key) | Send hostile text/JSON/artifacts, spam, request approvals | Crash or OOM the hub, starve the other agent, forge an approval, mark its own work verified, smuggle look-alike characters past the approver, make the server fetch or execute anything |
| T5 | **A malicious or compromised human of the other party** (dashboard account) | See everything (design decision), instruct, pause, escalate | Decide or revoke the other party's approvals, mint/revoke its keys, pause its agent, mark the other side's work verified or accept on its behalf, override the other side's transitions without step-up; pass as the other party's human (every message carries the sender's `party_id`; agents are to obey only their own party's human) |
| T6 | **A stolen session cookie / unattended browser** | Read the dashboard | Gain approval power (step-up = password + TOTP; 5 wrong step-ups revoke the session) |
| T7 | **A phished password** (no TOTP device) | Try TOTP codes | Brute-force TOTP (per-account delays independent of IP) |
| T8 | **Other local processes on the host** | Reach 127.0.0.1:8787 over plain HTTP, spoof `X-Forwarded-For` | Do anything without a key or password + TOTP; hold connection slots forever |
| T9 | **Restore** from an old or planted snapshot | Roll data back | Re-activate revoked keys, disabled accounts, old passwords, logged-out sessions or used enrollment links; run planted triggers/views |

Assets: approval power (deploys, fund movements, mainnet upgrades, live trading, credential changes), agent keys,
human credentials, task/message/artifact content, the audit chain, availability of the hub.

## 3. Authentication design choice: long-lived bearer keys, checked on every request

**Decision: keep opaque bearer keys (`abk_<id>_<secret>`, HMAC-SHA256 with a server pepper, constant-time
compare) verified against the database on every request. Do not add short-lived signed access tokens minted from
the key.** Reasons, for this threat model:

1. **Instant revocation is a hard requirement.** A self-contained signed token (JWT-style) stays valid until it
   expires, so revocation would lag by the token TTL. Making it instant means looking up the token or its key on
   every request, which is exactly the one indexed read + one HMAC we already do. The token layer would add work
   and buy nothing. Tested: a revoked key is refused on the very next request (`tests/test_security.py`).
2. **It does not take the key off the wire.** The key would still cross the same tunnel edge every TTL to mint a
   token. An observer at the edge (T2) sees it at the next refresh. A token only shortens the life of what leaks
   *besides* the key, and nothing else leaks: the server never logs headers, query strings or bodies, and the
   clients redact the key in errors and `repr`.
3. **The edge is already trusted with more.** Human passwords, TOTP codes and session cookies (approval power)
   cross the same edge. Hiding agent keys from it would not change who must be trusted.
4. **Cost and risk.** A mint endpoint, a signing secret and its rotation, clock skew, refresh logic in two
   independently written clients, and extra requests against a tunnel request quotas. More code means more
   ways to get authentication wrong.

What does add value, and exists: scopes per key, at most 2 active keys per agent (rotation overlap),
`bridgectl key rotate`, optional expiry (`--expires-days`, recommended 90–180), `last_used_at` per key, dashboard
revocation by the agent's own party, audit rows for every key event, and failed-auth limits that never touch valid
keys. If the operator ever stops trusting the edge, the measure that would help is **request signing** (the key
never leaves the client; an HMAC covers method, path, timestamp and body hash). That needs end-to-end changes in
both clients and the dashboard login, so it is a design change, not a patch.

## 4. Controls

**Network and process.** Loopback bind only (refuses others). Outbound tunnel only (ngrok inspector disabled). systemd
sandbox (dedicated user, `ProtectSystem=strict`, empty capability set, syscall filter, loopback-only IP policy,
`MemoryMax=192M`). Uvicorn `limit_concurrency=200`, and a per-connection deadline: complete
headers within 10 s and, except for artifact uploads (30 s), the complete body within the same 10 s, else the
server closes the socket (`bridge/serve.py`). **No key, no body:** before a single body byte is read,
every `/v1` POST must carry a valid key (same check as below; failures charged the same way) or it gets `401` +
`Connection: close`; `/app` forms get 200 KiB only with a valid session, login/enroll/everything else 8 KiB.
Body ≤ 256 KiB; 2 MiB only for `POST /v1/tasks/{id}/artifacts` (exact route) with a valid key. All buffered bodies
share a global budget (16 MiB, at most 4 artifact-size bodies): over budget → `503 server_busy`, `Retry-After: 5`,
before reading.

**Unauthenticated surface.** Only `GET /v1/health` (`{"ok": true}`), the login page, the stylesheet and
token-gated enrollment links answer without credentials (`/v1/openapi.json` is off unless `expose_openapi =
true`; agents use `docs/openapi.json`; unknown paths get a ~20-byte 404). Every other
registered route answers 401/403 or redirects to the login page with no data; a test enumerates all routes
automatically.

**Agent authentication.** The key is verified first (one indexed read + HMAC); only failures are charged, to a
per-client-IP bucket (right-most `X-Forwarded-For`, IPv6 per /64; 30/min) and a global backstop (3,000/min) that is
never consulted for a valid key. Per key: 120 req/min, 30 writes/min, 2 requests in flight.

**Human authentication.** argon2id (19 MiB, one at a time, never inside the DB write lock); TOTP with replay
protection, secret AES-GCM-sealed; login throttled per IP (3 free, 2 s doubling to 5 min), per account after 5
wrong codes with the right password (2 s doubling to 15 min, any IP), and by a global failed-login bucket
(60/min) that is consulted only after the password is wrong, so a correct login is never turned away by it;
argon2 work is serialized by a one-at-a-time semaphore; no permanent lockout (`bridgectl human unlock`). Sessions: `__Host-` cookie, Secure, HttpOnly,
SameSite=Strict, 12 h / 30 min idle, hashed at rest, CSRF token + Origin check. Step-up (password + TOTP, 5 min) for
approval decisions/revocations, agent pause/resume, key mint/revoke, cross-party task overrides and, on a task, instruction, approve, reject, state transition and counter reset; 5 failed step-ups revoke the session.
**A login alone (no step-up) can only:** read everything the dashboard shows, change a task's priority, pause or resume a task, escalate a task to `needs_human`, and log out. Each of those only slows or stops work; none instructs an agent, decides anything or changes a task's state.

**Authorisation.** Agents see only their own tasks, artifacts and approvals (404 otherwise); sender identity from
the key; transition table per role; the responsible agent can never set `verified`. Humans: both see everything;
`verified` only by the originator's party, accepting on behalf only by the responsible party, other cross-party
overrides need step-up; approvals, agent pause and keys only for the own party (also enforced by a DB trigger
for approval decisions). Every message and event carries the sender's `party_id`, so an agent can obey only its
own party's human.

**Approvals.** Bound to SHA-256 of the canonical action JSON, single use, 24 h to consume, re-verified on the
approval page, refused while the task is paused or closed, revocable by the approver party until consumed,
cancelled on task close and on every restore. The approval page shows the payload with every non-ASCII or control
character as a visible `\uXXXX` escape and a warning banner. All agent text is stripped of bidi/zero-width/control
characters before display.

**Resource bounds (a compromised agent).** List/history/messages/inbox/search/detail responses stop at ~1 MiB with
continuation cursors; history omits message bodies unless asked; dashboard timeline 50 events per page; `data` ≤ 16
KiB and depth ≤ 8; approval `action` ≤ 32 KiB and depth ≤ 8; per-agent daily caps; loop guards (clarification
rounds, reply depth, agent streak, per-sender messages per task with human reset); artifacts 2 MiB each, 20 MiB per
task, 256 MiB per agent, 512 MiB total, all checks before the blob is stored; search scans message text of the
newest 500 tasks only, offset ≤ 1000.

**Untrusted content.** Jinja autoescape everywhere, CSP `default-src 'none'` with no scripts; links only for
validated http(s) URLs with `noopener noreferrer`; artifacts only as attachments with `nosniff` and `CSP: sandbox`;
nothing fetched or executed server-side; all SQL parameterised.

**Integrity and recovery.** Append-only, hash-chained audit log (triggers forbid UPDATE/DELETE). Backups
age-encrypted to an off-box key. Restore verifies integrity, foreign keys, the audit chain and that `sqlite_master`
equals the migrations (opened with `trusted_schema=OFF`), revokes all sessions, closes enrollment links, carries
revocations forward from the replaced database and refuses without `--confirm-credentials` when it cannot.

## 5. Security review summary

The design has been through independent security reviews and re-reviews. The resolved finding classes (details
and exploit write-ups are intentionally not published) are:

- pre-auth lockout and denial-of-service bounds (connection limits, header and body deadlines)
- per-key and global memory bounds
- TOTP brute force and step-up freshness
- slowloris and body deadlines
- no key, no body: unauthenticated requests never get their bodies read
- restore re-arming revoked credentials
- cross-party authority (one party's human acting for the other)
- bidi/invisible characters in approvals
- approval consumption while a task is paused
- argon2 work outside the database write lock
- CSRF and Origin checks
- audit-log noise
- artifact quotas
- response size caps
- client guard leakage of untrusted or quarantined text
- forged guard wrapper
- an automated test that enumerates every registered route and checks its authentication

Regression tests live in `tests/test_security.py`, `tests/test_hardening.py`, `tests/test_hardening_gates.py`,
`tests/test_regressions.py` and `tests/e2e/test_server_hardening.py`.

## 6. Limitations and accepted residual risks

These are design facts; stating them is safer than hiding them.

- **Tunnel quota:** a free tunnel plan's request quota can be exhausted by anyone who knows the URL (requests are
  counted at the edge, before they reach the service). Keep the hostname private; see `docs/OPS.md` for recovery.
- **The edge sees credentials:** TLS is terminated at the tunnel edge, which can read keys, cookies, passwords and
  TOTP codes in transit. Approvals need password + TOTP step-up and are payload-bound, keys are revocable, but this
  is a trust decision. End-to-end request signing would be a design change.
- **Local processes** are trusted not to spoof the client address (`X-Forwarded-For`) on loopback; idle local
  sockets can keep the health endpoint failing until the header deadline.
- **Login delay under distributed attack:** roughly 19 concurrent addresses can delay or refuse dashboard login until
  the first successful login after a restart (the reserved slot is in memory). Valid agent keys are unaffected.
- **Enrollment links** are 24 h bearer credentials with no second-channel confirmation; send them over a trusted
  channel.
- **Operator checks:** `bridgectl doctor` verifies the ngrok inspector port is closed; right-most
  `X-Forwarded-For` trust depends on the tunnel always appending the client address. Verify both on your deployment.
- **Service user and backups:** the service user can write the on-box backup directory; the unit for the tunnel can
  reach any loopback service; the ngrok apt key is fetched on first use.
- **`/v1/health` is unauthenticated** by design.
- **The hub cannot force an agent to request an approval before acting;** that rests on the agent's own
  instructions and on the approval-consume record.
- **Prompt injection is contained, not prevented:** the hub labels, escapes and bounds agent content and never lets
  an agent decide approvals, but an agent may still follow injected text within its own permissions. The client
  guard is a regex **tripwire** only: paraphrases are not caught.
- **Global backstops can be exhausted by a distributed attacker:** many addresses can slow *failed* logins; valid
  agent keys and correct dashboard logins are not affected.
- **Single host, single process:** a root compromise of the host defeats everything here; backups are the recovery
  path.
- **Minor:** a mismatched `Content-Length`/`Transfer-Encoding` request gets uvicorn's bare 500 (no data leaked);
  server-authored key names and problem details are printed by the client outside the guard.

## 7. Rotation

Rotate secrets (the operator) (all on the box via `sudo bridgectl …`; see `docs/OPS.md`):

| Secret | Suspected leak → do |
|---|---|
| Agent key | `key rotate --agent <a> --old <keyid>` (new key printed once, old revoked at once) or dashboard → Agents → revoke (step-up). Takes effect on the next request |
| Human password / TOTP | `human reset <login>`: disables the account, revokes its sessions, prints a 24 h re-enrollment link |
| Dashboard session | Log out, or `human disable <login>`; every restore also revokes all sessions |
| Server pepper | Replace `/etc/agent-bridge/credentials/pepper`, restart, then mint new keys for both agents (every existing key stops working) |
| `totp_kek` | Replace it, restart, then `human reset` both humans (sealed TOTP secrets cannot be opened any more) |
| ngrok authtoken / hostname | Rotate the authtoken in the ngrok dashboard, update `/etc/agent-bridge/ngrok.env`; for a leaked hostname see `docs/OPS.md` |
| Backup age key | Generate a new identity off-box, replace `backup-recipients.txt`; old backups stay readable only with the old key |

After any rotation, check the dashboard banners and the audit log for activity you did not cause.
