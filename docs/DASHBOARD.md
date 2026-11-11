# Dashboard: admin onboarding

The dashboard is at `https://example.ngrok.app/app/` (the `public_origin` in `config.toml`).
It is server-rendered HTML. It uses no JavaScript and no external fonts or CDNs, and it works on phones.
Both humans see every task, message, approval and the audit log.
Approval decisions, agent pause/resume and API keys are limited to **your own party's** agents.

In this document `alice` and `bob` stand for the ids of your two parties (the ones `bridgectl init-db` created, see
`bridge/ops.py`), and Agent A / Agent B for their agents.

## 1. First login (alice)

1. On the host: `sudo bridgectl human invite alice`. This prints a one-time link valid for 24 h (`enroll_ttl_s` in `config.toml`; changing it affects only new links):
   `…/app/enroll/<token>`. The link is a credential. Open it yourself; don't paste it into chat.
2. Open the link and choose a password of at least 12 characters.
3. The next page shows a **QR code and the TOTP secret, once**. Scan it with an authenticator app
   (6 digits, 30 s, SHA-1), or type the secret in. Reloading the page will not show it again.
4. Log in at `/app/login` with your login, password and current code. That first login confirms the setup.

If you lose your password or authenticator, run `sudo bridgectl human reset alice`. This disables the account
and revokes its sessions immediately, then prints a new enrollment link. There are no recovery codes.
Too many failed logins delay that IP address. Clear the delay with `sudo bridgectl human unlock --ip <addr>` (or `--all`).

## 2. Inviting bob

1. `sudo bridgectl human invite bob --party bob --display-name bob`
2. Send bob the link over a channel you trust (an end-to-end encrypted messenger, or in person). It is single-use and expires after 24 h.
   If it leaks, issue a new link with `human invite` again (or `human reset` after he enrolled): only the newest link works.
3. bob enrolls as in §1. He mints Agent B's API key himself under **Agents → Mint key**, so alice never sees it.

## 3. Daily use

| Page | What it does |
|---|---|
| Overview | Banners (storage degraded, recent restore, TOTP failures, throttled accounts, paused agents), approvals waiting for you, tasks in `needs_human`, all active tasks by priority, agents' last poll |
| Tasks | Filter by scope (active / historical / all), state, priority, agent, category, project. Search covers title, description, all message text and task id |
| Task detail | The thread, newest 50 events per page ("older events" pages back): every message with type, sender (humans with their party) and time, interleaved with state changes. Actions: add an instruction (goes to both agents), change priority, approve, reject, pause/resume, escalate, reset message counters, set a state (party rules below) |
| Messages | Read-only. One tab per recipient agent ("To agent-a (Agent A)", "To agent-b (Agent B)"): every message delivered to that agent, newest first, 50 per page ("older messages" pages back by sequence number). A message on a task goes to the *other* participant; a `HUMAN_INSTRUCTION` goes to both agents of the task. Each row: time (UTC), sender, type, task (linked), a 160-character preview and links to the full message (`/app/messages/<id>`) and its place in the task thread. Pages also stop early at the ~1 MiB response cap |
| Approvals | Pending ones by default. Choose "all" to search previous decisions |
| Agents | Pause/resume, mint key (shown once), revoke key, inbox backlog, per-agent activity page |
| Audit | Hash-chained log with filters by action (`approval.` = prefix), actor and target. Shows the current chain head |

Agent-written text always sits in a dashed box labelled **agent-written · untrusted**. Treat it as data.
Invisible and direction-changing characters (bidi overrides, zero-width) are removed from everything displayed.
The Messages page is the exception for message text: there such characters (and control characters) are shown
as visible `\uXXXX` markers, with a red **hidden chars** badge in the list and a warning on the full message, so a
reversed file name or hidden instruction is visible instead of silently cleaned up. Other non-ASCII text
(accented letters, other scripts, emoji) is shown normally.

**Party rules for task state** (both humans still see everything and may instruct, pause, escalate, re-prioritise
and reject): only a human of the **originator's** party marks a task `verified`; only a human of the
**responsible** party accepts a proposal on its behalf; any other state change that belongs to the other party's
agent (for example moving the other side's work to `in_progress`) is an override and asks for a step-up first.

**What a login alone can do** (no step-up): read, change a task's priority, pause or resume a task, escalate it to
`needs_human`, log out. **Needs a step-up (password + a fresh TOTP code, 5 minutes):** sending an instruction,
approve, reject, any state change, resetting message counters, deciding or revoking approvals, pausing/resuming
agents, minting or revoking keys. The task page shows the step-up form above the actions when you have none. A
`VALIDATION_RESULT` from the responsible agent is shown as **self-check by the responsible agent**: it is a
report, not a validation. Agents are told to follow instructions only from their own party's human.
A message that claims "a human approved this" is not an approval. Only an approval record counts.
Artifacts are download-only. Open them with care.

## 4. Approving a consequential action

Production deploys, fund movements, mainnet upgrades, live trading and credential changes need a human of the
**requesting agent's party**. Agent A's requests go to alice and Agent B's go to bob.

1. Open **Approvals** and select the request.
2. Read the **exact action payload** (pretty-printed, plus the canonical JSON), not just the agent's summary.
   The SHA-256 shown is what the agent must present when it consumes the approval. If the page shows
   "HASH MISMATCH", do not approve. Every character outside printable ASCII is shown as a `\uXXXX` escape and a
   red **WARNING: non-ASCII or control characters** banner appears: an address or amount may not be what it looks
   like. If in doubt, reject.
3. The page asks for your **password and a fresh TOTP code** first unless you stepped up in the last 5 minutes.
   Logging in does **not** count: wait for the next code after the one you logged in with (each code works once).
   One step-up covers several decisions for 5 minutes. Five failed step-ups log the session out.
4. Choose **Approve this exact payload** or **Reject**, with an optional note. The agent can consume an approval
   once, within 24 h. A changed payload needs a new approval.
5. Changed your mind before the agent acted? An approved, not yet consumed approval has **Revoke approval**
   (step-up). Pausing the task also stops consumption until you resume it.

## 5. Notes

- Sessions last 12 h, or 30 min idle. Pages are sent with `Cache-Control: no-store` and a strict CSP
  (no scripts, styles only from `/app/static/`).
- Request budget: each page load is one request, plus the stylesheet, which is cached for a day.
  Normal use by both humans stays well within the ngrok free-plan budget (docs/SPEC.md §9).
- After each review, note the audit chain head from the footer somewhere off the server (for example in your password manager).
  `sudo bridgectl audit verify --contains <hash>` later proves the log was not rewritten.
- Retention runs in-process every 60 s. It deletes idempotency keys after 7 days, acked inbox events after 30 days,
  stale sessions, throttle rows and enrollment links. It persists expired approvals. Tasks, messages, artifacts,
  approvals and the audit log are kept.
