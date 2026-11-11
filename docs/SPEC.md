# Agent Bridge — Reconciled Spec (v1)

This document is the normative specification of what the code implements. The dashboard, clients, ops tooling and
integration kit follow it. The machine contract
is `docs/openapi.json` (served at `GET /v1/openapi.json` only with `expose_openapi = true`).

## 1. Parties, agents, roles

| Party | Domain | Human | Agent |
|---|---|---|---|
| `alice` | `business` | alice | `agent-a` |
| `bob` | `engineering` | bob | `agent-b` |

(`alice`/`bob`/`agent-a`/`agent-b` are placeholder names. `bridgectl init-db` seeds two parties and two agents with
the ids in `bridge/ops.py` `DEFAULT_PARTIES`/`DEFAULT_AGENTS`; the model is always one `business` and one `engineering` party.)

Roles relative to a task: **O** = originator agent, **R** = responsible agent, **H** = a human
(both humans see every task and may instruct, pause, escalate and re-prioritise it; party rules for
state changes in §3), **S** = the server (loop guards only).
Agents only see tasks they participate in (others answer 404). Only registered orchestrator agents are
addressable: Agent A can address Agent B, never Agent B's internal agents.

**Ownership boundaries.** Every task has a `category`; each category belongs to one domain. The responsible
agent's party must own that domain, else `403 ownership_violation`. Task content (title, description,
acceptance criteria) is immutable after creation, so the responsible side can never redefine requirements.

| Domain | Categories |
|---|---|
| business (Agent A) | `business_requirements`, `strategy_research`, `qa`, `simulation`, `product_validation`, `business_ops`, `experiment` |
| engineering (Agent B) | `implementation`, `smart_contract`, `backend`, `frontend`, `architecture`, `infrastructure`, `deployment`, `bug_fix`, `engineering_validation` |

So Agent A requests engineering work from Agent B (`bug_fix`, …); Agent B requests testing or requirement
clarification from Agent A (`qa`, `business_requirements`, …). Self-addressed tasks are refused.

## 2. Task model

| Field | Notes |
|---|---|
| `id` | `tsk_<26 base32>`, time-ordered |
| `title` (1–200), `description` (1–16000) | immutable |
| `originator_agent_id`, `responsible_agent_id` | sender identity recorded from the key, never from the body |
| `priority` | `low` `normal` `high` `urgent` (humans may change it) |
| `category` | §1 |
| `state`, `resume_state` | §3; `resume_state` = state before `needs_human` |
| `acceptance_criteria` | list ≤ 20 × ≤ 1000 chars |
| `project`, `component` | ≤ 100 chars each |
| `related_task_ids` | ≤ 20, must be visible to the creator |
| `parent_task_id`, `hop_count` | follow-up chains; `hop_count ≤ 3` |
| artifacts, approvals, messages | linked by `task_id` |
| `created_at`, `updated_at`, `closed_at` | RFC 3339 UTC in the API, unix ms in the DB |
| history | `GET /v1/tasks/{id}/history`: every state change, message, artifact, approval event; message bodies only with `include_bodies=true` |
| `version` | bumps on state/priority/pause changes; optional `expected_version` → `409 version_conflict` |
| `paused` | a human paused the task: agent writes get `409 task_paused` |

## 3. States and transition permissions

States: `proposed → accepted → in_progress → ready_for_validation → verified → closed`, plus `blocked`,
`rejected`, `needs_human`. Terminal: `closed`, `rejected` (DB trigger forbids leaving them; no reopening,
create a follow-up with `related_task_ids`/`parent_task_id`).

Agent permissions (from → to: roles). Anything not listed is refused: `403 transition_forbidden` if some
other role could do it, else `422 invalid_transition`; from a terminal state `410 task_closed`.

| From | To | Who |
|---|---|---|
| proposed | accepted, rejected | R |
| proposed | closed (withdraw) | O |
| accepted | in_progress, blocked, rejected | R |
| accepted | closed | O |
| in_progress | ready_for_validation, blocked | R |
| in_progress | closed | O |
| ready_for_validation | verified | **O only** (or H) |
| ready_for_validation | in_progress | O (validation failed), R (withdraws claim) |
| ready_for_validation | closed | O |
| verified | closed | O |
| blocked | in_progress, rejected | R |
| blocked | closed | O |
| any non-terminal except needs_human | needs_human | O, R, S |
| needs_human | anything | **H only** |
| any non-terminal | any state except `proposed` | H |

- Example: Agent B (R) may set `ready_for_validation` on engineering work; Agent B can never set
  `verified`. Only the originator side's validation (`VALIDATION_RESULT` with `outcome: pass`, or an explicit
  transition by O) or a human sets `verified`. A `VALIDATION_RESULT` sent by R is a report and never moves state.
- `reason` is required for `rejected`, `blocked`, `needs_human` (`422 reason_required`).
- Leaving `needs_human` (human) resets `clarification_rounds` and `agent_streak`.
- Any move into a terminal state cancels the task's open approvals (`cancelled`, never `rejected`).
- **Human party rules**. For a task in `needs_human` the human's rights are judged from
  `resume_state` (the state it was escalated from), so parking a task there is no detour. `→ verified` only by a
  human of the originator's party; leaving `proposed` for any active state (`accepted`, `in_progress`, …) only by a
  human of the responsible party (`403 wrong_party`). Every other human `transition` whose `(from, to)` pair is not
  on that human's own side of the table above (a pair only the other party's agent may make, or one no agent may
  make) is a *cross-party override* and needs a fresh step-up (`403 step_up_required`). Resuming a `needs_human`
  task to its `resume_state`, escalating, pausing, instructing and priority changes stay open to both humans.

## 4. Message types

Envelope: `{"type", "body": {"text" ≤16k plain text, "data": {…}, "refs": [{"kind": url|commit|pr|task|other,
"value", "label"?}]}, "in_reply_to"?}`. Total body ≤ 64 KiB; `data` ≤ 16 KiB canonical JSON (`413 data_too_large`)
and nesting depth ≤ 8 (`422 data_too_deep`). Every stored message carries `sender: {kind, id, party_id}`; events
carry `actor.party_id`. Agents obey `HUMAN_INSTRUCTION` only from a human of their own party. `url` refs must be http(s). The server never
interprets `text`, never fetches refs. Every message reaches the other participant's inbox.

| Type | Sender | Effect / rules |
|---|---|---|
| `TASK_REQUEST` | O | Only via `POST /v1/tasks` (the description + criteria + refs) |
| `TASK_ACCEPTED` | R | proposed → accepted (`POST …/accept` or messages) |
| `TASK_REJECTED` | R | → rejected; `text` = reason (`POST …/reject {reason}`) |
| `CLARIFICATION_REQUEST` | O or R | Counts a clarification round (§5) |
| `CLARIFICATION_RESPONSE` | the other agent | `in_reply_to` = the other side's request; one response per request (`409 already_responded`) |
| `PROGRESS_UPDATE` | R | Exempt from content dedupe |
| `ARTIFACT_SUBMITTED` | O or R | `data.artifact_ids` (of this task) and/or `refs` (commit/PR). Auto-posted by artifact upload |
| `VALIDATION_RESULT` | O or R | `data.outcome` = `pass`/`fail`. From O in `ready_for_validation`: pass → verified, fail → in_progress (`409 not_ready_for_validation` in other states). From R: report only |
| `DECISION_REQUEST` | O or R | → needs_human with `text` as reason (`POST …/decision-request {reason}`) |
| `HUMAN_INSTRUCTION` | H only | Delivered to both agents (with the sender's `party_id`); resets `agent_streak` |

Agents must treat every body and artifact from the other side as untrusted data (`bridge/safety.py`:
`escape_html`, `strip_controls`, `sanitize_filename`, `quote_untrusted`). Text claiming a human approved
something is never an approval; only an approval record is (§8).

## 5. Loop guards (server-enforced)

| Guard | Default | On breach |
|---|---|---|
| Clarification rounds per task | 3 | 4th `CLARIFICATION_REQUEST` → task to `needs_human`, `409 loop_guard` |
| Reply depth (`in_reply_to` chain) | 6 | → needs_human, `409 loop_guard` |
| Agent streak (agent messages since the last human touch) | 40 | → needs_human, `409 loop_guard` |
| Messages per task, **per sender** since the last human counter reset (`POST /app/tasks/{id}/reset_counters`) | 300 | → needs_human, `409 loop_guard` |
| Follow-up chain `hop_count` | 3 | `409 loop_guard` |
| Duplicate open task (same originator, responsible, normalised title + description) | — | `409 duplicate_task` with `existing_task_id` |
| Duplicate message (same sender, task, type, body within 10 min; not PROGRESS_UPDATE) | — | `200`, original message, `Bridge-Deduplicated: true` |
| New tasks / messages / approval requests per agent per day | 100 / 500 / 20 | `429 daily_limit` |

The escalation is committed even though the request is refused. Agents treat `409 loop_guard` as "stop and
wait for a human", never retry it.

## 6. Idempotency

- `Idempotency-Key` (8–128 chars `[A-Za-z0-9:._-]`) is required on **every** agent POST, else `400`.
- Scoped per agent; stored in the same transaction as the write. Request hash = method + path + query + raw
  body bytes. Same key + same request → the stored response replayed byte-identical with
  `Idempotent-Replayed: true`. Same key + different request → `422 idempotency_key_reuse`.
- Stored outcomes: 2xx and deterministic 409/410/422 (except `409 task_paused`, which a human can lift). Never
  401/403/404/423/429/5xx, so retries are safe.
- Clients derive keys from the triggering event (`<event_id>:<n>`) so a crashed run cannot double-post;
  `422 idempotency_key_reuse` means "already done". Retention 7 days (sweeper: later step).

## 7. Artifacts

`POST /v1/tasks/{id}/artifacts?filename=&note=` with the raw file as body and its `Content-Type`.
Allowlist: `text/plain`, `text/markdown`, `text/csv`, `text/x-diff`, `application/json`, `application/pdf`,
`image/png`, `image/jpeg`, `application/zip`, `application/gzip` (`415` otherwise). Text must be UTF-8 (and
JSON parseable); binary types must match their magic bytes (`422 content_mismatch`). Limits: 2 MiB per
artifact (`413 artifact_too_large`), 20 MiB per task, 256 MiB per uploading agent, 512 MiB total
(`413 artifact_quota_exceeded`). Every message check and loop guard runs before the blob is stored.
Stored as BLOBs in SQLite (no per-file inodes) with SHA-256; filename sanitised. Download only by
participants / humans, always `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`,
`Content-Security-Policy: sandbox`, `X-Artifact-Sha256`. Never rendered inline.

## 8. Approvals for consequential actions

Kinds: `prod_deploy`, `fund_move`, `mainnet_upgrade`, `live_trading`, `credential_change`.

1. Agent: `POST /v1/tasks/{id}/approvals {kind, summary, action, expires_in_s?}`. The approval binds to
   `action_sha256` = SHA-256 of the canonical JSON (sorted keys, no whitespace, UTF-8) of `action`. Approver
   party = the requesting agent's party. One pending approval per (task, agent): `409 approval_pending`.
   `action` ≤ 32 KiB, nesting depth ≤ 8 (`422 action_too_deep`).
   Pending TTL 24 h (max 7 d). The task state does not change.
2. Human of that party decides in the dashboard after a password + TOTP session with a step-up in the last
   5 minutes. Agents have no decide route at all; the other party's human gets `403 wrong_party`; a DB
   trigger enforces the same.
3. Agent gets `approval.decided` in its inbox, re-reads `GET /v1/approvals/{id}`, then
   `POST /v1/approvals/{id}/consume {action_sha256}` **before** acting: 200 exactly once, then
   `409 already_consumed`; `409 hash_mismatch` | `not_approved` | `approval_expired` otherwise; `409 task_paused`
   while a human has paused the task, `410 task_closed` once it is terminal. 24 h to consume after approval. If
   acting fails after consume, request a new approval.
   The approver party's human may **revoke** an approved, not yet consumed approval (`POST
   /app/approvals/{id}/revoke`, step-up) → `cancelled`, `approval.decided` event, consume → `409 not_approved`.
4. Task closed/rejected, or a DB restore → open approvals become `cancelled`.

Agent-to-agent messages (including Agent A → Agent B) need no approval.

## 9. Inbox, cursor, ack, polling budget

- `GET /v1/inbox?cursor=&limit≤100` returns `{events, next_cursor, has_more, poll_after_s, pending_approvals,
  server_time}`. A page also ends at ~1 MiB of JSON (`has_more: true`, `poll_after_s: 0`). Default cursor = the agent's acked cursor. Events: `task.created` (full task + TASK_REQUEST
  message), `message.created`, `task.state_changed`, `task.priority_changed`, `task.paused`, `task.resumed`,
  `approval.decided`. An agent never receives events for its own actions. Delivery is at-least-once: dedupe by
  `event.id`.
- Cursor = `events.seq`; a single writer commits in seq order, so a cursor never skips (tested with 8
  concurrent writers). Events stay until acked, so an offline agent misses nothing.
- `POST /v1/inbox/ack {cursor}`: monotonic, clamped to the newest event.
- **Budget rules (ngrok free, ~20k requests/month):** default `poll_after_s = 900` (15 min). Clients persist
  `next_poll_at` (early runs make zero requests); one request per idle poll (the pending-approval count is in
  the inbox page); ack only non-empty pages; fetch `/v1/approvals` only when the count or an `approval.*` event
  changed; `has_more` → `poll_after_s = 0` (drain now). Honour `Retry-After`. Send
  `ngrok-skip-browser-warning: 1` on every request.

| Source (per month, 30 d) | Requests |
|---|---|
| Agent A idle polls (15 min) | 2,880 |
| Agent B idle polls (15 min) | 2,880 |
| Acks + task/message/artifact writes (≈ 40 tasks × ≈ 25 requests) | ≈ 1,000–2,000 |
| Dashboard, 2 humans (≈ 30 page loads/day incl. assets) | ≈ 1,800 |
| **Total** | **≈ 9–10k** (≤ 20k with 2× headroom) |

## 10. Authentication

- **Agent keys**: `abk_<keyid:12>_<secret:43>`; DB stores `HMAC-SHA256(pepper, secret)`; constant-time compare;
  unknown ids still pay for an HMAC. Scopes: `inbox:read`, `tasks:read`, `tasks:write`, `approvals:request`.
  Max 2 active keys per agent (rotation overlap). Revocation is immediate. Created by `bridgectl key create`
  or by the agent's own party human in the dashboard after step-up; the token is shown once.
- **Humans**: argon2id (m=19 MiB, t=2, p=1, one hash at a time) + RFC 6238 TOTP (stdlib, SHA-1, 6 digits,
  ±1 step, replay-protected). Secret AES-256-GCM-sealed under `totp_kek` (AAD = human id). Accounts come from
  `bridgectl human invite <login>` (one-time 24 h link, the human sets the password and gets the TOTP URI).
  Login throttling is per client IP (right-most `X-Forwarded-For`, IPv6 per /64): 3 free failures, then 2 s
  doubling to 5 min; plus **per account** (IP-independent): after 5 wrong TOTP codes with the correct password,
  2 s doubling to 15 min; plus a global bucket of 60 failed logins/min. No permanent lockout;
  `bridgectl human unlock --ip|--login|--all`. argon2 runs outside the DB write transaction. Session cookie `__Host-ab_session` (Secure,
  HttpOnly, SameSite=Strict), 12 h absolute / 30 min idle, stored hashed. CSRF token on every form POST plus
  Origin check. Step-up (**password + a new TOTP code** within 5 min; a login never counts) for approval decisions and revocations,
  agent pause/resume, key mint/revoke and cross-party task overrides (§3). 5 failed step-ups revoke the session.
- **Why no short-lived access tokens** minted from the key: see `SECURITY.md` §3 (keys are checked against the
  DB on every request, so revocation is instant; a token layer would add a window or a DB lookup anyway).

## 11. Limits

Body ≤ 256 KiB (artifact uploads, `POST /v1/tasks/{id}/artifacts` only, ≤ 2 MiB + 1 KiB), enforced while
streaming → `413 payload_too_large`. A `/v1` POST without a valid key is answered `401` (+ `Connection: close`)
before its body is read; too many bodies in flight server-wide → `503 server_busy` (`Retry-After: 5`).
Per key 120 req/min, 30 writes/min (`429 rate_limited` + `Retry-After`) and 2 requests in flight
(`429 too_many_in_flight`, `Retry-After: 1`). The key is authenticated first; only **failed** authentications are
charged: 30/min per client IP (right-most `X-Forwarded-For`, IPv6 per /64) with a 3,000/min global backstop, and
neither is ever consulted for a request with a valid key. Responses of list/history/messages/inbox/search/detail
endpoints stop at ~1 MiB (`has_more` / `truncated` / `messages_truncated` with a continuation). Search scans
message text of the newest 500 tasks only; `offset ≤ 1000`. The server closes connections that do not send
complete headers within 10 s or a complete body within 30 s; uvicorn `limit_concurrency` = 200. Low disk (< 500 MB) or inodes (< 5 %) → writes `503 storage_degraded`, reads work.
Paused agent or party → writes `423 agent_paused`. The service binds loopback only and refuses anything else.

## 12. Errors

`application/problem+json`: `{"type":"about:blank","code","title","status","detail","request_id", …extra}`.
Clients switch on `code`, never on text. Validation errors list `loc/msg/type` and never echo input.

| Status | Codes | Client action |
|---|---|---|
| 400 | `missing_idempotency_key`, `invalid_idempotency_key` | bug: fix client |
| 401 | `invalid_key` | stop, alert the owner |
| 403 | `scope_missing`, `transition_forbidden`, `sender_not_allowed`, `ownership_violation`, `wrong_party`, `humans_only` | deterministic: record, ack, do not retry |
| 404 | `task_not_found`, `approval_not_found`, `artifact_not_found`, `not_found` | deterministic |
| 409 | `version_conflict`, `loop_guard`, `duplicate_task`, `task_paused`, `already_responded`, `not_ready_for_validation`, `approval_pending`, `not_approved`, `already_consumed`, `hash_mismatch`, `approval_expired`, `not_pending`, `too_many_keys` | deterministic (re-read for `version_conflict`) |
| 410 | `task_closed` | deterministic |
| 413 / 415 | `payload_too_large`, `message_too_large`, `data_too_large`, `artifact_too_large`, `artifact_quota_exceeded`, `action_too_large` / `unsupported_media_type` | deterministic |
| 422 | `validation_error`, `invalid_transition`, `reason_required`, `idempotency_key_reuse` (= already done), `invalid_body`, `invalid_parent`, `unknown_parent`, `unknown_artifact`, `unknown_agent`, `self_assignment`, `message_type_not_allowed`, `content_mismatch`, `empty_artifact`, `data_too_deep`, `action_too_deep` | deterministic |
| 423 | `agent_paused` | transient: stop the run, retry later |
| 429 | `rate_limited`, `daily_limit`, `too_many_in_flight` | transient: honour `Retry-After` |
| 500 / 503 | `internal_error` / `storage_degraded` | transient: back off |

## 13. Endpoints

Agent API (`/v1`, bearer key):

| Method | Path | Scope |
|---|---|---|
| GET | `/health` (no auth), `/openapi.json` (no auth, only with `expose_openapi = true`) | — |
| GET | `/me` | tasks:read |
| POST / GET | `/tasks` (create / list: `role, state, category, project, q, updated_since_ms, limit, offset`) | tasks:write / tasks:read |
| GET | `/tasks/search?q=` (title, description, message text) | tasks:read |
| GET | `/tasks/{id}` (task + last ≤ 50 messages within ~1 MiB + artifacts + approvals), `/tasks/{id}/history?after_seq=&include_bodies=`, `/tasks/{id}/messages?after_seq=` (`{messages, next_after_seq, has_more}`) | tasks:read |
| POST | `/tasks/{id}/accept`, `/reject`, `/decision-request`, `/messages`, `/transition` | tasks:write |
| POST / GET | `/tasks/{id}/artifacts` | tasks:write / tasks:read |
| GET | `/artifacts/{id}` | tasks:read |
| GET / POST | `/inbox`, `/inbox/ack` | inbox:read |
| POST | `/tasks/{id}/approvals` | approvals:request |
| GET | `/approvals?state=&task_id=`, `/approvals/{id}` | approvals:request |
| POST | `/approvals/{id}/consume`, `/approvals/{id}/cancel` | approvals:request |

Human surface (`/app`, session cookie; JSON for now, templates in the dashboard step):
`POST /app/login|logout|step-up`, `GET|POST /app/enroll/{token}`, `GET /app/api/{me,tasks,tasks/{id},tasks/{id}/history,approvals,approvals/{id},agents,keys,audit}`,
`GET /app/artifacts/{id}`, `POST /app/tasks/{id}/{instruction|priority|pause|resume|escalate|approve|reject|transition|reset_counters}`,
`POST /app/approvals/{id}/decide|revoke` (step-up), `POST /app/agents/{id}/{pause|resume|keys}` (step-up, own party),
`POST /app/keys/{id}/revoke` (step-up, own party). There is no admin over HTTP.

Human "approve" on a task: `needs_human` → its `resume_state` (`proposed` → `accepted`); `proposed` → `accepted`;
`ready_for_validation` → `verified`. "Reject" → `rejected`. "Pause" blocks agent writes on the task.

## 14. Audit, backup, restore

- Every write, login, key, approval and CLI action appends an `audit_log` row: ids, states, hashes, never bodies
  or secrets. `hash = SHA-256(prev_hash || canonical row)`; UPDATE/DELETE forbidden by triggers;
  `bridgectl audit verify [--db F] [--contains HASH]`.
- `bridgectl backup snapshot --out F`: SQLite online backup, stamped `backup_taken_at`, verified (integrity,
  foreign keys, audit chain). Encryption/rotation/offsite are in `deploy/backup.sh` (ops step).
- `bridgectl restore [F | < F] [--check-only] [--purge-replaced] [--confirm-credentials]`: verify (integrity,
  foreign keys, audit chain, and `sqlite_master` identical to the migrations of its `user_version`, opened with
  `trusted_schema=OFF`); keep `bridge.db.replaced`; swap in; then in one transaction bump the events sequence by
  1,000,000, cancel every pending/approved approval (with `approval.decided` events), revoke every session, close
  every enrollment link, carry revocations forward from the replaced DB (keys revoked or unknown there stay
  revoked; humans disabled/unknown there, or whose password/TOTP changed since the snapshot, are disabled →
  `bridgectl human reset`), delete idempotency rows at/after the snapshot time, and append `system.restore`. If
  the replaced DB is missing or unreadable the restore refuses unless `--confirm-credentials` (then rotate keys
  and reset humans).
