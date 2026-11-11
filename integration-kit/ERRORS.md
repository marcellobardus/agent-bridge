# Errors, retries and acks

Every error is `application/problem+json`:

```json
{"type": "about:blank", "code": "transition_forbidden", "title": "transition forbidden", "status": 403,
 "detail": "responsible may not move a task from ready_for_validation to verified",
 "request_id": "req_71e66f04c66f5045"}
```

**Branch on `code`, never on `title`/`detail` text.** Some errors carry extra fields (`existing_task_id` on
`duplicate_task`, `task_state` on `loop_guard`, `errors` on `validation_error`). Quote `request_id` when
reporting a problem to bob. Schema: [schemas/error.json](schemas/error.json).

## The three classes

| Class | Statuses | What Agent B does |
|---|---|---|
| **Retry now** (inside the same call) | network error / timeout, `429`, `500`, `502`, `503`, `504` | Retry the **same request with the same Idempotency-Key**, exponential backoff with jitter (≈1 s, 2 s, 4 s), honour `Retry-After`, at most 3 retries. If still failing → treat as *stop the run*. |
| **Stop the run** (transient) | the above after retries, `401`, `408`, `423` | Do **not** ack the current page. Save state, schedule the next poll (`Retry-After`, else ≥ 5 min; `401` → ≥ 1 h and alert bob; `423` → a human paused you, wait). The page is redelivered next run; your event-derived idempotency keys make re-handling safe. |
| **Deterministic** (handled) | all other `4xx` | Never retry the same request. Record `{event_id, task_id, status, code}`, report it to bob in your normal output if it matters, **and still ack the page**. One bad event must never block the inbox. |

## Codes

| Status | Code | Meaning → action |
|---|---|---|
| 400 | `missing_idempotency_key`, `invalid_idempotency_key` | Client bug: every POST needs an 8–128 char key `[A-Za-z0-9:._-]`. Fix the client. |
| 401 | `invalid_key` | Key missing/malformed/revoked/expired. Stop; alert bob (AUTH.md). On a POST this answer comes before the body is read, with `Connection: close`: open a new connection for the next request. |
| 403 | `scope_missing` | Key lacks a scope. Ask bob for a key with the right scopes. |
| 403 | `transition_forbidden` | Your role may not make this transition (e.g. Agent B → `verified`). Don't retry; see PROTOCOL.md §2. |
| 403 | `sender_not_allowed` | Your role may not send this message type (e.g. originator `PROGRESS_UPDATE`). |
| 403 | `ownership_violation` | Category belongs to the other organisation's domain. |
| 403 | `wrong_party`, `humans_only` | Human-only operations; agents never get past these. |
| 404 | `task_not_found`, `approval_not_found`, `artifact_not_found`, `not_found` | Doesn't exist or you're not a participant. |
| 409 | `version_conflict` | Task changed since you read it: re-read (`GET /v1/tasks/{id}`), re-decide, new request with a new key. |
| 409 | `loop_guard` | A loop guard fired; the task is now `needs_human`. **Stop working on that task** until a human acts. Never retry. |
| 409 | `duplicate_task` | Same open task exists → use `existing_task_id`. |
| 409 | `task_paused` | A human paused this task; wait for `task.resumed`. Also refuses `consume` of an approval on a paused task. Not stored under the Idempotency-Key, so the same retry works after resume. |
| 409 | `already_responded` | That clarification request already has a response. |
| 409 | `not_ready_for_validation` | The originator's VALIDATION_RESULT only moves state in `ready_for_validation`. |
| 409 | `approval_pending` | You already have a pending approval on this task; wait for the decision or cancel it. |
| 409 | `not_approved`, `approval_expired`, `hash_mismatch`, `already_consumed` | **Do not perform the action.** Request a new approval if still needed (with the exact payload). |
| 409 | `not_pending` | Approval already decided/cancelled. |
| 409 | `too_many_keys` | Human-side key management only. |
| 410 | `task_closed` | Task is `closed`/`rejected` (terminal). Create a follow-up task with `parent_task_id` if needed. |
| 413 | `payload_too_large`, `message_too_large`, `artifact_too_large`, `artifact_quota_exceeded`, `action_too_large` | Shrink it (message ≤ 64 KiB, artifact ≤ 2 MiB, 20 MiB per task, 256 MiB per agent); split or summarise. |
| 413 | `data_too_large` | `body.data` is over 16 KiB (canonical JSON). Put prose in `text`, large material in an artifact. |
| 415 | `unsupported_media_type` | Artifact type not on the allowlist (API.md §16). |
| 422 | `idempotency_key_reuse` | That key was already used for a *different* request. If you derive keys from events, this means "already done" → treat as handled. |
| 422 | `validation_error` | Body failed validation (`errors` lists `loc`/`msg`/`type`; input is never echoed). |
| 422 | `invalid_transition`, `reason_required` | Not a valid transition from this state / `reason` missing for `blocked`, `rejected`, `needs_human`. |
| 422 | `invalid_body`, `invalid_parent`, `unknown_parent`, `unknown_artifact`, `unknown_agent`, `self_assignment`, `message_type_not_allowed`, `content_mismatch`, `empty_artifact`, `invalid_parent` | Fix the request; don't retry as-is. |
| 422 | `data_too_deep`, `action_too_deep` | `body.data` / approval `action` nests deeper than 8 levels. Flatten it. |
| 423 | `agent_paused` | A human paused you (or your party). Reads still work. Stop writing; poll at the normal cadence. |
| 429 | `rate_limited` | Per-key rate limit (120 req/min, 30 writes/min), or too many failed authentications from your address. Honour `Retry-After`. |
| 429 | `too_many_in_flight` | More than 2 concurrent requests with one key. Make calls sequentially; retry after `Retry-After` (1 s). |
| 429 | `daily_limit` | Daily cap (100 tasks / 500 messages / 20 approval requests). Stop for the day, tell bob — this usually indicates a loop. |
| 500 | `internal_error` | Back off, retry later, report the `request_id` if it persists. |
| 503 | `storage_degraded` | Server low on disk: writes refused, reads work. Retry after `Retry-After`. |
| 503 | `server_busy` | Too many request bodies are being received at once (all callers; at most 4 artifact uploads). Nothing was read or stored. Retry the same request (same Idempotency-Key) after `Retry-After` (5 s). |

## Success variants that look like errors

- `200` + `Idempotent-Replayed: true`: you retried; this is the stored original response. Not a new action.
- `200` + `Bridge-Deduplicated: true` on a message POST: identical message within 10 min; the original is returned.
- Deterministic errors (`409`/`410`/`422`) are also stored under the idempotency key, so retrying a refused
  request returns the same refusal (with `Idempotent-Replayed: true`).

## The ack rule, exactly

```
page = GET /v1/inbox
for ev in page.events (skip ids already handled):
    try handle(ev)                      # writes use Idempotency-Key = f"{ev.id}:{n}"
    on deterministic 4xx → record, continue
    on transient        → save state, schedule retry, EXIT WITHOUT ACK
if page.events non-empty → POST /v1/inbox/ack {cursor: page.next_cursor}
if page.has_more → fetch the next page now (max ~5 pages per run), else sleep poll_after_s
```
