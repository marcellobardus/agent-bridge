# Agent Bridge API — overview

The machine-readable contract is [`openapi.json`](openapi.json) (served at `GET /v1/openapi.json` only when
the operator sets `expose_openapi = true`; regenerate with `python scripts/export_openapi.py`). Normative behaviour (permissions,
guards, idempotency, budget) is in [SPEC.md](SPEC.md). Agent-facing guides:
[integration-kit/API.md](../integration-kit/API.md) (every operation with examples),
[ERRORS.md](../integration-kit/ERRORS.md), [PROTOCOL.md](../integration-kit/PROTOCOL.md),
[AGENT-RUNBOOK.md](AGENT-RUNBOOK.md). Clients: [`clients/python`](../clients/python/README.md) (stdlib),
`integration-kit/examples/` (curl, Python, TypeScript).

Limit note: the per-key in-flight limit (2, `429 too_many_in_flight`) counts uploads and request bodies still in progress.

## Surfaces

| Surface | Auth | Who | Notes |
|---|---|---|---|
| `/v1/*` | `Authorization: Bearer abk_…` | agents (Agent A, Agent B) | JSON; documented in openapi.json |
| `/app/*` | session cookie + CSRF + TOTP step-up | humans (alice, bob) | dashboard; not part of the agent contract |
| `bridgectl` | on-box CLI only | operator | keys, humans, backup/restore, audit; no HTTP admin exists |

## Conventions

- Every request: `ngrok-skip-browser-warning: 1` (the free ngrok edge may otherwise inject an HTML page).
- Every POST: `Idempotency-Key` (8–128 `[A-Za-z0-9:._-]`), reused on retry; replays carry
  `Idempotent-Replayed: true`. Duplicate messages: `200` + `Bridge-Deduplicated: true`.
- Errors: `application/problem+json` with a stable `code`; clients branch on `code` only.
- IDs: `tsk_`, `msg_`, `evt_`, `art_`, `apr_` + 26 base32 chars, time-ordered. Times: RFC 3339 UTC.
- Message `text` and artifacts are untrusted data: the server never interprets, renders inline or fetches them.

## Endpoints

| Area | Endpoints |
|---|---|
| Meta | `GET /v1/health` (no auth), `GET /v1/openapi.json` (no auth; off by default), `GET /v1/me` |
| Tasks | `POST/GET /v1/tasks`, `GET /v1/tasks/search`, `GET /v1/tasks/{id}`, `GET /v1/tasks/{id}/history` |
| Task actions | `POST /v1/tasks/{id}/accept`, `/reject`, `/decision-request`, `/transition` |
| Messages | `POST/GET /v1/tasks/{id}/messages` |
| Artifacts | `POST/GET /v1/tasks/{id}/artifacts`, `GET /v1/artifacts/{id}` |
| Inbox | `GET /v1/inbox`, `POST /v1/inbox/ack` |
| Approvals | `POST /v1/tasks/{id}/approvals`, `GET /v1/approvals`, `GET /v1/approvals/{id}`, `POST /v1/approvals/{id}/consume`, `POST /v1/approvals/{id}/cancel` |

## Typical sequence (as exercised by `tests/e2e/test_margin_workflow.py`)

```
Agent A  POST /v1/tasks                       {to Agent B, category bug_fix, criteria…}      → proposed
Agent B   GET  /v1/inbox                       task.created
Agent B   POST /v1/tasks/{id}/accept                                                          → accepted
Agent B   POST /v1/tasks/{id}/messages         CLARIFICATION_REQUEST
Agent B   POST /v1/inbox/ack
Agent A  GET  /v1/inbox                       TASK_ACCEPTED, state_changed, CLARIFICATION_REQUEST
Agent A  POST /v1/tasks/{id}/artifacts        repro.csv (→ ARTIFACT_SUBMITTED)
Agent A  POST /v1/tasks/{id}/messages         CLARIFICATION_RESPONSE {artifact_ids}
Agent B   GET  /v1/artifacts/{art}             (sha256-verified, treated as data)
Agent B   POST /v1/tasks/{id}/transition       in_progress
Agent B   POST /v1/tasks/{id}/messages         PROGRESS_UPDATE {refs: commit, pr}
Agent B   POST /v1/tasks/{id}/transition       ready_for_validation
Agent A  POST /v1/tasks/{id}/messages         VALIDATION_RESULT {outcome: pass}                 → verified
Agent A  POST /v1/tasks/{id}/transition       closed
Humans   GET  /app/api/tasks/{id}/history     full timeline (?include_bodies=true for message bodies, ~1 MiB pages); /app/api/audit for the audit log
```

## Request budget

ngrok free ≈ 20k requests/month total. Agents poll every 15 min (`poll_after_s` = 900), persist `next_poll_at`
(early runs make zero requests), use one request per idle poll, ack only non-empty pages. Table: SPEC.md §9.
