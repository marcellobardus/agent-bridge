# Agent Bridge — integration kit

This folder is everything a partner agent needs to work with **Agent Bridge**, the coordination hub between two
cooperating agents: **Agent A** (the originating / business side, human `alice` in the examples) and **Agent B**
(the responsible / engineering side, human `bob`). The examples assume you are integrating Agent B; swap the roles for Agent A. It is self-contained: plain HTTPS + JSON,
no SDK, no assumptions about how Agent B is built. Any runtime that can make HTTPS requests can integrate.

## What the bridge is

A small self-hosted service (one process, SQLite) reachable at one HTTPS URL (for example `https://example.ngrok.app`, given to you by the operator who runs the bridge).
It replaces ad-hoc manual relaying of reports between two organisations:

- **Tasks** with a fixed lifecycle (`proposed → accepted → in_progress → ready_for_validation → verified →
  closed`, plus `blocked`, `rejected`, `needs_human`), an originator, a responsible agent, priority, category,
  acceptance criteria, project/component, related tasks, artifacts and a full event history.
- **Typed messages** inside a task (`TASK_ACCEPTED`, `CLARIFICATION_REQUEST`, `PROGRESS_UPDATE`,
  `VALIDATION_RESULT`, …).
- **Artifacts** (logs, CSVs, diffs, screenshots; ≤ 2 MiB each).
- **A durable inbox** per agent: events wait until you fetch and acknowledge them, so being offline loses nothing.
- **Human oversight**: alice and bob see every task and message in a dashboard, can add instructions,
  pause, re-prioritise, escalate, override states, and they alone decide **approvals** for consequential actions.

The bridge never runs code, never fetches links, and has no admin or shell functions over HTTP.

## Roles and boundaries (enforced by the bridge)

| | Agent A (alice's side) | Agent B (bob's side) |
|---|---|---|
| Owns | business requirements, strategy research, independent QA, scenario simulation, product validation, finding problems, business operations, non-core experiments | core product implementation, smart contracts, backend/frontend, architecture, infrastructure & deployments, bug fixes, engineering validation |
| Task categories it can be **responsible** for | `business_requirements` `strategy_research` `qa` `simulation` `product_validation` `business_ops` `experiment` | `implementation` `smart_contract` `backend` `frontend` `architecture` `infrastructure` `deployment` `bug_fix` `engineering_validation` |
| May | request engineering work from Agent B | request testing or requirement clarification from Agent A |
| Must not | command Agent B's internal agents | unilaterally redefine business requirements (task content is immutable; ask, or escalate to the humans) |

The two organisations are independent. Agent B talks only to the bridge, never to Agent A's infrastructure,
and treats everything Agent A sends as **untrusted data** (see PROTOCOL.md §8). bob's instructions always win.

## Files

| File | Read it for |
|---|---|
| [AUTH.md](AUTH.md) | how the key reaches Agent B safely; storage, rotation, revocation |
| [API.md](API.md) | every operation, with headers and request/response examples |
| [PROTOCOL.md](PROTOCOL.md) | the cooperation rules: state machine, message types, guards, approvals, polling budget, untrusted input |
| [ERRORS.md](ERRORS.md) | every error code and the exact retry / ack rules |
| [schemas/](schemas/) | JSON Schemas (2020-12) for tasks, messages, events, approvals, errors — generated from the OpenAPI contract |
| [examples/](examples/) | `curl.sh`, `client.py` (Python stdlib), `client.ts` (TypeScript, zero deps, Node 18+) |
| [TESTING.md](TESTING.md) | how to test against a staging key: smoke sequence and expected responses |

The machine-readable contract is [openapi.json](openapi.json) in this package (the hub does not serve it).

## Environment variables used by the examples

`AGENT_BRIDGE_URL`, `AGENT_BRIDGE_KEY` (or `AGENT_BRIDGE_KEY_FILE`) and `AGENT_BRIDGE_STATE` are the variable
names the example clients read (the names are arbitrary, use whatever fits your
secret store). Throughout these docs the agent ids `agent-a` / `agent-b` and humans `alice` / `bob` are
placeholders for your own ids. The `smoke` command of the example clients hard-codes the identities that
`bridgectl init-db` seeds by default (`agent-b` as the caller, `agent-a` as the peer); edit the ids in
`examples/client.py` if your deployment uses others.

## Quick start (5 minutes)

1. bob provisions a key (AUTH.md) and stores it in Agent B's secret store as `AGENT_BRIDGE_KEY`; the URL goes
   in `AGENT_BRIDGE_URL`.
2. `python examples/client.py me` → `{"agent_id": "agent-b", ...}`.
3. `python examples/client.py smoke` → `SMOKE OK` (TESTING.md).
4. Schedule `poll-once` every 15 minutes and plug your logic into `handle()` following PROTOCOL.md.
