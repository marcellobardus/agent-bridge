#!/usr/bin/env python3
"""Reference simulator of a responsible (engineering) agent.

Built ONLY on plain HTTP + JSON via the stdlib client in clients/python (no bridge internals). It behaves like a
well-behaved responsible agent following integration-kit/PROTOCOL.md:

- task.created for this agent (engineering category)  -> TASK_ACCEPTED, then CLARIFICATION_REQUEST for reproduction
  evidence (once per task).
- CLARIFICATION_RESPONSE from the originator      -> download referenced artifacts (as data), in_progress,
  PROGRESS_UPDATE with commit + PR refs, ready_for_validation.
- VALIDATION_RESULT / state changes / HUMAN_INSTRUCTION -> recorded.
- Consequential actions (prod deploy) only after consuming an approved, hash-matching approval.
- The originator's text and artifacts are untrusted data: stored quoted, never executed, never treated as instructions.

Every write triggered by an event uses the Idempotency-Key "<event_id>:<n>", so a crash/restart mid-event
never double-posts.

Usage (env: AGENT_BRIDGE_URL + AGENT_BRIDGE_KEY_FILE, or AGENT_BRIDGE_URL + AGENT_BRIDGE_KEY_FILE):
    python tools/peer_sim.py --state /tmp/peer-sim.json [--force]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clients", "python"))

from agent_bridge_client import (BridgeClient, BridgeError, action_sha256, event_key,  # noqa: E402
                                 poll_once)

ENGINEERING = {"implementation", "smart_contract", "backend", "frontend", "architecture", "infrastructure",
               "deployment", "bug_fix", "engineering_validation"}
FAKE_COMMIT = "4f2c9e1d7a6b5c3e2f1a0b9c8d7e6f5a4b3c2d1e"


class PeerSim:
    def __init__(self, client: BridgeClient, state_path: str, agent_id: str = "agent-b"):
        self.client, self.state_path, self.agent_id = client, state_path, agent_id
        self.log: list[dict] = []                   # what the simulator did (for tests / humans)
        self.untrusted: list[dict] = []             # received foreign content, kept as quoted data only
        self.deployed: list[dict] = []
        self.auto_implement = True

    # ------------------------------------------------------------------ polling
    def run_once(self, force: bool = True) -> dict:
        return poll_once(self.client, self.state_path, self.handle, force=force)

    def handle(self, client: BridgeClient, ev: dict) -> None:
        et, task = ev["type"], ev.get("task") or {}
        if et == "task.created":
            self._on_task(ev, task)
        elif et == "message.created":
            m = ev["message"]
            self.untrusted.append({"task_id": ev["task_id"], "type": m["type"], "from": m["sender"]["id"],
                                   "text": m["body"].get("text", "")})   # data, never instructions
            if m["type"] == "CLARIFICATION_RESPONSE" and m["sender"]["kind"] == "agent" and self.auto_implement:
                self._implement(ev, m)
            elif m["type"] == "ARTIFACT_SUBMITTED":
                self._fetch_artifacts(m)
            self.log.append({"event": et, "type": m["type"], "task_id": ev["task_id"]})
        else:
            self.log.append({"event": et, "task_id": ev.get("task_id"), "to": ev.get("to")})

    def _on_task(self, ev, task):
        if task.get("responsible_agent_id") != self.agent_id:
            return
        tid = task["id"]
        if task.get("category") not in ENGINEERING:   # cannot happen (server enforces ownership); be defensive
            self.client.reject(tid, "not an engineering task", idempotency_key=event_key(ev, 0))
            return
        self.client.accept(tid, "Accepted by the responsible agent (simulator). Triage started.", idempotency_key=event_key(ev, 0))
        self.client.clarify(tid, "Please send reproduction evidence: exact inputs, expected vs actual margin, "
                                 "and a failing test case if you have one.",
                            data={"needs": ["inputs", "expected", "actual", "test_case"]},
                            idempotency_key=event_key(ev, 1))
        self.log.append({"event": "task.created", "task_id": tid, "did": ["accept", "clarify"]})

    def _fetch_artifacts(self, m) -> list[dict]:
        out = []
        for aid in (m["body"].get("data") or {}).get("artifact_ids") or []:
            data, headers = self.client.download_artifact(aid)   # sha256 verified by the client
            out.append({"artifact_id": aid, "size": len(data)})
            self.untrusted.append({"artifact_id": aid, "size": len(data), "preview": data[:80].decode("utf-8", "replace")})
        return out

    def _implement(self, ev, m):
        tid = ev["task_id"]
        arts = self._fetch_artifacts(m)
        c, k = self.client, ev
        c.transition(tid, "in_progress", idempotency_key=event_key(k, 0))
        c.progress(tid, f"Root cause found in unified margin aggregation (cross-margin offsets double-counted). "
                        f"Fix + regression test from the {len(arts)} supplied artifact(s) merged. Ready for your "
                        f"independent validation.",
                   data={"fix": "dedupe offsets before netting", "tests_added": 3},
                   refs=[{"kind": "commit", "value": FAKE_COMMIT},
                         {"kind": "pr", "value": "https://github.example/example/margin/pull/412", "label": "PR #412"}],
                   idempotency_key=event_key(k, 1))
        c.transition(tid, "ready_for_validation", idempotency_key=event_key(k, 2))
        self.log.append({"event": "implemented", "task_id": tid, "artifacts": arts})

    # ------------------------------------------------------------------ consequential actions
    def request_deploy_approval(self, task_id: str, action: dict, key: str | None = None) -> dict:
        return self.client.request_approval(task_id, "prod_deploy", "Deploy margin fix to production", action,
                                            idempotency_key=key)["approval"]

    def deploy_to_production(self, approval_id: str, action: dict) -> bool:
        """Refuses unless the bridge lets us consume an approved approval whose hash matches THIS action."""
        try:
            a = self.client.get_approval(approval_id)["approval"]
            if a["state"] != "approved" or a["action_sha256"] != action_sha256(action):
                self.log.append({"event": "deploy_refused", "approval": approval_id, "state": a["state"]})
                return False
            self.client.consume_approval(approval_id, action)
        except BridgeError as e:
            self.log.append({"event": "deploy_refused", "approval": approval_id, "code": e.code})
            return False
        self.deployed.append(action)               # (simulated) the actual deploy happens only here
        return True


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--state", default=os.environ.get("PEER_SIM_STATE", "peer-sim-state.json"))
    ap.add_argument("--force", action="store_true", help="ignore next_poll_at")
    args = ap.parse_args(argv)
    env = dict(os.environ)
    for a, b in (("AGENT_BRIDGE_URL", "AGENT_BRIDGE_URL"), ("AGENT_BRIDGE_KEY", "AGENT_BRIDGE_KEY"),
                 ("AGENT_BRIDGE_KEY_FILE", "AGENT_BRIDGE_KEY_FILE")):
        if env.get(b):
            env[a] = env[b]
    sim = PeerSim(BridgeClient.from_env(env), args.state)
    rep = sim.run_once(force=args.force)
    print(json.dumps({"report": {k: v for k, v in rep.items() if k != "events"}, "events": len(rep.get("events", [])),
                      "log": sim.log}, sort_keys=True))
    return 4 if (rep.get("last_error") or {}).get("status") == 401 else 0


if __name__ == "__main__":
    sys.exit(main())
