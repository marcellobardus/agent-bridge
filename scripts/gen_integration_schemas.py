"""Generate integration-kit/schemas/*.json (standalone JSON Schema 2020-12) from docs/openapi.json.

    python scripts/gen_integration_schemas.py           # write
    python scripts/gen_integration_schemas.py --check   # exit 1 if the files are stale (used by the tests)

Each file inlines the referenced components under `$defs`, so a partner agent can validate with any JSON Schema library
without the OpenAPI document. Message-type rules and error codes (not expressible in the pydantic models) are
added here and mirror docs/SPEC.md §4 and §12.
"""
import copy
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OPENAPI = ROOT / "docs" / "openapi.json"
OUT = ROOT / "integration-kit" / "schemas"
BASE = "https://agent-bridge.invalid/schemas/"

ERROR_CODES = {
    400: ["missing_idempotency_key", "invalid_idempotency_key"],
    401: ["invalid_key"],
    403: ["scope_missing", "transition_forbidden", "sender_not_allowed", "ownership_violation", "wrong_party",
          "humans_only"],
    404: ["task_not_found", "approval_not_found", "artifact_not_found", "not_found"],
    409: ["version_conflict", "loop_guard", "duplicate_task", "task_paused", "already_responded",
          "not_ready_for_validation", "approval_pending", "not_approved", "already_consumed", "hash_mismatch",
          "approval_expired", "not_pending", "too_many_keys"],
    410: ["task_closed"],
    413: ["payload_too_large", "message_too_large", "artifact_too_large", "artifact_quota_exceeded",
          "action_too_large", "data_too_large"],
    415: ["unsupported_media_type"],
    422: ["validation_error", "invalid_transition", "reason_required", "idempotency_key_reuse", "invalid_body",
          "invalid_parent", "unknown_parent", "unknown_artifact", "unknown_agent", "self_assignment",
          "message_type_not_allowed", "content_mismatch", "empty_artifact", "data_too_deep", "action_too_deep"],
    423: ["agent_paused"],
    429: ["rate_limited", "daily_limit", "too_many_in_flight"],
    500: ["internal_error"],
    503: ["storage_degraded", "server_busy"],
}
EVENT_TYPES = ["task.created", "message.created", "task.state_changed", "task.priority_changed", "task.paused",
               "task.resumed", "approval.decided"]
ALL_MESSAGE_TYPES = ["TASK_REQUEST", "TASK_ACCEPTED", "TASK_REJECTED", "CLARIFICATION_REQUEST",
                     "CLARIFICATION_RESPONSE", "PROGRESS_UPDATE", "ARTIFACT_SUBMITTED", "VALIDATION_RESULT",
                     "DECISION_REQUEST", "HUMAN_INSTRUCTION"]

# file -> (root component, title, extra transform)
FILES = {
    "task.json": ("TaskOut", "Task as returned by the bridge"),
    "task-create.json": ("TaskCreate", "POST /v1/tasks request body"),
    "task-detail.json": ("TaskDetailOut", "GET /v1/tasks/{id} response"),
    "transition.json": ("TransitionIn", "POST /v1/tasks/{id}/transition request body"),
    "message.json": ("MessageOut", "A message as delivered (inbox events, task detail, history)"),
    "message-post.json": ("MessageIn", "POST /v1/tasks/{id}/messages request body (agent-postable types)"),
    "message-posted.json": ("MessagePostedOut", "Response of every message-posting endpoint"),
    "event.json": ("EventOut", "One inbox event"),
    "inbox-page.json": ("InboxOut", "GET /v1/inbox response"),
    "artifact.json": ("ArtifactOut", "Artifact metadata"),
    "approval.json": ("ApprovalOut", "Approval for a consequential action"),
    "approval-request.json": ("ApprovalIn", "POST /v1/tasks/{id}/approvals request body"),
    "error.json": ("ProblemOut", "application/problem+json error body"),
    "me.json": ("MeOut", "GET /v1/me response"),
}


def _refs(node, found):
    if isinstance(node, dict):
        r = node.get("$ref")
        if isinstance(r, str) and r.startswith("#/components/schemas/"):
            found.add(r.rsplit("/", 1)[1])
        for v in node.values():
            _refs(v, found)
    elif isinstance(node, list):
        for v in node:
            _refs(v, found)


def _rewrite(node):
    if isinstance(node, dict):
        return {k: (v.replace("#/components/schemas/", "#/$defs/") if k == "$ref" and isinstance(v, str)
                    else _rewrite(v)) for k, v in node.items()}
    if isinstance(node, list):
        return [_rewrite(v) for v in node]
    return node


def standalone(components: dict, root: str, title: str) -> dict:
    need, todo = set(), {root}
    while todo:
        name = todo.pop()
        if name in need:
            continue
        need.add(name)
        found = set()
        _refs(components[name], found)
        todo |= found - need
    schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": BASE + root,
              "title": title, "x-generated-from": f"docs/openapi.json#/components/schemas/{root}"}
    schema.update(_rewrite(copy.deepcopy(components[root])))
    schema["title"] = title
    defs = {n: _rewrite(copy.deepcopy(components[n])) for n in sorted(need - {root})}
    if defs:
        schema["$defs"] = defs
    return schema


def extras(schemas: dict) -> None:
    # message types: per-type body rules (SPEC §4)
    mp = schemas["message-post.json"]
    mp["allOf"] = [
        {"if": {"properties": {"type": {"const": "VALIDATION_RESULT"}}},
         "then": {"required": ["body"], "properties": {"body": {"required": ["data"], "properties": {"data": {
             "required": ["outcome"], "properties": {"outcome": {"enum": ["pass", "fail"]}}}}}}}},
        {"if": {"properties": {"type": {"const": "CLARIFICATION_RESPONSE"}}},
         "then": {"required": ["in_reply_to"], "properties": {"in_reply_to": {"type": "string"}}}},
        {"if": {"properties": {"type": {"const": "TASK_REJECTED"}}},
         "then": {"required": ["body"], "properties": {"body": {"required": ["text"],
                                                                "properties": {"text": {"minLength": 1}}}}}},
        {"if": {"properties": {"type": {"const": "ARTIFACT_SUBMITTED"}}},
         "then": {"required": ["body"], "properties": {"body": {"anyOf": [
             {"required": ["data"], "properties": {"data": {"required": ["artifact_ids"], "properties": {
                 "artifact_ids": {"type": "array", "minItems": 1, "items": {"type": "string"}}}}}},
             {"required": ["refs"], "properties": {"refs": {"minItems": 1}}}]}}}},
    ]
    schemas["message.json"]["properties"]["type"] = {"enum": ALL_MESSAGE_TYPES, "title": "Type", "type": "string"}
    for name in ("event.json", "inbox-page.json"):
        s = schemas[name]
        ev = s if name == "event.json" else s["$defs"]["EventOut"]
        ev["properties"]["type"] = {"enum": EVENT_TYPES, "title": "Type", "type": "string"}
    err = schemas["error.json"]
    err["properties"]["code"] = {"enum": sorted({c for cs in ERROR_CODES.values() for c in cs}), "type": "string",
                                 "title": "Code"}
    err["x-codes-by-status"] = {str(k): v for k, v in ERROR_CODES.items()}


def build() -> dict:
    spec = json.loads(OPENAPI.read_text())
    comps = spec["components"]["schemas"]
    out = {fn: standalone(comps, root, title) for fn, (root, title) in FILES.items()}
    extras(out)
    return {fn: json.dumps(s, indent=2, sort_keys=True) + "\n" for fn, s in out.items()}


PKG_OPENAPI = ROOT / "integration-kit" / "openapi.json"   # the contract ships with the package (not served)


def main(argv) -> int:
    files = build()
    if "--check" in argv:
        stale = [fn for fn, txt in files.items() if not (OUT / fn).exists() or (OUT / fn).read_text() != txt]
        if not PKG_OPENAPI.exists() or PKG_OPENAPI.read_text() != OPENAPI.read_text():
            stale.append("../openapi.json")
        if stale:
            print("stale schemas (run scripts/gen_integration_schemas.py):", ", ".join(stale))
            return 1
        print(f"{len(files)} schemas up to date")
        return 0
    OUT.mkdir(parents=True, exist_ok=True)
    for fn, txt in files.items():
        (OUT / fn).write_text(txt)
    PKG_OPENAPI.write_text(OPENAPI.read_text())
    print(f"wrote {len(files)} schemas to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
