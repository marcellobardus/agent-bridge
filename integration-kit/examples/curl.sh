#!/usr/bin/env bash
# Agent Bridge with curl: every operation Agent B needs, one call each.
# Requires: curl, and AGENT_BRIDGE_URL + AGENT_BRIDGE_KEY in the environment (from your secret store).
# The key is passed to curl through a header file on stdin-like process substitution, never on argv, so it does
# not show up in `ps`. Usage: source this file, then call the functions, e.g.  bridge_me ; bridge_inbox
set -euo pipefail

: "${AGENT_BRIDGE_URL:?set AGENT_BRIDGE_URL (https://example.ngrok.app)}"
: "${AGENT_BRIDGE_KEY:?set AGENT_BRIDGE_KEY (from your secret store, never hard-coded)}"
B="${AGENT_BRIDGE_URL%/}"
# https only; plain http solely to 127.0.0.1 (local tests). --proto makes curl itself refuse anything else.
PROTO="=https"
if [[ "$B" =~ ^http://127\.0\.0\.1(:[0-9]+)?(/.*)?$ ]]; then PROTO="=http,https"
elif [[ ! "$B" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?(/.*)?$ ]]; then
  echo "AGENT_BRIDGE_URL must be https://<host>" >&2; return 1 2>/dev/null || exit 1
fi

_hdrs() {  # common headers, written to a curl config on stdin (keeps the key off the command line)
  printf 'header = "Authorization: Bearer %s"\n' "$AGENT_BRIDGE_KEY"
  printf 'header = "ngrok-skip-browser-warning: 1"\n'
  printf 'header = "Accept: application/json"\n'
}
_get() { _hdrs | curl -sS --proto "$PROTO" --proto-redir =https --fail-with-body --max-time 20 --retry 3 --retry-all-errors -K - "$B$1"; }
# _post PATH JSON [IDEMPOTENCY_KEY]  — reuse the SAME key when you retry the same operation
_post() {
  local key="${3:-agent-b-$(date +%s)-$RANDOM$RANDOM}"
  { _hdrs; printf 'header = "Idempotency-Key: %s"\nheader = "Content-Type: application/json"\n' "$key"; } |
    curl -sS --proto "$PROTO" --proto-redir =https --fail-with-body --max-time 20 --retry 3 -K - -X POST --data-binary "$2" "$B$1"
}

bridge_me()        { _get /v1/me; }
bridge_inbox()     { _get "/v1/inbox?limit=50${1:+&cursor=$1}"; }        # [cursor]; default = your acked cursor
bridge_ack()       { _post /v1/inbox/ack "{\"cursor\": $1}" "ack-$1-$RANDOM"; }   # only after handling a NON-EMPTY page
bridge_task()      { _get "/v1/tasks/$1"; }
bridge_tasks()     { _get "/v1/tasks?role=responsible${1:+&state=$1}"; }  # [state]
bridge_search()    { _get "/v1/tasks/search?q=$(printf %s "$1" | jq -sRr @uri)"; }
bridge_history()   { _get "/v1/tasks/$1/history"; }
bridge_accept()    { _post "/v1/tasks/$1/accept" '{"body":{"text":"Accepted by Agent B"}}' "$2"; }   # TASK_ID IDEM
bridge_reject()    { _post "/v1/tasks/$1/reject" "$(jq -nc --arg r "$2" '{reason:$r}')" "$3"; }     # TASK_ID REASON IDEM
# bridge_msg TASK_ID TYPE TEXT IDEM [IN_REPLY_TO]
bridge_msg() {
  _post "/v1/tasks/$1/messages" "$(jq -nc --arg t "$2" --arg x "$3" --arg r "${5:-}" \
    '{type:$t, body:{text:$x}} + (if $r != "" then {in_reply_to:$r} else {} end)')" "$4"
}
# bridge_progress TASK_ID TEXT COMMIT_SHA PR_URL IDEM
bridge_progress() {
  _post "/v1/tasks/$1/messages" "$(jq -nc --arg x "$2" --arg c "$3" --arg p "$4" \
    '{type:"PROGRESS_UPDATE", body:{text:$x, refs:[{kind:"commit",value:$c},{kind:"pr",value:$p}]}}')" "$5"
}
bridge_status()    { _post "/v1/tasks/$1/transition" "$(jq -nc --arg s "$2" --arg r "${4:-}" \
                       '{to:$s} + (if $r != "" then {reason:$r} else {} end)')" "$3"; }   # TASK_ID STATE IDEM [REASON]
bridge_escalate()  { _post "/v1/tasks/$1/decision-request" "$(jq -nc --arg r "$2" '{reason:$r}')" "$3"; }
# bridge_upload TASK_ID FILE CONTENT_TYPE IDEM   (raw body; max 2 MiB; allowlisted types only)
bridge_upload() {
  { _hdrs; printf 'header = "Idempotency-Key: %s"\nheader = "Content-Type: %s"\n' "$4" "$3"; } |
    curl -sS --proto "$PROTO" --proto-redir =https --fail-with-body --max-time 60 -K - -X POST --data-binary "@$2" \
      "$B/v1/tasks/$1/artifacts?filename=$(basename "$2" | jq -sRr @uri)"
}
bridge_download()  { _hdrs | curl -sS --proto "$PROTO" --proto-redir =https --fail-with-body -K - -o "$2" "$B/v1/artifacts/$1"; }  # ARTIFACT_ID OUT_FILE
# Approvals for consequential actions (prod deploy, fund moves, mainnet upgrades, live trading, credentials)
bridge_approval_request() {  # TASK_ID KIND SUMMARY ACTION_JSON IDEM
  _post "/v1/tasks/$1/approvals" "$(jq -nc --arg k "$2" --arg s "$3" --argjson a "$4" \
    '{kind:$k, summary:$s, action:$a}')" "$5"
}
bridge_approval()  { _get "/v1/approvals/$1"; }
bridge_approvals() { _get "/v1/approvals?state=${1:-pending}"; }
bridge_consume() {   # APPROVAL_ID ACTION_JSON IDEM — hash of the canonical JSON (sorted keys, no spaces)
  local sha; sha=$(printf %s "$2" | jq -cS . | tr -d '\n' | sha256sum | cut -d' ' -f1)
  _post "/v1/approvals/$1/consume" "{\"action_sha256\":\"$sha\"}" "$3"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then   # executed (not sourced): quick read-only check
  bridge_me; echo; bridge_inbox; echo
fi
