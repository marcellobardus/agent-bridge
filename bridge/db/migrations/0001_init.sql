-- Agent Bridge schema v1. Timestamps are unix ms UTC. Applied by bridge.db.migrate (PRAGMA user_version).

CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;

CREATE TABLE parties (
  id TEXT PRIMARY KEY,                           -- 'alice' | 'bob'
  display_name TEXT NOT NULL,
  domain TEXT NOT NULL CHECK (domain IN ('business','engineering')),  -- ownership
  paused_at INTEGER,
  created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE humans (
  id TEXT PRIMARY KEY,
  party_id TEXT NOT NULL REFERENCES parties(id),
  login TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,                   -- argon2id PHC string
  totp_secret_enc BLOB NOT NULL,                 -- AES-256-GCM(totp_kek), nonce||ciphertext
  totp_last_step INTEGER NOT NULL DEFAULT 0,     -- replay protection
  created_at INTEGER NOT NULL,
  disabled_at INTEGER
) STRICT;

CREATE TABLE login_throttle (                    -- delays keyed by client IP, never by login
  ip TEXT PRIMARY KEY,
  failures INTEGER NOT NULL DEFAULT 0,
  next_allowed_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE enrollments (                       -- one-time invite / reset links (bridgectl human invite|reset)
  token_hash BLOB PRIMARY KEY,                   -- SHA-256 of the link token
  login TEXT NOT NULL COLLATE NOCASE,
  party_id TEXT NOT NULL REFERENCES parties(id),
  display_name TEXT NOT NULL,
  human_id TEXT REFERENCES humans(id),           -- set for a reset of an existing account
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
) STRICT;

CREATE TABLE sessions (
  token_hash BLOB PRIMARY KEY,                   -- SHA-256 of the cookie value
  human_id TEXT NOT NULL REFERENCES humans(id),
  csrf_token TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  step_up_at INTEGER,
  revoked_at INTEGER
) STRICT;

CREATE TABLE agents (
  id TEXT PRIMARY KEY CHECK (id GLOB '[a-z]*' AND length(id) BETWEEN 2 AND 32),
  party_id TEXT NOT NULL REFERENCES parties(id),
  display_name TEXT NOT NULL,
  paused_at INTEGER,
  disabled_at INTEGER,
  created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE api_keys (
  id TEXT PRIMARY KEY,                           -- public key id (12 chars) embedded in the token
  agent_id TEXT NOT NULL REFERENCES agents(id),
  secret_hash BLOB NOT NULL,                     -- HMAC-SHA256(pepper, secret)
  scopes TEXT NOT NULL CHECK (json_valid(scopes)),
  label TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  revoked_at INTEGER,
  last_used_at INTEGER
) STRICT;
CREATE INDEX api_keys_agent ON api_keys(agent_id);

CREATE TABLE tasks (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
  description TEXT NOT NULL CHECK (length(description) <= 16000),
  originator_agent_id TEXT NOT NULL REFERENCES agents(id),
  responsible_agent_id TEXT NOT NULL REFERENCES agents(id),
  priority TEXT NOT NULL CHECK (priority IN ('low','normal','high','urgent')),
  category TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('proposed','accepted','in_progress','ready_for_validation',
        'verified','closed','blocked','rejected','needs_human')),
  resume_state TEXT,                             -- state before needs_human
  acceptance_criteria TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(acceptance_criteria)),
  project TEXT,
  component TEXT,
  related_task_ids TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(related_task_ids)),
  parent_task_id TEXT REFERENCES tasks(id),
  hop_count INTEGER NOT NULL DEFAULT 0 CHECK (hop_count BETWEEN 0 AND 3),
  content_sha256 TEXT NOT NULL,                  -- duplicate detection
  clarification_rounds INTEGER NOT NULL DEFAULT 0,
  agent_streak INTEGER NOT NULL DEFAULT 0,       -- agent messages since the last human touch
  message_count INTEGER NOT NULL DEFAULT 0,
  paused_at INTEGER,
  paused_by TEXT,
  version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  closed_at INTEGER,
  CHECK (originator_agent_id <> responsible_agent_id)
) STRICT;
CREATE INDEX tasks_originator ON tasks(originator_agent_id, created_at);
CREATE INDEX tasks_responsible ON tasks(responsible_agent_id, updated_at);
CREATE INDEX tasks_dupe ON tasks(originator_agent_id, content_sha256);
CREATE TRIGGER tasks_terminal_guard BEFORE UPDATE OF state ON tasks
WHEN OLD.state IN ('closed','rejected') AND NEW.state <> OLD.state
BEGIN SELECT RAISE(ABORT, 'task is in a terminal state'); END;

CREATE TABLE messages (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  task_id TEXT NOT NULL REFERENCES tasks(id),
  type TEXT NOT NULL CHECK (type IN ('TASK_REQUEST','TASK_ACCEPTED','TASK_REJECTED',
        'CLARIFICATION_REQUEST','CLARIFICATION_RESPONSE','PROGRESS_UPDATE','ARTIFACT_SUBMITTED',
        'VALIDATION_RESULT','DECISION_REQUEST','HUMAN_INSTRUCTION')),
  sender_kind TEXT NOT NULL CHECK (sender_kind IN ('agent','human')),
  sender_id TEXT NOT NULL,
  in_reply_to TEXT REFERENCES messages(id),
  depth INTEGER NOT NULL DEFAULT 0,
  body TEXT NOT NULL CHECK (json_valid(body) AND length(body) <= 65536),
  body_sha256 TEXT NOT NULL,
  created_at INTEGER NOT NULL
) STRICT;
CREATE INDEX messages_task ON messages(task_id, seq);
CREATE INDEX messages_dedupe ON messages(task_id, sender_id, body_sha256, created_at);
CREATE UNIQUE INDEX messages_one_clarification_response ON messages(in_reply_to)
  WHERE type = 'CLARIFICATION_RESPONSE';

CREATE TABLE artifacts (
  id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES tasks(id),
  uploader_kind TEXT NOT NULL CHECK (uploader_kind IN ('agent','human')),
  uploader_id TEXT NOT NULL,
  filename TEXT NOT NULL CHECK (length(filename) BETWEEN 1 AND 200),
  content_type TEXT NOT NULL,
  size INTEGER NOT NULL CHECK (size BETWEEN 1 AND 8388608),
  sha256 TEXT NOT NULL,
  data BLOB NOT NULL,
  created_at INTEGER NOT NULL
) STRICT;
CREATE INDEX artifacts_task ON artifacts(task_id);

CREATE TABLE task_log (                          -- per-task event history (timeline)
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL REFERENCES tasks(id),
  ts INTEGER NOT NULL,
  actor_kind TEXT NOT NULL CHECK (actor_kind IN ('agent','human','system','cli')),
  actor_id TEXT NOT NULL,
  kind TEXT NOT NULL,                            -- created|state_changed|message|artifact|priority_changed|paused|resumed|approval_*
  from_state TEXT,
  to_state TEXT,
  message_id TEXT,
  detail TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail))
) STRICT;
CREATE INDEX task_log_task ON task_log(task_id, seq);

CREATE TABLE approvals (
  id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES tasks(id),
  requested_by_agent_id TEXT NOT NULL REFERENCES agents(id),
  approver_party_id TEXT NOT NULL REFERENCES parties(id),   -- always the requesting agent's party
  kind TEXT NOT NULL CHECK (kind IN ('prod_deploy','fund_move','mainnet_upgrade','live_trading','credential_change')),
  summary TEXT NOT NULL CHECK (length(summary) BETWEEN 1 AND 500),
  action TEXT NOT NULL CHECK (json_valid(action) AND length(action) <= 32768),
  action_sha256 TEXT NOT NULL,                   -- SHA-256 over canonical JSON of action
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN
        ('pending','approved','rejected','expired','cancelled','consumed')),
  decided_by_human_id TEXT REFERENCES humans(id),
  decided_at INTEGER,
  decision_note TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,                   -- deadline while pending
  valid_until INTEGER,                           -- deadline to consume after approval
  consumed_at INTEGER
) STRICT;
CREATE INDEX approvals_agent ON approvals(requested_by_agent_id, state);
CREATE UNIQUE INDEX approvals_one_pending_per_agent ON approvals(task_id, requested_by_agent_id)
  WHERE state = 'pending';
CREATE TRIGGER approvals_decider_guard BEFORE UPDATE OF state ON approvals
WHEN NEW.state IN ('approved','rejected') AND (OLD.state <> 'pending' OR NOT EXISTS (
  SELECT 1 FROM humans h WHERE h.id = NEW.decided_by_human_id
     AND h.party_id = NEW.approver_party_id AND h.disabled_at IS NULL))
BEGIN SELECT RAISE(ABORT, 'only a human of the approver party may decide a pending approval'); END;
CREATE TRIGGER approvals_consume_guard BEFORE UPDATE OF state ON approvals
WHEN NEW.state = 'consumed' AND OLD.state <> 'approved'
BEGIN SELECT RAISE(ABORT, 'only an approved approval can be consumed'); END;
CREATE TRIGGER approvals_final_guard BEFORE UPDATE OF state ON approvals
WHEN OLD.state IN ('rejected','expired','cancelled','consumed')
BEGIN SELECT RAISE(ABORT, 'approval is in a final state'); END;

CREATE TABLE events (                            -- transactional outbox = per-agent inbox
  seq INTEGER PRIMARY KEY AUTOINCREMENT,         -- the cursor
  id TEXT NOT NULL UNIQUE,
  recipient_agent_id TEXT NOT NULL REFERENCES agents(id),
  type TEXT NOT NULL,
  task_id TEXT REFERENCES tasks(id),
  payload TEXT NOT NULL CHECK (json_valid(payload)),
  created_at INTEGER NOT NULL
) STRICT;
CREATE INDEX events_inbox ON events(recipient_agent_id, seq);

CREATE TABLE agent_cursors (
  agent_id TEXT PRIMARY KEY REFERENCES agents(id),
  acked_seq INTEGER NOT NULL DEFAULT 0,
  acked_at INTEGER,
  last_poll_at INTEGER
) STRICT;

CREATE TABLE idempotency_keys (
  agent_id TEXT NOT NULL REFERENCES agents(id),
  key TEXT NOT NULL CHECK (length(key) BETWEEN 8 AND 128),
  request_sha256 TEXT NOT NULL,                  -- method + path + query + body bytes
  status INTEGER NOT NULL,
  response TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (agent_id, key)
) STRICT, WITHOUT ROWID;

CREATE TABLE audit_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  actor_kind TEXT NOT NULL CHECK (actor_kind IN ('agent','human','system','cli')),
  actor_id TEXT NOT NULL,
  credential_id TEXT,                            -- api key id or session prefix; never a secret
  action TEXT NOT NULL,
  target_kind TEXT,
  target_id TEXT,
  request_id TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail)),  -- ids, states, hashes; no bodies
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
) STRICT;
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
