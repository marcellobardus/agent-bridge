-- Security hardening (see SECURITY.md).
-- per-account TOTP failure counting (IP-independent) and per-session step-up failures.
ALTER TABLE humans ADD COLUMN totp_failures INTEGER NOT NULL DEFAULT 0;
ALTER TABLE humans ADD COLUMN totp_next_allowed_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN stepup_failures INTEGER NOT NULL DEFAULT 0;
-- the sender's party travels with every message (agents obey only their own party's human).
ALTER TABLE messages ADD COLUMN sender_party_id TEXT;
UPDATE messages SET sender_party_id = (SELECT party_id FROM agents WHERE agents.id = messages.sender_id)
  WHERE sender_kind = 'agent';
UPDATE messages SET sender_party_id = (SELECT party_id FROM humans WHERE humans.id = messages.sender_id)
  WHERE sender_kind = 'human';
-- per-sender message cap counts messages after this seq (a human can reset it).
ALTER TABLE tasks ADD COLUMN counter_reset_seq INTEGER NOT NULL DEFAULT 0;
CREATE INDEX messages_task_sender ON messages(task_id, sender_id, seq);
-- per-agent artifact quota.
CREATE INDEX artifacts_uploader ON artifacts(uploader_id);
