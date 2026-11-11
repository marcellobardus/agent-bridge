import json
import os
import sqlite3

from bridge import cli, ops
from bridge.db import connect
from bridge.domain.common import audit_verify


def test_audit_chain_verifies_and_detects_tamper(env):
    t = env.agent_a.create_task()
    env.agent_b.post(f"/v1/tasks/{t['id']}/accept", {})
    with env.db.read() as c:
        ok, n, bad = audit_verify(c)
        assert ok and n > 5
        detail = c.execute("SELECT detail FROM audit_log WHERE action='message.create'").fetchone()[0]
        assert "Unified margin" not in detail       # no bodies in audit rows
    raw = sqlite3.connect(env.settings.db_path)
    try:
        raw.execute("UPDATE audit_log SET actor_id='mallory' WHERE seq=3")
        raise AssertionError("trigger should forbid updates")
    except sqlite3.IntegrityError:
        pass
    raw.execute("DROP TRIGGER audit_no_update")
    raw.execute("UPDATE audit_log SET actor_id='mallory' WHERE seq=3")
    raw.commit()
    raw.close()
    with env.db.read() as c:
        ok, n, bad = audit_verify(c)
    assert not ok and bad == 3


def test_backup_restore_cancels_approvals(env, tmp_path):
    env.add_human("bob", "bob")
    t = env.agent_a.create_task()
    a = env.agent_b.post(f"/v1/tasks/{t['id']}/approvals",
                        {"kind": "prod_deploy", "summary": "s", "action": {"v": 1}}).json()["approval"]
    b = env.login("bob")
    assert b.post(f"/app/approvals/{a['id']}/decide", decision="approve").status_code == 200
    snap = str(tmp_path / "snap.db")
    info = ops.backup(env.settings.db_path, snap)
    assert info["backup_taken_at"] and oct(os.stat(snap).st_mode & 0o777) == "0o600"
    # after the snapshot: consume (an external action happens), more writes
    assert env.agent_b.post(f"/v1/approvals/{a['id']}/consume", {"action_sha256": a["action_sha256"]},
                           key="consume-key-01").status_code == 200
    with env.db.read() as c:
        old_head = c.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        old_max_evt = c.execute("SELECT max(seq) FROM events").fetchone()[0]
    env.db.close()
    detail = ops.restore(env.settings.db_path, snap)
    assert detail["cancelled_approvals"] == 1 and detail["replaced_head_hash"] == old_head[1]
    assert os.path.exists(env.settings.db_path + ".replaced")
    # the approval approved in the snapshot cannot be consumed again
    r = env.agent_b.post(f"/v1/approvals/{a['id']}/consume", {"action_sha256": a["action_sha256"]}, key="consume-key-02")
    assert r.status_code == 409 and r.json()["code"] == "not_approved"
    # the post-snapshot idempotency row is gone, so no replay of a write the DB doesn't contain
    r = env.agent_b.post(f"/v1/approvals/{a['id']}/consume", {"action_sha256": a["action_sha256"]}, key="consume-key-01")
    assert r.status_code == 409 and "idempotent-replayed" not in r.headers
    with env.db.read() as c:
        assert audit_verify(c)[0]
        row = c.execute("SELECT detail FROM audit_log WHERE action='system.restore'").fetchone()
        assert json.loads(row[0])["replaced_head_seq"] == old_head[0]
        new_evt = c.execute("SELECT max(seq) FROM events").fetchone()[0]
    assert new_evt > old_max_evt + 900_000   # sequence bumped: no client cursor can be ahead


def run_cli(tmp_path, monkeypatch, capsys, *args):
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path / "creds"))
    code = cli.main(["--config", str(tmp_path / "config.toml"), *args])
    return code, capsys.readouterr()


def test_cli_end_to_end(tmp_path, monkeypatch, capsys):
    import io
    assert cli.main(["gen-credentials", str(tmp_path / "creds")]) == 0
    assert oct(os.stat(tmp_path / "creds" / "pepper").st_mode & 0o777) == "0o400"
    # the sectioned layout written by deploy/install.sh
    (tmp_path / "config.toml").write_text(f'[server]\nhost = "127.0.0.1"\npublic_origin = "https://b.example"\n'
                                          f'[storage]\ndb_path = "{tmp_path}/b.db"\nbackup_dir = "/x"\n')
    code, out = run_cli(tmp_path, monkeypatch, capsys, "migrate")
    assert code == 0 and "schema version 2" in out.out
    code, out = run_cli(tmp_path, monkeypatch, capsys, "key", "create", "--agent", "agent-a")
    token = out.out.strip()
    assert code == 0 and token.startswith("abk_") and "\n" not in token   # stdout = token only
    key_id = token.split("_")[1]
    code, out = run_cli(tmp_path, monkeypatch, capsys, "key", "list")
    assert key_id in out.out and token.split("_", 2)[2] not in out.out
    code, out = run_cli(tmp_path, monkeypatch, capsys, "key", "rotate", "--agent", "agent-a", "--old", key_id)
    assert code == 0 and out.out.strip().startswith("abk_")
    code, out = run_cli(tmp_path, monkeypatch, capsys, "key", "revoke", key_id)
    assert code == 1 and "key_not_found" in out.err  # already revoked by rotate
    code, out = run_cli(tmp_path, monkeypatch, capsys, "human", "invite", "alice")
    assert code == 0 and out.out.startswith("https://b.example/app/enroll/")
    monkeypatch.setattr("sys.stdin", io.StringIO("a-long-enough-password\n"))
    code, out = run_cli(tmp_path, monkeypatch, capsys, "human", "create", "--login", "bob", "--party", "bob",
                        "--display-name", "Bob", "--password-stdin")
    assert code == 0 and out.out.startswith("otpauth://totp/")
    code, out = run_cli(tmp_path, monkeypatch, capsys, "human", "reset", "bob")
    assert code == 0 and "/app/enroll/" in out.out
    code, out = run_cli(tmp_path, monkeypatch, capsys, "human", "unlock", "--all")
    assert code == 0
    code, out = run_cli(tmp_path, monkeypatch, capsys, "audit", "verify")
    assert code == 0 and "OK" in out.out
    code, out = run_cli(tmp_path, monkeypatch, capsys, "audit", "verify", "--contains", "f" * 64)
    assert code == 1 and "NOT FOUND" in out.out
    code, out = run_cli(tmp_path, monkeypatch, capsys, "backup", "snapshot", "--out", str(tmp_path / "s.db"))
    assert code == 0 and json.loads(out.out)["audit_rows"] > 0
    snap = (tmp_path / "s.db").read_bytes()
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(snap)))
    code, out = run_cli(tmp_path, monkeypatch, capsys, "restore", "--check-only")
    assert code == 0 and json.loads(out.out)["head_hash"]
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(b"not a database" * 100)))
    code, out = run_cli(tmp_path, monkeypatch, capsys, "restore", "--check-only")
    assert code != 0
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(snap)))
    code, out = run_cli(tmp_path, monkeypatch, capsys, "restore")
    assert code == 0 and json.loads(out.out)["snapshot_head_hash"]
    code, out = run_cli(tmp_path, monkeypatch, capsys, "restore", "--purge-replaced")
    assert code == 0 and not (tmp_path / "b.db.replaced").exists()
    code, out = run_cli(tmp_path, monkeypatch, capsys, "doctor")
    assert "audit_chain" in out.out and "FAIL database" not in out.out
    assert not [p for p in os.listdir(tmp_path) if p.startswith(".restore-")]


def test_init_db_idempotent_and_wal(tmp_path):
    p = str(tmp_path / "x.db")
    assert ops.init_db(p) == 2 and ops.init_db(p) == 2
    c = connect(p)
    assert c.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert c.execute("SELECT count(*) FROM agents").fetchone()[0] == 2
    assert c.execute("SELECT strict FROM pragma_table_list WHERE name='tasks'").fetchone()[0] == 1
    c.close()
