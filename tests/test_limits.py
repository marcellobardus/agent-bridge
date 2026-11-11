import os

import pytest

from bridge import serve

PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 32


def test_rate_limit_429(make_env):
    e = make_env(per_key_per_min=3)
    for _ in range(3):
        assert e.agent_a.get("/v1/me").status_code == 200
    r = e.agent_a.get("/v1/me")
    assert r.status_code == 429 and r.json()["code"] == "rate_limited" and int(r.headers["retry-after"]) >= 1
    assert e.agent_b.get("/v1/me").status_code == 200   # per key


def test_unauthenticated_budget(make_env):
    e = make_env(unauth_global_per_min=2)
    for _ in range(2):
        assert e.client.get("/v1/me", headers={"Authorization": "Bearer junk"}).status_code == 401
    assert e.client.get("/v1/me", headers={"Authorization": "Bearer junk"}).status_code == 429


def test_request_size_limit_413(make_env):
    e = make_env(max_body_bytes=1000)
    r = e.agent_a.post("/v1/tasks", {"title": "t", "description": "x" * 2000, "responsible_agent_id": "agent-b",
                                     "category": "bug_fix"})
    assert r.status_code == 413 and r.json()["code"] == "payload_too_large"
    # chunked body without Content-Length is also bounded
    r = e.client.post("/v1/tasks", content=iter([b"{" + b" " * 600, b" " * 600 + b"}"]),
                      headers=e.agent_a.h({"Idempotency-Key": "chunked-001", "Content-Type": "application/json"}))
    assert r.status_code == 413


def test_storage_guard_503(make_env):
    e = make_env()
    e.settings.limits.min_free_bytes = 1 << 62
    e.app.state.bridge.storage._at = 0
    r = e.agent_a.post("/v1/tasks", {"title": "t"})
    assert r.status_code == 503 and r.json()["code"] == "storage_degraded"
    assert e.agent_a.get("/v1/tasks").status_code == 200


def upload(agent, task_id, data, ctype, name="f.bin"):
    return agent.post(f"/v1/tasks/{task_id}/artifacts?filename={name}", content=data, headers={"Content-Type": ctype})


def test_artifact_roundtrip_headers(env):
    t = env.agent_a.create_task()
    r = upload(env.agent_a, t["id"], PNG, "image/png", "../shot.png")
    assert r.status_code == 201, r.text
    art = r.json()["artifact"]
    assert art["filename"] == "shot.png" and art["size"] == len(PNG)
    d = env.agent_b.get(f"/v1/artifacts/{art['id']}")
    assert d.status_code == 200 and d.content == PNG
    assert d.headers["content-disposition"] == 'attachment; filename="shot.png"'
    assert d.headers["x-content-type-options"] == "nosniff" and "sandbox" in d.headers["content-security-policy"]
    assert env.agent_b.get(f"/v1/tasks/{t['id']}/artifacts").json()["artifacts"][0]["id"] == art["id"]
    ev = env.agent_b.get("/v1/inbox").json()["events"]
    assert ev[-1]["message"]["type"] == "ARTIFACT_SUBMITTED"


def test_artifact_type_and_content_checks(env):
    t = env.agent_a.create_task()
    assert upload(env.agent_a, t["id"], b"<html>", "text/html").status_code == 415
    assert upload(env.agent_a, t["id"], b"MZ...", "application/x-msdownload").status_code == 415
    r = upload(env.agent_a, t["id"], b"not a png", "image/png")
    assert r.status_code == 422 and r.json()["code"] == "content_mismatch"
    assert upload(env.agent_a, t["id"], b"\xff\xfe", "text/plain").json()["code"] == "content_mismatch"
    assert upload(env.agent_a, t["id"], b"{bad", "application/json").json()["code"] == "content_mismatch"
    assert upload(env.agent_a, t["id"], b"", "text/plain").status_code == 422


def test_artifact_size_and_quota(make_env):
    e = make_env(artifact_max_bytes=100, artifact_task_quota_bytes=150)
    t = e.agent_a.create_task()
    r = upload(e.agent_a, t["id"], b"x" * 101, "text/plain")
    assert r.status_code == 413 and r.json()["code"] == "artifact_too_large"
    r = upload(e.agent_a, t["id"], b"x" * 2000, "text/plain")   # beyond the middleware limit too
    assert r.status_code == 413
    assert upload(e.agent_a, t["id"], b"a" * 100, "text/plain").status_code == 201
    r = upload(e.agent_a, t["id"], b"b" * 100, "text/plain")
    assert r.status_code == 413 and r.json()["code"] == "artifact_quota_exceeded"


def test_artifact_not_visible_to_outsiders(env):
    t = env.agent_a.create_task()
    art = upload(env.agent_a, t["id"], b"hello", "text/plain").json()["artifact"]
    with env.db.write() as c:
        c.execute("INSERT INTO agents (id, party_id, display_name, created_at) VALUES ('qabot','alice','QA',0)")
    assert env.agent("qabot").get(f"/v1/artifacts/{art['id']}").status_code == 404
    assert env.client.get(f"/v1/artifacts/{art['id']}").status_code == 401


@pytest.mark.parametrize("host,ok", [("127.0.0.1", True), ("::1", True), ("localhost", True), ("127.0.0.2", True),
                                     ("0.0.0.0", False), ("::", False), ("10.0.0.5", False), ("example.com", False)])
def test_is_loopback(host, ok):
    assert serve.is_loopback(host) is ok


def test_serve_refuses_public_bind(tmp_path, monkeypatch, capsys):
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "pepper").write_text(os.urandom(32).hex())
    (creds / "totp_kek").write_text(os.urandom(32).hex())
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'db_path = "{tmp_path}/b.db"\nhost = "0.0.0.0"\n')
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))
    assert serve.main(["--config", str(cfg)]) == 2
    assert "refusing to bind" in capsys.readouterr().err
    assert serve.main(["--config", str(cfg), "--host", "192.168.1.10"]) == 2
    assert not (tmp_path / "b.db").exists()
