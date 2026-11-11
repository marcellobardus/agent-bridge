import logging


def test_no_secrets_or_bodies_in_logs(env, caplog):
    env.add_human("alice", "alice")
    caplog.set_level(logging.INFO, logger="bridge")
    marker = "SECRET-BODY-MARKER-7f3a"
    t = env.agent_a.create_task(description=f"contains {marker}")
    env.agent_b.post(f"/v1/tasks/{t['id']}/messages?x={marker}",
                    {"type": "PROGRESS_UPDATE", "body": {"text": marker}})
    env.client.get("/v1/me", headers={"Authorization": "Bearer abk_aaaaaaaaaaaa_" + "B" * 43})
    m = env.login("alice")
    env.client.post("/app/login", data={"login": "alice", "password": "hunter2-wrong-pass", "totp": "123456"})
    m.post(f"/app/tasks/{t['id']}/instruction", text=marker)
    text = "\n".join(r.getMessage() + str(getattr(r, "fields", "")) for r in caplog.records)
    assert "request" in text and "/v1/tasks" in text
    for secret in (env.agent_a.token, env.agent_a.token.split("_", 2)[2], env.agent_b.token.split("_", 2)[2],
                   "B" * 43, marker, "correct horse battery", "hunter2", m.csrf):
        assert secret not in text
    fields = [getattr(r, "fields", {}) for r in caplog.records if r.getMessage() == "request"]
    assert any(f.get("principal") == "agent-a" and f.get("key_id") for f in fields)
