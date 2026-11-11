import pytest


def msg(agent, task_id, mtype, text="", data=None, in_reply_to=None, refs=None):
    body = {"type": mtype, "body": {"text": text, "data": data or {}, "refs": refs or []}}
    if in_reply_to:
        body["in_reply_to"] = in_reply_to
    return agent.post(f"/v1/tasks/{task_id}/messages", body)


def inbox(agent):
    return agent.get("/v1/inbox").json()


def test_section6_workflow(env):
    g, h = env.agent_a, env.agent_b
    # 1-2: Agent A finds a problem and creates a task for Agent B
    t = g.create_task(title="Unified margin miscalculates cross-collateral", category="bug_fix", priority="high",
                      project="DEMO", component="margin-engine", acceptance_criteria=["repro test passes"])
    assert t["state"] == "proposed" and t["originator_agent_id"] == "agent-a"
    # 3: Agent B retrieves and accepts
    page = inbox(h)
    assert [e["type"] for e in page["events"]] == ["task.created"]
    assert page["events"][0]["message"]["type"] == "TASK_REQUEST"
    h.post("/v1/inbox/ack", {"cursor": page["next_cursor"]})
    assert h.post(f"/v1/tasks/{t['id']}/accept", {}).json()["task"]["state"] == "accepted"
    # 4: Agent B requests reproduction evidence
    q = msg(h, t["id"], "CLARIFICATION_REQUEST", "Please attach a reproduction").json()["message"]
    # 5: Agent A answers with evidence and an artifact
    r = msg(g, t["id"], "CLARIFICATION_RESPONSE", "See attached CSV", in_reply_to=q["id"])
    assert r.status_code == 201
    r = g.post(f"/v1/tasks/{t['id']}/artifacts?filename=repro.csv&note=repro", content=b"a,b\n1,2\n",
               headers={"Content-Type": "text/csv"})
    assert r.status_code == 201, r.text
    # 6: Agent B implements and references the PR
    assert h.to(t["id"], "in_progress").status_code == 200
    r = msg(h, t["id"], "ARTIFACT_SUBMITTED", "fix", refs=[{"kind": "pr", "value": "org/repo#42"}])
    assert r.status_code == 201
    assert h.to(t["id"], "ready_for_validation").json()["task"]["state"] == "ready_for_validation"
    # 7: Agent A receives the validation request
    types = [e["type"] for e in inbox(g)["events"]]
    assert "task.state_changed" in types and types.count("message.created") >= 3
    # 8-9: Agent A validates independently and closes
    r = msg(g, t["id"], "VALIDATION_RESULT", "independently verified", {"outcome": "pass"})
    assert r.json()["task"]["state"] == "verified"
    assert g.to(t["id"], "closed").json()["task"]["state"] == "closed"
    # 10: the whole sequence is in the history
    hist = g.get(f"/v1/tasks/{t['id']}/history").json()["events"]
    kinds = [(e["kind"], e.get("to_state") or (e.get("message") or {}).get("type")) for e in hist]
    for want in [("created", "proposed"), ("message", "TASK_REQUEST"), ("state_changed", "accepted"),
                 ("message", "CLARIFICATION_REQUEST"), ("message", "CLARIFICATION_RESPONSE"),
                 ("message", "ARTIFACT_SUBMITTED"), ("state_changed", "ready_for_validation"),
                 ("message", "VALIDATION_RESULT"), ("state_changed", "verified"), ("state_changed", "closed")]:
        assert want in kinds
    assert h.post(f"/v1/tasks/{t['id']}/messages", {"type": "PROGRESS_UPDATE"}).json()["code"] == "task_closed"


def test_validation_fail_returns_to_in_progress(env):
    t = env.agent_a.create_task()
    for s in ("accepted", "in_progress", "ready_for_validation"):
        env.agent_b.to(t["id"], s)
    r = msg(env.agent_a, t["id"], "VALIDATION_RESULT", "still broken", {"outcome": "fail"})
    assert r.json()["task"]["state"] == "in_progress"
    r = msg(env.agent_a, t["id"], "VALIDATION_RESULT", "x", {"outcome": "pass"})
    assert r.status_code == 409 and r.json()["code"] == "not_ready_for_validation"
    r = msg(env.agent_a, t["id"], "VALIDATION_RESULT", "y", {"outcome": "maybe"})
    assert r.json()["code"] == "invalid_body"


def test_ownership_boundaries(env):
    base = {"title": "t", "description": "d"}
    # Agent A may not ask Agent B for business requirements work; Agent B may not own QA
    r = env.agent_a.post("/v1/tasks", {**base, "responsible_agent_id": "agent-b", "category": "qa"})
    assert r.status_code == 403 and r.json()["code"] == "ownership_violation"
    r = env.agent_b.post("/v1/tasks", {**base, "responsible_agent_id": "agent-a", "category": "backend"})
    assert r.status_code == 403
    # Agent B may request testing / requirement clarification from Agent A
    assert env.agent_b.post("/v1/tasks", {**base, "responsible_agent_id": "agent-a",
                                         "category": "business_requirements"}).status_code == 201
    r = env.agent_a.post("/v1/tasks", {**base, "responsible_agent_id": "agent-a", "category": "qa"})
    assert r.json()["code"] in ("self_assignment", "ownership_violation")
    r = env.agent_a.post("/v1/tasks", {**base, "responsible_agent_id": "nobody", "category": "bug_fix"})
    assert r.json()["code"] == "unknown_agent"


def test_validation_strict(env):
    r = env.agent_a.post("/v1/tasks", {"title": "t", "description": "d", "responsible_agent_id": "agent-b",
                                       "category": "bug_fix", "extra": "nope"})
    assert r.status_code == 422 and r.json()["code"] == "validation_error"
    assert all("input" not in e for e in r.json()["errors"]) and "nope" not in r.text
    r = env.agent_a.post("/v1/tasks", {"title": "t", "description": "d", "responsible_agent_id": "agent-b",
                                       "category": "bug_fix", "refs": [{"kind": "url", "value": "javascript:x"}]})
    assert r.status_code == 422


def test_non_participant_gets_404(env):
    t = env.agent_a.create_task()
    with env.db.write() as c:
        c.execute("INSERT INTO agents (id, party_id, display_name, created_at) VALUES ('qabot','alice','QA',0)")
    other = env.agent("qabot")
    assert other.get(f"/v1/tasks/{t['id']}").status_code == 404
    assert other.post(f"/v1/tasks/{t['id']}/accept", {}).status_code == 404
    assert other.get("/v1/tasks").json()["tasks"] == []


def test_list_search_get(env):
    t = env.agent_a.create_task(title="Oracle price staleness", project="DEMO")
    msg(env.agent_a, t["id"], "CLARIFICATION_REQUEST", "the keyword zebracorn appears here")
    assert env.agent_b.get("/v1/tasks?role=responsible").json()["tasks"][0]["id"] == t["id"]
    assert env.agent_b.get("/v1/tasks?role=originator").json()["tasks"] == []
    assert env.agent_a.get("/v1/tasks?project=DEMO&state=proposed").json()["tasks"][0]["id"] == t["id"]
    assert env.agent_a.get("/v1/tasks/search?q=staleness").json()["tasks"][0]["id"] == t["id"]
    assert env.agent_a.get("/v1/tasks/search?q=zebracorn").json()["tasks"][0]["id"] == t["id"]
    assert env.agent_a.get("/v1/tasks/search?q=100%25").json()["tasks"] == []
    d = env.agent_b.get(f"/v1/tasks/{t['id']}").json()
    assert d["task"]["acceptance_criteria"] == ["tests pass"] and len(d["messages"]) == 2


def test_duplicate_task_detection(env):
    t = env.agent_a.create_task(title="Same", description="Same body")
    r = env.agent_a.post("/v1/tasks", {"title": "same ", "description": "Same body", "responsible_agent_id": "agent-b",
                                       "category": "bug_fix"})
    assert r.status_code == 409 and r.json()["existing_task_id"] == t["id"]
    env.agent_a.to(t["id"], "closed")
    assert env.agent_a.create_task(title="Same", description="Same body")["id"] != t["id"]


def test_message_dedupe_and_progress_exempt(env):
    t = env.agent_a.create_task()
    env.agent_b.post(f"/v1/tasks/{t['id']}/accept", {})
    r1 = msg(env.agent_a, t["id"], "CLARIFICATION_REQUEST", "same question")
    r2 = msg(env.agent_a, t["id"], "CLARIFICATION_REQUEST", "same question")
    assert r1.status_code == 201 and r2.status_code == 200
    assert r2.headers["bridge-deduplicated"] == "true" and r2.json()["message"]["id"] == r1.json()["message"]["id"]
    p1 = msg(env.agent_b, t["id"], "PROGRESS_UPDATE", "50%")
    p2 = msg(env.agent_b, t["id"], "PROGRESS_UPDATE", "50%")
    assert p1.status_code == p2.status_code == 201 and p1.json()["message"]["id"] != p2.json()["message"]["id"]


def test_clarification_rounds_bounded_then_needs_human(env):
    t = env.agent_a.create_task()
    env.agent_b.post(f"/v1/tasks/{t['id']}/accept", {})
    for i in range(3):
        assert msg(env.agent_b, t["id"], "CLARIFICATION_REQUEST", f"q{i}").status_code == 201
    r = msg(env.agent_b, t["id"], "CLARIFICATION_REQUEST", "q4")
    assert r.status_code == 409 and r.json()["code"] == "loop_guard"
    task = env.agent_a.get(f"/v1/tasks/{t['id']}").json()["task"]
    assert task["state"] == "needs_human" and task["resume_state"] == "accepted"
    # agents can no longer move it; only a human can
    assert env.agent_b.to(t["id"], "in_progress").status_code == 403


def test_clarification_response_rules(env):
    t = env.agent_a.create_task()
    q = msg(env.agent_b, t["id"], "CLARIFICATION_REQUEST", "?").json()["message"]
    assert msg(env.agent_b, t["id"], "CLARIFICATION_RESPONSE", "self", in_reply_to=q["id"]).json()["code"] == "invalid_parent"
    assert msg(env.agent_a, t["id"], "CLARIFICATION_RESPONSE", "no parent").json()["code"] == "invalid_parent"
    assert msg(env.agent_a, t["id"], "CLARIFICATION_RESPONSE", "a", in_reply_to=q["id"]).status_code == 201
    r = msg(env.agent_a, t["id"], "CLARIFICATION_RESPONSE", "b", in_reply_to=q["id"])
    assert r.status_code == 409 and r.json()["code"] == "already_responded"


def test_sender_rules(env):
    t = env.agent_a.create_task()
    assert msg(env.agent_a, t["id"], "PROGRESS_UPDATE", "x").json()["code"] == "sender_not_allowed"
    assert msg(env.agent_a, t["id"], "TASK_ACCEPTED").json()["code"] == "sender_not_allowed"
    r = env.agent_a.post(f"/v1/tasks/{t['id']}/messages", {"type": "HUMAN_INSTRUCTION", "body": {"text": "x"}})
    assert r.status_code == 422


def test_reply_depth_guard(make_env):
    e = make_env(max_reply_depth=2)
    t = e.agent_a.create_task()
    parent = None
    for i, a in enumerate([e.agent_a, e.agent_b, e.agent_a]):
        r = msg(a, t["id"], "ARTIFACT_SUBMITTED", f"r{i}", refs=[{"kind": "other", "value": str(i)}], in_reply_to=parent)
        assert r.status_code == 201
        parent = r.json()["message"]["id"]
    r = msg(e.agent_b, t["id"], "ARTIFACT_SUBMITTED", "deep", refs=[{"kind": "other", "value": "x"}], in_reply_to=parent)
    assert r.json()["code"] == "loop_guard"


def test_agent_streak_guard(make_env):
    e = make_env(max_agent_streak=4)
    t = e.agent_a.create_task()   # TASK_REQUEST counts as 1
    e.agent_b.post(f"/v1/tasks/{t['id']}/accept", {})
    msg(e.agent_b, t["id"], "PROGRESS_UPDATE", "a")
    msg(e.agent_b, t["id"], "PROGRESS_UPDATE", "b")
    r = msg(e.agent_b, t["id"], "PROGRESS_UPDATE", "c")
    assert r.status_code == 409 and r.json()["code"] == "loop_guard"
    assert e.agent_a.get(f"/v1/tasks/{t['id']}").json()["task"]["state"] == "needs_human"


def test_hop_guard(make_env):
    e = make_env(max_hop_count=1)
    t0 = e.agent_a.create_task()
    t1 = e.agent_a.create_task(parent_task_id=t0["id"])
    assert t1["hop_count"] == 1
    r = e.agent_a.post("/v1/tasks", {"title": "x", "description": "y", "responsible_agent_id": "agent-b",
                                     "category": "bug_fix", "parent_task_id": t1["id"]})
    assert r.status_code == 409 and r.json()["code"] == "loop_guard"


def test_decision_request_escalates(env):
    t = env.agent_a.create_task()
    r = env.agent_b.post(f"/v1/tasks/{t['id']}/decision-request", {"reason": "scope unclear"})
    assert r.status_code == 201 and r.json()["task"]["state"] == "needs_human"
    assert r.json()["message"]["type"] == "DECISION_REQUEST"


def test_reject_via_endpoint(env):
    t = env.agent_a.create_task()
    r = env.agent_b.post(f"/v1/tasks/{t['id']}/reject", {"reason": "not engineering work"})
    assert r.json()["task"]["state"] == "rejected" and r.json()["message"]["type"] == "TASK_REJECTED"


@pytest.mark.parametrize("who", ["agent", "party"])
def test_paused_agent_gets_423(env, who):
    with env.db.write() as c:
        if who == "agent":
            c.execute("UPDATE agents SET paused_at=1 WHERE id='agent-a'")
        else:
            c.execute("UPDATE parties SET paused_at=1 WHERE id='alice'")
    r = env.agent_a.post("/v1/tasks", {"title": "t"})
    assert r.status_code == 423 and r.json()["code"] == "agent_paused"
    assert env.agent_a.get("/v1/tasks").status_code == 200
