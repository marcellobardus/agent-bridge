import threading

from bridge.domain import inbox, messages, tasks
from bridge.domain.common import Actor


def test_inbox_ack_and_default_cursor(env):
    t = env.agent_a.create_task()
    page = env.agent_b.get("/v1/inbox").json()
    assert len(page["events"]) == 1 and page["has_more"] is False and page["poll_after_s"] == 900
    assert page["pending_approvals"] == 0
    # own actions never appear in your inbox
    assert env.agent_a.get("/v1/inbox").json()["events"] == []
    # unacked events are redelivered
    assert env.agent_b.get("/v1/inbox").json()["events"][0]["id"] == page["events"][0]["id"]
    r = env.agent_b.post("/v1/inbox/ack", {"cursor": page["next_cursor"]})
    assert r.json()["acked_seq"] == page["next_cursor"]
    assert env.agent_b.get("/v1/inbox").json()["events"] == []
    # ack is monotonic and clamped
    assert env.agent_b.post("/v1/inbox/ack", {"cursor": 0}).json()["acked_seq"] == page["next_cursor"]
    assert env.agent_b.post("/v1/inbox/ack", {"cursor": 10**9}).json()["acked_seq"] < 10**9
    # explicit cursor reads history again
    assert len(env.agent_b.get("/v1/inbox?cursor=0").json()["events"]) == 1
    env.agent_b.post(f"/v1/tasks/{t['id']}/accept", {})
    ev = env.agent_a.get("/v1/inbox").json()["events"]
    assert {e["type"] for e in ev} == {"message.created", "task.state_changed"}


def test_paging_has_more(env):
    for i in range(5):
        env.agent_a.create_task(title=f"page {i}")
    p1 = env.agent_b.get("/v1/inbox?limit=3").json()
    assert len(p1["events"]) == 3 and p1["has_more"] and p1["poll_after_s"] == 0
    p2 = env.agent_b.get(f"/v1/inbox?limit=3&cursor={p1['next_cursor']}").json()
    assert len(p2["events"]) == 2 and not p2["has_more"]


def test_cursor_never_skips_under_concurrent_writers(make_env):
    e = make_env(tasks_per_agent_per_day=10**6, messages_per_agent_per_day=10**6, max_agent_streak=10**6,
                 max_messages_per_task=10**6)
    g = Actor("agent", "agent-a", "alice")
    with e.db.write() as c:
        tid = tasks.create(c, g, {"title": "load", "description": "d", "responsible_agent_id": "agent-b",
                                  "category": "bug_fix", "priority": "normal"}, e.settings.limits)["task"]["id"]
    writers, per_writer, seen, stop = 8, 40, [], threading.Event()

    def write(n):
        for i in range(per_writer):
            with e.db.write() as c:
                messages.post_message(c, g, tid, "ARTIFACT_SUBMITTED",
                                      {"text": f"{n}-{i}", "data": {}, "refs": [{"kind": "other", "value": "x"}]},
                                      None, e.settings.limits)

    def read():
        cursor = 0
        while True:
            done = stop.is_set()
            with e.db.read() as c:
                page = inbox.fetch(c, "agent-b", cursor, 7, 900)
            seen.extend(ev["seq"] for ev in page["events"])
            cursor = page["next_cursor"]
            if done and not page["events"]:
                break

    r = threading.Thread(target=read)
    r.start()
    ws = [threading.Thread(target=write, args=(n,)) for n in range(writers)]
    for w in ws:
        w.start()
    for w in ws:
        w.join()
    stop.set()
    r.join()
    with e.db.read() as c:
        all_seqs = [x[0] for x in c.execute("SELECT seq FROM events WHERE recipient_agent_id='agent-b' ORDER BY seq")]
    assert len(all_seqs) == 1 + writers * per_writer
    assert seen == all_seqs           # every event seen exactly once, in order
