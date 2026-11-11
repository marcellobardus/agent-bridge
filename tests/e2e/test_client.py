"""Client behaviour: next_poll_at gating (zero requests), idle-month budget, per-event error handling,
ack only non-empty pages, atomic 0600 state, key redaction, CLI exit codes, insecure URL / redirect refusal."""
import io
import json
import os
import stat
import subprocess
import sys
import urllib.error

import pytest
from e2e_support import PY, REPO, server  # noqa: F401  (pytest fixture); first: sets sys.path
from agent_bridge_client import (BridgeClient, BridgeError, ConfigError, TransientError, event_key, load_state,
                                 poll_once, redact)
from agent_bridge_client import poller

CLIENT_PATH = os.path.join(REPO, "clients", "python")
# Documented budget (SPEC §9, integration-kit/PROTOCOL.md): ngrok free ~20k requests/month in total.
MONTHLY_BUDGET = 20_000
IDLE_POLLS_PER_AGENT_MONTH = 2_880          # one request per 15 min for 30 days


class FakeResp:
    def __init__(self, obj, status=200):
        self._b, self.status, self.headers = json.dumps(obj).encode(), status, {}

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeBridge:
    """In-process fake transport for budget simulations (no network)."""

    def __init__(self, pages=None, poll_after_s=900):
        self.pages, self.poll_after_s, self.calls = list(pages or []), poll_after_s, []

    def __call__(self, req, timeout):
        self.calls.append((req.get_method(), req.full_url, dict(req.header_items())))
        if "/v1/inbox/ack" in req.full_url:
            return FakeResp({"acked_seq": json.loads(req.data)["cursor"]})
        if "/v1/inbox" in req.full_url:
            if self.pages:
                return FakeResp(self.pages.pop(0))
            return FakeResp({"events": [], "next_cursor": 0, "has_more": False, "poll_after_s": self.poll_after_s,
                             "pending_approvals": 0, "server_time": "x"})
        if "/v1/approvals" in req.full_url:
            return FakeResp({"approvals": [{"id": "apr_1", "state": "pending"}]})
        return FakeResp({})


def fake_client(fake):
    return BridgeClient("https://bridge.example", "abk_testkeyid0001_" + "s" * 43, urlopen=fake,
                        sleep=lambda s: None)


def test_next_poll_at_gating_makes_zero_requests(server, tmp_path):
    g = server.client("agent-a")
    state = str(tmp_path / "s.json")
    rep = poll_once(g, state)
    assert rep["requests"] == 1 and rep["events"] == []          # idle poll = exactly one request, no ack
    before = g.requests_made
    for _ in range(5):
        rep = poll_once(g, state)
        assert rep["skipped"] and rep["requests"] == 0
    assert g.requests_made == before
    st = load_state(state)
    assert st["next_poll_at"] > st["last_run_at"] + 800           # server poll_after_s=900 honoured (minus slack)
    assert stat.S_IMODE(os.stat(state).st_mode) == 0o600
    assert not [f for f in os.listdir(tmp_path) if f.startswith(".state-")]   # atomic write left no temp files


def test_cli_poll_gated_by_state_file(server, tmp_path):
    env = {**server.env, "PYTHONPATH": CLIENT_PATH, "AGENT_BRIDGE_URL": server.url,
           "AGENT_BRIDGE_KEY_FILE": os.path.join(server.tmp, "agent-a.key"),
           "AGENT_BRIDGE_STATE": str(tmp_path / "cli-state.json")}

    def cli(*args):
        return subprocess.run([PY, "-m", "agent_bridge_client", *args], env=env, capture_output=True, text=True,
                              timeout=60)

    h = server.client("agent-b")
    p = cli("task", "create", "--to", "agent-b", "--title", "CLI margin task", "--description", "from the CLI",
            "--category", "bug_fix", "--criterion", "fixed", "--ref", "url=https://example.com/report")
    assert p.returncode == 0, p.stderr
    tid = json.loads(p.stdout)["task"]["item_id"]                # write echoes are wrapped too
    h.accept(tid, "ok")
    p = cli("poll")
    lines = [json.loads(x) for x in p.stdout.splitlines()]
    assert p.returncode == 0 and [x["type"] for x in lines] == ["message.created", "task.state_changed"]
    p2 = cli("poll-once")
    rep = json.loads(p2.stdout)
    assert p2.returncode == 0 and rep["skipped"] and rep["requests"] == 0
    # deterministic refusal -> exit 1; key never printed anywhere
    p3 = cli("status", tid, "ready_for_validation")
    assert p3.returncode == 1 and json.loads(p3.stderr)["error"]["code"] == "transition_forbidden"
    tok = server.tokens["agent-a"]
    for out in (p, p2, p3):
        assert tok not in out.stdout + out.stderr
    # artifact upload / download round trip and history via the CLI
    f = tmp_path / "evidence.md"
    f.write_text("# repro\nmargin off by 14%\n")
    p = cli("artifact", "upload", tid, str(f), "--note", "evidence")
    aid = json.loads(p.stdout)["artifact"]["item_id"]
    p = cli("artifact", "download", aid, "--out", str(tmp_path / "dl.md"))
    assert p.returncode == 0 and (tmp_path / "dl.md").read_text() == f.read_text()
    p = cli("history", tid)
    items = json.loads(p.stdout)["items"]
    kinds = [i["untrusted_data"]["kind"] for i in items]      # wrapped by default
    assert "artifact" in kinds
    # revoked key -> exit 4
    server.cli("key", "revoke", server.key_ids["agent-a"])
    p = cli("me")
    assert p.returncode == 4 and tok not in p.stderr


def test_idle_month_stays_within_budget(tmp_path):
    """30 days of a routine firing every 5 minutes (stricter than the 15-min schedule) while nothing happens."""
    totals = {}
    for routine_every in (300, 900):
        fake = FakeBridge()
        c = fake_client(fake)
        state = str(tmp_path / f"idle-{routine_every}.json")
        t = 1_800_000_000.0
        end = t + 30 * 86400
        while t < end:
            poll_once(c, state, now=lambda t=t: t)
            t += routine_every
        totals[routine_every] = len(fake.calls)
        assert all(m == "GET" and "/v1/inbox" in u for m, u, _ in fake.calls)   # idle: no acks, no extra reads
        assert all(h.get("Ngrok-skip-browser-warning") == "1" for _, _, h in fake.calls)
    assert totals[900] <= IDLE_POLLS_PER_AGENT_MONTH
    assert totals[300] <= IDLE_POLLS_PER_AGENT_MONTH
    # two idle agents + the documented dashboard/write allowance stay far below the free-plan budget
    assert 2 * max(totals.values()) + 1_800 + 2_000 < MONTHLY_BUDGET / 2


def _page(events, cursor, has_more=False, pending=0):
    return {"events": events, "next_cursor": cursor, "has_more": has_more, "poll_after_s": 0 if has_more else 900,
            "pending_approvals": pending, "server_time": "x"}


def _ev(i, typ="message.created"):
    return {"seq": i, "id": f"evt_{i:08d}", "type": typ, "task_id": "tsk_1", "created_at": "x"}


def test_per_event_errors_are_recorded_and_acked(tmp_path):
    fake = FakeBridge([_page([_ev(1), _ev(2), _ev(3)], 3)])
    c = fake_client(fake)
    handled = []

    def handler(client, ev):
        handled.append(ev["id"])
        if ev["seq"] == 2:
            raise BridgeError(409, "loop_guard", "stop and wait for a human")

    rep = poll_once(c, str(tmp_path / "s.json"), handler)
    assert handled == ["evt_00000001", "evt_00000002", "evt_00000003"]
    assert rep["failed"] == [{"event": "evt_00000002", "task_id": "tsk_1", "status": 409, "code": "loop_guard",
                              "detail": "stop and wait for a human"}]
    assert sum("/ack" in u for _, u, _ in fake.calls) == 1 and rep["cursor"] == 3


def test_transient_error_stops_run_without_ack_then_resumes(tmp_path):
    fake = FakeBridge([_page([_ev(1), _ev(2)], 2), _page([_ev(1), _ev(2)], 2)])
    c = fake_client(fake)
    state = str(tmp_path / "s.json")
    calls = []

    def handler(client, ev):
        calls.append(ev["id"])
        if ev["seq"] == 2 and calls.count(ev["id"]) == 1:
            raise TransientError(503, "storage_degraded", "", retry_after=120)

    rep = poll_once(c, state, handler, now=lambda: 1000.0)
    assert rep["last_error"]["code"] == "storage_degraded" and not any("/ack" in u for _, u, _ in fake.calls)
    assert rep["next_poll_at"] >= 1000 + 60
    assert poll_once(c, state, handler, now=lambda: 1001.0)["skipped"]        # backoff respected
    rep = poll_once(c, state, handler, now=lambda: 2000.0)
    assert rep["last_error"] is None and [e["id"] for e in rep["events"]] == ["evt_00000002"]  # evt 1 not re-handled
    assert calls == ["evt_00000001", "evt_00000002", "evt_00000002"]
    assert sum("/ack" in u for _, u, _ in fake.calls) == 1


def test_has_more_drains_and_approvals_fetched_only_on_change(tmp_path):
    fake = FakeBridge([_page([_ev(1)], 1, has_more=True), _page([_ev(2, "approval.decided")], 2, pending=1)])
    c = fake_client(fake)
    state = str(tmp_path / "s.json")
    rep = poll_once(c, state, now=lambda: 0.0)
    urls = [u for _, u, _ in fake.calls]
    assert sum("/v1/inbox?" in u for u in urls) == 2 and sum("/ack" in u for u in urls) == 2
    assert sum("/v1/approvals" in u for u in urls) == 1 and rep["pending_approvals"][0]["id"] == "apr_1"
    n = len(fake.calls)
    fake.pages = [_page([], 2, pending=1)]
    poll_once(c, state, now=lambda: 10_000.0)                                  # count unchanged -> no list fetch
    assert len(fake.calls) == n + 1


def test_handler_bug_retried_three_runs_then_recorded(tmp_path):
    fake = FakeBridge()
    c = fake_client(fake)
    state = str(tmp_path / "s.json")

    def bad(client, ev):
        raise KeyError("oops")

    for i in range(3):
        fake.pages = [_page([_ev(1)], 1)]
        rep = poll_once(c, state, bad, force=True)
    assert rep["failed"][0]["code"] == "handler_error" and rep["cursor"] == 1


def test_headers_redaction_and_safety():
    fake = FakeBridge()
    key = "abk_testkeyid0001_" + "s" * 43
    c = BridgeClient("https://bridge.example/", key, urlopen=fake, sleep=lambda s: None)
    c.post("/v1/inbox/ack", {"cursor": 1})
    _, url, h = fake.calls[0]
    h = {k.title(): v for k, v in h.items()}
    assert h["Authorization"] == f"Bearer {key}" and h["Ngrok-Skip-Browser-Warning"] == "1"
    assert h["Idempotency-Key"].startswith("cli-") and len(h["Idempotency-Key"]) >= 8
    assert key not in repr(c) and key not in redact(f"oops {key}") and "***" in redact(f"oops {key}")
    assert redact("abk_otherkey0001_" + "x" * 43) == "abk_***"
    with pytest.raises(ConfigError):
        BridgeClient("http://bridge.example", key)                              # plain http only to loopback
    BridgeClient("http://127.0.0.1:8787", key)
    assert event_key({"id": "evt_abc"}, 2) == "evt_abc:2"


def test_retry_reuses_idempotency_key_and_redirects_not_followed():
    seen = []

    def flaky(req, timeout):
        seen.append(req.get_header("Idempotency-key"))
        if len(seen) < 3:
            raise urllib.error.HTTPError(req.full_url, 502, "bad gateway", {}, io.BytesIO(b""))
        return FakeResp({"ok": True})

    c = fake_client(flaky)
    assert c.post("/v1/tasks", {"x": 1}) == {"ok": True}
    assert len(seen) == 3 and len(set(seen)) == 1

    def redirect(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 302, "Found", {"Location": "https://evil.example/"},
                                     io.BytesIO(b""))
    with pytest.raises(BridgeError) as ei:
        fake_client(redirect).me()
    assert ei.value.status == 302 and not ei.value.transient

    def down(req, timeout):
        raise urllib.error.URLError("connection refused")
    c = fake_client(down)
    with pytest.raises(TransientError) as ei:
        c.me()
    assert ei.value.code == "network_error" and c.requests_made == 4          # 1 + 3 retries


def test_state_lock_prevents_overlapping_runs(tmp_path):
    state = str(tmp_path / "s.json")
    import fcntl
    os.makedirs(tmp_path, exist_ok=True)
    fd = os.open(state + ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        fake = FakeBridge()
        rep = poll_once(fake_client(fake), state, force=True)
        assert rep["skipped"] and fake.calls == []
    finally:
        os.close(fd)
    assert poller.DEFAULT_INTERVAL_S == 900


def test_python_module_entry_point_help():
    p = subprocess.run([sys.executable, "-m", "agent_bridge_client", "--help"], capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": CLIENT_PATH, "PYTHONDONTWRITEBYTECODE": "1"})
    assert p.returncode == 0 and "poll-once" in p.stdout
