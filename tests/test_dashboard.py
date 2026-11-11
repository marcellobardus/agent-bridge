"""Dashboard (server-rendered HTML): escaping of hostile agent content, CSP/no-store, CSRF, step-up, party rules."""
import base64
import re
import time
import urllib.parse

import pytest
from fastapi.testclient import TestClient

from bridge import ops
from bridge.domain import humans
from bridge.domain.common import Actor, insert_message, load_task

HTML = {"Accept": "text/html,application/xhtml+xml"}
HOSTILE = ('<script>alert(1)</script>"><img src=x onerror=alert(2)>'
           '<a href="javascript:alert(3)">x</a><style>body{display:none}</style>')
ACTION = {"service": "margin-engine", "cmd": HOSTILE, "env": "prod"}


def fresh(env):
    return TestClient(env.app, base_url="https://testserver")


def page(h, path, status=200):
    r = h.c.get(path, headers=HTML)
    assert r.status_code == status, (path, r.status_code, r.text[:500])
    assert r.headers["content-type"].startswith("text/html")
    return r


def assert_safe(r):
    body = r.text
    low = body.lower()
    assert "<script" not in low and "<img" not in low and "<style" not in low
    assert not re.search(r"""(href|src|action)\s*=\s*["']?\s*javascript:""", low)
    for tag in re.findall(r"<[a-zA-Z][^>]*>", body):          # no event-handler attributes in any real tag
        assert not re.search(r"\son\w+\s*=", tag), tag
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "style-src 'self'" in csp and "script-src" not in csp
    assert "frame-ancestors 'none'" in csp
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in body


@pytest.fixture
def denv(env):
    env.add_human("alice", "alice")
    env.add_human("bob", "bob")
    return env


@pytest.fixture
def hostile(denv):
    """A task full of hostile agent-written content in every field the dashboard renders."""
    g, h = denv.agent_a, denv.agent_b
    t = g.create_task(title="Margin " + HOSTILE[:150], description=HOSTILE, acceptance_criteria=[HOSTILE],
                      project="demo<script>", component='"><img src=x>')
    assert h.post(f"/v1/tasks/{t['id']}/accept").status_code in (200, 201)
    r = h.post(f"/v1/tasks/{t['id']}/messages", {"type": "CLARIFICATION_REQUEST",
               "body": {"text": HOSTILE, "data": {"why": HOSTILE}, "refs": [
                   {"kind": "url", "value": "https://example.com/?q=1&x=2", "label": HOSTILE[:100]},
                   {"kind": "commit", "value": HOSTILE[:200]}]}})
    assert r.status_code == 201, r.text
    req = r.json()["message"]
    r = g.post(f"/v1/tasks/{t['id']}/messages", {"type": "CLARIFICATION_RESPONSE", "in_reply_to": req["id"],
               "body": {"text": "evidence " + HOSTILE}})
    assert r.status_code == 201, r.text
    r = g.post(f"/v1/tasks/{t['id']}/artifacts?filename=" + urllib.parse.quote('"><img src=x onerror=1>.csv'),
               content=HOSTILE.encode(), headers={"Content-Type": "text/csv"})
    assert r.status_code == 201, r.text
    r = h.post(f"/v1/tasks/{t['id']}/approvals", {"kind": "prod_deploy", "summary": HOSTILE[:400], "action": ACTION})
    assert r.status_code == 201, r.text
    apr = r.json()["approval"]
    # bypass API validation: refs the API would refuse (javascript: URLs, bogus task/artifact ids)
    with denv.db.write() as c:
        insert_message(c, load_task(c, t["id"]), Actor("agent", "agent-b", "bob"), "PROGRESS_UPDATE",
                       {"text": "javascript:alert(4)", "data": {"artifact_ids": ['"><img src=x>', "javascript:alert(5)"]},
                        "refs": [{"kind": "url", "value": "javascript:alert(6)"},
                                 {"kind": "url", "value": " JaVaScRiPt:alert(7)"},
                                 {"kind": "task", "value": "javascript:alert(8)"}]})
        c.execute("UPDATE agents SET display_name=? WHERE id='agent-b'", (HOSTILE,))
    return t, apr


def test_every_page_escapes_hostile_agent_content(denv, hostile):
    t, apr = hostile
    m = denv.login("alice")
    pages = ["/app/", "/app/tasks", "/app/tasks?scope=all&q=script", "/app/tasks?scope=history",
             f"/app/tasks/{t['id']}", "/app/approvals", "/app/approvals?state=all&q=img", f"/app/approvals/{apr['id']}",
             "/app/agents", "/app/agents/agent-b", "/app/agents/agent-a", "/app/audit", "/app/audit?actor=agent-b",
             "/app/step-up?next=/app/agents"]
    for p in pages:
        assert_safe(page(m, p))
    detail = page(m, f"/app/tasks/{t['id']}").text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in detail          # shown as text, escaped
    assert "agent-written" in detail
    # agent-supplied URLs are plain, escaped text, never links
    assert '<code class="extlink">https://example.com/?q=1&amp;x=2</code>' in detail
    assert "copy to open" in detail and 'href="https://example.com' not in detail
    assert 'javascript:alert(6)</code>' in detail and 'href="javascript' not in detail
    assert "CLARIFICATION_REQUEST" in detail and "CLARIFICATION_RESPONSE" in detail
    art = re.findall(r'href="(/app/artifacts/[^"]+)"', detail)
    assert len(art) >= 1 and all(re.fullmatch(r"/app/artifacts/art_[0-9a-z]{26}", a) for a in art)
    d = m.c.get(art[0])                                                   # download only, never inline
    assert d.headers["content-disposition"].startswith("attachment") and d.headers["x-content-type-options"] == "nosniff"
    ap = page(m, f"/app/approvals/{apr['id']}").text
    assert apr["action_sha256"] in ap and "matches stored canonical bytes" in ap
    assert "agent-written" in ap


def test_logged_out_pages(denv, hostile):
    c = fresh(denv)
    r = c.get("/app/login", headers=HTML)
    assert_safe(r)
    r = c.get("/app/", headers=HTML, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/app/login"
    css = c.get("/app/static/dashboard.css")
    assert css.status_code == 200 and css.headers["content-type"].startswith("text/css")
    assert "@import" not in css.text and "url(" not in css.text      # no external fonts/assets


def _pre(r):
    return re.search(r'name="pre_csrf" value="([^"]+)"', r.text).group(1)


def test_html_login_flow(denv):
    c = fresh(denv)
    pre = _pre(c.get("/app/login", headers=HTML))
    r = c.post("/app/login", data={"login": "alice", "password": "wrong password!!", "totp": "000000",
                                   "pre_csrf": pre}, headers=HTML)
    assert r.status_code == 401 and "Invalid login, password or code." in r.text and "<form" in r.text
    assert _pre(r) == pre                                  # the re-rendered form keeps the same token
    r = c.post("/app/login", data={"login": "alice", "password": "correct horse battery",
                                   "totp": denv.code("alice"), "pre_csrf": pre}, headers=HTML,
               follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/app/"
    assert r.headers["set-cookie"].startswith("__Host-ab_session=")
    home = c.get("/app/", headers=HTML)
    assert home.status_code == 200 and "Alice" in home.text
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', home.text).group(1)
    r = c.post("/app/logout", data={"csrf_token": csrf}, headers=HTML, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/app/login"
    assert c.get("/app/", headers=HTML, follow_redirects=False).status_code == 303


def test_json_routes_unchanged(denv):
    t = denv.agent_a.create_task()
    m = denv.login("alice")
    r = m.post(f"/app/tasks/{t['id']}/priority", priority="high")
    assert r.status_code == 200 and r.json()["task"]["priority"] == "high"
    assert m.get("/app/api/me").json()["login"] == "alice"
    assert m.c.get("/app/api/tasks/nope", headers=HTML).headers["content-type"].startswith("application/problem+json")


def test_csrf_missing_is_403(denv):
    t = denv.agent_a.create_task()
    m = denv.login("alice")
    for path, data in ((f"/app/tasks/{t['id']}/instruction", {"text": "hi"}), (f"/app/tasks/{t['id']}/pause", {}),
                       ("/app/agents/agent-a/pause", {}), ("/app/agents/agent-a/keys", {}), ("/app/step-up", {"totp": "1"}),
                       ("/app/logout", {})):
        r = m.c.post(path, data=data, headers=HTML)
        assert r.status_code == 403 and "csrf_failed" in r.text, path
        r = m.c.post(path, data={**data, "csrf_token": "forged"})
        assert r.status_code == 403 and r.json()["code"] == "csrf_failed"
    r = m.c.post(f"/app/tasks/{t['id']}/pause", data={"csrf_token": m.csrf},
                 headers={**HTML, "Origin": "https://evil.example"})
    assert r.status_code == 403 and "bad_origin" in r.text
    with denv.db.read() as c:
        assert c.execute("SELECT paused_at FROM tasks WHERE id=?", (t["id"],)).fetchone()[0] is None


def test_task_actions_via_forms(denv):
    t = denv.agent_a.create_task()
    m = denv.login("bob")
    tid = t["id"]
    for action, data, ok in (("instruction", {"text": "Look at <the> liquidation path"}, "instruction"),
                             ("priority", {"priority": "urgent"}, "priority"),
                             ("pause", {"reason": "hold"}, "pause"), ("resume", {}, "resume"),
                             ("escalate", {"reason": "unclear scope"}, "escalate"),
                             ("approve", {"reason": "go"}, "approve")):
        r = m.c.post(f"/app/tasks/{tid}/{action}", data={"csrf_token": m.csrf, **data}, headers=HTML,
                     follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == f"/app/tasks/{tid}?ok={ok}", (action, r.text)
    p = page(m, f"/app/tasks/{tid}?ok=approve")
    assert "Task approved." in p.text and "HUMAN_INSTRUCTION" in p.text and "Look at &lt;the&gt;" in p.text
    assert re.search(r'class="state s-accepted"', p.text) and "p-urgent" in p.text
    r = m.c.post(f"/app/tasks/{tid}/transition", data={"csrf_token": m.csrf, "to": "rejected"}, headers=HTML)
    assert r.status_code == 422 and "reason" in r.text.lower() and f'href="/app/tasks/{tid}"' in r.text
    r = m.c.post(f"/app/tasks/{tid}/reject", data={"csrf_token": m.csrf, "reason": "dup"}, headers=HTML)
    assert r.status_code == 200 and "(final)" in r.text and "Send instruction" not in r.text
    assert page(m, "/app/tasks?scope=history").text.count(tid) >= 1
    assert page(m, "/app/tasks/tsk_00000000000000000000000000", status=404)


def test_decision_requires_step_up_and_is_single_use(denv, hostile):
    t, apr = hostile
    b = denv.login("bob", step_up=False)    # a fresh login is not a step-up
    p = page(b, f"/app/approvals/{apr['id']}").text
    assert "Step-up required" in p and "/decide" not in p
    r = b.c.post(f"/app/approvals/{apr['id']}/decide", data={"csrf_token": b.csrf, "decision": "approve"}, headers=HTML)
    assert r.status_code == 403 and "Step-up required" in r.text
    assert b.post(f"/app/approvals/{apr['id']}/decide", decision="approve").json()["code"] == "step_up_required"
    r = b.c.post("/app/step-up?next=/app/approvals/" + apr["id"], data={"csrf_token": b.csrf, "password": "correct horse battery", "totp": "000000"},
                 headers=HTML)
    assert r.status_code == 401 and "invalid or already used code" in r.text
    r = b.c.post("/app/step-up?next=/app/approvals/" + apr["id"],
                 data={"csrf_token": b.csrf, "password": "correct horse battery",
                       "totp": denv.code("bob", time.time() + 30)}, headers=HTML,
                 follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/app/approvals/{apr['id']}?ok=stepup"
    p = page(b, f"/app/approvals/{apr['id']}").text
    assert "Approve this exact payload" in p
    r = b.c.post(f"/app/approvals/{apr['id']}/decide", data={"csrf_token": b.csrf, "decision": "approve", "note": "ok"},
                 headers=HTML, follow_redirects=False)
    assert r.status_code == 303
    p = page(b, f"/app/approvals/{apr['id']}?ok=decided").text
    assert "Decision recorded." in p and "s-approved" in p and "by <b>bob</b>" in p and "/decide" not in p
    r = b.c.post(f"/app/approvals/{apr['id']}/decide", data={"csrf_token": b.csrf, "decision": "reject"}, headers=HTML)
    assert r.status_code == 409 and "not_pending" in r.text
    # the agent consumes it exactly once
    h = denv.agent_b
    assert h.post(f"/v1/approvals/{apr['id']}/consume", {"action_sha256": apr["action_sha256"]}).status_code == 200
    assert h.post(f"/v1/approvals/{apr['id']}/consume", {"action_sha256": apr["action_sha256"]}).status_code == 409
    assert "s-consumed" in page(b, "/app/approvals?state=all").text


def test_other_party_cannot_decide(denv, hostile):
    t, apr = hostile                           # agent-b's approval -> approver party bob
    m = denv.login("alice")
    p = page(m, f"/app/approvals/{apr['id']}").text
    assert "Only a human of party <b>bob</b>" in p and "/decide" not in p
    r = m.c.post(f"/app/approvals/{apr['id']}/decide", data={"csrf_token": m.csrf, "decision": "approve"}, headers=HTML)
    assert r.status_code == 403 and "wrong_party" in r.text
    assert m.post(f"/app/approvals/{apr['id']}/decide", decision="approve").json()["code"] == "wrong_party"
    with denv.db.read() as c:
        assert c.execute("SELECT state FROM approvals WHERE id=?", (apr["id"],)).fetchone()[0] == "pending"


def test_agent_key_cannot_access_app(denv, hostile):
    t, apr = hostile
    c = fresh(denv)
    auth = {"Authorization": f"Bearer {denv.agent_b.token}"}
    r = c.get("/app/", headers={**HTML, **auth}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/app/login"
    for path in ("/app/api/me", "/app/api/tasks", f"/app/approvals/{apr['id']}", "/app/agents", "/app/audit"):
        assert c.get(path, headers=auth).status_code == 401, path
    r = c.post(f"/app/approvals/{apr['id']}/decide", data={"decision": "approve"}, headers=auth)
    assert r.status_code == 401
    r = c.post(f"/app/tasks/{t['id']}/pause", data={}, headers=auth)
    assert r.status_code == 401
    # nor can an agent key used as a session cookie
    c.cookies.set("__Host-ab_session", denv.agent_b.token)
    assert c.get("/app/api/me").status_code == 401


def test_agents_keys_pause_and_mint(denv):
    m = denv.login("alice")
    r = m.c.post("/app/agents/agent-a/keys", data={"csrf_token": m.csrf, "label": "<b>rot</b>"}, headers=HTML)
    assert r.status_code == 200 and "Shown <b>once</b>" in r.text
    token = re.search(r'<pre class="secret">(abk_[A-Za-z0-9_-]+)</pre>', r.text).group(1)
    key_id = token.split("_")[1]
    assert denv.client.get("/v1/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    agents = page(m, "/app/agents").text
    assert token not in agents and key_id in agents and "&lt;b&gt;rot&lt;/b&gt;" in agents
    # other party's agent: no controls, and the server refuses
    assert m.c.post("/app/agents/agent-b/pause", data={"csrf_token": m.csrf}, headers=HTML).status_code == 403
    r = m.c.post("/app/agents/agent-a/pause", data={"csrf_token": m.csrf}, headers=HTML, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/app/agents?ok=agent_pause"
    assert "Agent agent-a is paused" in page(m, "/app/").text
    r = m.c.post(f"/app/keys/{key_id}/revoke", data={"csrf_token": m.csrf}, headers=HTML, follow_redirects=False)
    assert r.status_code == 303
    assert denv.client.get("/v1/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    with denv.db.write() as c:
        c.execute("UPDATE sessions SET step_up_at=0")
    assert "Step-up required" in page(m, "/app/agents").text
    r = m.c.post("/app/agents/agent-a/resume", data={"csrf_token": m.csrf}, headers=HTML)
    assert r.status_code == 403 and "Step-up required" in r.text


def test_step_up_next_is_not_an_open_redirect(denv):
    m = denv.login("alice")
    for bad in ("https://evil.example/", "//evil.example", "/app/../../x", "/app/x?y=1", "javascript:alert(1)"):
        with denv.db.write() as c:             # allow re-using the same code (replay counter reset, test only)
            c.execute("UPDATE humans SET totp_last_step=0")
        r = m.c.post("/app/step-up?next=" + urllib.parse.quote(bad, safe=""),
                     data={"csrf_token": m.csrf, "password": "correct horse battery",
                           "totp": denv.code("alice", time.time() + 30)},
                     headers=HTML, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/app/?ok=stepup", bad


def test_enrollment_pages(denv):
    with denv.db.write() as c:
        token = humans.invite(c, ops.CLI, "bob2", "bob", "Bob <Two>")
    c = fresh(denv)
    r = c.get(f"/app/enroll/{token}", headers=HTML)
    assert_safe(r)
    assert "bob2" in r.text and "Bob &lt;Two&gt;" in r.text
    pre = _pre(r)
    assert c.get(f"/app/enroll/{token}").json()["login"] == "bob2"         # JSON clients unchanged
    r = c.post(f"/app/enroll/{token}", data={"password": "short", "password2": "short", "pre_csrf": pre}, headers=HTML)
    assert r.status_code == 422 and "at least 12" in r.text
    r = c.post(f"/app/enroll/{token}", data={"password": "a long enough pw", "password2": "a long enough pw",
                                             "pre_csrf": pre}, headers=HTML)
    assert_safe(r)
    assert "<svg" in r.text and "Shown <b>once</b>" in r.text and "style=" not in r.text
    secret = re.search(r'<code class="secret">([A-Z2-7 ]+)</code>', r.text).group(1).replace(" ", "")
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    from bridge.domain import totp
    r = c.post("/app/login", data={"login": "bob2", "password": "a long enough pw", "totp": totp.totp(key)},
               headers=HTML, follow_redirects=False)
    assert r.status_code == 403 and "Safari, Chrome or Firefox" in r.text     # browser login needs the form token
    pre = _pre(c.get("/app/login", headers=HTML))
    r = c.post("/app/login", data={"login": "bob2", "password": "a long enough pw", "totp": totp.totp(key),
                                   "pre_csrf": pre}, headers=HTML, follow_redirects=False)
    assert r.status_code == 303
    r = fresh(denv).get(f"/app/enroll/{token}", headers=HTML)
    assert r.status_code == 404 and "invalid, already used or expired" in r.text


def test_audit_and_overview(denv, hostile):
    t, apr = hostile
    m = denv.login("alice")
    with denv.db.read() as c:
        head = c.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()[0]
    a = page(m, "/app/audit").text
    assert head in a
    a = page(m, "/app/audit?action=approval.").text
    assert "approval.request" in a and "task.create" not in a
    a = page(m, f"/app/audit?target={t['id']}").text
    assert "task.create" in a
    o = page(m, "/app/").text
    assert t["id"] in o and "pending approvals" in o
    with denv.db.write() as c:
        c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('last_restore_at', ?)", (str(int(time.time() * 1000)),))
    assert "restored from a backup" in page(m, "/app/").text
    denv.app.state.bridge.storage._degraded, denv.app.state.bridge.storage._at = True, time.monotonic()
    assert "Storage degraded" in page(m, "/app/").text
    act = page(m, "/app/agents/agent-b").text
    assert "approval.request" in act and "CLARIFICATION_REQUEST" in act
