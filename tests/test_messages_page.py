"""Read-only Messages page (/app/messages, /app/messages/{id}): auth, per-recipient views, keyset pagination,
bounded previews, escaping of hostile bodies, hidden-character reveal, CSP."""
import re

import pytest
from fastapi.testclient import TestClient

from bridge.domain.common import Actor, insert_message, load_task

HTML = {"Accept": "text/html,application/xhtml+xml"}
HOSTILE = ('<script>alert(1)</script>"><img src=x onerror=alert(2)>'
           '<a href="javascript:alert(3)">x</a>')
ROW_ID = re.compile(r'href="/app/messages/(msg_[0-9a-z]{26})"')
AGENT_B = Actor("agent", "agent-b", "bob")
AGENT_A = Actor("agent", "agent-a", "alice")


@pytest.fixture
def menv(env):
    env.add_human("alice", "alice")
    env.add_human("bob", "bob")
    return env


def who(env, login):
    """One session per human per test (a TOTP code is single-use)."""
    cache = env.__dict__.setdefault("_sessions", {})
    if login not in cache:
        cache[login] = env.login(login)
    return cache[login]


def page(h, path, status=200):
    r = h.c.get(path, headers=HTML)
    assert r.status_code == status, (path, r.status_code, r.text[:500])
    assert r.headers["content-type"].startswith("text/html")
    return r


def assert_safe(r):
    body, low = r.text, r.text.lower()
    assert "<script" not in low and "<img" not in low
    assert not re.search(r"""(href|src|action)\s*=\s*["']?\s*javascript:""", low)
    for tag in re.findall(r"<[a-zA-Z][^>]*>", body):
        assert not re.search(r"\son\w+\s*=", tag), tag
    for ch in ("\u202e", "\u202d", "\u200b", "\u200d", "\u2066", "\ufeff", "\x07", "\x1b"):
        assert ch not in body, repr(ch)
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src" not in csp and "frame-ancestors 'none'" in csp
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-content-type-options"] == "nosniff"


def add(env, task_id, actor, text, mtype="PROGRESS_UPDATE", **body):
    with env.db.write() as c:
        return insert_message(c, load_task(c, task_id), actor, mtype, {"text": text, "data": {}, "refs": [], **body})["id"]


def rows(r) -> list[str]:
    return list(dict.fromkeys(ROW_ID.findall(r.text)))


@pytest.fixture
def convo(menv):
    """Task agent-a -> agent-b with one message from each agent and an instruction from each human."""
    g, h = menv.agent_a, menv.agent_b
    t = g.create_task(title="Margin tick bug", description="TASKREQ-TEXT reproduce the margin bug")
    assert h.post(f"/v1/tasks/{t['id']}/accept", {"body": {"text": "AGENT-B-ACCEPT on it"}}).status_code < 300
    add(menv, t["id"], AGENT_A, "AGENT-A-PROGRESS more context", "CLARIFICATION_REQUEST")
    assert who(menv, "alice").post(f"/app/tasks/{t['id']}/instruction", text="ALICE-INSTR").status_code == 200
    assert who(menv, "bob").post(f"/app/tasks/{t['id']}/instruction", text="BOB-INSTR").status_code == 200
    return t


# ---------------------------------------------------------------------------------------------------- auth

def test_requires_login(menv, convo):
    mid = add(menv, convo["id"], AGENT_B, "SECRET-MARKER")
    anon = TestClient(menv.app, base_url="https://testserver")
    for path in ("/app/messages", "/app/messages?to=agent-b", f"/app/messages/{mid}"):
        r = anon.get(path, headers=HTML, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/app/login", path
        r = anon.get(path)
        assert r.status_code == 401 and "SECRET-MARKER" not in r.text
        r = anon.get(path, headers=HTML, cookies={"__Host-ab_session": "forged"}, follow_redirects=False)
        assert r.status_code == 303 and "SECRET-MARKER" not in r.text


def test_agent_bearer_key_is_refused(menv, convo):
    mid = add(menv, convo["id"], AGENT_B, "SECRET-MARKER")
    for agent in (menv.agent_a, menv.agent_b):
        for path in ("/app/messages", f"/app/messages/{mid}"):
            r = agent.get(path)
            assert r.status_code == 401 and "SECRET-MARKER" not in r.text
            r = agent.get(path, headers=HTML, follow_redirects=False)
            assert r.status_code == 303 and r.headers["location"] == "/app/login"


def test_page_is_read_only(menv, convo):
    m = who(menv, "alice")
    with menv.db.read() as c:
        before = c.execute("SELECT count(*) FROM audit_log").fetchone()[0], c.execute(
            "SELECT count(*) FROM messages").fetchone()[0]
    page(m, "/app/messages")
    page(m, "/app/messages?to=agent-b")
    mid = rows(page(m, "/app/messages?to=agent-b"))[0]
    page(m, f"/app/messages/{mid}")
    with menv.db.read() as c:
        after = c.execute("SELECT count(*) FROM audit_log").fetchone()[0], c.execute(
            "SELECT count(*) FROM messages").fetchone()[0]
    assert before == after
    for path in ("/app/messages", f"/app/messages/{mid}"):
        assert m.post(path).status_code == 405
    assert "<form" not in page(m, f"/app/messages/{mid}").text.split("<main>")[1]
    assert "<form" not in page(m, "/app/messages").text.split("<main>")[1]


# ---------------------------------------------------------------------------------------------- views

@pytest.mark.parametrize("login", ["alice", "bob"])
def test_both_humans_see_both_views(menv, convo, login):
    h = who(menv, login)
    default = page(h, "/app/messages").text
    to_g = page(h, "/app/messages?to=agent-a").text
    to_h = page(h, "/app/messages?to=agent-b").text
    assert "AGENT-B-ACCEPT" in default and "AGENT-A-PROGRESS" not in default        # first tab = agent-a (sorted)
    assert re.search(r'href="/app/messages\?to=agent-a" class="on"', default)
    assert 'href="/app/messages"' in to_g and ">Messages<" in to_g               # nav link
    assert 'href="/app/messages?to=agent-a"' in to_g and 'href="/app/messages?to=agent-b"' in to_g
    assert "Alice's agent" in to_g and "Bob's agent" in to_g
    assert "Time (UTC)" in to_g
    # to agent-a: agent-b's messages + both human instructions, never agent-a's own
    for s in ("AGENT-B-ACCEPT", "ALICE-INSTR", "BOB-INSTR"):
        assert s in to_g
    assert "AGENT-A-PROGRESS" not in to_g and "TASKREQ-TEXT" not in to_g
    # to agent-b: agent-a's task request and progress + both instructions, never agent-b's own
    for s in ("TASKREQ-TEXT", "AGENT-A-PROGRESS", "ALICE-INSTR", "BOB-INSTR"):
        assert s in to_h
    assert "AGENT-B-ACCEPT" not in to_h
    assert "TASK_REQUEST" in to_h and "HUMAN_INSTRUCTION" in to_h and "TASK_ACCEPTED" in to_g
    # task id + title linked to the task page, message linked to full view and thread anchor
    assert f'href="/app/tasks/{convo["id"]}">Margin tick bug</a>' in to_h
    mid = rows(page(h, "/app/messages?to=agent-b"))[0]
    assert f'href="/app/tasks/{convo["id"]}#{mid}"' in to_h
    assert re.search(r"<time>\d{4}-\d\d-\d\d \d\d:\d\d:\d\dZ</time>", to_h)
    # sender labels
    assert "bob <small class=\"muted\">(human, party bob)</small>" in to_g
    assert "agent-b <small class=\"muted\">(agent)</small>" in to_g


def test_message_detail_view(menv, convo):
    mid = add(menv, convo["id"], AGENT_B, "FULL-BODY line one\nline two",
              refs=[{"kind": "url", "value": "https://example.com/x"}])
    for login in ("alice", "bob"):
        r = page(who(menv, login), f"/app/messages/{mid}")
        assert_safe(r)
        assert "FULL-BODY line one\nline two" in r.text
        assert 'href="/app/messages?to=agent-a">agent-a</a>' in r.text            # recipient
        assert f'href="/app/tasks/{convo["id"]}#{mid}"' in r.text
        assert "Time (UTC)" in r.text and "agent-written" in r.text
    m = who(menv, "alice")
    page(m, "/app/messages/msg_00000000000000000000000000", 404)
    page(m, "/app/messages/not-an-id", 404)
    page(m, "/app/messages?to=nobody", 404)
    assert m.c.get("/app/messages?to=%3Cscript%3E", headers=HTML).status_code == 422
    # a human instruction goes to both agents
    instr = [i for i in rows(page(m, "/app/messages?to=agent-b")) if i in rows(page(m, "/app/messages?to=agent-a"))]
    assert instr
    d = page(m, f"/app/messages/{instr[0]}").text
    assert 'href="/app/messages?to=agent-a">agent-a</a>, <a href="/app/messages?to=agent-b">agent-b</a>' in d


# ------------------------------------------------------------------------------------------- pagination

def test_pagination_newest_first_50_per_page(menv, convo):
    ids = [add(menv, convo["id"], AGENT_B, f"bulk {i:03d}") for i in range(120)]
    m = who(menv, "bob")
    with menv.db.read() as c:
        expected = [r[0] for r in c.execute(
            "SELECT m.id FROM messages m JOIN tasks t ON t.id=m.task_id WHERE m.sender_id!='agent-a'"
            " AND t.id=? ORDER BY m.seq DESC", (convo["id"],))]
    assert expected[:120] == ids[::-1]
    seen, path, pages = [], "/app/messages?to=agent-a", 0
    while path:
        r = page(m, path)
        got = rows(r)
        pages += 1
        assert len(got) == (50 if pages < 3 else len(expected) - 100)
        seen += got
        nxt = re.search(r'href="(/app/messages\?to=agent-a&amp;before=(\d+))"', r.text)
        path = nxt.group(1).replace("&amp;", "&") if nxt else None
        if path:
            with menv.db.read() as c:
                last_seq = c.execute("SELECT seq FROM messages WHERE id=?", (got[-1],)).fetchone()[0]
            assert int(nxt.group(2)) == last_seq                           # keyset: before=<seq of last row>
            assert pages == 1 or "newest messages" in r.text
    assert pages == 3 and seen == expected
    assert "No messages older" in page(m, f"/app/messages?to=agent-a&before=1").text


def test_long_bodies_are_truncated_and_page_is_bounded(menv, convo):
    for i in range(60):
        add(menv, convo["id"], AGENT_B, f"LONG{i:02d} " + "A" * 60_000 + " TAIL-NEVER-SHOWN")
    m = who(menv, "alice")
    r = page(m, "/app/messages?to=agent-a")
    assert len(rows(r)) == 50
    assert "TAIL-NEVER-SHOWN" not in r.text
    assert len(r.content) < 200_000                                       # 50 rows of ~160 chars, not 3 MB
    previews = re.findall(r'<span class="preview">([^<]*)</span>', r.text)
    assert len(previews) == 50 and all(p.endswith("…") and len(p) <= 170 for p in previews)
    full = page(m, f"/app/messages/{rows(r)[0]}").text                    # the full view has the whole body
    assert "TAIL-NEVER-SHOWN" in full


def test_response_byte_budget_limits_rows(make_env):
    env = make_env(max_response_bytes=40_000)
    env.add_human("alice", "alice")
    t = env.agent_a.create_task()
    for i in range(50):
        add(env, t["id"], AGENT_B, "&<>\"'" * 400)            # previews that inflate when HTML-escaped
    m = who(env, "alice")
    r = page(m, "/app/messages?to=agent-a")
    n = len(rows(r))
    assert 1 <= n < 50 and "older messages" in r.text
    assert len(r.content) <= 40_000 + 4096


# ---------------------------------------------------------------------------------------------- escaping

def test_hostile_bodies_are_escaped_and_hidden_chars_visible(menv, convo):
    spoof = "invoice_\u202egnp.exe pay\u200b now \u2066x\u2069 \ufeff bell\x07 esc\x1b[31m"
    mid = add(menv, convo["id"], AGENT_B, HOSTILE + " javascript:alert(9) " + spoof,
              refs=[{"kind": "url", "value": "javascript:alert(6)"}, {"kind": "commit", "value": "\u202eabc"}])
    plain = add(menv, convo["id"], AGENT_B, "Grüße naïve café 日本語 🚀 plain")
    with menv.db.write() as c:
        c.execute("UPDATE tasks SET title=? WHERE id=?", ("Title " + HOSTILE[:60] + "\u202e", convo["id"]))
    for login in ("alice", "bob"):
        h = who(menv, login)
        lst = page(h, "/app/messages?to=agent-a")
        assert_safe(lst)
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in lst.text
        assert "\\u202e" in lst.text and "\\u200b" in lst.text            # visible markers in the preview
        row = lst.text.split(f'/app/messages/{mid}"')[0].rsplit("<tr>", 1)[1]
        assert "hidden chars" in row
        prow = lst.text.split(f'/app/messages/{plain}"')[0].rsplit("<tr>", 1)[1]
        assert "Grüße naïve café 日本語 🚀 plain" in prow and "hidden chars" not in prow   # normal Unicode stays readable
        d = page(h, f"/app/messages/{mid}")
        assert_safe(d)
        for marker in ("\\u202e", "\\u200b", "\\u2066", "\\u2069", "\\ufeff", "\\u0007", "\\u001b"):
            assert marker in d.text, marker
        assert "hidden or direction-changing characters" in d.text
        assert "javascript:alert(6)</code>" in d.text and 'href="javascript' not in d.text   # never a link
        assert "<code>\\u202eabc</code>" in d.text
        assert "&lt;img src=x onerror=alert(2)&gt;" in d.text
        assert "hidden or direction-changing" not in page(h, f"/app/messages/{plain}").text


def test_csp_and_no_store_headers(menv, convo):
    m = who(menv, "alice")
    mid = rows(page(m, "/app/messages?to=agent-b"))[0]
    for path in ("/app/messages", "/app/messages?to=agent-b", f"/app/messages/{mid}"):
        r = page(m, path)
        assert_safe(r)
        assert r.headers["referrer-policy"] == "same-origin"
        assert 'href="/app/static/dashboard.css"' in r.text and "<script" not in r.text
