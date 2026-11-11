import pytest
from fastapi.testclient import TestClient

from bridge import ops
from bridge.api.human import origin_allowed
from bridge.domain import humans

NULL = {"Origin": "null", "Sec-Fetch-Site": "same-origin"}


@pytest.fixture
def henv(env):
    env.add_human("alice", "alice")
    return env


def fresh(env):
    return TestClient(env.app, base_url="https://testserver")


def invite(env, login="bob"):
    with env.db.write() as c:
        return humans.invite(c, ops.CLI, login, login, login.title())


def login_post(env, headers):
    return fresh(env).post("/app/login", data={"login": "alice", "password": "x", "totp": "000000"}, headers=headers)


def is_bad_origin(r):
    return r.status_code == 403 and r.json().get("code") == "bad_origin"


def test_null_origin_same_origin_fetch_enroll_and_login(henv):
    t = invite(henv)
    r = fresh(henv).post(f"/app/enroll/{t}", data={"password": "a-long-enough-pw"}, headers=NULL)
    assert r.status_code == 200
    assert not is_bad_origin(login_post(henv, NULL))


def test_null_origin_without_fetch_metadata_refused(henv):
    t = invite(henv)
    assert is_bad_origin(fresh(henv).post(f"/app/enroll/{t}", data={"password": "a-long-enough-pw"},
                                          headers={"Origin": "null"}))
    assert is_bad_origin(login_post(henv, {"Origin": "null"}))
    assert is_bad_origin(login_post(henv, {"Origin": "null", "Sec-Fetch-Site": "cross-site"}))


def test_evil_origin_refused(henv):
    assert is_bad_origin(login_post(henv, {"Origin": "https://evil.example"}))


def test_host_derived_origin_accepted_when_public_origin_stale(henv):
    henv.settings.public_origin = "https://old-tunnel.ngrok-free.app"
    assert not is_bad_origin(login_post(henv, {"Origin": "https://testserver"}))
    assert not is_bad_origin(login_post(henv, {"Origin": "https://TESTSERVER/"}))
    assert is_bad_origin(login_post(henv, {"Origin": "https://testserver:8443"}))


def test_public_origin_accepted(henv):
    henv.settings.public_origin = "https://x.ngrok-free.app/"
    assert not is_bad_origin(login_post(henv, {"Origin": "https://x.ngrok-free.app"}))


def test_cross_site_fetch_refused_even_without_origin(henv):
    for v in ("cross-site", "same-site"):
        assert is_bad_origin(login_post(henv, {"Sec-Fetch-Site": v}))
    assert not is_bad_origin(login_post(henv, {}))


def test_malformed_host_ignored():
    for host in ("evil.example/x", "a b", "u@evil.example", "", None):
        assert not origin_allowed("https://evil.example", None, host, "https", None)
        assert not origin_allowed("https://evil.example/x", None, host, "https", "https://ok.ngrok-free.app")
    assert origin_allowed("https://h.example:8443", None, "h.example:8443", "http", None)
    assert not origin_allowed("http://h.example", None, "h.example", "http", None)     # http only on loopback
    for host in ("127.0.0.1:8787", "localhost:8787", "[::1]:8787", "localhost"):
        assert origin_allowed(f"http://{host}", None, host, "http", None), host
    assert not origin_allowed("https://h.example:1", None, "h.example", "https", None)


def test_html_sends_same_origin_referrer_policy(henv):
    r = fresh(henv).get("/app/login", headers={"Accept": "text/html"})
    assert r.headers["referrer-policy"] == "same-origin"
    assert 'content="same-origin"' in r.text or r.status_code != 200
