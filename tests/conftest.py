import base64
import itertools
import os
import urllib.parse

import pytest
from fastapi.testclient import TestClient

from bridge import ops
from bridge.api.app import create_app
from bridge.config import Limits, Settings
from bridge.db import Database
from bridge.domain import humans, keys, totp

_n = itertools.count()


class Agent:
    """Test client for one agent: adds the bearer key and a fresh Idempotency-Key to every POST."""

    def __init__(self, client: TestClient, token: str, name: str):
        self.c, self.token, self.name = client, token, name

    def h(self, extra=None):
        return {"Authorization": f"Bearer {self.token}", **(extra or {})}

    def get(self, path, **kw):
        return self.c.get(path, headers=self.h(kw.pop("headers", None)), **kw)

    def post(self, path, json=None, key=None, **kw):
        hdrs = {"Idempotency-Key": key or f"test-key-{next(_n):08d}", **(kw.pop("headers", None) or {})}
        if json is None and "content" not in kw:
            json = {}
        return self.c.post(path, json=json, headers=self.h(hdrs), **kw)

    def create_task(self, **over):
        body = {"title": f"Margin calc bug {next(_n)}", "description": "Unified margin is off by one tick.",
                "responsible_agent_id": "agent-b" if self.name == "agent-a" else "agent-a",
                "category": "bug_fix" if self.name == "agent-a" else "qa", "acceptance_criteria": ["tests pass"]}
        body.update(over)
        r = self.post("/v1/tasks", body)
        assert r.status_code == 201, r.text
        return r.json()["task"]

    def to(self, task_id, state, reason=None):
        return self.post(f"/v1/tasks/{task_id}/transition", {"to": state, **({"reason": reason} if reason else {})})


def make_settings(tmp_path, **limit_over) -> Settings:
    return Settings(db_path=str(tmp_path / "bridge.db"), pepper=os.urandom(32), totp_kek=os.urandom(32),
                    public_origin="https://testserver",
                    limits=Limits(min_free_bytes=0, min_free_inodes_pct=0, **limit_over))


class Env:
    def __init__(self, tmp_path, **limit_over):
        self.settings = make_settings(tmp_path, **limit_over)
        ops.init_db(self.settings.db_path)
        self.db = Database(self.settings.db_path)
        self.app = create_app(self.settings, self.db)
        self.client = TestClient(self.app, base_url="https://testserver")
        self.agent_a = self.agent("agent-a")
        self.agent_b = self.agent("agent-b")
        self.totp_secrets = {}

    def agent(self, name, scopes=keys.SCOPES):
        with self.db.write() as c:
            _, token = keys.create(c, ops.CLI, name, "test", self.settings.pepper, scopes)
        return Agent(self.client, token, name)

    def add_human(self, login, party, password="correct horse battery"):
        with self.db.write() as c:
            hid, uri = humans.create(c, ops.CLI, party, login, login.title(), password, self.settings.totp_kek)
        b32 = urllib.parse.parse_qs(urllib.parse.urlparse(uri).query)["secret"][0]
        self.totp_secrets[login] = base64.b32decode(b32 + "=" * (-len(b32) % 8))
        return hid

    def code(self, login, t=None):
        return totp.totp(self.totp_secrets[login], t)

    def login(self, login, password="correct horse battery", client=None, step_up=True) -> "Human":
        """Log in; by default also step up (a login alone is never a step-up) with the NEXT TOTP step's code,
        since the login code is single-use."""
        import time
        c = client or TestClient(self.app, base_url="https://testserver")
        r = c.post("/app/login", data={"login": login, "password": password, "totp": self.code(login)})
        assert r.status_code == 200, r.text
        h = Human(c, r.json()["csrf_token"])
        if step_up:
            r = h.post("/app/step-up", password=password, totp=self.code(login, time.time() + 30))
            assert r.status_code == 200, r.text
        return h


class Human:
    def __init__(self, client, csrf):
        self.c, self.csrf = client, csrf

    def post(self, path, **data):
        return self.c.post(path, data={"csrf_token": self.csrf, **data})

    def get(self, path, **kw):
        return self.c.get(path, **kw)


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    e.db.close()


@pytest.fixture
def make_env(tmp_path):
    made = []

    def f(**limit_over):
        d = tmp_path / f"e{len(made)}"
        d.mkdir()
        e = Env(d, **limit_over)
        made.append(e)
        return e
    yield f
    for e in made:
        e.db.close()
