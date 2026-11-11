"""End-to-end harness: the REAL server (uvicorn subprocess via `python -m bridge.serve`) on 127.0.0.1:<random>,
a temp DB, throwaway credentials, keys and humans minted with the bridgectl CLI. Everything else is plain HTTP.

Deliberately NOT named conftest.py: tests/conftest.py is imported as `conftest` by the unit tests, and a second
conftest module would shadow it in a full run. Test modules import the `server` fixture from here."""
import base64
import hashlib
import hmac
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO, "clients", "python"))
sys.path.insert(0, os.path.join(REPO, "tools"))

from agent_bridge_client import BridgeClient  # noqa: E402

PY = sys.executable
# Server source tree (default: this repo). E2E_BRIDGE_SRC lets you run the e2e suite against another checkout,
# e.g. `git archive HEAD bridge | tar -x -C /some/dir` while the working tree is mid-edit.
SRC = os.path.abspath(os.environ.get("E2E_BRIDGE_SRC") or REPO)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def totp(secret: bytes, t: float) -> str:
    mac = hmac.new(secret, struct.pack(">Q", int(t // 30)), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return str((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000).zfill(6)


class HumanSession:
    """A human using the /app surface over plain HTTP (session cookie + CSRF token)."""

    def __init__(self, server: "BridgeServer", login: str, secret: bytes, password: str):
        self.server, self.login_name, self.secret, self.password = server, login, secret, password
        self.cookie = self.csrf = None
        self._last_step = 0

    def _code(self) -> str:
        step = max(int(time.time() // 30), self._last_step + 1)   # TOTP steps are single-use
        self._last_step = step
        return totp(self.secret, step * 30)

    def _req(self, method, path, form=None):
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        req = urllib.request.Request(self.server.url + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        if self.cookie:
            req.add_header("Cookie", self.cookie)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read() or b"{}"), r.headers
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}"), e.headers

    def login(self):
        st, body, headers = self._req("POST", "/app/login", {"login": self.login_name, "password": self.password,
                                                             "totp": self._code()})
        assert st == 200, body
        self.cookie = headers["Set-Cookie"].split(";")[0]
        self.csrf = body["csrf_token"]
        return self

    def get(self, path):
        return self._req("GET", path)

    def post(self, path, **form):
        return self._req("POST", path, {"csrf_token": self.csrf, **form})

    def step_up(self):
        st, body, _ = self.post("/app/step-up", password=self.password, totp=self._code())
        assert st == 200, body

    def decide(self, approval_id, decision, note="ok"):
        return self.post(f"/app/approvals/{approval_id}/decide", decision=decision, note=note)


class BridgeServer:
    def __init__(self, tmp):
        self.tmp = str(tmp)
        self.port = _free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.cred_dir = os.path.join(self.tmp, "creds")
        self.config = os.path.join(self.tmp, "config.toml")
        self.log_path = os.path.join(self.tmp, "server.log")
        self.proc = None
        self.tokens: dict[str, str] = {}
        self.key_ids: dict[str, str] = {}
        self.env = {k: v for k, v in os.environ.items() if k not in ("CREDENTIALS_DIRECTORY", "BRIDGE_CONFIG")}
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"
        self.env["PYTHONPATH"] = SRC
        self.cli("gen-credentials", self.cred_dir, config=False)
        with open(self.config, "w") as f:
            f.write(f'credentials_dir = "{self.cred_dir}"\n\n[server]\nhost = "127.0.0.1"\nport = {self.port}\n'
                    f'public_origin = "{self.url}"\npoll_after_s = 900\n\n[storage]\n'
                    f'db_path = "{os.path.join(self.tmp, "bridge.db")}"\n\n'
                    f'[limits]\nmin_free_bytes = 0\nmin_free_inodes_pct = 0.0\n')
        self.cli("init-db")

    def cli(self, *args, config=True, stdin=None, check=True):
        cmd = [PY, "-m", "bridge.cli"] + (["--config", self.config] if config else []) + list(args)
        p = subprocess.run(cmd, input=stdin, capture_output=True, text=True, env=self.env, cwd=SRC, timeout=60)
        if check:
            assert p.returncode == 0, p.stderr
        return p

    def mint_key(self, agent: str) -> str:
        p = self.cli("key", "create", "--agent", agent, "--label", "e2e")
        token = p.stdout.strip()
        self.key_ids[agent] = p.stderr.split("key id ")[1].split()[0]
        self.tokens[agent] = token
        path = os.path.join(self.tmp, f"{agent}.key")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(token + "\n")
        return path

    def add_human(self, login: str, party: str, password: str = "e2e throwaway password") -> HumanSession:
        p = self.cli("human", "create", "--login", login, "--party", party, "--display-name", login.title(),
                     "--password-stdin", stdin=password + "\n")
        q = urllib.parse.parse_qs(urllib.parse.urlparse(p.stdout.strip()).query)
        b32 = q["secret"][0]
        return HumanSession(self, login, base64.b32decode(b32 + "=" * (-len(b32) % 8)), password)

    def client(self, agent: str, **kw) -> BridgeClient:
        kw.setdefault("backoff_s", 0.05)
        return BridgeClient(self.url, self.tokens[agent], **kw)

    def start(self):
        self._log = open(self.log_path, "ab")
        self.proc = subprocess.Popen([PY, "-m", "bridge.serve", "--config", self.config], cwd=SRC, env=self.env,
                                     stdout=self._log, stderr=subprocess.STDOUT)
        deadline = time.time() + 20
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"server exited: {open(self.log_path).read()[-2000:]}")
            try:
                with urllib.request.urlopen(self.url + "/v1/health", timeout=1) as r:
                    if r.status == 200:
                        return self
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("server did not become healthy")

    def stop(self, kill: bool = False):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGKILL if kill else signal.SIGTERM)
            self.proc.wait(timeout=15)
        self.proc = None
        if getattr(self, "_log", None):
            self._log.close()

    def restart(self, kill: bool = True):
        self.stop(kill=kill)
        return self.start()

    def logs(self) -> str:
        with open(self.log_path, encoding="utf-8", errors="replace") as f:
            return f.read()


@pytest.fixture
def server(tmp_path):
    s = BridgeServer(tmp_path)
    s.mint_key("agent-a")
    s.mint_key("agent-b")
    s.start()
    yield s
    s.stop()
    logs = s.logs()
    for tok in s.tokens.values():                     # no key may ever appear in the server log
        assert tok not in logs and tok[17:] not in logs   # abk_<id:12>_<secret:43>
