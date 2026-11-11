"""Deploy: custom-domain readiness (any hostname), the committed ephemeral ngrok config, the tunnel part
of `bridgectl doctor`, and unit-file limits. Shell validators are exercised through their test hooks."""
import shutil
import socket
import subprocess
import tarfile
from pathlib import Path

import pytest

from bridge import cli, ops

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"

GOOD_HOSTS = ["x.ngrok-free.app", "abc-123.ngrok-free.dev", "bridge.ngrok.app", "bridge.ngrok.dev",
              "bridge.example.com", "a.b.c.example.co.uk", "x1.example", "xn--bcher-kva.example",
              "a" * 63 + ".example.com", ".".join(["a" * 63] * 3) + "." + "b" * 61]           # 253 chars
BAD_HOSTS = ["", "localhost", "example", "Bridge.example.com", "bridge.example.com.", ".example.com",
             "a..example.com", "-a.example.com", "a-.example.com", "a.-example.com", "bridge.example-.com",
             "a" * 64 + ".example.com", ".".join(["a" * 63] * 3) + "." + "b" * 62,              # 254 chars
             "https://bridge.example.com", "bridge.example.com:443", "bridge.example.com/x", "user@bridge.example.com",
             "bridge example.com", "bridge.example.com\n", "bridge.example.com\nx.example.com", "bridge_x.example.com",
             "1.2.3.4", "127.0.0.0x1", "bridge.example.1com", "bücher.example", "bridge.example.com|x", "bridge.example.com\"", "*.example.com"]


def _sh(*argv) -> int:
    return subprocess.run([*argv], capture_output=True, timeout=10).returncode


@pytest.mark.parametrize("host", GOOD_HOSTS)
def test_hostname_validators_accept(host):
    assert ops.valid_hostname(host)
    assert _sh("sh", str(DEPLOY / "ngrok/render-config.sh"), "--check-host", host) == 0
    assert _sh("bash", str(DEPLOY / "install.sh"), "--check-host", host) == 0
    assert _sh("bash", str(DEPLOY / "ngrok/sync-origin.sh"), "--check-url", f"https://{host}") == 0


@pytest.mark.parametrize("host", BAD_HOSTS)
def test_hostname_validators_reject(host):
    assert not ops.valid_hostname(host)
    assert _sh("sh", str(DEPLOY / "ngrok/render-config.sh"), "--check-host", host) == 1
    assert _sh("bash", str(DEPLOY / "install.sh"), "--check-host", host) == 1
    assert _sh("bash", str(DEPLOY / "ngrok/sync-origin.sh"), "--check-url", f"https://{host}") == 1


@pytest.mark.parametrize("url", ["http://bridge.example.com", "https://bridge.example.com/", "bridge.example.com",
                                 "https://bridge.example.com:8443", "https://u@bridge.example.com", "https://",
                                 "https://bridge.example.com/v1"])
def test_sync_origin_rejects_non_bare_https(url):
    assert _sh("bash", str(DEPLOY / "ngrok/sync-origin.sh"), "--check-url", url) == 1


@pytest.mark.skipif(not shutil.which("dash"), reason="dash not installed")
def test_render_config_validator_is_posix():
    assert _sh("dash", str(DEPLOY / "ngrok/render-config.sh"), "--check-host", "bridge.example.com") == 0
    assert _sh("dash", str(DEPLOY / "ngrok/render-config.sh"), "--check-host", "Bridge.example.com") == 1


def test_render_config_custom_domain(tmp_path):
    out = tmp_path / "ngrok.yml"
    env = {"PATH": "/usr/bin:/bin", "NGROK_DOMAIN": "bridge.example.com", "NGROK_AUTHTOKEN": "dummy-not-a-token"}
    r = subprocess.run(["sh", str(DEPLOY / "ngrok/render-config.sh"), str(DEPLOY / "ngrok/ngrok.yml.tmpl"), str(out)],
                       env=env, capture_output=True, text=True, timeout=10)
    assert r.returncode == 0, r.stderr
    text = out.read_text()
    assert "url: https://bridge.example.com\n" in text and "@NGROK_DOMAIN@" not in text
    assert "dummy-not-a-token" not in text and "dummy-not-a-token" not in r.stdout + r.stderr
    env["NGROK_DOMAIN"] = "bridge.example.com|e"
    r = subprocess.run(["sh", str(DEPLOY / "ngrok/render-config.sh"), str(DEPLOY / "ngrok/ngrok.yml.tmpl"),
                        str(tmp_path / "bad.yml")], env=env, capture_output=True, text=True, timeout=10)
    assert r.returncode == 1 and not (tmp_path / "bad.yml").exists()


def test_no_ngrok_free_only_restriction_left():
    for p in ("ngrok/render-config.sh", "ngrok/sync-origin.sh", "install.sh"):
        text = (DEPLOY / p).read_text()
        assert r"ngrok-free\.(app|dev)" not in text and "*.ngrok-free.app|" not in text, p


# ---- committed configs ------------------------------------------------------------------------------------

def _agent_settings(path: Path) -> dict:
    out, in_agent = {}, False
    for line in path.read_text().splitlines():
        if line.startswith("agent:"):
            in_agent = True
            continue
        if in_agent and line.startswith("  ") and ":" in line:
            k, v = line.split("#", 1)[0].strip().split(":", 1)
            out[k.strip()] = v.strip()
        elif in_agent and line and not line.startswith((" ", "#")):
            in_agent = False
    return out


@pytest.mark.parametrize("name", ["ngrok-ephemeral.yml", "ngrok.yml.tmpl"])
def test_ngrok_configs_keep_inspector_off(name):
    a = _agent_settings(DEPLOY / "ngrok" / name)
    assert a["web_addr"] == "false" and a["inspect_db_size"] == "-1"
    assert a["console_ui"] == "false" and a["update_check"] == "false"
    assert a["log"] == "stdout" and a["log_format"] == "json"


def test_ephemeral_config_content():
    p = DEPLOY / "ngrok/ngrok-ephemeral.yml"
    text = p.read_text()
    assert _agent_settings(p)["log_level"] == "info"         # sync-origin needs the tunnel-started line
    body = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    assert body[0] == "version: 3"
    assert "  - name: bridge" in body and '      url: "http://127.0.0.1:8787"' in body
    assert not any(ln.strip().startswith("url: https") for ln in body)   # no pinned url: ngrok assigns one
    assert "authtoken" not in "\n".join(body).lower()
    try:
        import yaml  # optional; not a dependency
    except ImportError:
        return
    d = yaml.safe_load(text)
    assert d["agent"]["web_addr"] is False and d["agent"]["inspect_db_size"] == -1
    assert d["endpoints"] == [{"name": "bridge", "upstream": {"url": "http://127.0.0.1:8787"}}]


def test_ephemeral_dropin_example_uses_release_copy():
    lines = [ln for ln in (DEPLOY / "systemd/agent-bridge-ngrok-ephemeral.conf.example").read_text().splitlines()
             if ln and not ln.startswith("#")]
    assert lines == [
        "[Service]",
        "ExecStartPre=",
        "ExecStart=",
        "ExecStart=/usr/local/bin/ngrok start --all --config /opt/agent-bridge/current/deploy/ngrok/ngrok-ephemeral.yml",
        "ExecStartPost=+/bin/sh -c 'sleep 8; /usr/local/sbin/agent-bridge-sync-origin >/dev/null'",
        "TimeoutStartSec=60",
    ]
    unit = (DEPLOY / "systemd/agent-bridge-ngrok.service").read_text()
    # the ngrok user must still be able to read the release copy (it already reads the template there)
    inaccessible = next(ln for ln in unit.splitlines() if ln.startswith("InaccessiblePaths="))
    assert "/opt/agent-bridge" not in inaccessible
    assert "/opt/agent-bridge/current/deploy/ngrok/ngrok.yml.tmpl" in unit


def _unit(name: str) -> dict:
    out = {}
    for ln in (DEPLOY / "systemd" / name).read_text().splitlines():
        if "=" in ln and not ln.startswith("#"):
            k, v = ln.split("=", 1)
            out.setdefault(k, []).append(v)
    return out


def test_unit_limits():
    u = _unit("agent-bridge.service")
    assert u["TasksMax"] == ["64"] and u["MemoryMax"] == ["192M"]
    for name in ("agent-bridge.service", "agent-bridge-ngrok.service", "agent-bridge-backup.service"):
        for ln in (DEPLOY / "systemd" / name).read_text().splitlines():
            if "=" in ln and not ln.startswith("#"):
                assert " #" not in ln, f"{name}: systemd has no trailing comments: {ln}"


@pytest.mark.skipif(not shutil.which("tar"), reason="tar missing")
def test_package_includes_ngrok_configs(tmp_path):
    r = subprocess.run(["bash", str(ROOT / "scripts/package.sh"), "0.0.0-test"], capture_output=True, text=True,
                       timeout=120, env={"PATH": "/usr/bin:/bin", "DIST_DIR": str(tmp_path)})
    if r.returncode != 0 and "requirements.lock missing" in r.stderr:
        pytest.skip("no requirements.lock")
    assert r.returncode == 0, r.stderr
    with tarfile.open(tmp_path / "agent-bridge-0.0.0-test.tar.gz") as t:
        names = set(t.getnames())
    pre = "agent-bridge-0.0.0-test/deploy/"
    for f in ("ngrok/ngrok-ephemeral.yml", "ngrok/ngrok.yml.tmpl", "ngrok/sync-origin.sh", "ngrok/render-config.sh",
              "systemd/agent-bridge-ngrok-ephemeral.conf.example"):
        assert pre + f in names


# ---- doctor --tunnel ------------------------------------------------------------------------------------------

INV = "0123456789abcdef0123456789abcdef"


class FakeRun:
    """subprocess.run stand-in: maps argv[0] to (returncode, stdout) or an exception."""

    def __init__(self, systemctl=(0, INV + "\n"), journalctl=(0, "")):
        self.res = {"systemctl": systemctl, "journalctl": journalctl}
        self.calls = []

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        r = self.res[argv[0]]
        if isinstance(r, BaseException):
            raise r
        return subprocess.CompletedProcess(argv, r[0], r[1], "")


def _journal(*urls):
    lines = ['{"lvl":"info","msg":"starting web service","obj":"web","addr":"disabled"}',
             '{"lvl":"eror","msg":"x","err":"see \\"url\\":\\"https://ngrok.com/docs/errors/err_ngrok_1\\""}',
             '{"lvl":"info","msg":"x","url":"https://ngrok.com/docs/errors/err_ngrok_313"}']
    lines += [f'{{"lvl":"info","msg":"started tunnel","obj":"tunnels","name":"bridge","addr":"http://127.0.0.1:8787",'
              f'"url":"{u}"}}' for u in urls]
    return 0, "\n".join(lines) + "\n"


@pytest.fixture
def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                              # nothing listens there now
    return ("127.0.0.1", port)


def _by_name(checks):
    return {n: (lvl, info) for n, lvl, info in checks}


def test_tunnel_match_ok(closed_port, tmp_path):
    run = FakeRun(journalctl=_journal("https://old.ngrok-free.app", "https://bridge.example.com"))
    c = _by_name(ops.tunnel_checks("https://bridge.example.com/", run=run, rendered=str(tmp_path / "none"),
                                   inspector=closed_port))
    assert c["ngrok_inspector"][0] == "OK"
    assert c["public_origin_tunnel"][0] == "OK" and "journal" in c["public_origin_tunnel"][1]
    assert run.calls[0] == ["systemctl", "show", "-p", "InvocationID", "--value", "agent-bridge-ngrok.service"]
    assert run.calls[1][:2] == ["journalctl", f"_SYSTEMD_INVOCATION_ID={INV}"]


def test_tunnel_mismatch_warns(closed_port, tmp_path):
    run = FakeRun(journalctl=_journal("https://abcd-1-2-3-4.ngrok-free.app"))
    c = _by_name(ops.tunnel_checks("https://bridge.example.com", run=run, rendered=str(tmp_path / "none"),
                                   inspector=closed_port))
    lvl, info = c["public_origin_tunnel"]
    assert lvl == "WARN" and "abcd-1-2-3-4.ngrok-free.app" in info


@pytest.mark.parametrize("run", [
    FakeRun(systemctl=FileNotFoundError("systemctl")),
    FakeRun(systemctl=(0, "\n")),                                    # unit not running
    FakeRun(journalctl=(1, "")),                                     # no journal access
    FakeRun(journalctl=subprocess.TimeoutExpired("journalctl", 15)),
    FakeRun(journalctl=_journal()),                                  # no tunnel line (log_level warn)
])
def test_tunnel_journal_unavailable_warns(run, closed_port, tmp_path):
    checks = ops.tunnel_checks("https://bridge.example.com", run=run, rendered=str(tmp_path / "none"),
                               inspector=closed_port)
    c = _by_name(checks)
    assert c["public_origin_tunnel"][0] == "WARN"
    assert not [x for x in checks if x[1] == "FAIL"]


def test_tunnel_rendered_config_fallback(closed_port, tmp_path):
    rendered = tmp_path / "ngrok.yml"
    rendered.write_text((DEPLOY / "ngrok/ngrok.yml.tmpl").read_text().replace("@NGROK_DOMAIN@", "bridge.example.com"))
    run = FakeRun(journalctl=_journal())
    c = _by_name(ops.tunnel_checks("https://bridge.example.com", run=run, rendered=str(rendered), inspector=closed_port))
    assert c["public_origin_tunnel"] == ("OK", "matches the running tunnel (rendered config)")
    c = _by_name(ops.tunnel_checks("https://other.example.com", run=run, rendered=str(rendered),
                                   inspector=closed_port))
    assert c["public_origin_tunnel"][0] == "WARN"


def test_inspector_listener_fails(tmp_path):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    try:
        run = FakeRun(journalctl=_journal("https://bridge.example.com"))
        c = _by_name(ops.tunnel_checks("https://bridge.example.com", run=run, rendered=str(tmp_path / "none"),
                                       inspector=srv.getsockname()))
        assert c["ngrok_inspector"][0] == "FAIL"
    finally:
        srv.close()
    assert ops.NGROK_INSPECTOR == ("127.0.0.1", 4040)


@pytest.mark.parametrize("origin,level", [
    (None, "WARN"), ("https://CHANGE-ME.ngrok-free.app", "WARN"), ("http://bridge.example.com", "FAIL"),
    ("http://127.0.0.1:8787", "OK"), ("https://bridge.example.com:8443", "WARN"), ("https://bridge.example.com/x", "WARN"),
])
def test_public_origin_shape(origin, level, closed_port, tmp_path):
    run = FakeRun(systemctl=(0, ""))
    c = _by_name(ops.tunnel_checks(origin, run=run, rendered=str(tmp_path / "none"), inspector=closed_port))
    assert c["public_origin"][0] == level


def test_cli_doctor_tunnel_needs_no_credentials(tmp_path, monkeypatch, capsys, closed_port):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[server]\nhost = "127.0.0.1"\npublic_origin = "https://bridge.example.com"\n'
                   f'[storage]\ndb_path = "{tmp_path}/b.db"\n')
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    monkeypatch.setattr(ops, "NGROK_INSPECTOR", closed_port)
    real = ops.tunnel_checks
    monkeypatch.setattr(ops, "tunnel_checks", lambda o: real(o, run=FakeRun(journalctl=_journal(
        "https://x.ngrok-free.app")), rendered=str(tmp_path / "none"), inspector=closed_port))
    assert cli.main(["--config", str(cfg), "doctor", "--tunnel"]) == 0       # mismatch is only a warning
    out = capsys.readouterr().out
    assert "WARN public_origin_tunnel" in out and "OK   ngrok_inspector" in out
    assert not (tmp_path / "b.db").exists()
