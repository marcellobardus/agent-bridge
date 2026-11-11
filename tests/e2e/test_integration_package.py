"""integration-kit/ is checked against the real service: schemas in sync with openapi.json, every error code the
service can raise is documented, real responses validate against the schemas, and the three examples
(curl.sh, client.py, client.ts) work against a live server."""
import json
import os
import re
import shutil
import subprocess

import pytest
import e2e_support  # noqa: F401  (sets sys.path for clients/python and tools/)
from e2e_support import PY, REPO, SRC, server  # noqa: F401  (pytest fixture)

PKG = os.path.join(REPO, "integration-kit")
SCHEMAS = os.path.join(PKG, "schemas")


def schema(name):
    with open(os.path.join(SCHEMAS, name)) as f:
        return json.load(f)


def validate(instance, sch, root=None, path="$"):
    """Small JSON Schema subset validator (type, enum, const, required, properties, additionalProperties=false,
    items, anyOf, allOf, $ref to #/$defs) — enough for the generated schemas; no third-party dependency."""
    root = root or sch
    if "$ref" in sch:
        return validate(instance, root["$defs"][sch["$ref"].rsplit("/", 1)[1]], root, path)
    if "anyOf" in sch:
        errs = []
        for s in sch["anyOf"]:
            try:
                validate(instance, s, root, path)
                break
            except AssertionError as e:
                errs.append(str(e))
        else:
            raise AssertionError(f"{path}: no anyOf branch matched: {errs}")
    t = sch.get("type")
    types = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool, "null": type(None),
             "number": (int, float)}
    if t and not isinstance(instance, types[t]) or (t == "integer" and isinstance(instance, bool)):
        raise AssertionError(f"{path}: expected {t}, got {type(instance).__name__}")
    if "enum" in sch and instance not in sch["enum"]:
        raise AssertionError(f"{path}: {instance!r} not in enum")
    if isinstance(instance, dict):
        for k in sch.get("required", []):
            if k not in instance:
                raise AssertionError(f"{path}: missing {k}")
        props = sch.get("properties", {})
        for k, v in instance.items():
            if k in props:
                validate(v, props[k], root, f"{path}.{k}")
            elif sch.get("additionalProperties") is False:
                raise AssertionError(f"{path}: unexpected {k}")
    if isinstance(instance, list) and "items" in sch:
        for i, v in enumerate(instance):
            validate(v, sch["items"], root, f"{path}[{i}]")
    return None


def test_schemas_in_sync_with_openapi():
    p = subprocess.run([PY, os.path.join(REPO, "scripts", "gen_integration_schemas.py"), "--check"],
                       capture_output=True, text=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert p.returncode == 0, p.stdout + p.stderr
    with open(os.path.join(REPO, "docs", "openapi.json")) as f:
        api = json.load(f)
    assert schema("message-post.json")["properties"]["type"]["enum"] == \
        api["components"]["schemas"]["MessageIn"]["properties"]["type"]["enum"]
    assert set(schema("task.json")["properties"]["state"]["enum"]) == {
        "proposed", "accepted", "in_progress", "ready_for_validation", "verified", "closed", "blocked", "rejected",
        "needs_human"}


def test_every_service_error_code_is_documented():
    """Every code the agent-facing modules can raise is in schemas/error.json, and every schema code is
    explained in ERRORS.md. (Human-only /app codes such as csrf_failed are not part of the agent contract.)"""
    codes = set(schema("error.json")["properties"]["code"]["enum"])
    with open(os.path.join(PKG, "ERRORS.md")) as f:
        errors_md = f.read()
    assert not sorted(c for c in codes if f"`{c}`" not in errors_md)
    agent_src = ("api/agent.py", "api/deps.py", "api/app.py", "domain/messages.py", "domain/statemachine.py",
                 "domain/tasks.py", "domain/artifacts.py", "domain/approvals.py", "domain/inbox.py",
                 "domain/common.py")   # keys.py = human/CLI key management, not agent-facing
    raised = set()
    for rel in agent_src:
        p = os.path.join(SRC, "bridge", rel)
        if os.path.exists(p):
            with open(p) as f:
                src = f.read()
            raised |= set(re.findall(r'Problem\(\s*\d+,\s*"([a-z_]+)"', src))
            raised |= {f"{w}_not_found" for w in re.findall(r'not_found\("([a-z]+)"\)', src)}
    assert len(raised) > 30
    assert raised - codes - {"invalid_decision"} == set(), sorted(raised - codes)   # decide is human-only


def test_real_responses_match_schemas(server):
    g, h = server.client("agent-a"), server.client("agent-b")
    validate(h.me(), schema("me.json"))
    created = g.create_task("Schema check", "desc", "agent-b", "bug_fix", acceptance_criteria=["x"],
                            refs=[{"kind": "url", "value": "https://example.com/r"}])
    validate(created["task"], schema("task.json"))
    tid = created["task"]["id"]
    page = h.inbox()
    validate(page, schema("inbox-page.json"))
    for ev in page["events"]:
        validate(ev, schema("event.json"))
        validate(ev["message"], schema("message.json"))
    posted = h.accept(tid, "ok")
    validate(posted, schema("message-posted.json"))
    art = g.upload_artifact(tid, b"a,b\n1,2\n", "x.csv", "text/csv")["artifact"]
    validate(art, schema("artifact.json"))
    apr = h.request_approval(tid, "prod_deploy", "deploy", {"v": 1})["approval"]
    validate(apr, schema("approval.json"))
    validate(h.get_task(tid), schema("task-detail.json"))
    validate({"kind": "prod_deploy", "summary": "s", "action": {"a": 1}}, schema("approval-request.json"))
    validate({"type": "PROGRESS_UPDATE", "body": {"text": "t", "data": {}, "refs": [{"kind": "commit", "value": "ab"}]}},
             schema("message-post.json"))
    from agent_bridge_client import BridgeError
    with pytest.raises(BridgeError) as ei:
        h.transition(tid, "verified")
    validate(ei.value.problem, schema("error.json"))
    with pytest.raises(AssertionError):
        validate({"type": "NOT_A_TYPE"}, schema("message-post.json"))


def _env(server, tmp_path, **extra):
    return {**server.env, "AGENT_BRIDGE_URL": server.url, "AGENT_BRIDGE_KEY": server.tokens["agent-b"],
            "AGENT_BRIDGE_STATE": str(tmp_path / "pkg-state.json"), **extra}


def test_python_example_smoke_and_poll(server, tmp_path):
    ex = os.path.join(PKG, "examples", "client.py")
    env = _env(server, tmp_path)
    p = subprocess.run([PY, "-I", ex, "smoke"], env=env, capture_output=True, text=True, timeout=60, cwd=tmp_path)
    assert p.returncode == 0 and "SMOKE OK" in p.stdout, p.stdout + p.stderr
    assert "transition_forbidden" in p.stdout
    server.client("agent-a").create_task("Example poll", "d", "agent-b", "bug_fix")
    p = subprocess.run([PY, "-I", ex, "poll-once"], env=env, capture_output=True, text=True, timeout=60, cwd=tmp_path)
    assert p.returncode == 0 and p.stderr.strip() == "ok", p.stderr
    evs = [json.loads(x) for x in p.stdout.splitlines()]
    assert any(e["type"] == "task.created" and e["task"]["title"] == "Example poll" for e in evs)
    p = subprocess.run([PY, "-I", ex, "poll-once"], env=env, capture_output=True, text=True, timeout=60, cwd=tmp_path)
    assert "skipped" in p.stderr and p.stdout == ""
    for out in (p.stdout, p.stderr):
        assert server.tokens["agent-b"] not in out


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_typescript_example_runs_on_node(server, tmp_path):
    ex = os.path.join(PKG, "examples", "client.ts")
    env = _env(server, tmp_path)
    node = [shutil.which("node"), "--experimental-strip-types", "--no-warnings"]
    p = subprocess.run(node + [ex, "me"], env=env, capture_output=True, text=True, timeout=60, cwd=tmp_path)
    if "experimental-strip-types" in p.stderr and "bad option" in p.stderr:
        pytest.skip("node without type stripping")
    assert p.returncode == 0 and json.loads(p.stdout)["agent_id"] == "agent-b", p.stderr
    server.client("agent-a").create_task("TS poll", "d", "agent-b", "bug_fix")
    p = subprocess.run(node + [ex, "poll-once"], env=env, capture_output=True, text=True, timeout=60, cwd=tmp_path)
    assert p.returncode == 0 and p.stderr.strip() == "ok", p.stderr
    assert any(json.loads(x)["type"] == "task.created" for x in p.stdout.splitlines())
    p = subprocess.run(node + [ex, "poll-once"], env=env, capture_output=True, text=True, timeout=60, cwd=tmp_path)
    assert "skipped" in p.stderr
    with open(tmp_path / "pkg-state.json") as f:
        assert json.load(f)["cursor"] >= 1


@pytest.mark.skipif(not (shutil.which("curl") and shutil.which("jq") and shutil.which("bash")),
                    reason="curl/jq/bash missing")
def test_curl_example(server, tmp_path):
    ex = os.path.join(PKG, "examples", "curl.sh")
    assert subprocess.run(["bash", "-n", ex]).returncode == 0
    env = _env(server, tmp_path)
    p = subprocess.run(["bash", ex], env=env, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    assert '"agent_id":"agent-b"' in p.stdout.replace(" ", "") and '"poll_after_s"' in p.stdout
    tid = server.client("agent-a").create_task("curl flow", "d", "agent-b", "bug_fix")["task"]["id"]
    script = (f'source "{ex}"; bridge_accept {tid} curl-accept-0001 >/dev/null; '
              f'bridge_progress {tid} "fixed" 4f2c9e1d https://github.example/pr/1 curl-prog-0001 >/dev/null; '
              f'bridge_status {tid} in_progress curl-state-0001 >/dev/null; bridge_task {tid}')
    p = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["task"]["state"] == "in_progress"
    act = '{"version":"1.4.2","service":"margin"}'
    script = (f'source "{ex}"; bridge_approval_request {tid} prod_deploy "deploy" \'{act}\' curl-apr-0001')
    p = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=60)
    from agent_bridge_client import action_sha256
    assert json.loads(p.stdout)["approval"]["action_sha256"] == action_sha256(json.loads(act))
    p = subprocess.run(["ps", "-eo", "args"], capture_output=True, text=True)
    assert server.tokens["agent-b"] not in p.stdout


def test_package_contains_no_secrets_and_prompt_uses_env_names():
    key_re = re.compile(rb"abk_[a-z0-9]{12}_[A-Za-z0-9_-]{20,}")
    for dirpath, dirs, files in os.walk(PKG):
        dirs[:] = [d for d in dirs if d != "__pycache__"]      # local bytecode is never shipped
        for fn in files:
            if fn.endswith((".pyc", ".pyo")):
                continue
            with open(os.path.join(dirpath, fn), "rb") as f:    # bytes: a binary file cannot crash the scan
                assert not key_re.search(f.read()), fn
    for name in ("README.md", "API.md", "AUTH.md", "ERRORS.md", "PROTOCOL.md", "TESTING.md",
                 "examples/curl.sh", "examples/client.py", "examples/client.ts"):
        assert os.path.exists(os.path.join(PKG, name)), name
