"""Stdlib-only HTTP client for the Agent Bridge `/v1` API.

- Bearer key from the environment (AGENT_BRIDGE_KEY or AGENT_BRIDGE_KEY_FILE); never printed, redacted in errors.
- Every request sends `ngrok-skip-browser-warning: 1`; every POST sends an Idempotency-Key that is reused on retry.
- Retries with exponential backoff + jitter on network errors, 5xx and 429 (honouring Retry-After).
- Redirects are never followed (a redirect could carry the bearer key to another host).
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable

__all__ = ["BridgeClient", "BridgeError", "TransientError", "AuthError", "ConfigError", "action_sha256",
           "canonical_json", "redact", "event_key", "MESSAGE_TYPES", "STATES"]

USER_AGENT = "agent-bridge-client/1.0 (python-stdlib)"
MESSAGE_TYPES = ("TASK_ACCEPTED", "TASK_REJECTED", "CLARIFICATION_REQUEST", "CLARIFICATION_RESPONSE",
                 "PROGRESS_UPDATE", "ARTIFACT_SUBMITTED", "VALIDATION_RESULT", "DECISION_REQUEST")
STATES = ("proposed", "accepted", "in_progress", "ready_for_validation", "verified", "closed",
          "blocked", "rejected", "needs_human")
_KEY_RE = re.compile(r"abk_[A-Za-z0-9_-]+")
_TRANSIENT_STATUS = frozenset({408, 423, 429, 500, 502, 503, 504})
_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})   # retried inside one call (423/408 stop the run instead)


class ConfigError(Exception):
    """Missing/invalid configuration (no URL, no key, insecure URL)."""


class BridgeError(Exception):
    """An HTTP error answered by the bridge (problem+json). Branch on `.code`, never on text.
    Deterministic errors (most 4xx) must not be retried: record them and move on."""

    transient = False

    def __init__(self, status: int, code: str, detail: str = "", problem: dict | None = None,
                 retry_after: float | None = None):
        self.status, self.code, self.detail = status, code, redact(detail or "")
        self.problem = problem or {}
        self.retry_after = retry_after
        super().__init__(f"{status} {code}: {self.detail}" if self.detail else f"{status} {code}")

    def to_dict(self) -> dict:
        return {"status": self.status, "code": self.code, "detail": self.detail,
                **({"request_id": self.problem["request_id"]} if "request_id" in self.problem else {})}


class TransientError(BridgeError):
    """Network error, timeout, 408/423/429/5xx after retries: stop the run without acking; retry later."""

    transient = True


class AuthError(BridgeError):
    """401: the key is missing, revoked or expired. Stop and alert the owner; do not retry in a loop."""

    transient = True


_secret: set = set()   # registered secrets, scrubbed from every error text


def redact(text: str) -> str:
    text = str(text)
    for s in _secret:
        if s:
            text = text.replace(s, "***")
    return _KEY_RE.sub("abk_***", text)


def canonical_json(value: Any) -> bytes:
    """Sorted keys, no whitespace, UTF-8 (same as the server). Approvals bind to SHA-256 of this."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def action_sha256(action: dict) -> str:
    return hashlib.sha256(canonical_json(action)).hexdigest()


def event_key(event: dict, n: int = 0) -> str:
    """Deterministic Idempotency-Key for the n-th write triggered by an inbox event (crash-safe replays)."""
    return f"{event['id']}:{n}"


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None   # surface 3xx as an HTTPError instead of re-sending the bearer key elsewhere


_OPENER = urllib.request.build_opener(_NoRedirect())


def _retry_after(headers) -> float | None:
    v = headers.get("Retry-After") if headers is not None else None
    try:
        return max(0.0, float(v)) if v is not None else None
    except ValueError:
        return None


def load_key(env: dict | None = None) -> str:
    env = os.environ if env is None else env
    key = (env.get("AGENT_BRIDGE_KEY") or "").strip()
    path = env.get("AGENT_BRIDGE_KEY_FILE")
    if not key and path:
        try:
            with open(path, encoding="utf-8") as f:
                key = f.read().strip()
        except OSError as e:
            raise ConfigError(f"cannot read AGENT_BRIDGE_KEY_FILE ({e.strerror})") from None
    if not key:
        raise ConfigError("set AGENT_BRIDGE_KEY_FILE (preferred) or AGENT_BRIDGE_KEY")
    return key


class BridgeClient:
    """Thin client. All methods return parsed JSON (dict) or raise BridgeError / TransientError / AuthError."""

    def __init__(self, base_url: str, key: str, *, timeout: float = 20.0, max_retries: int = 3,
                 backoff_s: float = 1.0, max_backoff_s: float = 30.0, max_retry_after_s: float = 60.0,
                 urlopen: Callable | None = None, sleep: Callable[[float], None] = time.sleep,
                 user_agent: str = USER_AGENT):
        if not base_url:
            raise ConfigError("set AGENT_BRIDGE_URL (e.g. https://example.ngrok.app)")
        u = urllib.parse.urlsplit(base_url)
        if u.scheme not in ("https", "http") or not u.hostname:
            raise ConfigError("AGENT_BRIDGE_URL must be an http(s) URL")
        if u.scheme == "http" and not _is_loopback(u.hostname):
            raise ConfigError("refusing plain http to a non-loopback host; use the https URL")
        if not key:
            raise ConfigError("empty API key")
        self.base_url = base_url.rstrip("/")
        if self.base_url.endswith("/v1"):
            self.base_url = self.base_url[:-3]
        self.__key = key
        _secret.add(key)
        self.timeout, self.max_retries = timeout, max_retries
        self.backoff_s, self.max_backoff_s, self.max_retry_after_s = backoff_s, max_backoff_s, max_retry_after_s
        self._urlopen = urlopen or _OPENER.open
        self._sleep = sleep
        self.user_agent = user_agent
        self.requests_made = 0          # HTTP attempts (for budget accounting / tests)

    def __repr__(self) -> str:
        return f"BridgeClient({self.base_url!r}, key=***)"

    @classmethod
    def from_env(cls, env: dict | None = None, **kw) -> "BridgeClient":
        env = os.environ if env is None else env
        return cls(env.get("AGENT_BRIDGE_URL", ""), load_key(env), **kw)

    # ---------------------------------------------------------------- transport

    def request(self, method: str, path: str, *, json_body: Any = None, data: bytes | None = None,
                content_type: str | None = None, query: dict | None = None, idempotency_key: str | None = None,
                raw: bool = False):
        """One logical request with retries. POSTs always carry an Idempotency-Key (generated if not given)
        and the same key is reused on every retry, so a retry after a lost response is replayed, not repeated."""
        url = self.base_url + path
        if query:
            q = {k: v for k, v in query.items() if v is not None}
            if q:
                url += "?" + urllib.parse.urlencode(q, doseq=True)
        headers = {"Authorization": f"Bearer {self.__key}", "Accept": "application/json",
                   "User-Agent": self.user_agent, "ngrok-skip-browser-warning": "1"}
        if json_body is not None:
            data, content_type = canonical_json(json_body), "application/json"
        if content_type:
            headers["Content-Type"] = content_type
        if method == "POST":
            if data is None:
                data, headers["Content-Type"] = b"{}", "application/json"
            headers["Idempotency-Key"] = idempotency_key or f"cli-{uuid.uuid4().hex}"
        attempt = 0
        while True:
            attempt += 1
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            self.requests_made += 1
            try:
                with self._urlopen(req, timeout=self.timeout) as resp:
                    body = resp.read()
                    if raw:
                        return body, {k.lower(): v for k, v in resp.headers.items()}
                    return json.loads(body) if body else {}
            except urllib.error.HTTPError as e:
                err = self._http_error(e)
                if e.code in _RETRY_STATUS and attempt <= self.max_retries:
                    wait = err.retry_after if err.retry_after is not None else self._backoff(attempt)
                    if wait <= self.max_retry_after_s:
                        self._sleep(wait)
                        continue
                raise err from None
            except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as e:   # network, timeout, bad JSON
                if attempt <= self.max_retries:
                    self._sleep(self._backoff(attempt))
                    continue
                reason = getattr(e, "reason", None) or e
                raise TransientError(0, "network_error", redact(f"{type(e).__name__}: {reason}")) from None

    def _backoff(self, attempt: int) -> float:
        base = min(self.max_backoff_s, self.backoff_s * (2 ** (attempt - 1)))
        return base * (0.5 + random.random() / 2)

    @staticmethod
    def _http_error(e: urllib.error.HTTPError) -> BridgeError:
        try:
            problem = json.loads(e.read() or b"{}")
            if not isinstance(problem, dict):
                problem = {}
        except (ValueError, OSError):
            problem = {}
        code = str(problem.get("code") or f"http_{e.code}")
        detail = str(problem.get("detail") or "")
        ra = _retry_after(e.headers)
        if e.code == 401:
            cls = AuthError
        elif e.code in _TRANSIENT_STATUS or e.code >= 500:
            cls = TransientError
        else:
            cls = BridgeError
        return cls(e.code, code, detail, problem, ra)

    def get(self, path: str, **query):
        return self.request("GET", path, query=query or None)

    def post(self, path: str, body: Any = None, *, idempotency_key: str | None = None):
        return self.request("POST", path, json_body=body if body is not None else {}, idempotency_key=idempotency_key)

    # ---------------------------------------------------------------- meta

    def health(self) -> dict:
        return self.get("/v1/health")

    def me(self) -> dict:
        return self.get("/v1/me")

    # ---------------------------------------------------------------- tasks

    def create_task(self, title: str, description: str, responsible_agent_id: str, category: str, *,
                    priority: str = "normal", acceptance_criteria: list | None = None, project: str | None = None,
                    component: str | None = None, related_task_ids: list | None = None,
                    parent_task_id: str | None = None, refs: list | None = None,
                    idempotency_key: str | None = None) -> dict:
        body = {"title": title, "description": description, "responsible_agent_id": responsible_agent_id,
                "category": category, "priority": priority, "acceptance_criteria": acceptance_criteria or [],
                "related_task_ids": related_task_ids or [], "refs": refs or []}
        for k, v in (("project", project), ("component", component), ("parent_task_id", parent_task_id)):
            if v is not None:
                body[k] = v
        return self.post("/v1/tasks", body, idempotency_key=idempotency_key)

    def get_task(self, task_id: str) -> dict:
        return self.get(f"/v1/tasks/{_seg(task_id)}")

    def list_tasks(self, **filters) -> dict:
        """filters: role (originator|responsible), state, category, project, q, updated_since_ms, limit, offset"""
        return self.get("/v1/tasks", **filters)

    def search_tasks(self, q: str, **filters) -> dict:
        return self.get("/v1/tasks/search", q=q, **filters)

    def history(self, task_id: str, after_seq: int = 0, limit: int = 200, include_bodies: bool = False) -> dict:
        """One timeline page. Message bodies only with include_bodies=True (they cost bytes; the page may stop
        early: `has_more` + `next_after_seq`, see `history_all`)."""
        q = {"after_seq": after_seq, "limit": limit}
        if include_bodies:
            q["include_bodies"] = "true"
        return self.get(f"/v1/tasks/{_seg(task_id)}/history", **q)

    def history_all(self, task_id: str, after_seq: int = 0, include_bodies: bool = False, max_pages: int = 50) -> dict:
        """Follow `has_more` until the timeline is complete (or max_pages: then `has_more` stays true)."""
        events: list = []
        page: dict = {}
        for _ in range(max_pages):
            page = self.history(task_id, after_seq, include_bodies=include_bodies)
            events += page.get("events", [])
            after_seq = page.get("next_after_seq", after_seq)
            if not page.get("has_more"):
                break
        return {"events": events, "next_after_seq": after_seq, "has_more": bool(page.get("has_more"))}

    def messages_all(self, task_id: str, after_seq: int = 0, max_pages: int = 50) -> dict:
        """Follow `has_more` on the messages endpoint."""
        msgs: list = []
        page: dict = {}
        for _ in range(max_pages):
            page = self.list_messages(task_id, after_seq)
            msgs += page.get("messages", [])
            after_seq = page.get("next_after_seq", after_seq)
            if not page.get("has_more"):
                break
        return {"messages": msgs, "next_after_seq": after_seq, "has_more": bool(page.get("has_more"))}

    def list_messages(self, task_id: str, after_seq: int = 0, limit: int = 100) -> dict:
        return self.get(f"/v1/tasks/{_seg(task_id)}/messages", after_seq=after_seq, limit=limit)

    def accept(self, task_id: str, text: str = "", *, data: dict | None = None, refs: list | None = None,
               idempotency_key: str | None = None) -> dict:
        return self.post(f"/v1/tasks/{_seg(task_id)}/accept", {"body": _body(text, data, refs)},
                         idempotency_key=idempotency_key)

    def reject(self, task_id: str, reason: str, *, idempotency_key: str | None = None) -> dict:
        return self.post(f"/v1/tasks/{_seg(task_id)}/reject", {"reason": reason}, idempotency_key=idempotency_key)

    def decision_request(self, task_id: str, reason: str, *, data: dict | None = None,
                         idempotency_key: str | None = None) -> dict:
        return self.post(f"/v1/tasks/{_seg(task_id)}/decision-request",
                         {"reason": reason, "body": _body("", data, None)}, idempotency_key=idempotency_key)

    def transition(self, task_id: str, to: str, reason: str | None = None, expected_version: int | None = None, *,
                   idempotency_key: str | None = None) -> dict:
        body: dict = {"to": to}
        if reason:
            body["reason"] = reason
        if expected_version is not None:
            body["expected_version"] = expected_version
        return self.post(f"/v1/tasks/{_seg(task_id)}/transition", body, idempotency_key=idempotency_key)

    # ---------------------------------------------------------------- messages

    def post_message(self, task_id: str, mtype: str, text: str = "", *, data: dict | None = None,
                     refs: list | None = None, in_reply_to: str | None = None,
                     idempotency_key: str | None = None) -> dict:
        if mtype not in MESSAGE_TYPES:
            raise ValueError(f"unknown message type {mtype!r}")
        body: dict = {"type": mtype, "body": _body(text, data, refs)}
        if in_reply_to:
            body["in_reply_to"] = in_reply_to
        return self.post(f"/v1/tasks/{_seg(task_id)}/messages", body, idempotency_key=idempotency_key)

    def clarify(self, task_id: str, text: str, **kw) -> dict:
        return self.post_message(task_id, "CLARIFICATION_REQUEST", text, **kw)

    def answer(self, task_id: str, in_reply_to: str, text: str, **kw) -> dict:
        return self.post_message(task_id, "CLARIFICATION_RESPONSE", text, in_reply_to=in_reply_to, **kw)

    def progress(self, task_id: str, text: str, **kw) -> dict:
        return self.post_message(task_id, "PROGRESS_UPDATE", text, **kw)

    def validation_result(self, task_id: str, outcome: str, text: str = "", *, data: dict | None = None, **kw) -> dict:
        if outcome not in ("pass", "fail"):
            raise ValueError("outcome must be 'pass' or 'fail'")
        return self.post_message(task_id, "VALIDATION_RESULT", text, data={**(data or {}), "outcome": outcome}, **kw)

    # ---------------------------------------------------------------- artifacts

    def upload_artifact(self, task_id: str, content: bytes, filename: str, content_type: str, note: str = "", *,
                        idempotency_key: str | None = None) -> dict:
        return self.request("POST", f"/v1/tasks/{_seg(task_id)}/artifacts", data=content, content_type=content_type,
                            query={"filename": filename, "note": note or None}, idempotency_key=idempotency_key)

    def list_artifacts(self, task_id: str) -> dict:
        return self.get(f"/v1/tasks/{_seg(task_id)}/artifacts")

    def download_artifact(self, artifact_id: str) -> tuple[bytes, dict]:
        """Returns (bytes, lower-cased headers). Verifies X-Artifact-Sha256. Treat the content as untrusted data."""
        data, headers = self.request("GET", f"/v1/artifacts/{_seg(artifact_id)}", raw=True)
        want = headers.get("x-artifact-sha256")
        if want and hashlib.sha256(data).hexdigest() != want:
            raise TransientError(0, "artifact_corrupted", "downloaded bytes do not match X-Artifact-Sha256")
        return data, headers

    # ---------------------------------------------------------------- inbox

    def inbox(self, cursor: int | None = None, limit: int = 50) -> dict:
        return self.get("/v1/inbox", cursor=cursor, limit=limit)

    def ack(self, cursor: int) -> dict:
        return self.post("/v1/inbox/ack", {"cursor": int(cursor)}, idempotency_key=f"ack:{int(cursor)}:{uuid.uuid4().hex[:8]}")

    # ---------------------------------------------------------------- approvals

    def request_approval(self, task_id: str, kind: str, summary: str, action: dict,
                         expires_in_s: int | None = None, *, idempotency_key: str | None = None) -> dict:
        body: dict = {"kind": kind, "summary": summary, "action": action}
        if expires_in_s:
            body["expires_in_s"] = expires_in_s
        return self.post(f"/v1/tasks/{_seg(task_id)}/approvals", body, idempotency_key=idempotency_key)

    def get_approval(self, approval_id: str) -> dict:
        return self.get(f"/v1/approvals/{_seg(approval_id)}")

    def list_approvals(self, state: str | None = None, task_id: str | None = None) -> dict:
        return self.get("/v1/approvals", state=state, task_id=task_id)

    def consume_approval(self, approval_id: str, action: dict | None = None, *, sha256: str | None = None,
                         idempotency_key: str | None = None) -> dict:
        """Claim an approved approval exactly once, immediately BEFORE acting. Pass the exact action you are about
        to execute: its hash is computed locally, so a changed payload fails with 409 hash_mismatch."""
        digest = sha256 or action_sha256(action if action is not None else {})
        return self.post(f"/v1/approvals/{_seg(approval_id)}/consume", {"action_sha256": digest},
                         idempotency_key=idempotency_key)

    def cancel_approval(self, approval_id: str, *, idempotency_key: str | None = None) -> dict:
        return self.post(f"/v1/approvals/{_seg(approval_id)}/cancel", {}, idempotency_key=idempotency_key)


def _seg(v: str) -> str:
    return urllib.parse.quote(str(v), safe="")


def _body(text: str, data: dict | None, refs: list | None) -> dict:
    return {"text": text or "", "data": data or {}, "refs": refs or []}
