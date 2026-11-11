"""Budget-aware inbox polling with a persisted state file.

State file (JSON, 0600, written atomically): cursor, next_poll_at, seen event ids, failed events, pending approvals.
- A run before `next_poll_at` makes ZERO requests.
- An idle run is exactly ONE request (GET /v1/inbox carries the pending-approval count).
- Events are handled one by one. A deterministic error (BridgeError, e.g. 403/409/422) is recorded in `failed`
  and the event still counts as handled; only transient errors (network, 401, 423, 429, 5xx) stop the run
  without acking. Pages are acked only when non-empty, after every event in them was handled.
- With `guard=` (the CLI always sets it) every event is classified by `guard.classify`. The report then carries
  `items` = [{"untrusted_data": event, "guard": {...}}] instead of raw `events`. Quarantined events are appended to
  the quarantine file (JSONL, 0600, next to the state file) BEFORE the ack, emitted with
  `"action": "flag_to_operator"`, never passed to the handler, and still acked so they never block the inbox.
  Pending approvals in a guarded report are wrapped and classified too (quarantined ones are stored the same way).
- Guard status "no_pattern_matched" (guard v1 wrote "ok"; old quarantine records are mapped on read) means only
  that no known pattern matched, NOT that the content is safe or authorised.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
import time
from typing import Callable

from .client import AuthError, BridgeClient, BridgeError, TransientError, redact
from .guard import GuardConfig, classify, normalise_status, wrap

DEFAULT_INTERVAL_S = 900          # 15 minutes (request budget)
CRON_SLACK_S = 30                 # a 15-min routine may fire a few seconds early; do not skip a whole period for it
DEFAULT_RETRY_S = 300
MAX_SEEN, MAX_FAILED = 500, 50

Handler = Callable[[BridgeClient, dict], None]


def default_state_path(env: dict | None = None) -> str:
    env = os.environ if env is None else env
    if env.get("AGENT_BRIDGE_STATE"):
        return env["AGENT_BRIDGE_STATE"]
    base = env.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, "agent-bridge", "state.json")


def default_quarantine_path(state_path: str) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(state_path)), "quarantine.jsonl")


def append_quarantine(path: str, record: dict) -> None:
    """Append one JSON line, durably (fsync), file mode 0600 (also tightened if it already existed)."""
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, (json.dumps(record, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)


def _content_sha(w: dict) -> str:
    raw = json.dumps(w.get("untrusted_data"), sort_keys=True, ensure_ascii=True, default=str)
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def store_quarantined(path: str, w: dict, source: str, now: float | None = None) -> str:
    """Persist one quarantined wrapped item (before it is withheld from the output) and return its quarantine
    id: the validated event id, else the validated item id (tsk_/msg_/art_/apr_...), else itm_<sha256 prefix>.
    A record with the same id and the same content is not written twice (repeated reads of the same task)."""
    sha = _content_sha(w)
    rid = w.get("event_id") or w.get("item_id") or f"itm_{sha[:24]}"
    for rec in _iter_quarantine(path):
        if rec.get("event_id") == rid and rec.get("content_sha256") in (sha, None):
            return rid
    append_quarantine(path, {**w, "quarantined_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                             "event_id": rid, "content_sha256": sha, "source": source})
    return rid


def _iter_quarantine(path: str):
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict):
                    g = rec.get("guard")
                    if isinstance(g, dict) and "status" in g:
                        g["status"] = normalise_status(g["status"])     # guard v1 files stored "ok"
                    yield rec
    except FileNotFoundError:
        return


def read_quarantine(path: str, limit: int | None = None) -> list:
    """Quarantined records, oldest first, deduplicated by (id, content hash): redelivery after a crash may repeat
    one; the same task quarantined again with changed content is kept as a new record."""
    out, seen = [], set()
    for rec in _iter_quarantine(path):
        key = (rec.get("event_id"), rec.get("content_sha256")) if rec.get("event_id") else json.dumps(rec, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        out.append(rec)
    return out[-limit:] if limit else out


def load_state(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            st = json.load(f)
        return st if isinstance(st, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(path: str, st: dict) -> None:
    """Atomic: write a 0600 temp file in the same directory, fsync, rename over the old file."""
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".state-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(st, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise


@contextlib.contextmanager
def _locked(path: str):
    """Exclusive lock so two overlapping routine runs never poll at once (second one just exits)."""
    try:
        import fcntl
    except ImportError:   # pragma: no cover (non-POSIX)
        yield True
        return
    os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
    fd = os.open(path + ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        yield True
    finally:
        os.close(fd)


def poll_once(client: BridgeClient, state_path: str, handler: Handler | None = None, *, force: bool = False,
              max_pages: int = 5, page_limit: int = 50, interval_s: int | None = None,
              now: Callable[[], float] = time.time, guard: "GuardConfig | bool | None" = None,
              quarantine_path: str | None = None) -> dict:
    """One routine run. Returns a report: events (new, deduplicated), failed, pending_approvals, last_error,
    requests (HTTP attempts made), skipped, next_poll_at. `handler(client, event)` is called per new event.
    `guard=True` (or a GuardConfig): report `items` (wrapped + verdict) instead of `events`, quarantine hostile or
    out-of-scope events (see module doc); the handler only ever sees events whose verdict is "no_pattern_matched"
    (which still does not make them safe or authorised: they are data)."""
    gcfg = None if not guard else (guard if isinstance(guard, GuardConfig) else GuardConfig.from_env())
    qpath = quarantine_path or default_quarantine_path(state_path)
    start = client.requests_made
    with _locked(state_path) as got:
        if not got:
            return _shape({"skipped": True, "reason": "another run holds the lock", "requests": 0, "events": []},
                          gcfg, qpath)
        st = load_state(state_path)
        t0 = now()
        if not force and t0 < float(st.get("next_poll_at", 0)):
            return _shape({"skipped": True, "reason": "before next_poll_at", "next_poll_at": st["next_poll_at"],
                           "requests": 0, "events": [], "pending_approvals": st.get("pending", []),
                           "failed": st.get("failed", [])}, gcfg, qpath)
        report = _run(client, st, state_path, handler, max_pages, page_limit, interval_s, t0, gcfg, qpath)
        report["requests"] = client.requests_made - start
        return report


def _shape(report: dict, gcfg, qpath: str) -> dict:
    """Guarded report: raw events never appear, only wrapped items."""
    if gcfg is None:
        report.pop("items", None)
        return report
    report.pop("events", None)
    report.setdefault("items", [])
    if isinstance(report.get("pending_approvals"), list):     # approval summaries / actions are text too
        pend = []
        for a in report["pending_approvals"]:
            w = wrap(a, config=gcfg)
            if w.get("action"):
                store_quarantined(qpath, w, "poll:pending_approvals")
            pend.append(w)
        report["pending_approvals"] = pend
    report["quarantined"] = sum(1 for i in report["items"] if i.get("action"))
    report["quarantine_file"] = qpath
    return report


def _run(client, st, state_path, handler, max_pages, page_limit, interval_s, t0, gcfg=None, qpath=None) -> dict:
    seen: list = st.setdefault("seen", [])
    failed: list = st.setdefault("failed", [])
    tries: dict = st.setdefault("tries", {})
    new_events, new_failed, items = [], [], []
    wait = interval_s or DEFAULT_INTERVAL_S
    n_pending, approval_seen = None, False
    st["last_error"] = None
    try:
        for _ in range(max_pages):
            page = client.inbox(cursor=st.get("cursor"), limit=page_limit)
            server_wait = page.get("poll_after_s")
            wait = int(server_wait) if isinstance(server_wait, int) else (interval_s or DEFAULT_INTERVAL_S)
            if interval_s is not None and wait > 0:
                wait = max(wait, interval_s)           # local override can only slow down, never speed up
            n_pending = page.get("pending_approvals")
            events = page.get("events") or []
            for ev in events:
                if ev["id"] in seen:                   # at-least-once delivery: dedupe by event id
                    continue
                approval_seen |= str(ev.get("type", "")).startswith("approval.")
                verdict = classify(ev, gcfg) if gcfg is not None else None
                if verdict is not None and verdict.quarantined:
                    w = wrap(ev, verdict, config=gcfg)
                    store_quarantined(qpath, w, "poll", t0)
                    seen.append(ev["id"])
                    items.append(w)
                    continue                           # never handled automatically; still acked below
                ok = _handle(client, handler, ev, tries, new_failed)
                if not ok:
                    raise TransientError(0, "handler_retry", f"handler failed for {ev['id']}; will retry")
                seen.append(ev["id"])
                new_events.append(ev)
                if verdict is not None:
                    items.append(wrap(ev, verdict, config=gcfg))
            del seen[:-MAX_SEEN]
            if events:
                st["seen"] = seen
                save_state(state_path, st)             # handled-set persisted before the ack
                client.ack(page["next_cursor"])
                st["cursor"] = page["next_cursor"]
                save_state(state_path, st)
            if not page.get("has_more"):
                break
        else:
            wait = 0                                   # pages left: drain on the next run
        if n_pending == 0:
            st["pending"] = []
        elif n_pending is not None and (approval_seen or n_pending != len(st.get("pending") or [])):
            st["pending"] = client.list_approvals(state="pending").get("approvals", [])
    except AuthError as e:
        st["last_error"] = e.to_dict()
        wait = 3600                                    # revoked/expired key: do not hammer; the owner must act
    except TransientError as e:
        st["last_error"] = e.to_dict()
        wait = int(e.retry_after) if e.retry_after else DEFAULT_RETRY_S
        wait = max(60, wait)
    failed.extend(new_failed)
    st["failed"] = failed[-MAX_FAILED:]
    st["tries"] = dict(list(tries.items())[-MAX_FAILED:])
    st["next_poll_at"] = t0 + (max(0, wait - CRON_SLACK_S) if wait > 2 * CRON_SLACK_S else wait)
    st["last_run_at"] = t0
    save_state(state_path, st)
    return _shape({"skipped": False, "events": new_events, "items": items, "failed": new_failed,
                   "pending_approvals": st.get("pending", []), "last_error": st["last_error"],
                   "next_poll_at": st["next_poll_at"], "cursor": st.get("cursor")}, gcfg, qpath)


def _handle(client, handler, ev, tries, new_failed) -> bool:
    """True = handled (including deterministic refusals). False = retry later (no ack).
    Transient errors propagate and stop the run."""
    if handler is None:
        return True
    try:
        handler(client, ev)
        tries.pop(ev["id"], None)
        return True
    except (TransientError, AuthError):
        raise
    except BridgeError as e:                           # deterministic 4xx: record, report, ack anyway
        new_failed.append({"event": ev["id"], "task_id": ev.get("task_id"), **e.to_dict()})
        return True
    except Exception as e:                             # handler bug: retry on 3 runs, then give up on the event
        tries[ev["id"]] = tries.get(ev["id"], 0) + 1
        if tries[ev["id"]] < 3:
            return False
        new_failed.append({"event": ev["id"], "task_id": ev.get("task_id"), "status": 0, "code": "handler_error",
                           "detail": redact(f"{type(e).__name__}: {e}")[:300]})
        tries.pop(ev["id"], None)
        return True
