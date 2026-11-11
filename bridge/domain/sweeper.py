"""In-process retention sweeper, run every 60 s on a daemon thread while the app is up.

| Data                 | Kept for                                                       |
|----------------------|----------------------------------------------------------------|
| Idempotency keys     | 7 days (SPEC §6)                                               |
| Inbox events         | 30 days, and only once the recipient's cursor has acked them   |
| Sessions             | 1 day after expiry / revocation / idle timeout                 |
| Login throttle rows  | 1 hour after the last failure (and never while a delay is due); capped at 10k rows |
| Enrollment links     | 7 days after use or expiry (only hashes are stored)            |
| Approvals            | kept forever; a pending/approved one past its deadline is persisted as `expired` |
| Tasks, messages, artifacts, audit | forever (v1)                                      |

Each tick also refreshes the storage guard (low disk / inodes -> writes 503), so the dashboard banner and the
write refusal follow the disk state even when no agent writes. Deletions are logged, not audited: they remove
derived/transient rows only, and auditing them every minute would bloat the chain."""
import contextlib
import logging
import threading

from .. import logs
from ..util import now_ms
from . import approvals

DAY_MS = 86_400_000
IDEMPOTENCY_TTL_MS = 7 * DAY_MS
EVENT_TTL_MS = 30 * DAY_MS
SESSION_GRACE_MS = DAY_MS
THROTTLE_TTL_MS = 3_600_000
THROTTLE_MAX_ROWS = 10_000
ENROLLMENT_GRACE_MS = 7 * DAY_MS
INTERVAL_S = 60


def sweep(conn, session_idle_s: int, now: int | None = None) -> dict:
    """One retention pass inside the caller's write transaction. Returns row counts per table."""
    now = now if now is not None else now_ms()
    out = {}
    out["idempotency_keys"] = conn.execute("DELETE FROM idempotency_keys WHERE created_at<?",
                                           (now - IDEMPOTENCY_TTL_MS,)).rowcount
    out["events"] = conn.execute(
        "DELETE FROM events WHERE created_at<? AND seq<=coalesce((SELECT c.acked_seq FROM agent_cursors c"
        " WHERE c.agent_id=events.recipient_agent_id),0)", (now - EVENT_TTL_MS,)).rowcount
    cut = now - SESSION_GRACE_MS
    out["sessions"] = conn.execute(
        "DELETE FROM sessions WHERE expires_at<? OR revoked_at<? OR last_seen_at<?",
        (cut, cut, cut - session_idle_s * 1000)).rowcount
    n = conn.execute("DELETE FROM login_throttle WHERE updated_at<? AND next_allowed_at<=?",
                     (now - THROTTLE_TTL_MS, now)).rowcount
    n += conn.execute("DELETE FROM login_throttle WHERE ip IN (SELECT ip FROM login_throttle ORDER BY updated_at DESC"
                      " LIMIT -1 OFFSET ?)", (THROTTLE_MAX_ROWS,)).rowcount
    out["login_throttle"] = n
    out["enrollments"] = conn.execute("DELETE FROM enrollments WHERE used_at<? OR expires_at<?",
                                      (now - ENROLLMENT_GRACE_MS, now - ENROLLMENT_GRACE_MS)).rowcount
    due = conn.execute("SELECT * FROM approvals WHERE (state='pending' AND expires_at<=?) OR"
                       " (state='approved' AND valid_until<=?)", (now, now)).fetchall()
    for a in due:
        approvals._expire_if_due(conn, a)
    out["approvals_expired"] = len(due)
    return out


class Sweeper:
    def __init__(self, bridge, interval_s: float = INTERVAL_S):
        self.b, self.interval = bridge, interval_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._degraded: bool | None = None

    def run_once(self) -> dict:
        degraded = self.b.storage.degraded()
        if degraded != self._degraded:
            if degraded or self._degraded is not None:
                logs.event("storage_degraded" if degraded else "storage_ok",
                           logging.WARNING if degraded else logging.INFO)
            self._degraded = degraded
        if degraded:
            return {}                 # free space first; deleting rows needs WAL space too
        with self.b.db.write() as conn:
            counts = sweep(conn, self.b.settings.session_idle_s)
        if any(counts.values()):
            logs.event("sweep", **{k: v for k, v in counts.items() if v})
        return counts

    def _loop(self) -> None:
        while True:
            try:
                self.run_once()
            except Exception as exc:          # never kill the thread; next tick retries
                logs.event("sweep_failed", logging.ERROR, exc_type=type(exc).__name__)
            if self._stop.wait(self.interval):
                return

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="bridge-sweeper", daemon=True)
            self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
            self._thread = None


def install(app) -> None:
    """Start the sweeper with the app's lifespan (uvicorn startup) and stop it on shutdown."""
    inner = app.router.lifespan_context

    @contextlib.asynccontextmanager
    async def lifespan(a):
        sw = Sweeper(a.state.bridge)
        a.state.sweeper = sw
        sw.start()
        try:
            async with inner(a) as state:
                yield state
        finally:
            sw.stop()

    app.router.lifespan_context = lifespan
