"""SQLite access: one writer connection behind a mutex (BEGIN IMMEDIATE), per-thread readers, migrations."""
import contextlib
import sqlite3
import threading
from importlib import resources

PRAGMAS = (
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=FULL",
    "PRAGMA foreign_keys=ON",
    "PRAGMA busy_timeout=5000",
    "PRAGMA cache_size=-8000",
    "PRAGMA mmap_size=0",
    "PRAGMA journal_size_limit=67108864",
    "PRAGMA trusted_schema=OFF",
)


def connect(path: str, *, readonly: bool = False) -> sqlite3.Connection:
    conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=5.0)
    conn.row_factory = sqlite3.Row
    for p in PRAGMAS:
        conn.execute(p)
    if readonly:
        conn.execute("PRAGMA query_only=ON")
    return conn


def migrations() -> list[tuple[int, str]]:
    out = []
    for f in resources.files("bridge.db").joinpath("migrations").iterdir():
        if f.name.endswith(".sql"):
            out.append((int(f.name.split("_", 1)[0]), f.read_text()))
    return sorted(out)


def migrate(conn: sqlite3.Connection) -> int:
    """Apply pending migrations; returns the resulting schema version."""
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    for version, sql in migrations():
        if version > current:
            conn.executescript(f"BEGIN IMMEDIATE;\n{sql}\nPRAGMA user_version={version};\nCOMMIT;")
            current = version
    return current


class Database:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._writer: sqlite3.Connection | None = None
        self._local = threading.local()
        self._gen = 0   # bumped by close(): per-thread readers reconnect

    def _get_writer(self) -> sqlite3.Connection:
        if self._writer is None:
            self._writer = connect(self.path)
        return self._writer

    @contextlib.contextmanager
    def writer(self):
        """Exclusive access to the single write connection; caller manages BEGIN/COMMIT."""
        with self._lock:
            conn = self._get_writer()
            try:
                yield conn
            finally:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")

    @contextlib.contextmanager
    def write(self):
        """One BEGIN IMMEDIATE transaction; commits on success, rolls back on any exception."""
        with self.writer() as conn:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")

    @contextlib.contextmanager
    def read(self):
        conn = getattr(self._local, "conn", None)
        if conn is None or self._local.gen != self._gen:
            conn = connect(self.path, readonly=True)
            self._local.conn, self._local.gen = conn, self._gen
        conn.execute("BEGIN")
        try:
            yield conn
        finally:
            conn.execute("ROLLBACK")

    def close(self):
        if self._writer is not None:
            self._writer.close()
            self._writer = None
        self._gen += 1
