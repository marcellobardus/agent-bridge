"""Small shared helpers: clock, ids, canonical JSON, request-id context."""
import contextvars
import datetime as _dt
import hashlib
import json
import os
import time

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")

_CROCKFORD = "0123456789abcdefghjkmnpqrstvwxyz"


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def new_id(prefix: str) -> str:
    """Time-ordered id (48-bit ms timestamp + 80 random bits), Crockford base32, with a type prefix."""
    n = (now_ms() << 80) | int.from_bytes(os.urandom(10), "big")
    out = []
    for _ in range(26):
        out.append(_CROCKFORD[n & 31])
        n >>= 5
    return f"{prefix}_{''.join(reversed(out))}"


def canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dumps(value) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def iso(ms: int | None) -> str | None:
    if ms is None:
        return None
    return _dt.datetime.fromtimestamp(ms / 1000, _dt.UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Budget:
    """Response byte budget: list endpoints stop adding items once ~max_bytes of JSON are reached.
    The first item is always admitted (single items are already bounded by input limits)."""

    def __init__(self, max_bytes: int):
        self.left, self.n, self.truncated = max_bytes, 0, False

    def admit(self, item) -> bool:
        size = len(dumps(item).encode())
        if self.n and size > self.left:
            self.truncated = True
            return False
        self.left -= size
        self.n += 1
        return True


def json_depth_exceeds(value, max_depth: int) -> bool:
    """True if containers nest deeper than max_depth (iterative: no recursion on hostile input)."""
    stack = [(value, 1)]
    while stack:
        v, d = stack.pop()
        if isinstance(v, dict):
            if d > max_depth:
                return True
            stack.extend((x, d + 1) for x in v.values())
        elif isinstance(v, list):
            if d > max_depth:
                return True
            stack.extend((x, d + 1) for x in v)
    return False
