"""RFC 6238 TOTP (stdlib only), with replay protection via the last accepted time step."""
import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse


def hotp(key: bytes, counter: int, digits: int = 6, algo: str = "sha1") -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), getattr(hashlib, algo)).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp(key: bytes, t: float | None = None, step: int = 30, digits: int = 6, algo: str = "sha1") -> str:
    return hotp(key, int((time.time() if t is None else t) // step), digits, algo)


def verify(key: bytes, code: str, last_step: int, t: float | None = None, window: int = 1, step: int = 30) -> int | None:
    """Return the matched time step if `code` is valid within ±window steps and newer than last_step."""
    if not (isinstance(code, str) and code.isdigit() and len(code) == 6):
        return None
    now_step = int((time.time() if t is None else t) // step)
    for s in range(now_step - window, now_step + window + 1):
        if s > last_step and hmac.compare_digest(hotp(key, s), code):
            return s
    return None


def new_secret() -> bytes:
    return secrets.token_bytes(20)


def otpauth_uri(key: bytes, login: str, issuer: str = "Agent Bridge") -> str:
    b32 = base64.b32encode(key).decode().rstrip("=")
    label = urllib.parse.quote(f"{issuer}:{login}")
    return f"otpauth://totp/{label}?secret={b32}&issuer={urllib.parse.quote(issuer)}&algorithm=SHA1&digits=6&period=30"
