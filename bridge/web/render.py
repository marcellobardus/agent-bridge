"""Jinja2 rendering for the human dashboard: autoescape everywhere, strict CSP, no-store, no JavaScript.
Agent-written content is untrusted data: it is only ever emitted through autoescaped `{{ }}` expressions."""
import json
import re
from pathlib import Path

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

from ..safety import _CONTROL, _INVISIBLE, is_safe_url, strip_controls

HERE = Path(__file__).parent
CSP = ("default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; "
       "frame-ancestors 'none'; base-uri 'none'")
HTML_HEADERS = {"Content-Security-Policy": CSP, "Cache-Control": "no-store", "Referrer-Policy": "same-origin"}
_ID = re.compile(r"(tsk|msg|art|apr)_[0-9a-z]{26}")
_NEXT = re.compile(r"/app(/[A-Za-z0-9_\-/]*)?")

OK_MESSAGES = {
    "instruction": "Instruction sent to both agents.", "priority": "Priority changed.", "pause": "Task paused.",
    "resume": "Task resumed.", "escalate": "Task escalated to needs_human.", "approve": "Task approved.",
    "reject": "Task rejected.", "transition": "Task state changed.", "decided": "Decision recorded.",
    "stepup": "Step-up confirmed for 5 minutes.", "agent_pause": "Agent paused.", "agent_resume": "Agent resumed.",
    "revoked": "Key revoked.", "approval_revoked": "Approval revoked; the agent can no longer consume it.",
    "reset_counters": "Message counters reset.",
}


def _ts(value) -> str:
    """ISO-8601 string -> 'YYYY-MM-DD HH:MM:SSZ' (UTC)."""
    if not value:
        return "—"
    s = str(value)
    return s[:19].replace("T", " ") + "Z" if "T" in s else s


_NON_PRINTABLE_ASCII = re.compile(r"[^\x20-\x7e\n]")


def _esc(m) -> str:
    c = ord(m.group())
    return f"\\u{c:04x}" if c <= 0xFFFF else "\\u{:04x}\\u{:04x}".format(*(
        0xD800 + ((c - 0x10000) >> 10), 0xDC00 + ((c - 0x10000) & 0x3FF)))


def ascii_view(text: str) -> str:
    """Every character outside printable ASCII becomes a visible \\uXXXX escape (bidi overrides, zero-width
    characters, homoglyphs, DEL), so what the human reads is unambiguous. Used for approval payloads."""
    return _NON_PRINTABLE_ASCII.sub(_esc, text)


_HIDDEN = re.compile(f"{_CONTROL.pattern}|{_INVISIBLE.pattern}")
_WS = re.compile(r"\s+")
PREVIEW_CHARS = 160


def reveal(text: str) -> str:
    """For message bodies: exactly the characters `strip_controls` would silently drop (C0 controls, DEL,
    bidi overrides/isolates, zero-width) become visible \\uXXXX markers; ordinary non-ASCII text (accented
    letters, other scripts, emoji) stays readable."""
    return _HIDDEN.sub(_esc, text)


def has_hidden(text) -> bool:
    return isinstance(text, str) and _HIDDEN.search(text) is not None


def preview(text: str, total_len: int | None = None, n: int = PREVIEW_CHARS) -> str:
    """One-line preview: the first n characters, hidden characters revealed, whitespace collapsed, '…' if cut."""
    text = text or ""
    cut = len(text) > n or (total_len or 0) > n
    return _WS.sub(" ", reveal(text[:n])).strip() + ("…" if cut else "")


def needs_warning(text: str) -> bool:
    """True if the text holds anything a human could misread: non-ASCII, controls, bidi or invisible chars."""
    return _NON_PRINTABLE_ASCII.search(text.replace("\n", "")) is not None


def _pretty(value) -> str:
    return ascii_view(json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True))


def _compact(value) -> str:
    return ascii_view(json.dumps(value, separators=(", ", ": "), ensure_ascii=True, sort_keys=True))


def _finalize(value):
    """Every {{ }} string loses C0 controls, bidi overrides and zero-width characters before autoescape."""
    if isinstance(value, str) and not isinstance(value, Markup):   # Markup = already-escaped template output
        return strip_controls(value)
    return value


def _safe_href(value) -> bool:
    return isinstance(value, str) and is_safe_url(value)


def _is_id(value, prefix: str = "") -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None and value.startswith(prefix)


env = Environment(loader=FileSystemLoader(str(HERE / "templates")), autoescape=select_autoescape(default=True),
                  trim_blocks=True, lstrip_blocks=True, finalize=_finalize)
env.filters.update(ts=_ts, pretty=_pretty, compact=_compact, ascii_view=ascii_view, reveal=reveal, preview=preview)
env.tests.update(suspicious=lambda v: isinstance(v, str) and needs_warning(v))
env.tests.update(safe_href=_safe_href, bridge_id=_is_id, hidden=has_hidden)
env.globals.update(OK_MESSAGES=OK_MESSAGES)


def wants_html(request: Request) -> bool:
    """Browsers navigating or submitting forms send Accept: text/html; API/test clients send */* or JSON."""
    return "text/html" in request.headers.get("accept", "")


def safe_next(value: str | None, default: str = "/app/") -> str:
    """Only same-site dashboard paths (no scheme, host, query or '//') are accepted as redirect targets."""
    return value if isinstance(value, str) and _NEXT.fullmatch(value) and "//" not in value else default


def back_for(path: str) -> str:
    """Where a dashboard form POST returns to, derived from its own path (never from client input)."""
    parts = path.strip("/").split("/")
    if len(parts) >= 3 and parts[1] in ("tasks", "approvals"):
        return f"/app/{parts[1]}/{parts[2]}"
    if len(parts) >= 2 and parts[1] in ("agents", "keys"):
        return "/app/agents"
    return "/app/"


def page_context(request: Request) -> dict:
    """Layout data for logged-in pages: who, CSRF token, pending approvals for my party, audit head."""
    from ..domain.common import audit_head
    from ..util import now_ms
    sess = getattr(request.state, "sess", None)
    if sess is None:
        return {"me": None}
    b = request.app.state.bridge
    with b.db.read() as conn:
        seq, head = audit_head(conn)
        pending = conn.execute("SELECT count(*) FROM approvals WHERE state='pending' AND expires_at>?"
                               " AND approver_party_id=?", (now_ms(), sess["party_id"])).fetchone()[0]
    step_up_ok = sess["step_up_at"] is not None and now_ms() - sess["step_up_at"] <= b.settings.step_up_window_s * 1000
    return {"me": {"login": sess["login"], "display_name": sess["display_name"], "party_id": sess["party_id"],
                   "human_id": sess["human_id"]},
            "csrf": sess["csrf_token"], "audit_head": {"seq": seq, "hash": head}, "my_pending": pending,
            "step_up_ok": step_up_ok}


PRE_COOKIE = "__Host-ab_pre"                 # pre-session CSRF token for the login and enroll forms
PRE_SESSION_TEMPLATES = ("login.html", "enroll.html")
_PRE_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")


def pre_token(request: Request) -> str:
    """The caller's pre-session token: the existing cookie value if well-formed (several tabs keep working),
    else a new random one."""
    import secrets
    cur = request.cookies.get(PRE_COOKIE)
    return cur if isinstance(cur, str) and _PRE_TOKEN.fullmatch(cur) else secrets.token_urlsafe(32)


def pre_token_ok(request: Request, supplied) -> bool:
    import hmac
    cur = request.cookies.get(PRE_COOKIE)
    return (isinstance(cur, str) and isinstance(supplied, str) and _PRE_TOKEN.fullmatch(cur) is not None
            and hmac.compare_digest(cur.encode(), supplied.encode()))


def render(request: Request, template: str, status: int = 200, headers: dict | None = None, **ctx) -> HTMLResponse:
    ok = request.query_params.get("ok")
    pre = pre_token(request) if template in PRE_SESSION_TEMPLATES else None
    data = {"request": request, "path": request.url.path, "flash": OK_MESSAGES.get(ok or ""), **page_context(request),
            "pre_csrf": pre, **ctx}
    html = env.get_template(template).render(**data)
    resp = HTMLResponse(html, status_code=status, headers={**HTML_HEADERS, **(headers or {})})
    if pre:
        resp.set_cookie(PRE_COOKIE, pre, max_age=3600, path="/", secure=True, httponly=True, samesite="strict")
    return resp


def redirect(url: str, ok: str | None = None) -> RedirectResponse:
    return RedirectResponse(url + (f"?ok={ok}" if ok else ""), status_code=303, headers={"Cache-Control": "no-store"})


def done(request: Request, result, ok: str, back: str | None = None):
    """Form POST outcome: browsers get a 303 back to the page (PRG); JSON clients get the original body."""
    if wants_html(request):
        return redirect(back or back_for(request.url.path), ok)
    return result


def html_problem(request: Request, exc) -> HTMLResponse | RedirectResponse:
    """Render a Problem for a browser instead of problem+json."""
    path = request.url.path
    if exc.code == "not_authenticated" or exc.extra.get("session_revoked"):
        return redirect("/app/login")
    hdrs = {k: v for k, v in exc.headers.items() if k.lower() == "retry-after"}
    if path == "/app/login":
        return render(request, "login.html", exc.status, hdrs, error=exc)
    if path.startswith("/app/enroll/"):
        return render(request, "enroll.html", exc.status, hdrs, error=exc, token=path.rsplit("/", 1)[-1],
                      enroll=None)
    if path == "/app/step-up" or exc.code == "step_up_required":
        nxt = safe_next(request.query_params.get("next")) if path == "/app/step-up" else back_for(path)
        return render(request, "step_up.html", exc.status if path == "/app/step-up" else 403, error=exc, next=nxt)
    return render(request, "error.html", exc.status, hdrs, error=exc, back=back_for(path))
