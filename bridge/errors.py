"""Problem+json errors with a stable machine-readable `code`."""


class Problem(Exception):
    """Raised by domain and API code. `commit=True` keeps the transaction's side effects
    (e.g. a loop guard that moved the task to needs_human) while still answering with an error."""

    def __init__(self, status: int, code: str, detail: str = "", *, title: str | None = None,
                 extra: dict | None = None, headers: dict | None = None, commit: bool = False):
        super().__init__(f"{status} {code}")
        self.status = status
        self.code = code
        self.title = title or code.replace("_", " ")
        self.detail = detail
        self.extra = extra or {}
        self.headers = headers or {}
        self.commit = commit

    def body(self, request_id: str) -> dict:
        return {"type": "about:blank", "code": self.code, "title": self.title, "status": self.status,
                "detail": self.detail, "request_id": request_id, **self.extra}


def not_found(what: str = "task") -> Problem:
    return Problem(404, f"{what}_not_found", f"{what} not found")
