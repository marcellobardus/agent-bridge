"""Structured JSON logs to stderr (journald). Only ids, routes, statuses and durations — never
Authorization, cookies, bodies, query strings or secrets."""
import json
import logging
import sys

from .util import request_id_var

log = logging.getLogger("bridge")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {"ts": round(record.created, 3), "level": record.levelname.lower(), "msg": record.getMessage(),
               "request_id": request_id_var.get()}
        out.update(getattr(record, "fields", {}))
        return json.dumps(out, separators=(",", ":"), default=str)


def setup(level: str = "INFO") -> None:
    if any(isinstance(h.formatter, JsonFormatter) for h in log.handlers):
        return
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(JsonFormatter())
    log.addHandler(h)
    log.setLevel(level)
    log.propagate = True


def event(msg: str, level: int = logging.INFO, **fields) -> None:
    log.log(level, msg, extra={"fields": fields})
