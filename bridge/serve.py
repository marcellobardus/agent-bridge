"""Entry point: `python -m bridge.serve --config /etc/agent-bridge/config.toml`. Refuses non-loopback binds."""
import argparse
import ipaddress
import sys


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def timeout_protocol(header_timeout_s: float, body_timeout_s: float, small_body_timeout_s: float | None = None):
    """Uvicorn's h11 protocol with header and body read timeouts. Stock uvicorn (0.54) arms its keep-alive
    timer only after a response, so a socket that connects and sends nothing (or half a request line) holds a
    connection slot forever. Here every request cycle gets a deadline: no complete headers within
    header_timeout_s (counted from the connection opening or the end of the previous response), or no complete
    body within its body limit, closes the connection. Requests already being processed by the app are never cut off.
    the body limit runs from the moment the request's HEADERS completed (so a kept-alive connection that
    sends a request just before its idle deadline is not cut mid-body): body_timeout_s for the artifact upload
    route, small_body_timeout_s (default: header_timeout_s) for every other request."""
    import asyncio
    import re

    small = header_timeout_s if small_body_timeout_s is None else small_body_timeout_s
    artifact = re.compile(r"/v1/tasks/[^/]+/artifacts")

    import h11
    from uvicorn.protocols.http.h11_impl import H11Protocol

    class TimeoutH11Protocol(H11Protocol):
        _deadline: asyncio.TimerHandle | None = None

        def _arm(self, delay: float, phase: str) -> None:
            self._disarm()
            self._deadline = self.loop.call_later(delay, self._expired, phase)

        def _disarm(self) -> None:
            if self._deadline is not None:
                self._deadline.cancel()
                self._deadline = None

        def _expired(self, phase: str) -> None:
            self._deadline = None
            if self.transport is None or self.transport.is_closing():
                return
            state = self.conn.their_state
            if state is h11.IDLE and (self.cycle is None or self.cycle.response_complete):
                self.transport.close()                       # headers never completed
            elif state is h11.SEND_BODY:
                self.transport.close()                       # body (armed when the headers completed) stalled

        def handle_events(self) -> None:
            before = self.scope
            super().handle_events()
            if (self.scope is not before and self.scope is not None and self.transport is not None
                    and not self.transport.is_closing() and self.conn.their_state is h11.SEND_BODY):
                big = self.scope.get("method") == "POST" and artifact.fullmatch(self.scope.get("path") or "") is not None
                self._arm(body_timeout_s if big else small, "body")    # measured from the end of the headers

        def connection_made(self, transport) -> None:
            super().connection_made(transport)
            self._arm(header_timeout_s, "header")

        def on_response_complete(self) -> None:
            super().on_response_complete()
            if not self.transport.is_closing() and self.conn.their_state is h11.IDLE:
                self._arm(header_timeout_s, "header")        # next request on a kept-alive connection

        def connection_lost(self, exc) -> None:
            self._disarm()
            super().connection_lost(exc)

    return TimeoutH11Protocol


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="agent-bridge")
    ap.add_argument("--config")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    args = ap.parse_args(argv)
    from .config import load_settings
    settings = load_settings(args.config)
    host = args.host or settings.host
    port = args.port or settings.port
    if not is_loopback(host):
        print(f"refusing to bind {host!r}: only loopback addresses are allowed (the host firewall is all-ACCEPT)",
              file=sys.stderr)
        return 2
    import uvicorn

    from .api.app import create_app
    from .db import Database, connect, migrate
    conn = connect(settings.db_path)
    migrate(conn)
    conn.close()
    app = create_app(settings, Database(settings.db_path))
    uvicorn.run(app, host=host, port=port, workers=1, limit_concurrency=settings.limit_concurrency,
                timeout_keep_alive=15, http=timeout_protocol(settings.header_timeout_s, settings.body_timeout_s,
                                                  settings.small_body_timeout_s),
                h11_max_incomplete_event_size=16 * 1024, access_log=False, proxy_headers=False, server_header=False,
                log_config=None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
