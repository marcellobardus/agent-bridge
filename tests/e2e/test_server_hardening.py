"""Connection timeouts against the real server (uvicorn + h11 via `python -m bridge.serve`): idle or half-sent connections
must neither block other requests nor hold a connection slot forever."""
import socket
import time
import urllib.request

import pytest

from e2e_support import BridgeServer


@pytest.fixture
def fast_timeout_server(tmp_path):
    s = BridgeServer(tmp_path)
    with open(s.config) as f:
        cfg = f.read()
    with open(s.config, "w") as f:                 # 1 s header timeout, 3 s body timeout (defaults 10 s / 30 s)
        f.write(cfg.replace("poll_after_s = 900\n", "poll_after_s = 900\nheader_timeout_s = 1\nbody_timeout_s = 5\n"
                                                     "small_body_timeout_s = 2\n"))
    s.mint_key("agent-a")
    s.start()
    yield s
    s.stop()


def _health(url):
    with urllib.request.urlopen(url + "/v1/health", timeout=3) as r:
        return r.status, r.read()


def _closed_by_server(sock, wait):
    """True if the server closes the connection within `wait` s (any response bytes before EOF are drained)."""
    deadline = time.time() + wait
    try:
        while True:
            sock.settimeout(max(deadline - time.time(), 0.01))
            if sock.recv(4096) == b"":
                return True
    except TimeoutError:
        return False
    except ConnectionResetError:
        return True


def test_idle_sockets_do_not_block_health(fast_timeout_server):
    s = fast_timeout_server
    idle = [socket.create_connection(("127.0.0.1", s.port)) for _ in range(40)]       # > the old limit of 32
    half = [socket.create_connection(("127.0.0.1", s.port)) for _ in range(5)]
    for h in half:
        h.sendall(b"GET /v1/health HTTP/1.1\r\nHost: x\r\n")                          # headers never finished
    body = socket.create_connection(("127.0.0.1", s.port))
    body.sendall(b"POST /v1/inbox/ack HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n{")   # body stalls
    try:
        t0 = time.time()
        assert _health(s.url) == (200, b'{"ok":true}')
        assert time.time() - t0 < 2
        for sock in idle[:3] + half[:2]:
            assert _closed_by_server(sock, 4), "server must close connections that never send complete headers"
        assert _closed_by_server(body, 6), "server must close connections whose body stalls"
        for _ in range(3):
            assert _health(s.url)[0] == 200
    finally:
        for sock in idle + half + [body]:
            sock.close()


def test_keepalive_connection_is_not_cut_mid_use(fast_timeout_server):
    s = fast_timeout_server
    sock = socket.create_connection(("127.0.0.1", s.port))
    try:
        for _ in range(3):
            sock.sendall(b"GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n")
            data = b""
            sock.settimeout(3)
            while b'{"ok":true}' not in data:
                chunk = sock.recv(4096)
                assert chunk, "connection closed while in use"
                data += chunk
            assert data.startswith(b"HTTP/1.1 200")
            time.sleep(0.4)
    finally:
        sock.close()


def _post_stalled(s, path, auth=True):
    sock = socket.create_connection(("127.0.0.1", s.port))
    hdr = f"Authorization: Bearer {s.tokens['agent-a']}\r\n" if auth else ""
    sock.sendall(f"POST {path} HTTP/1.1\r\nHost: x\r\n{hdr}Content-Length: 1000\r\n\r\n{{".encode())
    return sock


def _closed_within(sock, lo, hi):
    t0 = time.time()
    assert _closed_by_server(sock, hi + 1)
    took = time.time() - t0
    assert lo <= took <= hi + 0.5, took
    return took


def test_non_artifact_body_deadline_is_short(fast_timeout_server):
    """With a valid key the body is awaited: 2 s for ordinary routes, 5 s only for the artifact upload route."""
    s = fast_timeout_server
    small = _post_stalled(s, "/v1/inbox/ack")
    big = _post_stalled(s, "/v1/tasks/tsk_x/artifacts")
    try:
        _closed_within(small, 1.0, 2.5)
        _closed_within(big, 0.5, 4.5)                              # the remaining ~3 s of the 5 s artifact deadline
    finally:
        small.close()
        big.close()


def test_body_deadline_runs_from_the_end_of_the_headers(fast_timeout_server):
    """A POST that starts just before the keep-alive connection's idle deadline (1 s) and whose body arrives after
    that deadline still gets its full small-body window (2 s) and is answered, not cut."""
    s = fast_timeout_server
    sock = socket.create_connection(("127.0.0.1", s.port))
    try:
        sock.sendall(b"GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n")
        sock.settimeout(3)
        first = b""
        while b'{"ok":true}' not in first:
            chunk = sock.recv(4096)
            assert chunk
            first += chunk
        assert first.startswith(b"HTTP/1.1 200")
        time.sleep(0.8)                                            # 0.2 s before the idle deadline
        body = b'{"cursor": 1}'
        sock.sendall((f"POST /v1/inbox/ack HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {s.tokens['agent-a']}\r\n"
                      f"Idempotency-Key: body-test-key-1\r\nContent-Type: application/json\r\n"
                      f"Content-Length: {len(body)}\r\n\r\n").encode())
        time.sleep(0.6)                                            # the idle deadline passes mid-body
        sock.sendall(body)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            assert chunk, "server closed the connection mid-body"
            data += chunk
        assert data.startswith(b"HTTP/1.1 ")
    finally:
        sock.close()


def test_unauthenticated_body_is_refused_at_once(fast_timeout_server):
    s = fast_timeout_server
    sock = _post_stalled(s, "/v1/tasks/tsk_x/artifacts", auth=False)
    try:
        sock.settimeout(1.5)
        data = sock.recv(150)
        assert data.startswith(b"HTTP/1.1 401") and b"connection: close" in data.lower()
        assert _closed_by_server(sock, 1.5)
    finally:
        sock.close()
