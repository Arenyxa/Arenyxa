from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from arenyxa.infrastructure.capture.proxy import InterceptingProxy, ProxySettings
from arenyxa.infrastructure.capture.proxy_transport import (
    _format_authority,
    _normalize_forward_request,
    _parse_head,
    _read_chunked,
    _read_message_body,
    _read_response,
    _relay,
    _split_host_port,
)


class _NoReceive:
    @staticmethod
    def recv(_size: int) -> bytes:
        raise AssertionError("complete in-memory message unexpectedly attempted a socket read")


def test_chunked_reader_accepts_terminal_chunk_without_waiting() -> None:
    encoded = b"4\r\ntest\r\n0\r\n\r\n"
    assert _read_chunked(_NoReceive(), encoded, 1024) == encoded


def test_chunked_reader_accepts_safe_trailer_and_rejects_framing_trailer() -> None:
    encoded = b"4\r\ntest\r\n0\r\nDigest: sha-256=abc\r\n\r\n"
    assert _read_chunked(_NoReceive(), encoded, 1024) == encoded
    with pytest.raises(ValueError, match="Forbidden HTTP trailer"):
        _read_chunked(_NoReceive(), b"0\r\nContent-Length: 7\r\n\r\n", 1024)


@pytest.mark.parametrize(
    "headers",
    [
        [("Content-Length", "4"), ("Content-Length", "5")],
        [("Content-Length", "4"), ("Transfer-Encoding", "chunked")],
        [("Transfer-Encoding", "chunked, gzip")],
        [("Transfer-Encoding", "chunked, chunked")],
    ],
)
def test_request_body_reader_rejects_ambiguous_message_framing(
    headers: list[tuple[str, str]],
) -> None:
    with pytest.raises(ValueError):
        _read_message_body(_NoReceive(), headers, b"", 1024)


def test_request_body_reader_accepts_identical_duplicate_content_length() -> None:
    headers = [("Content-Length", "4"), ("Content-Length", "4")]
    assert _read_message_body(_NoReceive(), headers, b"test", 1024) == b"test"


@pytest.mark.parametrize(
    "raw",
    [
        b"GET / HTTP/1.1\r\nContent-Length : 0\r\n\r\n",
        b"GET\t/ HTTP/1.1\r\nHost: example.test\r\n\r\n",
        b"GET / HTTP/1.1\r\nX-Test: ok\x00bad\r\n\r\n",
        b"GET / HTTP/1.1\r\n Folded: no\r\n\r\n",
    ],
)
def test_header_parser_rejects_smuggling_prone_syntax(raw: bytes) -> None:
    with pytest.raises(ValueError):
        _parse_head(raw)


def test_forward_normalization_brackets_ipv6_and_removes_connection_named_headers() -> None:
    normalized = _normalize_forward_request(
        "GET",
        "/resource",
        "HTTP/1.1",
        [("Host", "old.test"), ("Connection", "X-Hop"), ("X-Hop", "remove-me"), ("X-End", "keep-me")],
        b"",
        "2001:db8::1",
        8443,
        "https",
    )
    assert b"Host: [2001:db8::1]:8443\r\n" in normalized
    assert b"X-Hop:" not in normalized
    assert b"X-End: keep-me\r\n" in normalized


def test_forward_normalization_rejects_duplicate_host_and_incomplete_chunked_body() -> None:
    with pytest.raises(ValueError, match="Multiple Host"):
        _normalize_forward_request(
            "GET", "/", "HTTP/1.1", [("Host", "one"), ("Host", "two")], b"", "one", 80, "http"
        )
    with pytest.raises(ValueError, match="incomplete"):
        _normalize_forward_request(
            "POST",
            "/",
            "HTTP/1.1",
            [("Host", "example.test"), ("Transfer-Encoding", "chunked")],
            b"4\r\ntest\r\n",
            "example.test",
            80,
            "http",
        )


def test_response_reader_skips_bounded_informational_response() -> None:
    left, right = socket.socketpair()
    try:
        right.sendall(
            b"HTTP/1.1 100 Continue\r\n\r\n"
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        )
        right.shutdown(socket.SHUT_WR)
        response = _read_response(left, "POST", 8192, 8192)
    finally:
        left.close()
        right.close()
    assert response == b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


def test_response_reader_rejects_conflicting_content_length() -> None:
    left, right = socket.socketpair()
    try:
        right.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok")
        right.shutdown(socket.SHUT_WR)
        with pytest.raises(ValueError, match="Conflicting"):
            _read_response(left, "GET", 8192, 8192)
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize("authority", ["[::1]:bad", "[::1]:0", "example.test:65536", "example.test:"])
def test_authority_parser_rejects_invalid_ports(authority: str) -> None:
    with pytest.raises(ValueError):
        _split_host_port(authority, 443)


def test_authority_formatter_uses_idna_and_ipv6_brackets() -> None:
    assert _format_authority("2001:db8::1", 443, 443) == "[2001:db8::1]"
    assert _format_authority("例子.测试", 443, 443).isascii()


class _PostHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def test_proxy_completes_expect_continue_handshake_without_deadlock(tmp_path) -> None:
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _PostHandler)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    proxy = InterceptingProxy(tmp_path / "proxy", ProxySettings(bind_port=0, tls_interception=False))
    try:
        _, proxy_port = proxy.start()
        client = socket.create_connection(("127.0.0.1", proxy_port), timeout=3)
        try:
            client.sendall(
                (
                    f"POST http://127.0.0.1:{upstream.server_port}/upload HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{upstream.server_port}\r\n"
                    "Expect: 100-continue\r\n"
                    "Content-Length: 4\r\n\r\n"
                ).encode()
            )
            interim = client.recv(4096)
            assert interim == b"HTTP/1.1 100 Continue\r\n\r\n"
            client.sendall(b"test")
            response_parts: list[bytes] = []
            while True:
                part = client.recv(4096)
                if not part:
                    break
                response_parts.append(part)
            response = b"".join(response_parts)
        finally:
            client.close()
        assert b"HTTP/1.0 200 OK" in response
        assert response.endswith(b"test")
        assert b"Expect:" not in proxy.history()[-1].request_raw
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=2)


def test_bidirectional_relay_applies_bounded_backpressure_and_preserves_half_close() -> None:
    client, relay_left = socket.socketpair()
    relay_right, upstream = socket.socketpair()
    result: dict[str, tuple[int, int]] = {}
    relay_thread = threading.Thread(
        target=lambda: result.setdefault("counts", _relay(relay_left, relay_right, 5.0)),
        daemon=True,
    )
    relay_thread.start()
    request = bytes(range(256)) * 8192
    response = b"response:" + request[::-1]

    sender = threading.Thread(
        target=lambda: (client.sendall(request), client.shutdown(socket.SHUT_WR)),
        daemon=True,
    )
    sender.start()
    try:
        received_request = bytearray()
        while True:
            chunk = upstream.recv(65536)
            if not chunk:
                break
            received_request.extend(chunk)
        upstream.sendall(response)
        upstream.shutdown(socket.SHUT_WR)
        received_response = bytearray()
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            received_response.extend(chunk)
        sender.join(timeout=3)
        relay_thread.join(timeout=3)
        assert not sender.is_alive()
        assert not relay_thread.is_alive()
        assert bytes(received_request) == request
        assert bytes(received_response) == response
        assert result["counts"] == (len(request), len(response))
    finally:
        for item in (client, relay_left, relay_right, upstream):
            item.close()


class _BlockingHandler(BaseHTTPRequestHandler):
    entered = threading.Event()
    release = threading.Event()

    def do_GET(self) -> None:
        type(self).entered.set()
        type(self).release.wait(timeout=5)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, _format: str, *_args: object) -> None:
        return


def _proxy_get(proxy_port: int, upstream_port: int) -> bytes:
    client = socket.create_connection(("127.0.0.1", proxy_port), timeout=3)
    try:
        client.sendall(
            (
                f"GET http://127.0.0.1:{upstream_port}/slow HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{upstream_port}\r\n\r\n"
            ).encode()
        )
        chunks: list[bytes] = []
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        client.close()


def test_upstream_concurrency_budget_covers_full_exchange_lifetime(tmp_path) -> None:
    _BlockingHandler.entered.clear()
    _BlockingHandler.release.clear()
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _BlockingHandler)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    proxy = InterceptingProxy(
        tmp_path / "proxy-limit",
        ProxySettings(bind_port=0, tls_interception=False, max_concurrent_upstreams=1),
    )
    first_result: dict[str, bytes] = {}
    try:
        _, proxy_port = proxy.start()
        first = threading.Thread(
            target=lambda: first_result.setdefault("response", _proxy_get(proxy_port, upstream.server_port)),
            daemon=True,
        )
        first.start()
        assert _BlockingHandler.entered.wait(timeout=2)
        second = _proxy_get(proxy_port, upstream.server_port)
        assert b"502 Proxy Error" in second
        assert b"Network concurrency safety limit reached" in second
        _BlockingHandler.release.set()
        first.join(timeout=3)
        assert b"200 OK" in first_result["response"]
    finally:
        _BlockingHandler.release.set()
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=2)


def test_proxy_close_releases_history_wal_and_is_idempotent(tmp_path) -> None:
    proxy = InterceptingProxy(tmp_path / "proxy-close", ProxySettings(bind_port=0, tls_interception=False))
    database = proxy.history_store.path
    proxy.close()
    proxy.close()
    assert not database.with_name(database.name + "-wal").exists()
    assert not database.with_name(database.name + "-shm").exists()


def test_proxy_close_quiesces_blocked_client_before_database_close(tmp_path) -> None:
    proxy = InterceptingProxy(tmp_path / "proxy-active-close", ProxySettings(bind_port=0, tls_interception=False))
    _host, port = proxy.start()
    client = socket.create_connection(("127.0.0.1", port), timeout=2)
    try:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            with proxy._lock:
                if proxy._active_clients:
                    break
            time.sleep(0.01)
        proxy.close()
        with proxy._lock:
            assert not proxy._active_clients
            assert proxy._closed is True
    finally:
        client.close()
