from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from arenyxa.infrastructure.capture.proxy import InterceptingProxy, ProxySettings


class _Handler(BaseHTTPRequestHandler):
    last_path = ""

    def do_GET(self):
        type(self).last_path = self.path
        body = f"ok:{self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def _upstream():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _request(proxy_port: int, upstream_port: int, path: str = "/hello") -> bytes:
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    try:
        raw = (
            f"GET http://127.0.0.1:{upstream_port}{path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{upstream_port}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        sock.sendall(raw)
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)
    finally:
        sock.close()


def test_proxy_captures_http_history(tmp_path: Path):
    upstream, thread = _upstream()
    proxy = InterceptingProxy(tmp_path / "proxy", ProxySettings(bind_port=0, tls_interception=False))
    try:
        _, port = proxy.start()
        response = _request(port, upstream.server_address[1])
        assert b"200 OK" in response
        assert b"ok:/hello" in response
        history = proxy.history()
        assert len(history) == 1
        assert history[0].method == "GET"
        assert history[0].host == "127.0.0.1"
        assert history[0].target == "/hello"
        assert history[0].status == 200
        assert b"GET /hello HTTP/1.1" in history[0].request_raw
        assert b"ok:/hello" in history[0].response_raw
        assert (tmp_path / "proxy" / "archive" / "history.jsonl").exists()
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=2)


def test_proxy_request_intercept_can_modify_message(tmp_path: Path):
    upstream, thread = _upstream()
    proxy = InterceptingProxy(
        tmp_path / "proxy",
        ProxySettings(bind_port=0, tls_interception=False, intercept_requests=True, intercept_timeout_seconds=5),
    )
    result = {}
    try:
        _, port = proxy.start()
        client = threading.Thread(target=lambda: result.setdefault("response", _request(port, upstream.server_address[1], "/before")), daemon=True)
        client.start()
        deadline = time.monotonic() + 3
        pending = []
        while time.monotonic() < deadline:
            pending = proxy.pending()
            if pending:
                break
            time.sleep(0.01)
        assert pending
        raw = bytes(pending[0]["raw"]).replace(b"GET /before HTTP/1.1", b"GET /after HTTP/1.1")
        assert proxy.resolve(str(pending[0]["id"]), "forward", raw)
        client.join(timeout=5)
        assert b"ok:/after" in result["response"]
        assert _Handler.last_path == "/after"
        assert proxy.history()[0].target == "/after"
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=2)


def test_proxy_drop_returns_local_response(tmp_path: Path):
    upstream, thread = _upstream()
    proxy = InterceptingProxy(
        tmp_path / "proxy",
        ProxySettings(bind_port=0, tls_interception=False, intercept_requests=True, intercept_timeout_seconds=5),
    )
    result = {}
    try:
        _, port = proxy.start()
        client = threading.Thread(target=lambda: result.setdefault("response", _request(port, upstream.server_address[1], "/drop")), daemon=True)
        client.start()
        deadline = time.monotonic() + 3
        pending = []
        while time.monotonic() < deadline:
            pending = proxy.pending()
            if pending:
                break
            time.sleep(0.01)
        assert pending
        proxy.resolve(str(pending[0]["id"]), "drop")
        client.join(timeout=5)
        assert b"403 Dropped by Arenyxa Proxy" in result["response"]
        assert proxy.history()[0].dropped is True
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=2)


def test_proxy_rejects_remote_bind_without_opt_in(tmp_path: Path):
    with pytest.raises(ValueError):
        InterceptingProxy(tmp_path / "proxy", ProxySettings(bind_host="0.0.0.0", bind_port=8080))


def test_proxy_ca_is_persistent_and_exportable(tmp_path: Path):
    proxy = InterceptingProxy(tmp_path / "proxy", ProxySettings(bind_port=0))
    first = proxy.ca.fingerprint()
    cert, key = proxy.ca.certificate_for_host("example.com")
    assert cert.exists()
    assert key.exists()
    exported = proxy.export_ca_certificate(tmp_path / "ca.pem")
    assert exported.exists()
    second_proxy = InterceptingProxy(tmp_path / "proxy", ProxySettings(bind_port=0))
    assert second_proxy.ca.fingerprint() == first


def test_proxy_https_connect_mitm_roundtrip(tmp_path: Path):
    import ssl

    proxy = InterceptingProxy(
        tmp_path / "proxy",
        ProxySettings(bind_port=0, tls_interception=True, verify_upstream_tls=False),
    )
    upstream_cert, upstream_key = proxy.ca.certificate_for_host("localhost")
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(str(upstream_cert), str(upstream_key))
    upstream.socket = server_context.wrap_socket(upstream.socket, server_side=True)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        _, proxy_port = proxy.start()
        sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
        target = f"localhost:{upstream.server_address[1]}"
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        connected = b""
        while b"\r\n\r\n" not in connected:
            connected += sock.recv(4096)
        assert b"200 Connection Established" in connected
        client_context = ssl.create_default_context(cafile=str(proxy.ca.cert_path))
        client_context.set_alpn_protocols(["http/1.1"])
        tls_sock = client_context.wrap_socket(sock, server_hostname="localhost")
        tls_sock.sendall(f"GET /secure HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode())
        chunks = []
        while True:
            data = tls_sock.recv(65536)
            if not data:
                break
            chunks.append(data)
        response = b"".join(chunks)
        assert b"200 OK" in response
        assert b"ok:/secure" in response
        history = proxy.history()
        assert any(flow.method == "CONNECT" and flow.status == 200 for flow in history)
        https = [flow for flow in history if flow.method == "GET"]
        assert len(https) == 1
        assert https[0].scheme == "https"
        assert https[0].tls_intercepted is True
        assert https[0].target == "/secure"
        assert b"GET /secure HTTP/1.1" in https[0].request_raw
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=2)


def test_proxy_response_intercept_can_modify_message(tmp_path: Path):
    upstream, thread = _upstream()
    proxy = InterceptingProxy(
        tmp_path / "proxy",
        ProxySettings(bind_port=0, tls_interception=False, intercept_responses=True, intercept_timeout_seconds=5),
    )
    result = {}
    try:
        _, port = proxy.start()
        client = threading.Thread(target=lambda: result.setdefault("response", _request(port, upstream.server_address[1], "/response")), daemon=True)
        client.start()
        deadline = time.monotonic() + 3
        pending = []
        while time.monotonic() < deadline:
            pending = proxy.pending()
            if pending and pending[0]["phase"] == "response":
                break
            time.sleep(0.01)
        assert pending
        raw = bytes(pending[0]["raw"])
        old_body = b"ok:/response"
        new_body = b"edited-response"
        raw = raw.replace(old_body, new_body).replace(
            f"Content-Length: {len(old_body)}".encode(),
            f"Content-Length: {len(new_body)}".encode(),
        )
        assert proxy.resolve(str(pending[0]["id"]), "forward", raw)
        client.join(timeout=5)
        assert new_body in result["response"]
        assert new_body in proxy.history()[0].response_raw
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=2)
