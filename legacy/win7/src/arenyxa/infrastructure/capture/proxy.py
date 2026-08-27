from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import select
import shutil
import socket
import socketserver
import ssl
import threading
import time
import uuid
from dataclasses import asdict, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from arenyxa.compat import dataclass
from arenyxa.domain.models import utc_now


@dataclass(slots=True)
class ProxySettings:
    bind_host: str = "127.0.0.1"
    bind_port: int = 8080
    intercept_requests: bool = False
    intercept_responses: bool = False
    tls_interception: bool = True
    allow_remote_clients: bool = False
    verify_upstream_tls: bool = True
    intercept_timeout_seconds: float = 120.0
    connect_timeout_seconds: float = 15.0
    read_timeout_seconds: float = 45.0
    max_header_bytes: int = 256 * 1024
    max_message_bytes: int = 32 * 1024 * 1024
    history_limit: int = 5000

    def validate(self) -> None:
        host = str(self.bind_host).strip()
        if not host:
            raise ValueError("Proxy bind host is required")
        if not isinstance(self.bind_port, int) or isinstance(self.bind_port, bool) or self.bind_port < 0 or self.bind_port > 65535:
            raise ValueError("Proxy bind port must be between 0 and 65535")
        if not self.allow_remote_clients and not _is_loopback_host(host):
            raise ValueError("Remote proxy listeners require explicit allow_remote_clients")
        for value, label, low, high in (
            (self.intercept_timeout_seconds, "intercept timeout", 1.0, 600.0),
            (self.connect_timeout_seconds, "connect timeout", 1.0, 120.0),
            (self.read_timeout_seconds, "read timeout", 1.0, 600.0),
        ):
            numeric = float(value)
            if numeric < low or numeric > high:
                raise ValueError(f"{label} must be between {low:g} and {high:g} seconds")
        if self.max_header_bytes < 8192 or self.max_header_bytes > 4 * 1024 * 1024:
            raise ValueError("max_header_bytes is outside the safe range")
        if self.max_message_bytes < 64 * 1024 or self.max_message_bytes > 256 * 1024 * 1024:
            raise ValueError("max_message_bytes is outside the safe range")
        if self.history_limit < 100 or self.history_limit > 100000:
            raise ValueError("history_limit is outside the safe range")


@dataclass(slots=True)
class ProxyFlow:
    id: str
    sequence: int
    started_at: str
    client: str
    scheme: str
    method: str
    host: str
    port: int
    target: str
    request_raw: bytes = b""
    response_raw: bytes = b""
    status: int | None = None
    reason: str = ""
    duration_ms: float = 0.0
    request_bytes: int = 0
    response_bytes: int = 0
    tls_intercepted: bool = False
    tunnel: bool = False
    dropped: bool = False
    error: str = ""
    completed_at: str = ""

    @property
    def url(self) -> str:
        default_port = 443 if self.scheme == "https" else 80
        authority = self.host if self.port == default_port else f"{self.host}:{self.port}"
        target = self.target if self.target.startswith("/") else f"/{self.target}"
        return f"{self.scheme}://{authority}{target}"

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "sequence": self.sequence,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "client": self.client,
            "scheme": self.scheme,
            "method": self.method,
            "host": self.host,
            "port": self.port,
            "target": self.target,
            "url": self.url,
            "status": self.status,
            "reason": self.reason,
            "duration_ms": self.duration_ms,
            "request_bytes": self.request_bytes,
            "response_bytes": self.response_bytes,
            "tls_intercepted": self.tls_intercepted,
            "tunnel": self.tunnel,
            "dropped": self.dropped,
            "error": self.error,
        }


@dataclass(slots=True)
class PendingIntercept:
    id: str
    flow_id: str
    phase: str
    created_at: str
    raw: bytes
    method: str
    host: str
    target: str
    event: threading.Event = field(default_factory=threading.Event, repr=False)
    action: str = "forward"
    modified_raw: bytes | None = None

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "flow_id": self.flow_id,
            "phase": self.phase,
            "created_at": self.created_at,
            "raw": self.raw,
            "method": self.method,
            "host": self.host,
            "target": self.target,
        }


@dataclass(slots=True)
class ProxyStatus:
    running: bool
    host: str
    port: int
    flows: int
    pending: int
    started_at: str
    tls_interception: bool


class LocalCertificateAuthority:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.hosts = self.root / "hosts"
        self.hosts.mkdir(parents=True, exist_ok=True)
        self.key_path = self.root / "arenyxa-proxy-ca-key.pem"
        self.cert_path = self.root / "arenyxa-proxy-ca-cert.pem"
        self._lock = threading.RLock()
        self._ensure_ca()

    def _ensure_ca(self) -> None:
        if self.key_path.exists() and self.cert_path.exists():
            return
        from datetime import datetime, timedelta, timezone

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Arenyxa Local Proxy CA")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )
        _secure_write(self.key_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        _secure_write(self.cert_path, cert.public_bytes(serialization.Encoding.PEM), public=False)

    def fingerprint(self) -> str:
        cert = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
        return cert.fingerprint(hashes.SHA256()).hex().upper()

    def export_certificate(self, destination: Path) -> Path:
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.cert_path, destination)
        return destination

    def certificate_for_host(self, hostname: str) -> tuple[Path, Path]:
        canonical = str(hostname).strip().rstrip(".")
        if not canonical:
            raise ValueError("TLS hostname is required")
        digest = hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()[:32]
        cert_path = self.hosts / f"{digest}.cert.pem"
        key_path = self.hosts / f"{digest}.key.pem"
        with self._lock:
            if cert_path.exists() and key_path.exists():
                return cert_path, key_path
            self._issue(canonical, cert_path, key_path)
        return cert_path, key_path

    def _issue(self, hostname: str, cert_path: Path, key_path: Path) -> None:
        from datetime import datetime, timedelta, timezone

        ca_key = serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        try:
            san: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(hostname))
        except ValueError:
            san = x509.DNSName(hostname)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .issuer_name(ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        _secure_write(key_path, leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        _secure_write(cert_path, cert.public_bytes(serialization.Encoding.PEM), public=False)


class ProxyArchive:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.flows = self.root / "flows"
        self.flows.mkdir(parents=True, exist_ok=True)
        self.index = self.root / "history.jsonl"
        self._lock = threading.RLock()

    def store(self, flow: ProxyFlow) -> None:
        request_path = self.flows / f"{flow.id}.request"
        response_path = self.flows / f"{flow.id}.response"
        if flow.request_raw:
            _secure_write(request_path, flow.request_raw, public=False)
        if flow.response_raw:
            _secure_write(response_path, flow.response_raw, public=False)
        row = flow.summary()
        row["request_file"] = request_path.name if flow.request_raw else ""
        row["response_file"] = response_path.name if flow.response_raw else ""
        encoded = (json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        with self._lock:
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            descriptor = os.open(str(self.index), flags, 0o600)
            try:
                with os.fdopen(descriptor, "ab", closefd=True) as handle:
                    handle.write(encoded)
                    handle.flush()
                    try:
                        os.fsync(handle.fileno())
                    except OSError:
                        pass
                try:
                    os.chmod(self.index, 0o600)
                except OSError:
                    pass
            except Exception:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                raise


class InterceptingProxy:
    def __init__(self, root: Path, settings: ProxySettings | None = None) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.settings = settings or ProxySettings()
        self.settings.validate()
        self.ca = LocalCertificateAuthority(self.root / "ca")
        self.archive = ProxyArchive(self.root / "archive")
        self._lock = threading.RLock()
        self._history: list[ProxyFlow] = []
        self._pending: dict[str, PendingIntercept] = {}
        self._sequence = 0
        self._server: _ProxyTCPServer | None = None
        self._thread: threading.Thread | None = None
        self._started_at = ""
        self._listeners: list[Callable[[str, Any], None]] = []

    def add_listener(self, callback: Callable[[str, Any], None]) -> None:
        with self._lock:
            if callback not in self._listeners:
                self._listeners.append(callback)

    def remove_listener(self, callback: Callable[[str, Any], None]) -> None:
        with self._lock:
            if callback in self._listeners:
                self._listeners.remove(callback)

    def _emit(self, kind: str, value: Any) -> None:
        with self._lock:
            listeners = list(self._listeners)
        for callback in listeners:
            try:
                callback(kind, value)
            except Exception:
                continue

    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def address(self) -> tuple[str, int]:
        server = self._server
        if server is None:
            return self.settings.bind_host, int(self.settings.bind_port)
        host, port = server.server_address[:2]
        return str(host), int(port)

    def status(self) -> ProxyStatus:
        host, port = self.address
        with self._lock:
            flows = len(self._history)
            pending = len(self._pending)
        return ProxyStatus(self.running, host, port, flows, pending, self._started_at, bool(self.settings.tls_interception))

    def update_policy(self, intercept_requests: bool, intercept_responses: bool) -> None:
        with self._lock:
            self.settings.intercept_requests = bool(intercept_requests)
            self.settings.intercept_responses = bool(intercept_responses)
        self._emit("policy", {"intercept_requests": bool(intercept_requests), "intercept_responses": bool(intercept_responses)})

    def start(self) -> tuple[str, int]:
        with self._lock:
            if self._server is not None:
                return self.address
            self.settings.validate()
            server_type = _ProxyTCPServerV6 if ":" in self.settings.bind_host else _ProxyTCPServer
            server = server_type((self.settings.bind_host, int(self.settings.bind_port)), _ProxyRequestHandler)
            server.engine = self
            thread = threading.Thread(target=server.serve_forever, name="arenyxa-proxy-listener", daemon=True)
            self._server = server
            self._thread = thread
            self._started_at = utc_now()
            thread.start()
        self._emit("started", self.status())
        return self.address

    def stop(self) -> None:
        with self._lock:
            server = self._server
            thread = self._thread
            self._server = None
            self._thread = None
            pending = list(self._pending.values())
            self._pending.clear()
        for item in pending:
            item.action = "forward"
            item.modified_raw = item.raw
            item.event.set()
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=3.0)
        self._emit("stopped", self.status())

    def history(self) -> list[ProxyFlow]:
        with self._lock:
            return list(self._history)

    def pending(self) -> list[dict[str, Any]]:
        with self._lock:
            return [item.snapshot() for item in self._pending.values()]

    def resolve(self, intercept_id: str, action: str, raw: bytes | str | None = None) -> bool:
        normalized = str(action).strip().casefold()
        if normalized not in {"forward", "drop"}:
            raise ValueError("Intercept action must be forward or drop")
        with self._lock:
            item = self._pending.get(str(intercept_id))
            if item is None:
                return False
            item.action = normalized
            if raw is None:
                item.modified_raw = item.raw
            elif isinstance(raw, bytes):
                item.modified_raw = raw
            else:
                item.modified_raw = str(raw).encode("latin-1", "replace")
            item.event.set()
        return True

    def export_ca_certificate(self, destination: Path) -> Path:
        return self.ca.export_certificate(destination)

    def _new_flow(self, client: str, scheme: str, method: str, host: str, port: int, target: str) -> ProxyFlow:
        with self._lock:
            self._sequence += 1
            sequence = self._sequence
        return ProxyFlow(uuid.uuid4().hex, sequence, utc_now(), client, scheme, method, host, int(port), target)

    def _complete(self, flow: ProxyFlow, started: float) -> None:
        flow.duration_ms = max(0.0, (time.monotonic() - started) * 1000.0)
        flow.completed_at = utc_now()
        with self._lock:
            self._history.append(flow)
            if len(self._history) > self.settings.history_limit:
                del self._history[: len(self._history) - self.settings.history_limit]
        try:
            self.archive.store(flow)
        except OSError:
            pass
        self._emit("flow", flow)

    def _intercept(self, flow: ProxyFlow, phase: str, raw: bytes) -> tuple[str, bytes]:
        should_intercept = self.settings.intercept_requests if phase == "request" else self.settings.intercept_responses
        if not should_intercept:
            return "forward", raw
        item = PendingIntercept(uuid.uuid4().hex, flow.id, phase, utc_now(), raw, flow.method, flow.host, flow.target)
        with self._lock:
            self._pending[item.id] = item
        self._emit("intercept", item.snapshot())
        item.event.wait(timeout=float(self.settings.intercept_timeout_seconds))
        with self._lock:
            self._pending.pop(item.id, None)
        if not item.event.is_set():
            return "forward", raw
        return item.action, item.modified_raw if item.modified_raw is not None else raw

    def _handle_client(self, sock: socket.socket, client_address: tuple[Any, ...]) -> None:
        client = str(client_address[0]) if client_address else ""
        try:
            sock.settimeout(float(self.settings.read_timeout_seconds))
            head, rest = _read_head(sock, self.settings.max_header_bytes)
            if not head:
                return
            start_line, headers = _parse_head(head)
            parts = start_line.split(" ", 2)
            if len(parts) != 3:
                _send_error(sock, 400, "Bad Request")
                return
            method, target, version = parts
            if method.upper() == "CONNECT":
                self._handle_connect(sock, client, target)
                return
            body = _read_message_body(sock, headers, rest, self.settings.max_message_bytes)
            raw = _assemble_message(start_line, headers, body)
            self._handle_http(sock, client, raw, scheme_hint="http")
        except (ConnectionError, OSError, ssl.SSLError, ValueError) as exc:
            try:
                _send_error(sock, 502, "Proxy Error", str(exc))
            except OSError:
                pass

    def _handle_connect(self, client_sock: socket.socket, client: str, target: str) -> None:
        host, port = _split_host_port(target, 443)
        started = time.monotonic()
        flow = self._new_flow(client, "https", "CONNECT", host, port, "/")
        flow.tunnel = not self.settings.tls_interception
        flow.request_raw = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("latin-1")
        flow.request_bytes = len(flow.request_raw)
        if not self.settings.tls_interception:
            upstream = None
            try:
                upstream = socket.create_connection((host, port), timeout=float(self.settings.connect_timeout_seconds))
                client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: Arenyxa\r\n\r\n")
                flow.status = 200
                flow.reason = "Connection Established"
                sent_up, sent_down = _relay(client_sock, upstream, float(self.settings.read_timeout_seconds))
                flow.request_bytes += sent_up
                flow.response_bytes = sent_down
            except Exception as exc:
                flow.error = str(exc)
                if flow.status is None:
                    flow.status = 502
                raise
            finally:
                if upstream is not None:
                    try:
                        upstream.close()
                    except OSError:
                        pass
                self._complete(flow, started)
            return
        try:
            cert_path, key_path = self.ca.certificate_for_host(host)
            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: Arenyxa\r\n\r\n")
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.minimum_version = ssl.TLSVersion.TLSv1_2
            server_context.set_alpn_protocols(["http/1.1"])
            server_context.load_cert_chain(str(cert_path), str(key_path))
            tls_client = server_context.wrap_socket(client_sock, server_side=True)
            flow.tls_intercepted = True
            flow.status = 200
            flow.reason = "Connection Established"
            self._complete(flow, started)
            self._handle_tls_http(tls_client, client, host, port)
        except Exception as exc:
            flow.error = str(exc)
            if not flow.completed_at:
                self._complete(flow, started)
            raise

    def _handle_tls_http(self, client_sock: ssl.SSLSocket, client: str, host: str, port: int) -> None:
        try:
            client_sock.settimeout(float(self.settings.read_timeout_seconds))
            head, rest = _read_head(client_sock, self.settings.max_header_bytes)
            if not head:
                return
            start_line, headers = _parse_head(head)
            parts = start_line.split(" ", 2)
            if len(parts) != 3:
                _send_error(client_sock, 400, "Bad Request")
                return
            body = _read_message_body(client_sock, headers, rest, self.settings.max_message_bytes)
            raw = _assemble_message(start_line, headers, body)
            self._handle_http(client_sock, client, raw, scheme_hint="https", fixed_destination=(host, port))
        finally:
            try:
                client_sock.close()
            except OSError:
                pass

    def _handle_http(
        self,
        client_sock: socket.socket,
        client: str,
        raw_request: bytes,
        scheme_hint: str,
        fixed_destination: tuple[str, int] | None = None,
    ) -> None:
        started = time.monotonic()
        start_line, headers, body = _parse_raw_message(raw_request)
        parts = start_line.split(" ", 2)
        if len(parts) != 3:
            _send_error(client_sock, 400, "Bad Request")
            return
        method, request_target, version = parts
        scheme, host, port, origin_target = _request_destination(request_target, headers, scheme_hint, fixed_destination)
        flow = self._new_flow(client, scheme, method.upper(), host, port, origin_target)
        normalized = _normalize_forward_request(method, origin_target, version, headers, body, host, port, scheme)
        flow.request_raw = normalized
        flow.request_bytes = len(normalized)
        if scheme == "https":
            flow.tls_intercepted = True
        action, intercepted = self._intercept(flow, "request", normalized)
        if action == "drop":
            flow.dropped = True
            flow.status = 403
            flow.reason = "Dropped by Arenyxa Proxy"
            response = _error_response(403, "Dropped by Arenyxa Proxy")
            flow.response_raw = response
            flow.response_bytes = len(response)
            client_sock.sendall(response)
            self._complete(flow, started)
            return
        try:
            start_line, headers, body = _parse_raw_message(intercepted)
            method, request_target, version = start_line.split(" ", 2)
            scheme, host, port, origin_target = _request_destination(request_target, headers, scheme, fixed_destination)
            flow.method = method.upper()
            flow.scheme = scheme
            flow.host = host
            flow.port = port
            flow.target = origin_target
            normalized = _normalize_forward_request(method, origin_target, version, headers, body, host, port, scheme)
            flow.request_raw = normalized
            flow.request_bytes = len(normalized)
            upstream = socket.create_connection((host, port), timeout=float(self.settings.connect_timeout_seconds))
            try:
                upstream.settimeout(float(self.settings.read_timeout_seconds))
                if scheme == "https":
                    context = ssl.create_default_context()
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    context.set_alpn_protocols(["http/1.1"])
                    if not self.settings.verify_upstream_tls:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    upstream = context.wrap_socket(upstream, server_hostname=host)
                upstream.sendall(normalized)
                response = _read_response(upstream, method.upper(), self.settings.max_header_bytes, self.settings.max_message_bytes)
            finally:
                try:
                    upstream.close()
                except OSError:
                    pass
            flow.response_raw = response
            flow.response_bytes = len(response)
            response_line, response_headers, response_body = _parse_raw_message(response)
            status_parts = response_line.split(" ", 2)
            if len(status_parts) >= 2:
                try:
                    flow.status = int(status_parts[1])
                except ValueError:
                    flow.status = None
                flow.reason = status_parts[2] if len(status_parts) > 2 else ""
            response_action, response_bytes = self._intercept(flow, "response", response)
            if response_action == "drop":
                flow.dropped = True
                response_bytes = _error_response(502, "Response dropped by Arenyxa Proxy")
                flow.response_raw = response_bytes
                flow.response_bytes = len(response_bytes)
                flow.status = 502
                flow.reason = "Response dropped by Arenyxa Proxy"
            else:
                flow.response_raw = response_bytes
                flow.response_bytes = len(response_bytes)
                try:
                    edited_line, _edited_headers, _edited_body = _parse_raw_message(response_bytes)
                    edited_parts = edited_line.split(" ", 2)
                    if len(edited_parts) >= 2 and edited_parts[1].isdigit():
                        flow.status = int(edited_parts[1])
                        flow.reason = edited_parts[2] if len(edited_parts) > 2 else ""
                except ValueError:
                    pass
            client_sock.sendall(response_bytes)
        except Exception as exc:
            flow.error = str(exc)
            if flow.status is None:
                flow.status = 502
                flow.reason = "Proxy Error"
            error_response = _error_response(502, "Proxy Error", str(exc))
            flow.response_raw = error_response
            flow.response_bytes = len(error_response)
            try:
                client_sock.sendall(error_response)
            except OSError:
                pass
        finally:
            self._complete(flow, started)


class _ProxyTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    engine: InterceptingProxy


class _ProxyTCPServerV6(_ProxyTCPServer):
    address_family = socket.AF_INET6


class _ProxyRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.server.engine._handle_client(self.request, self.client_address)


def _is_loopback_host(host: str) -> bool:
    text = str(host).strip().casefold()
    if text == "localhost":
        return True
    try:
        return ipaddress.ip_address(text).is_loopback
    except ValueError:
        return False


def _secure_write(path: Path, data: bytes, public: bool = False) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    mode = 0o644 if public else 0o600
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(str(temp), flags, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
        try:
            os.chmod(temp, mode)
        except OSError:
            pass
        os.replace(temp, path)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def _read_head(sock: socket.socket, limit: int) -> tuple[bytes, bytes]:
    buffer = bytearray()
    marker = b"\r\n\r\n"
    while marker not in buffer:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buffer.extend(chunk)
        if len(buffer) > limit:
            raise ValueError("HTTP headers exceeded configured limit")
    index = buffer.find(marker)
    if index < 0:
        return bytes(buffer), b""
    end = index + len(marker)
    return bytes(buffer[:end]), bytes(buffer[end:])


def _parse_head(head: bytes) -> tuple[str, list[tuple[str, str]]]:
    text = head.decode("latin-1")
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        raise ValueError("HTTP start line is missing")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        if line[0] in " \t":
            raise ValueError("Obsolete folded HTTP headers are not accepted")
        name, separator, value = line.partition(":")
        if not separator or not name.strip():
            raise ValueError("Malformed HTTP header")
        headers.append((name.strip(), value.lstrip()))
    return lines[0], headers


def _header(headers: list[tuple[str, str]], name: str) -> str:
    wanted = name.casefold()
    for key, value in headers:
        if key.casefold() == wanted:
            return value
    return ""


def _read_exact(sock: socket.socket, size: int, initial: bytes, limit: int) -> bytes:
    if size > limit:
        raise ValueError("HTTP message body exceeded configured limit")
    buffer = bytearray(initial[:size])
    while len(buffer) < size:
        chunk = sock.recv(min(65536, size - len(buffer)))
        if not chunk:
            raise ConnectionError("Connection closed before HTTP body completed")
        buffer.extend(chunk)
        if len(buffer) > limit:
            raise ValueError("HTTP message body exceeded configured limit")
    return bytes(buffer)


def _read_chunked(sock: socket.socket, initial: bytes, limit: int) -> bytes:
    buffer = bytearray(initial)
    position = 0
    while True:
        while b"\r\n" not in buffer[position:]:
            chunk = sock.recv(65536)
            if not chunk:
                raise ConnectionError("Connection closed during chunked body")
            buffer.extend(chunk)
            if len(buffer) > limit:
                raise ValueError("Chunked HTTP body exceeded configured limit")
        line_end = buffer.find(b"\r\n", position)
        line = bytes(buffer[position:line_end]).split(b";", 1)[0].strip()
        try:
            chunk_size = int(line, 16)
        except ValueError as exc:
            raise ValueError("Invalid HTTP chunk size") from exc
        position = line_end + 2
        required = position + chunk_size + 2
        while len(buffer) < required:
            chunk = sock.recv(min(65536, required - len(buffer)))
            if not chunk:
                raise ConnectionError("Connection closed during HTTP chunk")
            buffer.extend(chunk)
            if len(buffer) > limit:
                raise ValueError("Chunked HTTP body exceeded configured limit")
        if bytes(buffer[position + chunk_size : position + chunk_size + 2]) != b"\r\n":
            raise ValueError("Malformed HTTP chunk terminator")
        position = required
        if chunk_size == 0:
            while b"\r\n\r\n" not in buffer[position - 2 :]:
                if bytes(buffer[position - 2 : position + 2]) == b"\r\n\r\n":
                    break
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buffer.extend(chunk)
                if len(buffer) > limit:
                    raise ValueError("Chunked HTTP trailer exceeded configured limit")
                if buffer.endswith(b"\r\n\r\n"):
                    break
            return bytes(buffer[:position]) if position <= len(buffer) else bytes(buffer)


def _read_message_body(sock: socket.socket, headers: list[tuple[str, str]], initial: bytes, limit: int) -> bytes:
    transfer = _header(headers, "Transfer-Encoding").casefold()
    if "chunked" in transfer:
        return _read_chunked(sock, initial, limit)
    length_text = _header(headers, "Content-Length").strip()
    if not length_text:
        return b""
    try:
        length = int(length_text)
    except ValueError as exc:
        raise ValueError("Invalid Content-Length") from exc
    if length < 0:
        raise ValueError("Invalid Content-Length")
    return _read_exact(sock, length, initial, limit)


def _assemble_message(start_line: str, headers: list[tuple[str, str]], body: bytes) -> bytes:
    lines = [start_line, *[f"{name}: {value}" for name, value in headers], "", ""]
    return "\r\n".join(lines).encode("latin-1") + body


def _parse_raw_message(raw: bytes) -> tuple[str, list[tuple[str, str]], bytes]:
    marker = raw.find(b"\r\n\r\n")
    if marker < 0:
        raise ValueError("HTTP message is missing the header terminator")
    head = raw[: marker + 4]
    body = raw[marker + 4 :]
    start_line, headers = _parse_head(head)
    return start_line, headers, body


def _split_host_port(value: str, default_port: int) -> tuple[str, int]:
    text = str(value).strip()
    if not text:
        raise ValueError("Destination host is missing")
    if text.startswith("["):
        close = text.find("]")
        if close < 0:
            raise ValueError("Invalid IPv6 authority")
        host = text[1:close]
        suffix = text[close + 1 :]
        port = int(suffix[1:]) if suffix.startswith(":") and suffix[1:] else default_port
        return host, port
    if text.count(":") == 1:
        host, port_text = text.rsplit(":", 1)
        if port_text.isdigit():
            return host, int(port_text)
    return text, default_port


def _request_destination(
    request_target: str,
    headers: list[tuple[str, str]],
    scheme_hint: str,
    fixed_destination: tuple[str, int] | None,
) -> tuple[str, str, int, str]:
    if fixed_destination is not None:
        host, port = fixed_destination
        target = request_target if request_target.startswith("/") else "/"
        return "https", host, int(port), target
    parsed = urlsplit(request_target)
    if parsed.scheme.casefold() in {"http", "https"} and parsed.hostname:
        scheme = parsed.scheme.casefold()
        port = parsed.port or (443 if scheme == "https" else 80)
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        return scheme, parsed.hostname, int(port), target
    authority = _header(headers, "Host")
    if not authority:
        raise ValueError("HTTP Host header is required")
    default_port = 443 if scheme_hint == "https" else 80
    host, port = _split_host_port(authority, default_port)
    target = request_target if request_target.startswith("/") else "/" + request_target
    return scheme_hint, host, int(port), target


def _normalize_forward_request(
    method: str,
    target: str,
    version: str,
    headers: list[tuple[str, str]],
    body: bytes,
    host: str,
    port: int,
    scheme: str,
) -> bytes:
    transfer_chunked = any(
        name.casefold() == "transfer-encoding" and "chunked" in value.casefold()
        for name, value in headers
    )
    filtered: list[tuple[str, str]] = []
    seen_host = False
    saw_content_length = False
    for name, value in headers:
        key = name.casefold()
        if key in {"proxy-connection", "proxy-authorization", "connection"}:
            continue
        if key == "host":
            if seen_host:
                continue
            seen_host = True
            default_port = 443 if scheme == "https" else 80
            authority = host if port == default_port else f"{host}:{port}"
            filtered.append(("Host", authority))
            continue
        if key == "content-length":
            if saw_content_length or transfer_chunked:
                continue
            saw_content_length = True
            filtered.append(("Content-Length", str(len(body))))
            continue
        filtered.append((name, value))
    if not seen_host:
        default_port = 443 if scheme == "https" else 80
        authority = host if port == default_port else f"{host}:{port}"
        filtered.insert(0, ("Host", authority))
    filtered.append(("Connection", "close"))
    if not transfer_chunked and body and not saw_content_length:
        filtered.append(("Content-Length", str(len(body))))
    return _assemble_message(f"{method} {target} {version}", filtered, body)


def _read_response(sock: socket.socket, request_method: str, header_limit: int, message_limit: int) -> bytes:
    head, rest = _read_head(sock, header_limit)
    if not head:
        raise ConnectionError("Upstream server returned no HTTP response")
    status_line, headers = _parse_head(head)
    parts = status_line.split(" ", 2)
    status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    if request_method == "HEAD" or 100 <= status < 200 or status in {204, 304}:
        return head
    transfer = _header(headers, "Transfer-Encoding").casefold()
    if "chunked" in transfer:
        body = _read_chunked(sock, rest, message_limit)
        return head + body
    length_text = _header(headers, "Content-Length").strip()
    if length_text:
        try:
            length = int(length_text)
        except ValueError as exc:
            raise ValueError("Invalid upstream Content-Length") from exc
        body = _read_exact(sock, length, rest, message_limit)
        return head + body
    buffer = bytearray(rest)
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buffer.extend(chunk)
        if len(buffer) > message_limit:
            raise ValueError("Upstream HTTP response exceeded configured limit")
    return head + bytes(buffer)


def _relay(left: socket.socket, right: socket.socket, idle_timeout: float) -> tuple[int, int]:
    left.setblocking(False)
    right.setblocking(False)
    last_activity = time.monotonic()
    up = 0
    down = 0
    sockets = [left, right]
    while True:
        remaining = max(0.0, idle_timeout - (time.monotonic() - last_activity))
        if remaining <= 0:
            break
        readable, _, exceptional = select.select(sockets, [], sockets, min(1.0, remaining))
        if exceptional:
            break
        if not readable:
            continue
        for source in readable:
            destination = right if source is left else left
            try:
                data = source.recv(65536)
            except (BlockingIOError, InterruptedError):
                continue
            if not data:
                return up, down
            destination.sendall(data)
            last_activity = time.monotonic()
            if source is left:
                up += len(data)
            else:
                down += len(data)
    return up, down


def _error_response(status: int, reason: str, detail: str = "") -> bytes:
    text = reason if not detail else f"{reason}\n{detail}"
    body = text.encode("utf-8", "replace")[:65536]
    headers = [
        f"HTTP/1.1 {int(status)} {reason}",
        "Content-Type: text/plain; charset=utf-8",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "Proxy-Agent: Arenyxa",
        "",
        "",
    ]
    return "\r\n".join(headers).encode("latin-1", "replace") + body


def _send_error(sock: socket.socket, status: int, reason: str, detail: str = "") -> None:
    sock.sendall(_error_response(status, reason, detail))
