from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import base64
import hashlib
import fnmatch
import ipaddress
import json
import os
import select
import shutil
import socket
import socketserver
import ssl
import statistics
import threading
import time
import uuid
from dataclasses import asdict, field
from pathlib import Path
from typing import Any, Callable, Sequence
from urllib.parse import parse_qsl, urlsplit
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from arenyxa.compat import dataclass
from arenyxa.domain.models import utc_now
from arenyxa.domain.errors import ArenyxaError
from arenyxa.security.network_guard import NetworkGuardPolicy, NetworkUseGuard
from arenyxa.security.key_protection import DPAPIKeyProtectionAdapter, KeyProtectionAdapter, SecretBuffer

from arenyxa.infrastructure.capture.proxy_transport import (
    _ProxyTCPServer,
    _ProxyTCPServerV6,
    _ProxyRequestHandler,
    _is_loopback_host,
    _secure_write,
    _read_head,
    _parse_head,
    _header,
    _read_exact,
    _read_chunked,
    _read_message_body,
    _assemble_message,
    _connect_validated_candidates,
    _parse_raw_message,
    _split_host_port,
    _request_destination,
    _normalize_forward_request,
    _read_response,
    _relay,
    _error_response,
    _send_error,
)

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
    network_guard_enabled: bool = True
    max_concurrent_upstreams: int = 128
    max_upstream_connects_per_minute: int = 1200
    max_target_connects_per_minute: int = 240
    max_distinct_targets_per_minute: int = 512
    max_tracked_targets: int = 2048
    block_cloud_metadata: bool = True
    block_private_targets_when_remote: bool = True
    persistence_queue_capacity: int = 1024
    persistence_flush_timeout_seconds: float = 5.0

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
        if self.persistence_queue_capacity < 16 or self.persistence_queue_capacity > 10000:
            raise ValueError("persistence_queue_capacity is outside the safe range")
        if not 0.1 <= float(self.persistence_flush_timeout_seconds) <= 30.0:
            raise ValueError("persistence_flush_timeout_seconds is outside the safe range")
        NetworkGuardPolicy(
            enabled=self.network_guard_enabled,
            max_concurrent_connections=self.max_concurrent_upstreams,
            max_global_connects_per_minute=self.max_upstream_connects_per_minute,
            max_target_connects_per_minute=self.max_target_connects_per_minute,
            max_distinct_targets_per_minute=self.max_distinct_targets_per_minute,
            max_tracked_targets=self.max_tracked_targets,
            block_cloud_metadata=self.block_cloud_metadata,
            block_private_or_loopback=bool(self.allow_remote_clients and self.block_private_targets_when_remote),
        ).validate()

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
    rewrite_rule_ids: list[str] = field(default_factory=list)

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
            "rewrite_rule_ids": list(self.rewrite_rule_ids),
        }

@dataclass(slots=True)
class ProxySessionSummary:
    flow_count: int
    completed_count: int
    error_count: int
    dropped_count: int
    tls_intercepted_count: int
    tunnel_count: int
    request_bytes: int
    response_bytes: int
    duration_p50_ms: float
    duration_p95_ms: float
    hosts: list[dict[str, Any]]
    methods: dict[str, int]
    status_families: dict[str, int]
    content_types: list[dict[str, Any]]
    slowest: list[dict[str, Any]]
    rewritten_flow_count: int

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)

def summarize_proxy_flows(flows: Sequence[ProxyFlow]) -> ProxySessionSummary:
    rows = list(flows)
    host_counts: dict[str, int] = {}
    method_counts: dict[str, int] = {}
    status_counts = {"1xx": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
    content_counts: dict[str, int] = {}
    durations = [max(0.0, float(item.duration_ms)) for item in rows if float(item.duration_ms) >= 0.0]
    for flow in rows:
        host = str(flow.host or "").casefold()
        if host:
            host_counts[host] = host_counts.get(host, 0) + 1
        method = str(flow.method or "").upper() or "UNKNOWN"
        method_counts[method] = method_counts.get(method, 0) + 1
        status = flow.status
        if isinstance(status, int) and 100 <= status <= 599:
            status_counts[f"{status // 100}xx"] += 1
        else:
            status_counts["other"] += 1
        if flow.response_raw:
            try:
                _line, headers, _body = _parse_raw_message(flow.response_raw)
                content_type = _header(headers, "Content-Type").split(";", 1)[0].strip().casefold()
                if content_type:
                    content_counts[content_type] = content_counts.get(content_type, 0) + 1
            except ValueError:
                record_current_exception(__name__, 'summarize_proxy_flows:222')
    ordered_durations = sorted(durations)
    def percentile(fraction: float) -> float:
        if not ordered_durations:
            return 0.0
        index = min(len(ordered_durations) - 1, max(0, int(round((len(ordered_durations) - 1) * fraction))))
        return round(float(ordered_durations[index]), 3)
    top_hosts = [
        {"host": host, "flows": count}
        for host, count in sorted(host_counts.items(), key=lambda item: (-item[1], item[0]))[:20]
    ]
    top_types = [
        {"content_type": content_type, "flows": count}
        for content_type, count in sorted(content_counts.items(), key=lambda item: (-item[1], item[0]))[:20]
    ]
    slowest = [
        {"id": item.id, "method": item.method, "url": item.url, "status": item.status, "duration_ms": round(float(item.duration_ms), 3)}
        for item in sorted(rows, key=lambda flow: float(flow.duration_ms), reverse=True)[:20]
    ]
    return ProxySessionSummary(
        flow_count=len(rows),
        completed_count=sum(1 for item in rows if bool(item.completed_at)),
        error_count=sum(1 for item in rows if bool(item.error)),
        dropped_count=sum(1 for item in rows if bool(item.dropped)),
        tls_intercepted_count=sum(1 for item in rows if bool(item.tls_intercepted)),
        tunnel_count=sum(1 for item in rows if bool(item.tunnel)),
        request_bytes=sum(max(0, int(item.request_bytes)) for item in rows),
        response_bytes=sum(max(0, int(item.response_bytes)) for item in rows),
        duration_p50_ms=percentile(0.50),
        duration_p95_ms=percentile(0.95),
        hosts=top_hosts,
        methods=dict(sorted(method_counts.items())),
        status_families=status_counts,
        content_types=top_types,
        slowest=slowest,
        rewritten_flow_count=sum(1 for item in rows if bool(item.rewrite_rule_ids)),
    )

@dataclass(slots=True)
class ProxyInspection:
    flow_id: str
    protocol: str
    request: dict[str, Any]
    response: dict[str, Any]
    cookies: list[dict[str, Any]]
    security_headers: dict[str, bool]
    cache: dict[str, Any]
    cors: dict[str, Any]
    timing: dict[str, Any]
    notes: list[str]

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)

def _header_values(headers: list[tuple[str, str]], name: str) -> list[str]:
    wanted = str(name).casefold()
    return [value for key, value in headers if key.casefold() == wanted]

def _inspect_cookie(value: str) -> dict[str, Any]:
    parts = [item.strip() for item in str(value).split(";") if item.strip()]
    name = parts[0].split("=", 1)[0].strip() if parts else ""
    flags = {item.split("=", 1)[0].strip().casefold(): item.split("=", 1)[1].strip() if "=" in item else True for item in parts[1:]}
    same_site = str(flags.get("samesite", ""))
    return {
        "name": name[:128],
        "secure": "secure" in flags,
        "http_only": "httponly" in flags,
        "same_site": same_site[:32],
        "partitioned": "partitioned" in flags,
        "has_domain": "domain" in flags,
        "has_path": "path" in flags,
    }

def inspect_proxy_flow(flow: ProxyFlow) -> ProxyInspection:
    notes: list[str] = []
    request_headers: list[tuple[str, str]] = []
    response_headers: list[tuple[str, str]] = []
    request_body = b""
    response_body = b""
    request_line = ""
    response_line = ""
    try:
        request_line, request_headers, request_body = _parse_raw_message(flow.request_raw)
    except ValueError:
        if flow.request_raw:
            notes.append("Request message could not be parsed as HTTP/1.x")
    try:
        response_line, response_headers, response_body = _parse_raw_message(flow.response_raw)
    except ValueError:
        if flow.response_raw:
            notes.append("Response message could not be parsed as HTTP/1.x")

    content_type = _header(response_headers, "Content-Type")
    content_encoding = _header(response_headers, "Content-Encoding")
    transfer_encoding = _header(response_headers, "Transfer-Encoding")
    request_content_type = _header(request_headers, "Content-Type")
    cookies = [_inspect_cookie(value) for value in _header_values(response_headers, "Set-Cookie")[:128]]
    security_names = {
        "strict_transport_security": "Strict-Transport-Security",
        "content_security_policy": "Content-Security-Policy",
        "x_content_type_options": "X-Content-Type-Options",
        "x_frame_options": "X-Frame-Options",
        "referrer_policy": "Referrer-Policy",
        "permissions_policy": "Permissions-Policy",
        "cross_origin_opener_policy": "Cross-Origin-Opener-Policy",
        "cross_origin_resource_policy": "Cross-Origin-Resource-Policy",
    }
    security = {key: bool(_header(response_headers, header)) for key, header in security_names.items()}
    cache_control = _header(response_headers, "Cache-Control")
    expires = _header(response_headers, "Expires")
    age = _header(response_headers, "Age")
    vary = _header(response_headers, "Vary")
    cors = {
        "allow_origin": _header(response_headers, "Access-Control-Allow-Origin")[:512],
        "allow_credentials": _header(response_headers, "Access-Control-Allow-Credentials")[:64],
        "allow_methods": _header(response_headers, "Access-Control-Allow-Methods")[:512],
        "vary_origin": "origin" in {item.strip().casefold() for item in vary.split(",") if item.strip()},
    }
    if flow.scheme == "https" and not security["strict_transport_security"]:
        notes.append("HTTPS response does not advertise HSTS")
    if cookies and any(not item["secure"] for item in cookies) and flow.scheme == "https":
        notes.append("At least one HTTPS Set-Cookie lacks Secure")
    if cookies and any(not item["http_only"] for item in cookies):
        notes.append("At least one Set-Cookie lacks HttpOnly")
    if cors["allow_origin"] == "*" and str(cors["allow_credentials"]).casefold() == "true":
        notes.append("CORS combines wildcard origin with credentials; verify intended behavior")
    duration = float(flow.duration_ms)
    timing_class = "fast" if duration < 200 else "normal" if duration < 1000 else "slow" if duration < 5000 else "very_slow"
    return ProxyInspection(
        flow_id=flow.id,
        protocol="HTTP/1.x",
        request={
            "start_line": request_line, "header_count": len(request_headers), "body_bytes": len(request_body),
            "content_type": request_content_type, "host": _header(request_headers, "Host")[:512],
            "authorization_present": bool(_header(request_headers, "Authorization")),
            "cookie_present": bool(_header(request_headers, "Cookie")),
        },
        response={
            "start_line": response_line, "status": flow.status, "header_count": len(response_headers),
            "body_bytes": len(response_body), "content_type": content_type, "content_encoding": content_encoding,
            "transfer_encoding": transfer_encoding, "redirect_location": _header(response_headers, "Location")[:2048],
        },
        cookies=cookies,
        security_headers=security,
        cache={"cache_control": cache_control[:1024], "expires": expires[:256], "age": age[:64], "vary": vary[:1024]},
        cors=cors,
        timing={"duration_ms": duration, "class": timing_class, "request_bytes": flow.request_bytes, "response_bytes": flow.response_bytes},
        notes=notes[:64],
    )

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
class ProxyAutoResponderRule:
    id: str
    enabled: bool
    host_pattern: str
    path_pattern: str
    method: str
    status: int
    reason: str
    content_type: str
    body: str

    def validate(self) -> None:
        if not self.id or len(self.id) > 96:
            raise ValueError("AutoResponder rule id is invalid")
        if not self.host_pattern or len(self.host_pattern) > 253:
            raise ValueError("AutoResponder host pattern is invalid")
        if not self.path_pattern or len(self.path_pattern) > 2048:
            raise ValueError("AutoResponder path pattern is invalid")
        method = self.method.upper()
        if method != "*" and (not method.isalpha() or len(method) > 16):
            raise ValueError("AutoResponder method is invalid")
        if self.status < 100 or self.status > 599:
            raise ValueError("AutoResponder status must be between 100 and 599")
        for value, label, limit in ((self.reason, "reason", 128), (self.content_type, "content type", 256)):
            if len(value) > limit or "\r" in value or "\n" in value:
                raise ValueError(f"AutoResponder {label} is invalid")
        if len(self.body.encode("utf-8")) > 2 * 1024 * 1024:
            raise ValueError("AutoResponder body exceeds the 2 MiB safety limit")

    def matches(self, method: str, host: str, target: str) -> bool:
        if not self.enabled:
            return False
        method_ok = self.method == "*" or self.method.upper() == str(method).upper()
        return method_ok and fnmatch.fnmatchcase(str(host).casefold(), self.host_pattern.casefold()) and fnmatch.fnmatchcase(str(target), self.path_pattern)

    def response(self) -> bytes:
        body = self.body.encode("utf-8")
        reason = self.reason or "Arenyxa AutoResponder"
        headers = [
            f"HTTP/1.1 {self.status} {reason}",
            f"Content-Type: {self.content_type or 'text/plain; charset=utf-8'}",
            f"Content-Length: {len(body)}",
            "Connection: close",
            "X-Arenyxa-AutoResponder: 1",
            "",
            "",
        ]
        return "\r\n".join(headers).encode("latin-1", "replace") + body

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id, "enabled": self.enabled, "host_pattern": self.host_pattern,
            "path_pattern": self.path_pattern, "method": self.method, "status": self.status,
            "reason": self.reason, "content_type": self.content_type, "body": self.body,
        }

@dataclass(slots=True)
class ProxyMatchReplaceRule:
    id: str
    enabled: bool
    phase: str
    scope: str
    host_pattern: str
    path_pattern: str
    method: str
    header_name: str
    match: str
    replacement: str

    def validate(self) -> None:
        if not self.id or len(self.id) > 96:
            raise ValueError("Match/Replace rule id is invalid")
        if self.phase not in {"request", "response"}:
            raise ValueError("Match/Replace phase must be request or response")
        if self.scope not in {"header", "body"}:
            raise ValueError("Match/Replace scope must be header or body")
        if not self.host_pattern or len(self.host_pattern) > 253:
            raise ValueError("Match/Replace host pattern is invalid")
        if not self.path_pattern or len(self.path_pattern) > 2048:
            raise ValueError("Match/Replace path pattern is invalid")
        method = self.method.upper()
        if method != "*" and (not method.isalpha() or len(method) > 16):
            raise ValueError("Match/Replace method is invalid")
        if self.scope == "header":
            if not self.header_name or len(self.header_name) > 128 or any(ch in self.header_name for ch in "\r\n:"):
                raise ValueError("Match/Replace header name is invalid")
            if "\r" in self.replacement or "\n" in self.replacement:
                raise ValueError("Match/Replace header replacement cannot contain line breaks")
        if not self.match or len(self.match.encode("utf-8")) > 4096:
            raise ValueError("Match/Replace match value is empty or too large")
        if len(self.replacement.encode("utf-8")) > 16 * 1024:
            raise ValueError("Match/Replace replacement exceeds the 16 KiB safety limit")

    def matches_message(self, phase: str, method: str, host: str, target: str) -> bool:
        return (
            self.enabled
            and self.phase == str(phase)
            and (self.method == "*" or self.method.upper() == str(method).upper())
            and fnmatch.fnmatchcase(str(host).casefold(), self.host_pattern.casefold())
            and fnmatch.fnmatchcase(str(target), self.path_pattern)
        )

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)

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
    _PROTECTED_PREFIX = b"ARENYXA-PROXY-CA-PROTECTED\x00"

    def __init__(
        self,
        root: Path,
        *,
        key_protector: KeyProtectionAdapter | None = None,
        root_authorizer: Callable[[str], bool] | None = None,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.hosts = self.root / "hosts"
        self.hosts.mkdir(parents=True, exist_ok=True)
        self.key_path = self.root / "arenyxa-proxy-ca-key.pem"
        self.cert_path = self.root / "arenyxa-proxy-ca-cert.pem"
        default_protector = DPAPIKeyProtectionAdapter()
        self._key_protector = key_protector or (default_protector if default_protector.available() else None)
        self._root_authorizer = root_authorizer
        self._lock = threading.RLock()
        self._ensure_ca()

    def set_root_authorizer(self, callback: Callable[[str], bool] | None) -> None:
        """Attach the process-local Root Owner authorization session callback."""
        with self._lock:
            self._root_authorizer = callback

    def _authorize(self, operation: str) -> None:
        callback = self._root_authorizer
        if callback is not None and not bool(callback(str(operation))):
            raise ArenyxaError(
                "ROOT_OWNER_AUTHORIZATION_REQUIRED",
                "Root Owner authorization is required for Certificate Manager private-key operations.",
                domain="PROXY",
                context={"operation": str(operation)},
            )

    def _ensure_ca(self) -> None:
        if self.key_path.exists() and self.cert_path.exists():
            return
        self._authorize("generate-root-ca")
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
        private_bytes = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        if self._key_protector is not None and self._key_protector.available():
            protected = self._key_protector.protect(private_bytes, purpose="Arenyxa Proxy Root CA")
            private_bytes = self._PROTECTED_PREFIX + protected
        _secure_write(self.key_path, private_bytes)
        _secure_write(self.cert_path, cert.public_bytes(serialization.Encoding.PEM), public=False)

    def _load_ca_private_key(self) -> Any:
        payload = self.key_path.read_bytes()
        if payload.startswith(self._PROTECTED_PREFIX):
            if self._key_protector is None or not self._key_protector.available():
                raise ArenyxaError(
                    "PROXY_CA_KEY_PROTECTION_UNAVAILABLE",
                    "The Root CA private key is protected but its platform provider is unavailable.",
                    domain="PROXY",
                )
            payload = self._key_protector.unprotect(
                payload[len(self._PROTECTED_PREFIX):],
                purpose="Arenyxa Proxy Root CA",
            )
        with SecretBuffer(payload) as secret:
            return serialization.load_pem_private_key(secret.copy_bytes(), password=None)

    def fingerprint(self) -> str:
        cert = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
        return cert.fingerprint(hashes.SHA256()).hex().upper()

    @staticmethod
    def _certificate_snapshot(path: Path) -> dict[str, Any]:
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        try:
            expires_at = cert.not_valid_after_utc.isoformat()
            valid_from = cert.not_valid_before_utc.isoformat()
        except AttributeError:
            expires_at = cert.not_valid_after.isoformat()
            valid_from = cert.not_valid_before.isoformat()
        common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return {
            "subject": common_names[0].value if common_names else cert.subject.rfc4514_string(),
            "serial_number": format(cert.serial_number, "X"),
            "valid_from": valid_from,
            "expires_at": expires_at,
            "sha256": cert.fingerprint(hashes.SHA256()).hex().upper(),
        }

    def status(self) -> dict[str, Any]:
        """Return public CA metadata without exposing any private key material."""
        root = self._certificate_snapshot(self.cert_path)
        return {
            "root": root,
            "fingerprint": root["sha256"],
            "cached_certificates": len(list(self.hosts.glob("*.cert.pem"))),
            "private_key_export_api": False,
            "key_storage": (
                self._key_protector.name
                if self.key_path.read_bytes().startswith(self._PROTECTED_PREFIX) and self._key_protector is not None
                else "restricted-local-pem"
            ),
            "hardware_backed": bool(
                self._key_protector is not None
                and self._key_protector.available()
                and self._key_protector.name in {"tpm", "windows-cng"}
            ),
            "root_owner_authorization_configured": self._root_authorizer is not None,
        }

    def certificates(self, *, limit: int = 1000) -> list[dict[str, Any]]:
        """List bounded public certificate metadata from the domain cache."""
        bounded = max(1, min(int(limit), 10_000))
        rows: list[dict[str, Any]] = []
        for path in sorted(self.hosts.glob("*.cert.pem"), key=lambda item: item.stat().st_mtime, reverse=True)[:bounded]:
            try:
                value = self._certificate_snapshot(path)
            except (OSError, ValueError):
                continue
            value["cache_id"] = path.stem.removesuffix(".cert")
            rows.append(value)
        return rows

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

        self._authorize("issue-domain-certificate")
        ca_key = self._load_ca_private_key()
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
        # Create the append-only index eagerly so callers can observe archive readiness even
        # while Phase-6 persistence is draining asynchronously.
        if not self.index.exists():
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            descriptor = os.open(str(self.index), flags, 0o600)
            os.close(descriptor)
            try:
                os.chmod(self.index, 0o600)
            except OSError:
                record_current_exception(__name__, 'ProxyArchive.__init__:726')

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
                        record_current_exception(__name__, 'ProxyArchive.store:751')
                try:
                    os.chmod(self.index, 0o600)
                except OSError:
                    record_current_exception(__name__, 'ProxyArchive.store:755')
            except Exception:
                try:
                    os.close(descriptor)
                except OSError:
                    record_current_exception(__name__, 'ProxyArchive.store:760')
                raise
