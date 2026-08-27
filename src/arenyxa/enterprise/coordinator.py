from __future__ import annotations

import base64
import collections
import hashlib
import http.client
import http.server
import json
import logging
import os
import secrets
import socket
import ssl
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import new_id, utc_now
from arenyxa.enterprise.enrollment import EnrollmentService, _canonical as canonical_json, _unb64u, _b64u
from arenyxa.enterprise.identity import LocalEnterpriseIdentityService
from arenyxa.enterprise.transport_security import normalize_correlation_id

COORDINATOR_IDENTITY_SCHEMA = "arenyxa.office-coordinator-identity/v1"
COORDINATOR_CHALLENGE_SCHEMA = "arenyxa.office-coordinator-challenge/v1"
MAX_REQUEST_BYTES = 128 * 1024
MAX_CHALLENGES = 1024
MAX_SESSIONS = 2048
CHALLENGE_TTL_SECONDS = 90
SESSION_TTL_SECONDS = 60 * 60
SERVICE_LEASE_TTL_SECONDS = 24 * 60 * 60
MAX_HTTP_THREADS = 64
MAX_RATE_BUCKETS = 512
MAX_REQUESTS_PER_MINUTE = 180
SERVICE_LEASE_RENEW_SECONDS = 60 * 60
COORDINATOR_CERT_VALID_DAYS = 7
COORDINATOR_CERT_RENEW_WINDOW_SECONDS = 24 * 60 * 60
COORDINATOR_CERT_CHECK_INTERVAL_SECONDS = 5 * 60
LOGGER = logging.getLogger(__name__)
CORRELATION_HEADER = "X-Arenyxa-Correlation-ID"


def _fail(code: str, message: str, **context: Any) -> ArenyxaError:
    return ArenyxaError(code, message, domain="ENTERPRISE", context=context)


def _strict_json_loads(raw: bytes) -> Any:
    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _fail("COORDINATOR_REQUEST_INVALID", "Coordinator JSON contains duplicate keys", key=key)
            result[key] = value
        return result
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=hook)
    except ArenyxaError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _fail("COORDINATOR_REQUEST_INVALID", "Coordinator JSON cannot be decoded") from exc


def verify_coordinator_identity(artifact: Mapping[str, Any], *, expected_root_fingerprint: str, peer_certificate_der: bytes) -> dict[str, Any]:
    required = {"schema", "payload", "root_public_key", "root_fingerprint", "signature"}
    if set(artifact) != required or artifact.get("schema") != COORDINATOR_IDENTITY_SCHEMA or not isinstance(artifact.get("payload"), dict):
        raise _fail("COORDINATOR_IDENTITY_INVALID", "Coordinator identity artifact schema is invalid")
    payload = dict(artifact["payload"])
    expected_payload = {"enterprise_id", "coordinator_id", "tls_cert_sha256", "signing_public_key", "issued_at", "expires_at"}
    if set(payload) != expected_payload:
        raise _fail("COORDINATOR_IDENTITY_INVALID", "Coordinator identity payload fields are invalid")
    root_public = _unb64u(str(artifact.get("root_public_key", "")), 64)
    fingerprint = hashlib.sha256(root_public).hexdigest()
    if fingerprint != str(artifact.get("root_fingerprint", "")) or fingerprint != str(expected_root_fingerprint):
        raise _fail("COORDINATOR_ROOT_MISMATCH", "Coordinator identity is not signed by the expected Enterprise Root")
    signature = _unb64u(str(artifact.get("signature", "")), 96)
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(root_public).verify(signature, canonical_json(payload))
    except (ValueError, InvalidSignature) as exc:
        raise _fail("COORDINATOR_IDENTITY_INVALID", "Coordinator Enterprise Root signature is invalid") from exc
    cert_sha = hashlib.sha256(bytes(peer_certificate_der)).hexdigest()
    if cert_sha != str(payload.get("tls_cert_sha256", "")):
        raise _fail("COORDINATOR_TLS_IDENTITY_MISMATCH", "TLS peer certificate does not match the signed Coordinator identity")
    expires = datetime.fromisoformat(str(payload["expires_at"]).replace("Z", "+00:00"))
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires <= datetime.now(timezone.utc):
        raise _fail("COORDINATOR_IDENTITY_EXPIRED", "Coordinator identity artifact has expired")
    signing_public = _unb64u(str(payload.get("signing_public_key", "")), 64)
    if len(signing_public) != 32:
        raise _fail("COORDINATOR_IDENTITY_INVALID", "Coordinator signing public key is invalid")
    return payload


class OfficeCoordinatorService:
    






    def __init__(self, identity: LocalEnterpriseIdentityService, enrollment: EnrollmentService, data_root: Path) -> None:
        self.identity = identity
        self.enrollment = enrollment
        self.data_root = Path(data_root)
        self.coordinator_id = new_id("coordinator")
        self._signing_key = ed25519.Ed25519PrivateKey.generate()
        self._process_nonce = secrets.token_bytes(24)
        self._lock = threading.Lock()
        self._challenges: dict[str, dict[str, Any]] = {}
        self._sessions: dict[str, dict[str, Any]] = {}
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._identity_artifact: dict[str, Any] | None = None
        self._tls_artifacts_by_context: dict[int, dict[str, Any]] = {}
        self._active_tls_context: ssl.SSLContext | None = None
        self._tls_rotation_stop = threading.Event()
        self._tls_rotation_thread: threading.Thread | None = None
        self._tls_rotation_error = ""
        self._tls_rotation_count = 0
        self._service_lease = ""
        self._service_lease_stop = threading.Event()
        self._service_lease_thread = None
        self._service_lease_error = ""
        self._rate_buckets: "collections.OrderedDict[str, tuple[float, int]]" = collections.OrderedDict()

    @property
    def running(self) -> bool:
        with self._lock:
            return self._server is not None

    def _cleanup(self) -> None:
        now = time.monotonic()
        with self._lock:
            self._challenges = {k: v for k, v in self._challenges.items() if float(v.get("expires_mono", 0)) > now}
            self._sessions = {k: v for k, v in self._sessions.items() if float(v.get("expires_mono", 0)) > now}
            if len(self._challenges) > MAX_CHALLENGES:
                ordered = sorted(self._challenges.items(), key=lambda item: float(item[1].get("created_mono", 0)))
                self._challenges = dict(ordered[-MAX_CHALLENGES:])
            if len(self._sessions) > MAX_SESSIONS:
                ordered = sorted(self._sessions.items(), key=lambda item: float(item[1].get("created_mono", 0)))
                self._sessions = dict(ordered[-MAX_SESSIONS:])

    def _allow_remote_request(self, peer: str) -> bool:
        key = str(peer)[:128] or "unknown"
        now = time.monotonic()
        with self._lock:
            start, count = self._rate_buckets.get(key, (now, 0))
            if now - float(start) >= 60.0:
                start, count = now, 0
            count += 1
            self._rate_buckets[key] = (float(start), int(count))
            self._rate_buckets.move_to_end(key)
            while len(self._rate_buckets) > MAX_RATE_BUCKETS:
                self._rate_buckets.popitem(last=False)
            return count <= MAX_REQUESTS_PER_MINUTE

    def health(self) -> dict[str, Any]:
        self._cleanup()
        with self._lock:
            identity_payload = (self._identity_artifact or {}).get("payload", {})
            identity_expires_at = str(identity_payload.get("expires_at", "")) if isinstance(identity_payload, dict) else ""
            return {
                "coordinator_id": self.coordinator_id,
                "running": self._server is not None,
                "pending_challenges": len(self._challenges),
                "active_sessions": len(self._sessions),
                "offline_policy": "deny-new-authentication-when-coordinator-unavailable",
                "trust_model": "enterprise-root-signed-tls-identity",
                "service_lease_status": "degraded" if self._service_lease_error else "ok",
                "service_lease_error": self._service_lease_error[:256],
                "identity_expires_at": identity_expires_at,
                "tls_rotation_status": "degraded" if self._tls_rotation_error else "ok",
                "tls_rotation_error": self._tls_rotation_error[:256],
                "tls_rotation_count": self._tls_rotation_count,
                "rate_limit_buckets": len(self._rate_buckets),
                "max_requests_per_minute": MAX_REQUESTS_PER_MINUTE,
                "time": utc_now(),
            }

    def identity_artifact(self, tls_context: ssl.SSLContext | None = None) -> dict[str, Any]:
        with self._lock:
            artifact = self._tls_artifacts_by_context.get(id(tls_context)) if tls_context is not None else None
            if artifact is None:
                artifact = self._identity_artifact
            if artifact is None:
                raise _fail("COORDINATOR_NOT_STARTED", "Coordinator TLS identity has not been prepared")
            return json.loads(json.dumps(artifact))

    @staticmethod
    def _artifact_expiry_epoch(artifact: Mapping[str, Any] | None) -> float:
        try:
            payload = artifact.get("payload", {}) if isinstance(artifact, Mapping) else {}
            expires = datetime.fromisoformat(str(payload.get("expires_at", "")).replace("Z", "+00:00"))
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            return float(expires.timestamp())
        except (TypeError, ValueError, OverflowError):
            return 0.0

    def _require_service_lease(self) -> str:
        with self._lock:
            token = self._service_lease
        if not token:
            raise _fail("COORDINATOR_SERVICE_LEASE_INVALID", "Coordinator service lease is not active")
        return token

    def discovery_record(self, host: str, port: int) -> dict[str, Any]:
        
        artifact = self.identity_artifact()
        return {
            "service": "arenyxa-office-coordinator",
            "enterprise_id": str(artifact["payload"]["enterprise_id"]),
            "coordinator_id": self.coordinator_id,
            "host": str(host), "port": int(port),
            "identity_required": True,
        }

    def migration_descriptor(self) -> dict[str, Any]:
        






        root = self.identity.root_public_identity()
        return {
            "schema": "arenyxa.office-coordinator-migration/v1",
            "enterprise_id": root["enterprise_id"],
            "root_fingerprint": root["fingerprint"],
            "durable_state": "enterprise-identity-vault",
            "coordinator_private_key_exported": False,
            "device_reenrollment_required_after_verified_vault_restore": False,
            "offline_policy": "deny-new-authentication-when-coordinator-unavailable",
        }

    def enroll(self, token: Mapping[str, Any], device_public: Mapping[str, str]) -> dict[str, Any]:
        return self.enrollment.consume(token, device_public, service_lease=self._require_service_lease())

    def create_challenge(self, device_id: str) -> dict[str, Any]:
        self._cleanup()
        device = self.enrollment.validate_active_device(
            str(device_id), service_lease=self._require_service_lease(),
        )
        challenge_id = new_id("coord_challenge")
        payload = {
            "schema": COORDINATOR_CHALLENGE_SCHEMA,
            "challenge_id": challenge_id,
            "coordinator_id": self.coordinator_id,
            "device_id": str(device_id),
            "nonce": _b64u(secrets.token_bytes(32)),
            "process_nonce": _b64u(self._process_nonce),
            "issued_at": utc_now(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=CHALLENGE_TTL_SECONDS)).isoformat(),
        }
        with self._lock:
            if len(self._challenges) >= MAX_CHALLENGES:
                raise _fail("COORDINATOR_BUSY", "Coordinator challenge queue is full")
            self._challenges[challenge_id] = {"payload": payload, "created_mono": time.monotonic(), "expires_mono": time.monotonic() + CHALLENGE_TTL_SECONDS}
        return payload

    def authenticate_device(self, challenge_id: str, signature_b64: str) -> dict[str, Any]:
        self._cleanup()
        with self._lock:
            entry = self._challenges.pop(str(challenge_id), None)
        if not isinstance(entry, dict):
            raise _fail("COORDINATOR_CHALLENGE_INVALID", "Coordinator challenge is missing, expired, or already consumed")
        payload = entry["payload"]
        if float(entry.get("expires_mono", 0)) <= time.monotonic():
            raise _fail("COORDINATOR_CHALLENGE_EXPIRED", "Coordinator challenge has expired")
        device = self.enrollment.validate_active_device(
            str(payload["device_id"]), service_lease=self._require_service_lease(),
        )
        public = _unb64u(str(device.get("public_key", "")), 64)
        signature = _unb64u(str(signature_b64), 96)
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(public).verify(signature, canonical_json(payload))
        except (ValueError, InvalidSignature) as exc:
            raise _fail("COORDINATOR_DEVICE_PROOF_INVALID", "Device challenge signature is invalid") from exc
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._lock:
            if len(self._sessions) >= MAX_SESSIONS:
                raise _fail("COORDINATOR_BUSY", "Coordinator session capacity is full")
            self._sessions[token_hash] = {
                "device_id": device["id"], "account_id": device["account_id"],
                "auth_generation": int(device.get("auth_generation", 0)),
                "created_mono": time.monotonic(), "expires_mono": time.monotonic() + SESSION_TTL_SECONDS,
            }
        return {"session_token": token, "device_id": device["id"], "account_id": device["account_id"], "expires_in": SESSION_TTL_SECONDS}

    def validate_session(self, token: str) -> dict[str, Any]:
        self._cleanup()
        digest = hashlib.sha256(str(token).encode("utf-8")).hexdigest()
        with self._lock:
            row = self._sessions.get(digest)
        if not isinstance(row, dict):
            raise _fail("COORDINATOR_SESSION_INVALID", "Coordinator device session is missing or expired")
        try:
            device = self.enrollment.validate_active_device(
                str(row.get("device_id", "")), service_lease=self._require_service_lease(),
            )
        except ArenyxaError:
            with self._lock:
                self._sessions.pop(digest, None)
            raise
        if int(device.get("auth_generation", -1)) != int(row.get("auth_generation", -2)):
            with self._lock:
                self._sessions.pop(digest, None)
            raise _fail("COORDINATOR_SESSION_STALE", "Coordinator session authorization generation is stale")
        return dict(row)

    def _maintain_service_lease(self, lease: str) -> None:
        while not self._service_lease_stop.wait(SERVICE_LEASE_RENEW_SECONDS):
            try:
                self.identity.renew_service_lease(lease, "enrollment", ttl_seconds=SERVICE_LEASE_TTL_SECONDS)
                with self._lock:
                    self._service_lease_error = ""
            except Exception as exc:
                LOGGER.exception("Office Coordinator service-lease renewal failed")
                with self._lock:
                    self._service_lease_error = f"{type(exc).__name__}: {exc}"[:256]

    def _build_tls_context(self) -> tuple[ssl.SSLContext, bytes, dict[str, Any]]:
                                                                                             
                                                                                              
                                                             
        tls_key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Arenyxa Coordinator {self.coordinator_id[-24:]}")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(tls_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=COORDINATOR_CERT_VALID_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(tls_key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        key_pem = tls_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        public = self._signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        payload = {
            "enterprise_id": self.identity.root_public_identity()["enterprise_id"],
            "coordinator_id": self.coordinator_id,
            "tls_cert_sha256": hashlib.sha256(cert_der).hexdigest(),
            "signing_public_key": _b64u(public),
            "issued_at": utc_now(),
            "expires_at": (now + timedelta(days=COORDINATOR_CERT_VALID_DAYS)).isoformat(),
        }
        signed = self.identity.sign_enterprise_artifact(canonical_json(payload), capability="enterprise.coordinator.manage", resource="enterprise:coordinator", step_up=True)
        artifact = {
            "schema": COORDINATOR_IDENTITY_SCHEMA, "payload": payload,
            "root_public_key": signed["root_public_key"], "root_fingerprint": signed["root_fingerprint"], "signature": signed["signature"],
        }
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        temp_dir = self.data_root / "enterprise" / "coordinator" / "runtime"
        temp_dir.mkdir(parents=True, exist_ok=True)
        cert_path: Path | None = None
        key_path: Path | None = None
        try:
                                                                                              
                                                                                                    
            with tempfile.NamedTemporaryFile(
                mode="wb", prefix=f".{self.coordinator_id}.", suffix=".cert.pem", dir=temp_dir, delete=False
            ) as cert_file:
                cert_file.write(cert_pem)
                cert_file.flush()
                os.fsync(cert_file.fileno())
                cert_path = Path(cert_file.name)
            with tempfile.NamedTemporaryFile(
                mode="wb", prefix=f".{self.coordinator_id}.", suffix=".key.pem", dir=temp_dir, delete=False
            ) as key_file:
                key_file.write(key_pem)
                key_file.flush()
                os.fsync(key_file.fileno())
                key_path = Path(key_file.name)
            context.load_cert_chain(str(cert_path), str(key_path))
        finally:
            for runtime_path in (cert_path, key_path):
                if runtime_path is None:
                    continue
                try:
                    runtime_path.unlink(missing_ok=True)
                except OSError as exc:
                    LOGGER.warning("Failed to remove Coordinator TLS runtime file %s: %s", runtime_path, exc)
        return context, cert_der, artifact

    def _rotate_tls_context(self) -> bool:
        """Hot-rotate the listener TLS context while preserving existing accepted sessions."""
        with self._lock:
            server = self._server
        if server is None:
            return False
        context, _cert_der, artifact = self._build_tls_context()
        with self._lock:
            if self._server is not server:
                return False
            if not isinstance(server.socket, ssl.SSLSocket):
                raise _fail("COORDINATOR_TLS_ROTATION_FAILED", "Coordinator listener is not an SSL socket")
            # The listening socket keeps a stable dispatcher SSLContext. During every new
            # handshake its SNI callback selects this active context. Existing accepted
            # sockets retain their prior context/certificate and continue uninterrupted.
            self._active_tls_context = context
            self._identity_artifact = artifact
            self._tls_artifacts_by_context[id(context)] = artifact
            # Retain a small generation window so already accepted keep-alive connections
            # can still receive an identity artifact matching the certificate they saw.
            while len(self._tls_artifacts_by_context) > 4:
                oldest = next(iter(self._tls_artifacts_by_context))
                if oldest == id(context):
                    break
                self._tls_artifacts_by_context.pop(oldest, None)
            self._tls_rotation_count += 1
            self._tls_rotation_error = ""
        LOGGER.info("Office Coordinator TLS identity hot-rotated generation=%d", self._tls_rotation_count)
        return True

    def _maintain_tls_identity(self) -> None:
        while not self._tls_rotation_stop.wait(COORDINATOR_CERT_CHECK_INTERVAL_SECONDS):
            with self._lock:
                artifact = self._identity_artifact
                running = self._server is not None
            if not running:
                return
            remaining = self._artifact_expiry_epoch(artifact) - time.time()
            if remaining > COORDINATOR_CERT_RENEW_WINDOW_SECONDS:
                continue
            try:
                self._rotate_tls_context()
            except (ArenyxaError, OSError, ssl.SSLError, ValueError) as exc:
                LOGGER.exception("Office Coordinator TLS hot rotation failed")
                with self._lock:
                    self._tls_rotation_error = f"{type(exc).__name__}: {exc}"[:256]

    def start_tls(self, host: str = "127.0.0.1", port: int = 0) -> tuple[str, int]:
        if self.running:
            raise _fail("COORDINATOR_ALREADY_RUNNING", "Office Coordinator is already running")
        context, _cert_der, artifact = self._build_tls_context()
        lease = self.identity.issue_service_lease(
            "office-coordinator", ("enrollment",),
            (
                ("enterprise.coordinator.manage", "enterprise:coordinator"),
                ("enterprise.enrollment.manage", "enterprise:enrollment"),
                ("enterprise.device.manage", "enterprise:devices"),
            ),
            ttl_seconds=SERVICE_LEASE_TTL_SECONDS,
        )
        with self._lock:
            self._service_lease = lease
        service = self

        class Handler(http.server.BaseHTTPRequestHandler):
            server_version = "ArenyxaOfficeCoordinator/1"
            protocol_version = "HTTP/1.1"
            def log_message(self, _fmt: str, *_args: Any) -> None:
                return
            def _rate_limit(self) -> bool:
                peer = self.client_address[0] if self.client_address else "unknown"
                if service._allow_remote_request(str(peer)):
                    return True
                self._send(429, {"error": "rate_limited", "message": "Coordinator request rate limit exceeded"})
                return False
            def _send(self, status: int, payload: Mapping[str, Any]) -> None:
                raw = json.dumps(dict(payload), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                try:
                    expiry = str(service.identity_artifact(getattr(self.connection, "context", None)).get("payload", {}).get("expires_at", ""))
                except ArenyxaError:
                    expiry = ""
                if expiry:
                    self.send_header("X-Arenyxa-Cert-Expiry", expiry)
                trace = normalize_correlation_id(self.headers.get(CORRELATION_HEADER))
                self.send_header(CORRELATION_HEADER, trace)
                self.end_headers()
                self.wfile.write(raw)
                LOGGER.info(
                    "office coordinator request",
                    extra={
                        "correlation_id": trace,
                        "phase": "office-coordinator-http",
                        "resource_id": self.path[:256],
                        "error_code": "" if status < 400 else f"HTTP_{status}",
                    },
                )
            def _body(self) -> dict[str, Any]:
                if self.headers.get("Transfer-Encoding"):
                    self.close_connection = True
                    raise _fail("COORDINATOR_REQUEST_INVALID", "Coordinator does not accept transfer-encoded request bodies")
                raw_length = self.headers.get("Content-Length")
                if raw_length is None:
                    self.close_connection = True
                    raise _fail("COORDINATOR_REQUEST_INVALID", "Coordinator request requires Content-Length")
                try:
                    size = int(raw_length)
                except ValueError:
                    size = -1
                if size < 0 or size > MAX_REQUEST_BYTES:
                    self.close_connection = True
                    raise _fail("COORDINATOR_REQUEST_INVALID", "Coordinator request body is outside the safety bound")
                raw = self.rfile.read(size)
                if len(raw) != size:
                    self.close_connection = True
                    raise _fail("COORDINATOR_REQUEST_INVALID", "Coordinator request body length does not match Content-Length")
                value = _strict_json_loads(raw) if raw else {}
                if not isinstance(value, dict):
                    raise _fail("COORDINATOR_REQUEST_INVALID", "Coordinator request body must be a JSON object")
                return value
            def do_GET(self) -> None:
                if not self._rate_limit():
                    return
                try:
                    if self.path == "/v1/identity":
                        self._send(200, service.identity_artifact(getattr(self.connection, "context", None)))
                    elif self.path == "/v1/health":
                        self._send(200, service.health())
                    else:
                        self._send(404, {"error": "not_found"})
                except ArenyxaError as exc:
                    self._send(400, {"error": exc.code, "message": str(exc)[:512]})
                except (ValueError, TypeError, json.JSONDecodeError) as exc:
                    self._send(400, {"error": "request_invalid", "message": str(exc)[:512]})
                except Exception:
                    LOGGER.exception("Unhandled Coordinator GET request failure")
                    self._send(500, {"error": "internal_error", "message": "Coordinator request failed"})
            def do_POST(self) -> None:
                if not self._rate_limit():
                    return
                try:
                    body = self._body()
                    if self.path == "/v1/enroll":
                        result = service.enroll(body.get("token", {}), body.get("device", {}))
                    elif self.path == "/v1/challenge":
                        result = service.create_challenge(str(body.get("device_id", "")))
                    elif self.path == "/v1/auth":
                        result = service.authenticate_device(str(body.get("challenge_id", "")), str(body.get("signature", "")))
                    else:
                        self._send(404, {"error": "not_found"}); return
                    self._send(200, result)
                except ArenyxaError as exc:
                    self._send(400, {"error": exc.code, "message": str(exc)[:512]})
                except (ValueError, TypeError, json.JSONDecodeError) as exc:
                    self._send(400, {"error": "request_invalid", "message": str(exc)[:512]})
                except Exception:
                    LOGGER.exception("Unhandled Coordinator POST request failure")
                    self._send(500, {"error": "internal_error", "message": "Coordinator request failed"})

        class BoundedThreadingHTTPServer(http.server.ThreadingHTTPServer):
            daemon_threads = True
            request_queue_size = MAX_HTTP_THREADS
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                self._request_slots = threading.BoundedSemaphore(MAX_HTTP_THREADS)
                super().__init__(*args, **kwargs)
            def process_request(self, request: Any, client_address: Any) -> None:
                if not self._request_slots.acquire(blocking=False):
                    self.shutdown_request(request)
                    return
                try:
                    super().process_request(request, client_address)
                except Exception:
                    self._request_slots.release()
                    raise
            def process_request_thread(self, request: Any, client_address: Any) -> None:
                try:
                    super().process_request_thread(request, client_address)
                finally:
                    self._request_slots.release()

        server: http.server.ThreadingHTTPServer | None = None
        thread = None
        lease_thread = None
        tls_rotation_thread = None
        try:
            server = BoundedThreadingHTTPServer((str(host), int(port)), Handler)
            server.daemon_threads = True

            def _select_active_tls_context(ssl_socket: ssl.SSLSocket, _server_name: str | None, _initial: ssl.SSLContext) -> None:
                with service._lock:
                    selected = service._active_tls_context
                if selected is not None and ssl_socket.context is not selected:
                    ssl_socket.context = selected

            context.set_servername_callback(_select_active_tls_context)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, name="arenyxa-office-coordinator", daemon=True)
            with self._lock:
                self._server = server
                self._thread = thread
                self._identity_artifact = artifact
                self._active_tls_context = context
                self._tls_artifacts_by_context = {id(context): artifact}
                self._service_lease_error = ""
                self._tls_rotation_error = ""
                self._service_lease_stop.clear()
                self._tls_rotation_stop.clear()
                lease_thread = threading.Thread(
                    target=self._maintain_service_lease, args=(lease,),
                    name="arenyxa-office-coordinator-authority", daemon=True,
                )
                self._service_lease_thread = lease_thread
                tls_rotation_thread = threading.Thread(
                    target=self._maintain_tls_identity,
                    name="arenyxa-office-coordinator-tls-rotation", daemon=True,
                )
                self._tls_rotation_thread = tls_rotation_thread
            thread.start()
            lease_thread.start()
            tls_rotation_thread.start()
            bound_host, bound_port = server.server_address[:2]
            return str(bound_host), int(bound_port)
        except Exception:
            if server is not None:
                try:
                    server.shutdown()
                except Exception:
                    LOGGER.exception("Coordinator startup rollback could not stop the HTTP server")
                try:
                    server.server_close()
                except Exception:
                    LOGGER.exception("Coordinator startup rollback could not close the HTTP server")
            if thread is not None and thread is not threading.current_thread() and thread.is_alive():
                thread.join(timeout=3.0)
            if lease_thread is not None and lease_thread is not threading.current_thread() and lease_thread.is_alive():
                self._service_lease_stop.set()
                lease_thread.join(timeout=3.0)
            if tls_rotation_thread is not None and tls_rotation_thread is not threading.current_thread() and tls_rotation_thread.is_alive():
                self._tls_rotation_stop.set()
                tls_rotation_thread.join(timeout=3.0)
            with self._lock:
                self._server = None
                self._thread = None
                self._service_lease = ""
                self._service_lease_thread = None
                self._service_lease_stop.set()
                self._tls_rotation_thread = None
                self._tls_rotation_stop.set()
                self._identity_artifact = None
                self._active_tls_context = None
                self._tls_artifacts_by_context.clear()
            self.identity.revoke_service_lease(lease, reason="COORDINATOR_START_FAILED")
            raise

    def stop(self) -> None:
        with self._lock:
            server = self._server
            thread = self._thread
            lease = self._service_lease
            lease_thread = self._service_lease_thread
            tls_rotation_thread = self._tls_rotation_thread
            self._server = None
            self._thread = None
            self._service_lease = ""
            self._service_lease_thread = None
            self._service_lease_stop.set()
            self._tls_rotation_thread = None
            self._tls_rotation_stop.set()
            self._challenges.clear()
            self._sessions.clear()
            self._rate_buckets.clear()
            self._identity_artifact = None
            self._active_tls_context = None
            self._tls_artifacts_by_context.clear()
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=3.0)
        if lease_thread is not None and lease_thread is not threading.current_thread():
            lease_thread.join(timeout=3.0)
        if tls_rotation_thread is not None and tls_rotation_thread is not threading.current_thread():
            tls_rotation_thread.join(timeout=3.0)
        if lease:
            self.identity.revoke_service_lease(lease, reason="COORDINATOR_STOP")


class CoordinatorClient:
    








    def __init__(
        self, host: str, port: int, expected_root_fingerprint: str, *, ca_file: Path | None = None,
        require_ca_validation: bool = False,
    ) -> None:
        self.host = str(host)
        self.port = int(port)
        self.expected_root_fingerprint = str(expected_root_fingerprint).strip().casefold()
        if len(self.expected_root_fingerprint) != 64 or any(ch not in "0123456789abcdef" for ch in self.expected_root_fingerprint):
            raise ValueError("expected Enterprise Root fingerprint must be SHA-256 hex")
        self.ca_file = Path(ca_file) if ca_file is not None else None
        self.require_ca_validation = bool(require_ca_validation or self.ca_file is not None)
        self.tls_mode = "ca+enterprise-identity" if self.require_ca_validation else "enterprise-identity-pinned"

    def _client_tls_context(self) -> ssl.SSLContext:
        if self.require_ca_validation:
            context = ssl.create_default_context(cafile=str(self.ca_file) if self.ca_file is not None else None)
                                                                                                 
                                                                                              
                                                                                                     
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            if hasattr(ssl, "OP_NO_COMPRESSION"):
                context.options |= ssl.OP_NO_COMPRESSION
            return context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        if hasattr(ssl, "OP_NO_COMPRESSION"):
            context.options |= ssl.OP_NO_COMPRESSION
        return context

    def _verified_connection(self, timeout: float = 5.0, correlation_id: str | None = None) -> http.client.HTTPSConnection:
        trace = normalize_correlation_id(correlation_id)
        context = self._client_tls_context()
        connection = http.client.HTTPSConnection(self.host, self.port, context=context, timeout=timeout)
        try:
            connection.connect()
            sock = connection.sock
            if sock is None:
                raise _fail("COORDINATOR_TLS_FAILED", "Coordinator TLS socket is unavailable")
            cert_der = sock.getpeercert(binary_form=True)
            connection.request("GET", "/v1/identity", headers={"Connection": "keep-alive", CORRELATION_HEADER: trace})
            response = connection.getresponse()
            raw = response.read(MAX_REQUEST_BYTES + 1)
            if response.status != 200 or len(raw) > MAX_REQUEST_BYTES:
                raise _fail("COORDINATOR_IDENTITY_INVALID", "Coordinator identity endpoint failed")
            artifact = _strict_json_loads(raw)
            verify_coordinator_identity(artifact, expected_root_fingerprint=self.expected_root_fingerprint, peer_certificate_der=cert_der)
            return connection
        except Exception:
            connection.close()
            raise

    def verify_peer(self, timeout: float = 5.0) -> dict[str, Any]:
        trace = normalize_correlation_id("coordinator-verify")
        connection = self._verified_connection(timeout, trace)
        try:
                                                                                                 
                                                                                       
            connection.request("GET", "/v1/health", headers={"Connection": "close", CORRELATION_HEADER: trace})
            response = connection.getresponse()
            raw = response.read(MAX_REQUEST_BYTES + 1)
            if response.status != 200 or len(raw) > MAX_REQUEST_BYTES:
                raise _fail("COORDINATOR_HEALTH_FAILED", "Coordinator health endpoint failed")
            value = _strict_json_loads(raw)
            if not isinstance(value, dict):
                raise _fail("COORDINATOR_HEALTH_FAILED", "Coordinator health response is invalid")
            return value
        finally:
            connection.close()

    def _post(self, path: str, payload: Mapping[str, Any], timeout: float = 8.0) -> dict[str, Any]:
        trace = normalize_correlation_id("coordinator:" + path.strip("/").replace("/", ":")[:96])
        connection = self._verified_connection(timeout, trace)
        try:
            raw = json.dumps(dict(payload), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if len(raw) > MAX_REQUEST_BYTES:
                raise _fail("COORDINATOR_REQUEST_INVALID", "Coordinator request exceeds safety bound")
            connection.request(
                "POST", path, body=raw,
                headers={"Content-Type": "application/json", "Content-Length": str(len(raw)), "Connection": "close", CORRELATION_HEADER: trace},
            )
            response = connection.getresponse()
            body = response.read(MAX_REQUEST_BYTES + 1)
            if len(body) > MAX_REQUEST_BYTES:
                raise _fail("COORDINATOR_RESPONSE_INVALID", "Coordinator response exceeds safety bound")
            value = _strict_json_loads(body) if body else {}
            if response.status != 200:
                code = str(value.get("error", "COORDINATOR_REQUEST_FAILED")) if isinstance(value, dict) else "COORDINATOR_REQUEST_FAILED"
                message = str(value.get("message", "Coordinator request failed")) if isinstance(value, dict) else "Coordinator request failed"
                raise _fail(code, message)
            if not isinstance(value, dict):
                raise _fail("COORDINATOR_RESPONSE_INVALID", "Coordinator response is invalid")
            return value
        finally:
            connection.close()

    def enroll(self, token: Mapping[str, Any], device_public: Mapping[str, str]) -> dict[str, Any]:
        return self._post("/v1/enroll", {"token": dict(token), "device": dict(device_public)})

    def challenge(self, device_id: str) -> dict[str, Any]:
        return self._post("/v1/challenge", {"device_id": str(device_id)})

    def authenticate(self, challenge_id: str, signature: bytes) -> dict[str, Any]:
        return self._post("/v1/auth", {"challenge_id": str(challenge_id), "signature": _b64u(bytes(signature))})
