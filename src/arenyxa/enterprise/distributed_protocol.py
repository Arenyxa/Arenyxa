from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import secrets
import sqlite3
from contextlib import contextmanager
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from arenyxa import __compat_version__
from arenyxa.compat import dataclass
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import Task, new_id, utc_now
from arenyxa.enterprise.governance import EnterpriseGovernanceService
from arenyxa.enterprise.runtime_storage import DistributedRuntimeStorageBackend, storage_backend_for
from arenyxa.enterprise.identity import LocalEnterpriseIdentityService
from arenyxa.application.runner import RunOrchestrator

LOGGER = logging.getLogger(__name__)

DISTRIBUTED_SCHEMA = "arenyxa.enterprise-distributed/v1"

CURRENT_PROTOCOL = 2

MIN_COMPATIBLE_PROTOCOL = 1

MAX_JOB_PAYLOAD_BYTES = 2 * 1024 * 1024

MAX_RESULT_BYTES = 256 * 1024

MAX_CHECKPOINT_BYTES = 128 * 1024

MAX_RESOURCE_DECLARATION_BYTES = 64 * 1024

MAX_JOBS = 100_000

MAX_WORKERS = 4096

MAX_CHALLENGES = 4096

MAX_WORKER_SESSIONS = 4096

MAX_WORKER_SLOTS = 64

MAX_JOB_EVENTS_PER_JOB = 128

MAX_EVENT_DETAILS_BYTES = 16 * 1024

DEFAULT_LEASE_SECONDS = 60

MAX_LEASE_SECONDS = 15 * 60

WORKER_SESSION_TTL_SECONDS = 15 * 60

CHALLENGE_TTL_SECONDS = 120

_JOB_STATES = frozenset({"queued", "leased", "running", "completed", "failed", "review_required", "cancelled"})

_ALLOWED_JOB_TRANSITIONS = frozenset({
    ("", "queued"),
    ("queued", "queued"), ("queued", "leased"), ("queued", "cancelled"),
    ("leased", "leased"), ("leased", "running"), ("leased", "queued"), ("leased", "completed"),
    ("leased", "failed"), ("leased", "review_required"), ("leased", "cancelled"),
    ("running", "running"), ("running", "queued"), ("running", "completed"), ("running", "failed"),
    ("running", "review_required"), ("running", "cancelled"),
    ("review_required", "review_required"), ("review_required", "queued"), ("review_required", "failed"),
    ("review_required", "cancelled"),
    ("completed", "completed"), ("failed", "failed"), ("cancelled", "cancelled"),
})

def _fail(code: str, message: str, **context: Any) -> ArenyxaError:
    return ArenyxaError(code, message, domain="ENTERPRISE_DISTRIBUTED", context=context)

def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")

def _bounded_json(value: Mapping[str, Any], max_bytes: int, label: str) -> tuple[str, str]:
    if not isinstance(value, Mapping):
        raise _fail("DISTRIBUTED_PAYLOAD_INVALID", f"{label} must be a JSON object")
    raw = _canonical(dict(value))
    if len(raw) > max_bytes:
        raise _fail("DISTRIBUTED_PAYLOAD_TOO_LARGE", f"{label} exceeds the safety limit", bytes=len(raw), limit=max_bytes)
    return raw.decode("utf-8"), hashlib.sha256(raw).hexdigest()

def _load_json(text: str, max_bytes: int, label: str) -> dict[str, Any]:
    raw = str(text).encode("utf-8")
    if len(raw) > max_bytes:
        raise _fail("DISTRIBUTED_STATE_CORRUPT", f"{label} exceeds the safety limit")
    def no_duplicates(pairs):
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise _fail("DISTRIBUTED_STATE_CORRUPT", f"{label} cannot be decoded") from exc
    if not isinstance(value, dict):
        raise _fail("DISTRIBUTED_STATE_CORRUPT", f"{label} must be an object")
    return value

def _clean_token(value: str, label: str, max_len: int = 160) -> str:
    text = str(value).strip()
    if (
        not text
        or len(text) > max_len
        or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in text)
    ):
        raise _fail("DISTRIBUTED_IDENTIFIER_INVALID", f"{label} is invalid")
    return text

def _b64u_decode(value: str, *, expected: int | None = None, max_bytes: int = 512) -> bytes:
    text = str(value).strip()
    if not text or "=" in text or len(text) > max_bytes * 2:
        raise _fail("DISTRIBUTED_KEY_INVALID", "base64url value is invalid")
    try:
        data = base64.urlsafe_b64decode(text + "=" * ((4 - len(text) % 4) % 4))
    except (binascii.Error, ValueError) as exc:
        raise _fail("DISTRIBUTED_KEY_INVALID", "base64url value cannot be decoded") from exc
    if len(data) > max_bytes:
        raise _fail("DISTRIBUTED_KEY_INVALID", "decoded value exceeds safety limit")
    canonical = base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    if not hmac.compare_digest(canonical, text):
        raise _fail("DISTRIBUTED_KEY_INVALID", "base64url value is not canonical")
    if expected is not None and len(data) != expected:
        raise _fail("DISTRIBUTED_KEY_INVALID", "decoded value has an unexpected length")
    return data

def negotiate_protocol(peer_min: int, peer_max: int) -> int:
    low = max(MIN_COMPATIBLE_PROTOCOL, int(peer_min))
    high = min(CURRENT_PROTOCOL, int(peer_max))
    if low > high:
        raise _fail(
            "PROTOCOL_INCOMPATIBLE",
            "No compatible Arenyxa Enterprise protocol version is available",
            server_min=MIN_COMPATIBLE_PROTOCOL,
            server_max=CURRENT_PROTOCOL,
            peer_min=int(peer_min),
            peer_max=int(peer_max),
        )
    return high

def verify_enterprise_server_identity(artifact: Mapping[str, Any], expected_root_fingerprint: str, peer_cert_der: bytes) -> dict[str, Any]:
    
    required = {
        "schema", "enterprise_id", "server_id", "tls_certificate_sha256", "protocol_min",
        "protocol_max", "issued_at", "expires_at", "root_public_key", "root_fingerprint", "signature",
    }
    if set(artifact) != required or artifact.get("schema") != "arenyxa.enterprise-server-identity/v1":
        raise _fail("SERVER_IDENTITY_INVALID", "Enterprise Server identity schema is invalid")
    expected_fp = str(expected_root_fingerprint).strip().casefold()
    actual_fp = str(artifact.get("root_fingerprint", "")).strip().casefold()
    if len(expected_fp) != 64 or not hmac.compare_digest(expected_fp, actual_fp):
        raise _fail("SERVER_IDENTITY_UNTRUSTED", "Enterprise Server Root fingerprint does not match the expected Enterprise")
    public_raw = _b64u_decode(str(artifact.get("root_public_key", "")), expected=32)
    if not hmac.compare_digest(hashlib.sha256(public_raw).hexdigest(), actual_fp):
        raise _fail("SERVER_IDENTITY_UNTRUSTED", "Enterprise Server Root fingerprint/public key binding is invalid")
    cert_hash = hashlib.sha256(bytes(peer_cert_der)).hexdigest()
    if not hmac.compare_digest(cert_hash, str(artifact.get("tls_certificate_sha256", "")).casefold()):
        raise _fail("SERVER_TLS_BINDING_INVALID", "Enterprise Server identity is not bound to this TLS certificate")
    try:
        issued = datetime.fromisoformat(str(artifact.get("issued_at", "")).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(str(artifact.get("expires_at", "")).replace("Z", "+00:00"))
    except (TypeError, ValueError, OverflowError) as exc:
        raise _fail("SERVER_IDENTITY_TIME_INVALID", "Enterprise Server identity time fields are invalid") from exc
    if issued.tzinfo is None or expires.tzinfo is None:
        raise _fail("SERVER_IDENTITY_TIME_INVALID", "Enterprise Server identity time fields require a timezone")
    issued = issued.astimezone(timezone.utc)
    expires = expires.astimezone(timezone.utc)
    now = datetime.now(timezone.utc)
    if issued > now + timedelta(minutes=5) or expires <= issued or (expires - issued) > timedelta(days=8):
        raise _fail("SERVER_IDENTITY_TIME_INVALID", "Enterprise Server identity validity window is invalid")
    if expires <= now:
        raise _fail("SERVER_IDENTITY_EXPIRED", "Enterprise Server identity has expired")
    negotiate_protocol(int(artifact.get("protocol_min", 0)), int(artifact.get("protocol_max", 0)))
    signed = {key: value for key, value in artifact.items() if key not in {"signature", "root_public_key", "root_fingerprint"}}
    signature = _b64u_decode(str(artifact.get("signature", "")), expected=64)
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, _canonical(signed))
    except InvalidSignature as exc:
        raise _fail("SERVER_IDENTITY_SIGNATURE_INVALID", "Enterprise Server identity signature is invalid") from exc
    return dict(artifact)

@dataclass(frozen=True, slots=True)
class DistributedLease:
    job_id: str
    worker_id: str
    lease_token: str
    lease_expires_at: float
    kind: str
    payload: dict[str, Any]
    resource_id: str
    permission: str
    attempt: int
    max_attempts: int
    side_effect_mode: str
    checkpoint: dict[str, Any]
    checkpoint_seq: int
    protocol_version: int
    traceparent: str = ""
    tracestate: str = ""

class _NoopLock:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

