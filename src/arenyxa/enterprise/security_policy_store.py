from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from arenyxa.domain.errors import ArenyxaError
from arenyxa.security.zero_trust import ZeroTrustPolicy

_POLICY_KEY = "zero_trust_network_policy_v1"
_POLICY_SCHEMA = "arenyxa.enterprise-zero-trust-policy/v1"
_MAX_POLICY_BYTES = 64 * 1024


def _fail(code: str, message: str, **context: Any) -> ArenyxaError:
    return ArenyxaError(code, message, domain="ENTERPRISE_ZERO_TRUST", context=context)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _b64u_decode(value: str, expected: int) -> bytes:
    text = str(value).strip()
    if not text or "=" in text:
        raise _fail("ZERO_TRUST_POLICY_SIGNATURE_INVALID", "Zero Trust policy signature encoding is invalid")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * ((4 - len(text) % 4) % 4))
    except (ValueError, TypeError) as exc:
        raise _fail("ZERO_TRUST_POLICY_SIGNATURE_INVALID", "Zero Trust policy signature cannot be decoded") from exc
    if len(raw) != expected:
        raise _fail("ZERO_TRUST_POLICY_SIGNATURE_INVALID", "Zero Trust policy signature has an unexpected size")
    return raw


def _read_raw(queue: Any) -> str:
    with queue._connection() as connection:  # internal package-level durable metadata boundary
        row = connection.execute("SELECT value FROM distributed_meta WHERE key=?", (_POLICY_KEY,)).fetchone()
    return "" if row is None else str(row[0])


def _write_raw(queue: Any, raw: str) -> None:
    if len(raw.encode("utf-8")) > _MAX_POLICY_BYTES:
        raise _fail("ZERO_TRUST_POLICY_TOO_LARGE", "Zero Trust policy artifact exceeds its safety bound")
    with queue._lock, queue._connection() as connection:
        queue._begin(connection)
        if queue.storage_capabilities.get("backend") == "postgresql":
            connection.execute(
                "INSERT INTO distributed_meta(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                (_POLICY_KEY, raw),
            )
        else:
            connection.execute("INSERT OR REPLACE INTO distributed_meta(key,value) VALUES(?,?)", (_POLICY_KEY, raw))
        connection.commit()


def persist_signed_zero_trust_policy(queue: Any, identity: Any, policy: ZeroTrustPolicy) -> dict[str, Any]:
    payload = {
        "schema": _POLICY_SCHEMA,
        "revision": time.time_ns(),
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "policy": policy.as_dict(),
    }
    proof = identity.sign_enterprise_artifact(
        _canonical(payload), capability="enterprise.policy.modify", resource="enterprise:network", step_up=False
    )
    artifact = {**payload, **proof}
    raw = _canonical(artifact).decode("utf-8")
    _write_raw(queue, raw)
    return artifact


def load_signed_zero_trust_policy(queue: Any, identity: Any) -> tuple[ZeroTrustPolicy, int] | None:
    raw = _read_raw(queue)
    if not raw:
        return None
    if len(raw.encode("utf-8")) > _MAX_POLICY_BYTES:
        raise _fail("ZERO_TRUST_POLICY_INTEGRITY", "Stored Zero Trust policy exceeds its safety bound")
    try:
        artifact = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise _fail("ZERO_TRUST_POLICY_INTEGRITY", "Stored Zero Trust policy is not valid JSON") from exc
    required = {
        "schema", "revision", "issued_at", "policy", "enterprise_id",
        "root_public_key", "root_fingerprint", "signature",
    }
    if not isinstance(artifact, dict) or set(artifact) != required or artifact.get("schema") != _POLICY_SCHEMA:
        raise _fail("ZERO_TRUST_POLICY_INTEGRITY", "Stored Zero Trust policy artifact schema is invalid")
    if not isinstance(artifact.get("policy"), Mapping):
        raise _fail("ZERO_TRUST_POLICY_INTEGRITY", "Stored Zero Trust policy payload is invalid")
    root = identity.root_public_identity()
    expected_fp = str(root.get("fingerprint", "")).casefold()
    expected_public = str(root.get("public_key", ""))
    if not hmac.compare_digest(str(artifact.get("root_fingerprint", "")).casefold(), expected_fp):
        raise _fail("ZERO_TRUST_POLICY_INTEGRITY", "Stored Zero Trust policy is signed by another Enterprise Root")
    if not hmac.compare_digest(str(artifact.get("root_public_key", "")), expected_public):
        raise _fail("ZERO_TRUST_POLICY_INTEGRITY", "Stored Zero Trust policy public-key binding is invalid")
    public_raw = _b64u_decode(expected_public, 32)
    if not hmac.compare_digest(hashlib.sha256(public_raw).hexdigest(), expected_fp):
        raise _fail("ZERO_TRUST_POLICY_INTEGRITY", "Enterprise Root public key fingerprint is invalid")
    signed = {
        "schema": artifact["schema"],
        "revision": artifact["revision"],
        "issued_at": artifact["issued_at"],
        "policy": artifact["policy"],
    }
    signature = _b64u_decode(str(artifact.get("signature", "")), 64)
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, _canonical(signed))
    except InvalidSignature as exc:
        raise _fail("ZERO_TRUST_POLICY_INTEGRITY", "Stored Zero Trust policy signature is invalid") from exc
    try:
        revision = int(artifact["revision"])
    except (TypeError, ValueError, OverflowError) as exc:
        raise _fail("ZERO_TRUST_POLICY_INTEGRITY", "Stored Zero Trust policy revision is invalid") from exc
    return ZeroTrustPolicy.from_mapping(dict(artifact["policy"])), revision
