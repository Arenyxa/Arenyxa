from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature

from arenyxa.compat import UTC, dataclass
from arenyxa.domain.errors import ArenyxaError
from arenyxa.security.developer_credentials import (
    HARDWARE_ROOT_SCHEMA,
    HARDWARE_ROOT_SCHEMA_V3,
    HARDWARE_ROOT_SCHEMA_V4,
    ROOT_SCHEMA,
    TRUST_STORE_SCHEMA,
    DeveloperTrustStore,
    artifact_sha256,
    b64u_decode,
    canonical_json,
    validate_root_trust,
)
from arenyxa.security.hardware_identity import WindowsTPMEcdsaP256Provider
from arenyxa.security.developer_crypto import (
    ECDSA_P256_SHA256,
    ED25519,
    normalize_signature_algorithm,
    validate_public_key_raw,
    verify_signature_raw,
)

ROOT_ROTATION_SCHEMA = "arenyxa.developer-root-rotation/v1"
ROOT_RECOVERY_BINDING_SCHEMA = "arenyxa.developer-root-recovery-binding/v1"
ROOT_RECOVERY_ACTIVATION_SCHEMA = "arenyxa.developer-root-recovery-activation/v1"
ROOT_HEALTH_PROOF_SCHEMA = "arenyxa.developer-root-health-proof/v1"
ROOT_TRANSITION_BUNDLE_SCHEMA = "arenyxa.developer-root-transition-bundle/v1"
ROOT_AUTHORITY_CHECKPOINT_SCHEMA = "arenyxa.developer-root-authority-checkpoint/v1"


@dataclass(frozen=True, slots=True)
class RootIntegrityStatus:
    """Read-only integrity projection for a trusted Developer Root artifact.

    Startup probes are deliberately passive for Hardware Roots: they inspect the
    TPM key and policy without signing, so normal application launch never
    triggers a high-protection CNG consent prompt. ``authority_ready`` becomes
    true for a Hardware Root only after an explicit proof-of-possession probe.
    """

    root_key_id: str = ""
    root_schema: str = ""
    generation: int = 0
    artifact_sha256: str = ""
    artifact_valid: bool = False
    hardware_required: bool = False
    provider: str = ""
    key_name: str = ""
    provider_available: bool = False
    hardware_backed: bool = False
    key_present: bool = False
    policy_valid: bool = False
    public_key_match: bool = False
    key_binding_match: bool = False
    proof_of_possession: bool = False
    integrity_valid: bool = False
    authority_ready: bool = False
    reason: str = ""


def _root_integrity_failure(
    root: Mapping[str, Any],
    *,
    reason: str,
    artifact_valid: bool = False,
    **values: Any,
) -> RootIntegrityStatus:
    return RootIntegrityStatus(
        root_key_id=str(root.get("key_id") or ""),
        root_schema=str(root.get("schema") or ""),
        generation=int(values.pop("generation", 0) or 0),
        artifact_sha256=str(values.pop("artifact_sha256", "") or ""),
        artifact_valid=artifact_valid,
        hardware_required=bool(values.pop("hardware_required", False)),
        provider=str(values.pop("provider", root.get("provider") or "") or ""),
        key_name=str(values.pop("key_name", root.get("key_name") or "") or ""),
        provider_available=bool(values.pop("provider_available", False)),
        hardware_backed=bool(values.pop("hardware_backed", False)),
        key_present=bool(values.pop("key_present", False)),
        policy_valid=bool(values.pop("policy_valid", False)),
        public_key_match=bool(values.pop("public_key_match", False)),
        key_binding_match=bool(values.pop("key_binding_match", False)),
        proof_of_possession=bool(values.pop("proof_of_possession", False)),
        integrity_valid=False,
        authority_ready=False,
        reason=str(reason),
    )


def probe_root_integrity(
    root: Mapping[str, Any],
    *,
    active_proof: bool = False,
    provider: Any | None = None,
) -> RootIntegrityStatus:
    """Validate Root artifact integrity and, when applicable, its local TPM key.

    The function never creates, rotates, repairs, imports, or deletes a key.
    For v1 software Roots, cryptographic artifact validation is sufficient. For
    v2-v4 Hardware Roots, startup uses passive metadata inspection; an explicit
    ``active_proof`` additionally proves possession of the non-exportable TPM
    private key before Root authority may be minted.
    """
    raw = dict(root)
    try:
        validated = validate_root_trust(raw)
        generation = root_generation(validated)
        digest = artifact_sha256(validated)
    except (ArenyxaError, ValueError, TypeError, KeyError) as exc:
        return _root_integrity_failure(
            raw, reason=getattr(exc, "code", "DEVELOPER_ROOT_INVALID")
        )

    schema = str(validated["schema"])
    hardware_required = schema in {HARDWARE_ROOT_SCHEMA, HARDWARE_ROOT_SCHEMA_V3, HARDWARE_ROOT_SCHEMA_V4}
    if not hardware_required:
        return RootIntegrityStatus(
            root_key_id=str(validated["key_id"]),
            root_schema=schema,
            generation=generation,
            artifact_sha256=digest,
            artifact_valid=True,
            hardware_required=False,
            public_key_match=True,
            key_binding_match=True,
            integrity_valid=True,
            authority_ready=True,
            reason="ROOT_ARTIFACT_VALID",
        )

    key_name = str(validated.get("key_name") or "")
    provider_name = str(validated.get("provider") or "")
    active_provider = provider if provider is not None else WindowsTPMEcdsaP256Provider()
    try:
        provider_status = active_provider.status()
    except (ArenyxaError, OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
        return _root_integrity_failure(
            validated,
            reason=getattr(exc, "code", "ROOT_HARDWARE_PROVIDER_UNAVAILABLE"),
            artifact_valid=True,
            generation=generation,
            artifact_sha256=digest,
            hardware_required=True,
            provider=provider_name,
            key_name=key_name,
        )

    provider_available = bool(getattr(provider_status, "available", False))
    provider_hardware = bool(getattr(provider_status, "hardware_backed", False))
    if not provider_available or not provider_hardware:
        return _root_integrity_failure(
            validated,
            reason=str(getattr(provider_status, "reason", "") or "ROOT_HARDWARE_PROVIDER_UNAVAILABLE"),
            artifact_valid=True,
            generation=generation,
            artifact_sha256=digest,
            hardware_required=True,
            provider=provider_name,
            key_name=key_name,
            provider_available=provider_available,
            hardware_backed=provider_hardware,
        )

    try:
        metadata = dict(active_provider.inspect_key(key_name, machine_scope=True))
        public = bytes(metadata.get("public_key_uncompressed") or b"")
        expected_public = b64u_decode(str(validated["public_key"]), max_bytes=96)
        public_match = bool(public) and hashlib.sha256(public).digest() == hashlib.sha256(expected_public).digest()
        policy_valid = (
            metadata.get("provider") == provider_name
            and bool(metadata.get("provider_available"))
            and bool(metadata.get("hardware_backed"))
            and bool(metadata.get("machine_scope"))
            and not bool(metadata.get("private_exportable"))
            and bool(metadata.get("signing_only"))
            and bool(metadata.get("high_protection"))
        )
        unique_name = str(metadata.get("unique_name") or "").strip()
        actual_binding = hashlib.sha256(unique_name.encode("utf-8")).hexdigest() if unique_name else ""
        expected_binding = str(validated.get("key_binding_sha256") or "")
        binding_match = True if schema == HARDWARE_ROOT_SCHEMA else bool(actual_binding and actual_binding == expected_binding)
    except (ArenyxaError, OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
        return _root_integrity_failure(
            validated,
            reason=getattr(exc, "code", "ROOT_HARDWARE_KEY_NOT_FOUND"),
            artifact_valid=True,
            generation=generation,
            artifact_sha256=digest,
            hardware_required=True,
            provider=provider_name,
            key_name=key_name,
            provider_available=True,
            hardware_backed=True,
        )

    passive_valid = bool(policy_valid and public_match and binding_match)
    if not passive_valid:
        reason = (
            "ROOT_HARDWARE_POLICY_INVALID" if not policy_valid
            else "ROOT_HARDWARE_PUBLIC_KEY_MISMATCH" if not public_match
            else "ROOT_HARDWARE_BINDING_MISMATCH"
        )
        return _root_integrity_failure(
            validated,
            reason=reason,
            artifact_valid=True,
            generation=generation,
            artifact_sha256=digest,
            hardware_required=True,
            provider=provider_name,
            key_name=key_name,
            provider_available=True,
            hardware_backed=True,
            key_present=True,
            policy_valid=policy_valid,
            public_key_match=public_match,
            key_binding_match=binding_match,
        )

    proof = False
    if active_proof:
        try:
            health = active_provider.probe_key(key_name, machine_scope=True)
            proof = bool(
                getattr(health, "healthy", False)
                and getattr(health, "proof_of_possession", False)
                and str(getattr(health, "public_key_sha256", "")) == hashlib.sha256(expected_public).hexdigest()
                and (
                    schema == HARDWARE_ROOT_SCHEMA
                    or str(getattr(health, "key_binding_sha256", "")) == str(validated.get("key_binding_sha256") or "")
                )
            )
        except (ArenyxaError, OSError, RuntimeError, ValueError, TypeError, KeyError):
            proof = False

    return RootIntegrityStatus(
        root_key_id=str(validated["key_id"]),
        root_schema=schema,
        generation=generation,
        artifact_sha256=digest,
        artifact_valid=True,
        hardware_required=True,
        provider=provider_name,
        key_name=key_name,
        provider_available=True,
        hardware_backed=True,
        key_present=True,
        policy_valid=True,
        public_key_match=True,
        key_binding_match=True,
        proof_of_possession=proof,
        integrity_valid=True,
        authority_ready=bool(proof),
        reason=(
            "ROOT_HARDWARE_PROOF_VALID" if proof
            else "ROOT_HARDWARE_PROOF_FAILED" if active_proof
            else "ROOT_HARDWARE_PROOF_REQUIRED"
        ),
    )


def _error(code: str, message: str, **context: Any) -> ArenyxaError:
    return ArenyxaError(code, message, domain="DEVELOPER_ACCESS", context=context)


def _parse_utc(value: object) -> datetime:
    text = str(value or "").strip()
    if not text or len(text) > 64:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Lifecycle timestamp is missing or too large")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Lifecycle timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Lifecycle timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _exact_fields(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise _error(
            "DEVELOPER_ROOT_LIFECYCLE_INVALID",
            f"{label} contains unexpected or missing fields",
            missing=sorted(expected - actual),
            unexpected=sorted(actual - expected),
        )


def root_generation(root: Mapping[str, Any]) -> int:
    validated = validate_root_trust(root)
    schema = str(validated["schema"])
    if schema in {HARDWARE_ROOT_SCHEMA_V3, HARDWARE_ROOT_SCHEMA_V4}:
        return int(validated["generation"])
    if schema == HARDWARE_ROOT_SCHEMA:
        return 1
    if schema == ROOT_SCHEMA:
        return 0
    raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Unsupported Developer Root schema")


def _root_public(root: Mapping[str, Any]) -> tuple[str, bytes]:
    validated = validate_root_trust(root)
    algorithm = normalize_signature_algorithm(str(validated.get("algorithm") or ED25519))
    public = b64u_decode(str(validated["public_key"]), max_bytes=96)
    return algorithm, validate_public_key_raw(algorithm, public)


def _verify_signature_block(
    block: object,
    payload: Mapping[str, Any],
    root: Mapping[str, Any],
    *,
    label: str,
) -> None:
    if not isinstance(block, Mapping):
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", f"{label} signature block is missing")
    signature = dict(block)
    _exact_fields(signature, {"algorithm", "signer_key_id", "value"}, f"{label} signature")
    validated_root = validate_root_trust(root)
    algorithm, public = _root_public(validated_root)
    try:
        block_algorithm = normalize_signature_algorithm(str(signature["algorithm"]))
    except ValueError as exc:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", f"{label} signature algorithm is invalid") from exc
    if block_algorithm != algorithm or signature["signer_key_id"] != validated_root["key_id"]:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", f"{label} signature signer does not match its Root")
    raw_signature = b64u_decode(str(signature["value"]), max_bytes=128)
    try:
        verify_signature_raw(algorithm, public, raw_signature, canonical_json(payload))
    except InvalidSignature as exc:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", f"{label} signature verification failed") from exc


def _rotation_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key not in {"old_signature", "new_signature"}}


def validate_root_rotation(
    artifact: Mapping[str, Any],
    old_root: Mapping[str, Any],
    new_root: Mapping[str, Any],
) -> dict[str, Any]:
    item = dict(artifact)
    _exact_fields(
        item,
        {
            "schema", "old_root_key_id", "new_root_key_id", "old_root_sha256", "new_root_sha256",
            "old_generation", "new_generation", "reason", "created_at", "old_signature", "new_signature",
        },
        "Developer Root rotation",
    )
    if item["schema"] != ROOT_ROTATION_SCHEMA:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root rotation schema is invalid")
    old_valid = validate_root_trust(old_root)
    new_valid = validate_root_trust(new_root)
    if str(new_valid["schema"]) == HARDWARE_ROOT_SCHEMA_V4 and str(new_valid["purpose"]) != "primary":
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Scheduled Root rotation must target a primary Hardware Root")
    if item["old_root_key_id"] != old_valid["key_id"] or item["new_root_key_id"] != new_valid["key_id"]:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root rotation key binding is invalid")
    if item["old_root_sha256"] != artifact_sha256(old_valid) or item["new_root_sha256"] != artifact_sha256(new_valid):
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root rotation artifact digest is invalid")
    old_generation = root_generation(old_valid)
    new_generation = root_generation(new_valid)
    if item["old_generation"] != old_generation or item["new_generation"] != new_generation:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root rotation generation binding is invalid")
    expected_generation = 1 if old_generation == 0 else old_generation + 1
    if new_generation != expected_generation:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root generation must advance exactly once")
    reason = str(item["reason"]).strip()
    if not 4 <= len(reason) <= 512:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root rotation reason is invalid")
    created = _parse_utc(item["created_at"])
    if created < _parse_utc(old_valid["created_at"]) or created < _parse_utc(new_valid["created_at"]):
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root rotation predates one of its Root artifacts")
    payload = _rotation_payload(item)
    _verify_signature_block(item["old_signature"], payload, old_valid, label="old Root")
    _verify_signature_block(item["new_signature"], payload, new_valid, label="new Root")
    return item


def _binding_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key not in {"primary_signature", "recovery_signature"}}


def validate_root_recovery_binding(
    artifact: Mapping[str, Any],
    primary_root: Mapping[str, Any],
    recovery_root: Mapping[str, Any],
) -> dict[str, Any]:
    item = dict(artifact)
    _exact_fields(
        item,
        {
            "schema", "primary_root_key_id", "recovery_root_key_id", "primary_root_sha256", "recovery_root_sha256",
            "created_at", "expires_at", "policy", "primary_signature", "recovery_signature",
        },
        "Developer Root recovery binding",
    )
    if item["schema"] != ROOT_RECOVERY_BINDING_SCHEMA:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root recovery binding schema is invalid")
    primary = validate_root_trust(primary_root)
    recovery = validate_root_trust(recovery_root)
    if str(recovery["schema"]) not in {HARDWARE_ROOT_SCHEMA, HARDWARE_ROOT_SCHEMA_V3, HARDWARE_ROOT_SCHEMA_V4}:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Recovery Root must be hardware-backed")
    if str(recovery["schema"]) == HARDWARE_ROOT_SCHEMA_V4 and str(recovery["purpose"]) != "recovery":
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Recovery binding must target a dedicated recovery Hardware Root")
    if primary["key_id"] == recovery["key_id"]:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Primary and recovery Root must be different keys")
    expected_recovery_generation = 1 if root_generation(primary) == 0 else root_generation(primary) + 1
    if root_generation(recovery) != expected_recovery_generation:
        raise _error(
            "DEVELOPER_ROOT_LIFECYCLE_INVALID",
            "Recovery Root generation must immediately follow the active primary Root generation",
        )
    if item["primary_root_key_id"] != primary["key_id"] or item["recovery_root_key_id"] != recovery["key_id"]:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root recovery key binding is invalid")
    if item["primary_root_sha256"] != artifact_sha256(primary) or item["recovery_root_sha256"] != artifact_sha256(recovery):
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root recovery digest binding is invalid")
    created = _parse_utc(item["created_at"])
    expires = _parse_utc(item["expires_at"])
    if expires <= created or expires - created > timedelta(days=3660):
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root recovery binding expiry is invalid")
    if created < _parse_utc(primary["created_at"]) or created < _parse_utc(recovery["created_at"]):
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root recovery binding predates one of its Root artifacts")
    expected_policy = {
        "mode": "dual-hardware-root",
        "activation": "offline-explicit-ceremony",
        "private_key_backup": False,
    }
    if item["policy"] != expected_policy:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root recovery policy is invalid")
    payload = _binding_payload(item)
    _verify_signature_block(item["primary_signature"], payload, primary, label="primary Root")
    _verify_signature_block(item["recovery_signature"], payload, recovery, label="recovery Root")
    return item


def _activation_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "signature"}


def validate_root_recovery_activation(
    artifact: Mapping[str, Any],
    binding: Mapping[str, Any],
    primary_root: Mapping[str, Any],
    recovery_root: Mapping[str, Any],
) -> dict[str, Any]:
    valid_binding = validate_root_recovery_binding(binding, primary_root, recovery_root)
    item = dict(artifact)
    _exact_fields(
        item,
        {
            "schema", "binding_sha256", "failed_root_key_id", "recovery_root_key_id", "incident_id",
            "activated_at", "nonce", "signature",
        },
        "Developer Root recovery activation",
    )
    if item["schema"] != ROOT_RECOVERY_ACTIVATION_SCHEMA:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root recovery activation schema is invalid")
    primary = validate_root_trust(primary_root)
    recovery = validate_root_trust(recovery_root)
    if item["binding_sha256"] != artifact_sha256(valid_binding):
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Recovery activation does not reference the expected binding")
    if item["failed_root_key_id"] != primary["key_id"] or item["recovery_root_key_id"] != recovery["key_id"]:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Recovery activation Root binding is invalid")
    incident_id = str(item["incident_id"]).strip()
    if not 8 <= len(incident_id) <= 128:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Recovery activation incident id is invalid")
    activated = _parse_utc(item["activated_at"])
    binding_start = _parse_utc(valid_binding["created_at"])
    binding_end = _parse_utc(valid_binding["expires_at"])
    if activated < binding_start or activated >= binding_end:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Recovery activation falls outside its binding validity window")
    nonce = b64u_decode(str(item["nonce"]), max_bytes=64)
    if len(nonce) < 16:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Recovery activation nonce is too short")
    _verify_signature_block(item["signature"], _activation_payload(item), recovery, label="recovery activation")
    return item


def validate_root_health_proof(
    artifact: Mapping[str, Any],
    root: Mapping[str, Any],
    *,
    expected_challenge: bytes | None = None,
    at: datetime | None = None,
    max_age_seconds: int | None = None,
) -> dict[str, Any]:
    item = dict(artifact)
    _exact_fields(
        item,
        {
            "schema", "root_key_id", "generation", "challenge_sha256", "public_key_sha256", "policy_sha256",
            "created_at", "signature",
        },
        "Developer Root health proof",
    )
    if item["schema"] != ROOT_HEALTH_PROOF_SCHEMA:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root health proof schema is invalid")
    validated = validate_root_trust(root)
    if item["root_key_id"] != validated["key_id"] or item["generation"] != root_generation(validated):
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root health proof binding is invalid")
    for key in ("challenge_sha256", "public_key_sha256", "policy_sha256"):
        digest = str(item[key])
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", f"{key} is not a canonical SHA-256 digest")
    created = _parse_utc(item["created_at"])
    if created < _parse_utc(validated["created_at"]):
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root health proof predates its Root artifact")
    if expected_challenge is not None:
        challenge = bytes(expected_challenge)
        if not 16 <= len(challenge) <= 1024:
            raise ValueError("expected Hardware Root health challenge must contain 16-1024 bytes")
        if item["challenge_sha256"] != hashlib.sha256(challenge).hexdigest():
            raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root health proof challenge does not match")
    if max_age_seconds is not None:
        max_age = int(max_age_seconds)
        if not 1 <= max_age <= 86_400:
            raise ValueError("Hardware Root health proof max age must be between 1 and 86400 seconds")
        current = datetime.now(UTC) if at is None else at
        current = current.replace(tzinfo=UTC) if current.tzinfo is None else current.astimezone(UTC)
        if created > current + timedelta(minutes=5):
            raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root health proof is from the future")
        if current - created > timedelta(seconds=max_age):
            raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root health proof is stale")
    _verify_signature_block(item["signature"], _activation_payload(item), validated, label="Root health proof")
    return item


def validate_root_health_proof_for_challenge(
    artifact: Mapping[str, Any],
    root: Mapping[str, Any],
    challenge: bytes,
    *,
    at: datetime | None = None,
    max_age_seconds: int = 300,
) -> dict[str, Any]:
    """Validate a Root health proof against the verifier's challenge and freshness window."""
    raw_challenge = bytes(challenge)
    if not 16 <= len(raw_challenge) <= 1024:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Root health challenge length is invalid")
    max_age = int(max_age_seconds)
    if not 1 <= max_age <= 3600:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Root health proof max age must be 1-3600 seconds")
    valid = validate_root_health_proof(artifact, root)
    expected = hashlib.sha256(raw_challenge).hexdigest()
    if valid["challenge_sha256"] != expected:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Root health proof challenge does not match")
    now = datetime.now(UTC) if at is None else at
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    now = now.astimezone(UTC)
    created = _parse_utc(valid["created_at"])
    if created > now + timedelta(seconds=30):
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Root health proof timestamp is in the future")
    if now - created > timedelta(seconds=max_age):
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Root health proof is stale")
    return valid


def validate_root_authority_checkpoint(
    artifact: Mapping[str, Any],
    root: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a hardware-Root signed snapshot of private Authority state/audit heads."""
    item = dict(artifact)
    _exact_fields(
        item,
        {
            "schema", "root_key_id", "root_sha256", "generation", "state_sha256",
            "audit_records", "audit_head_sha256", "created_at", "signature",
        },
        "Developer Root authority checkpoint",
    )
    if item["schema"] != ROOT_AUTHORITY_CHECKPOINT_SCHEMA:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root authority checkpoint schema is invalid")
    validated = validate_root_trust(root)
    if str(validated["schema"]) not in {
        HARDWARE_ROOT_SCHEMA,
        HARDWARE_ROOT_SCHEMA_V3,
        HARDWARE_ROOT_SCHEMA_V4,
    }:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Authority checkpoint must be signed by a Hardware Root")
    if item["root_key_id"] != validated["key_id"] or item["root_sha256"] != artifact_sha256(validated):
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Authority checkpoint Root binding is invalid")
    if item["generation"] != root_generation(validated):
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Authority checkpoint generation is invalid")
    for field in ("state_sha256", "audit_head_sha256"):
        digest = str(item[field])
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", f"Authority checkpoint {field} is invalid")
    records = item["audit_records"]
    if not isinstance(records, int) or isinstance(records, bool) or not 0 <= records <= 10_000_000:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Authority checkpoint audit record count is invalid")
    created = _parse_utc(item["created_at"])
    if created < _parse_utc(validated["created_at"]):
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Authority checkpoint predates its Hardware Root")
    payload = {key: value for key, value in item.items() if key != "signature"}
    _verify_signature_block(item["signature"], payload, validated, label="authority checkpoint")
    return item


def validate_root_transition_bundle(artifact: Mapping[str, Any]) -> dict[str, Any]:
    item = dict(artifact)
    _exact_fields(
        item,
        {"schema", "mode", "created_at", "old_root", "new_root", "rotation"},
        "Developer Root transition bundle",
    )
    if item["schema"] != ROOT_TRANSITION_BUNDLE_SCHEMA or item["mode"] != "overlap-then-retire-old":
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root transition bundle policy is invalid")
    if not isinstance(item["old_root"], Mapping) or not isinstance(item["new_root"], Mapping) or not isinstance(item["rotation"], Mapping):
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root transition bundle members are invalid")
    old_root = validate_root_trust(item["old_root"])
    new_root = validate_root_trust(item["new_root"])
    rotation = validate_root_rotation(item["rotation"], old_root, new_root)
    created = _parse_utc(item["created_at"])
    rotation_at = _parse_utc(rotation["created_at"])
    if created < rotation_at:
        raise _error("DEVELOPER_ROOT_LIFECYCLE_INVALID", "Developer Root transition bundle predates its rotation")
    return {
        "schema": ROOT_TRANSITION_BUNDLE_SCHEMA,
        "mode": "overlap-then-retire-old",
        "created_at": item["created_at"],
        "old_root": old_root,
        "new_root": new_root,
        "rotation": rotation,
    }


def build_overlap_trust_store(
    transition: Mapping[str, Any],
    current_roots: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build a public trust-store artifact that overlaps old and new Roots during migration."""
    valid = validate_root_transition_bundle(transition)
    existing = DeveloperTrustStore(current_roots).roots()
    old_sha = artifact_sha256(valid["old_root"])
    if not any(artifact_sha256(root) == old_sha for root in existing):
        raise _error(
            "DEVELOPER_ROOT_TRANSITION_INVALID",
            "Current trust store does not contain the transition's old Root",
        )
    by_key = {str(root["key_id"]): root for root in existing}
    for root in (valid["old_root"], valid["new_root"]):
        key_id = str(root["key_id"])
        previous = by_key.get(key_id)
        if previous is not None and artifact_sha256(previous) != artifact_sha256(root):
            raise _error("DEVELOPER_ROOT_TRANSITION_INVALID", "Root key id conflicts with current trust store")
        by_key[key_id] = root
    store = DeveloperTrustStore(by_key.values())
    return {"schema": TRUST_STORE_SCHEMA, "roots": list(store.roots())}


def build_retired_trust_store(
    transition: Mapping[str, Any],
    overlap_roots: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Retire the old public Root only after an overlap trust store contains the verified new Root."""
    valid = validate_root_transition_bundle(transition)
    existing = DeveloperTrustStore(overlap_roots).roots()
    old_sha = artifact_sha256(valid["old_root"])
    new_sha = artifact_sha256(valid["new_root"])
    if not any(artifact_sha256(root) == old_sha for root in existing):
        raise _error("DEVELOPER_ROOT_TRANSITION_INVALID", "Overlap trust store no longer contains the old Root")
    if not any(artifact_sha256(root) == new_sha for root in existing):
        raise _error("DEVELOPER_ROOT_TRANSITION_INVALID", "Overlap trust store does not contain the new Root")
    retained = [root for root in existing if artifact_sha256(root) != old_sha]
    if not retained:
        raise _error("DEVELOPER_ROOT_TRANSITION_INVALID", "Root retirement would leave an empty trust store")
    store = DeveloperTrustStore(retained)
    return {"schema": TRUST_STORE_SCHEMA, "roots": list(store.roots())}
