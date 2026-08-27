from __future__ import annotations

import hashlib
from datetime import datetime, timedelta

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from arenyxa.compat import UTC
from arenyxa.domain.errors import ArenyxaError
from arenyxa.security.developer_credentials import (
    HARDWARE_ROOT_PROTECTION_SCHEMA_V2,
    HARDWARE_ROOT_SCHEMA_V3,
    HARDWARE_ROOT_SCHEMA_V4,
    artifact_sha256,
    b64u_encode,
    canonical_json,
    key_fingerprint,
    validate_root_trust,
)
from arenyxa.security.developer_crypto import ECDSA_P256_SHA256
from arenyxa.security.hardware_identity import WindowsTPMEcdsaP256Provider
from arenyxa.security.hardware_root_lifecycle import (
    ROOT_AUTHORITY_CHECKPOINT_SCHEMA,
    ROOT_HEALTH_PROOF_SCHEMA,
    ROOT_RECOVERY_ACTIVATION_SCHEMA,
    ROOT_RECOVERY_BINDING_SCHEMA,
    ROOT_ROTATION_SCHEMA,
    ROOT_TRANSITION_BUNDLE_SCHEMA,
    build_overlap_trust_store,
    build_retired_trust_store,
    validate_root_authority_checkpoint,
    validate_root_health_proof,
    validate_root_recovery_activation,
    validate_root_recovery_binding,
    validate_root_rotation,
    validate_root_transition_bundle,
)


def _sign(private: ec.EllipticCurvePrivateKey, payload: dict, key_id: str) -> dict[str, str]:
    der = private.sign(canonical_json(payload), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return {
        "algorithm": ECDSA_P256_SHA256,
        "signer_key_id": key_id,
        "value": b64u_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")),
    }


def _root(generation: int) -> tuple[dict, ec.EllipticCurvePrivateKey]:
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    key_id = "devroot_tpm_" + hashlib.sha256(public).hexdigest()[:20]
    unsigned = {
        "schema": HARDWARE_ROOT_SCHEMA_V3,
        "key_id": key_id,
        "generation": generation,
        "algorithm": ECDSA_P256_SHA256,
        "public_key": b64u_encode(public),
        "fingerprint": key_fingerprint(public),
        "owner_label": f"Hardware Root {generation}",
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "provider": "windows-tpm-cng",
        "key_name": f"Arenyxa.Developer.HardwareRoot.g{generation:04d}",
        "key_binding_sha256": hashlib.sha256(f"binding-{generation}".encode()).hexdigest(),
        "protection_profile": {
            "schema": HARDWARE_ROOT_PROTECTION_SCHEMA_V2,
            "layers": [
                "tpm-platform-provider",
                "machine-scope-persistence",
                "private-export-disabled",
                "signing-only-key-usage",
                "high-protection-ui",
            ],
            "machine_scope": True,
            "private_exportable": False,
            "signing_only": True,
            "high_protection": True,
            "hardware_required": True,
            "provider": "windows-tpm-cng",
            "algorithm": ECDSA_P256_SHA256,
        },
    }
    root = {**unsigned, "signature": _sign(private, unsigned, key_id)}
    return validate_root_trust(root), private


def _root_v4(generation: int, purpose: str) -> tuple[dict, ec.EllipticCurvePrivateKey]:
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    key_id = "devroot_tpm_" + hashlib.sha256(public).hexdigest()[:20]
    prefix = "Arenyxa.Developer.HardwareRecoveryRoot.g" if purpose == "recovery" else "Arenyxa.Developer.HardwareRoot.g"
    unsigned = {
        "schema": HARDWARE_ROOT_SCHEMA_V4,
        "key_id": key_id,
        "generation": generation,
        "purpose": purpose,
        "algorithm": ECDSA_P256_SHA256,
        "public_key": b64u_encode(public),
        "fingerprint": key_fingerprint(public),
        "owner_label": f"Hardware {purpose} Root {generation}",
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "provider": "windows-tpm-cng",
        "key_name": f"{prefix}{generation:04d}",
        "key_binding_sha256": hashlib.sha256(f"binding-{purpose}-{generation}".encode()).hexdigest(),
        "protection_profile": _root(generation)[0]["protection_profile"],
    }
    root = {**unsigned, "signature": _sign(private, unsigned, key_id)}
    return validate_root_trust(root), private


def test_hardware_root_v3_generation_and_binding_are_fail_closed() -> None:
    root, _ = _root(2)
    assert root["generation"] == 2
    tampered = {**root, "generation": 3}
    with pytest.raises(ArenyxaError):
        validate_root_trust(tampered)


def test_hardware_root_v4_separates_primary_and_recovery_namespaces() -> None:
    primary, _ = _root_v4(2, "primary")
    recovery, _ = _root_v4(2, "recovery")
    assert primary["key_name"] != recovery["key_name"]
    assert primary["purpose"] == "primary"
    assert recovery["purpose"] == "recovery"
    bad = {**recovery, "key_name": primary["key_name"]}
    with pytest.raises(ArenyxaError):
        validate_root_trust(bad)


def test_hardware_root_authority_checkpoint_binds_state_and_audit_head() -> None:
    root, private = _root_v4(3, "primary")
    payload = {
        "schema": ROOT_AUTHORITY_CHECKPOINT_SCHEMA,
        "root_key_id": root["key_id"],
        "root_sha256": artifact_sha256(root),
        "generation": 3,
        "state_sha256": "1" * 64,
        "audit_records": 42,
        "audit_head_sha256": "2" * 64,
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
    }
    artifact = {**payload, "signature": _sign(private, payload, root["key_id"])}
    assert validate_root_authority_checkpoint(artifact, root)["audit_records"] == 42
    tampered = {**artifact, "audit_head_sha256": "3" * 64}
    with pytest.raises(ArenyxaError):
        validate_root_authority_checkpoint(tampered, root)


def test_rotation_requires_old_and_new_hardware_root_signatures() -> None:
    old_root, old_private = _root(1)
    new_root, new_private = _root(2)
    payload = {
        "schema": ROOT_ROTATION_SCHEMA,
        "old_root_key_id": old_root["key_id"],
        "new_root_key_id": new_root["key_id"],
        "old_root_sha256": artifact_sha256(old_root),
        "new_root_sha256": artifact_sha256(new_root),
        "old_generation": 1,
        "new_generation": 2,
        "reason": "Scheduled Root rotation",
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
    }
    artifact = {
        **payload,
        "old_signature": _sign(old_private, payload, old_root["key_id"]),
        "new_signature": _sign(new_private, payload, new_root["key_id"]),
    }
    assert validate_root_rotation(artifact, old_root, new_root)["new_generation"] == 2
    artifact["reason"] = "tampered"
    with pytest.raises(ArenyxaError):
        validate_root_rotation(artifact, old_root, new_root)


def test_recovery_binding_and_activation_require_recovery_root_proof() -> None:
    primary, primary_private = _root(1)
    recovery, recovery_private = _root(2)
    now = datetime.now(UTC).replace(microsecond=0)
    payload = {
        "schema": ROOT_RECOVERY_BINDING_SCHEMA,
        "primary_root_key_id": primary["key_id"],
        "recovery_root_key_id": recovery["key_id"],
        "primary_root_sha256": artifact_sha256(primary),
        "recovery_root_sha256": artifact_sha256(recovery),
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(days=90)).isoformat(),
        "policy": {
            "mode": "dual-hardware-root",
            "activation": "offline-explicit-ceremony",
            "private_key_backup": False,
        },
    }
    binding = {
        **payload,
        "primary_signature": _sign(primary_private, payload, primary["key_id"]),
        "recovery_signature": _sign(recovery_private, payload, recovery["key_id"]),
    }
    valid_binding = validate_root_recovery_binding(binding, primary, recovery)
    activation_payload = {
        "schema": ROOT_RECOVERY_ACTIVATION_SCHEMA,
        "binding_sha256": artifact_sha256(valid_binding),
        "failed_root_key_id": primary["key_id"],
        "recovery_root_key_id": recovery["key_id"],
        "incident_id": "INCIDENT-ROOT-0001",
        "activated_at": now.isoformat(),
        "nonce": b64u_encode(b"r" * 32),
    }
    activation = {
        **activation_payload,
        "signature": _sign(recovery_private, activation_payload, recovery["key_id"]),
    }
    assert validate_root_recovery_activation(activation, binding, primary, recovery)["incident_id"] == "INCIDENT-ROOT-0001"


def test_health_proof_is_root_bound_and_tamper_evident() -> None:
    root, private = _root(1)
    challenge = b"root-health-challenge-01"
    payload = {
        "schema": ROOT_HEALTH_PROOF_SCHEMA,
        "root_key_id": root["key_id"],
        "generation": 1,
        "challenge_sha256": hashlib.sha256(challenge).hexdigest(),
        "public_key_sha256": hashlib.sha256(
            ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(),
                __import__("base64").urlsafe_b64decode(root["public_key"] + "=="),
            ).public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        ).hexdigest(),
        "policy_sha256": hashlib.sha256(canonical_json(root["protection_profile"])).hexdigest(),
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
    }
    proof = {**payload, "signature": _sign(private, payload, root["key_id"])}
    assert validate_root_health_proof(
        proof,
        root,
        expected_challenge=challenge,
        max_age_seconds=60,
    )["root_key_id"] == root["key_id"]
    with pytest.raises(ArenyxaError, match="challenge"):
        validate_root_health_proof(proof, root, expected_challenge=b"wrong-health-challenge")
    with pytest.raises(ArenyxaError, match="stale"):
        validate_root_health_proof(
            proof,
            root,
            at=datetime.fromisoformat(payload["created_at"]) + timedelta(seconds=120),
            max_age_seconds=60,
        )
    proof["challenge_sha256"] = "0" * 64
    with pytest.raises(ArenyxaError):
        validate_root_health_proof(proof, root)


def test_transition_bundle_requires_valid_dual_signed_rotation() -> None:
    old_root, old_private = _root(1)
    new_root, new_private = _root(2)
    now = datetime.now(UTC).replace(microsecond=0)
    payload = {
        "schema": ROOT_ROTATION_SCHEMA,
        "old_root_key_id": old_root["key_id"],
        "new_root_key_id": new_root["key_id"],
        "old_root_sha256": artifact_sha256(old_root),
        "new_root_sha256": artifact_sha256(new_root),
        "old_generation": 1,
        "new_generation": 2,
        "reason": "Rotate into the next TPM Root generation",
        "created_at": now.isoformat(),
    }
    rotation = {
        **payload,
        "old_signature": _sign(old_private, payload, old_root["key_id"]),
        "new_signature": _sign(new_private, payload, new_root["key_id"]),
    }
    bundle = {
        "schema": ROOT_TRANSITION_BUNDLE_SCHEMA,
        "mode": "overlap-then-retire-old",
        "created_at": now.isoformat(),
        "old_root": old_root,
        "new_root": new_root,
        "rotation": rotation,
    }
    assert validate_root_transition_bundle(bundle)["new_root"]["key_id"] == new_root["key_id"]
    bundle["mode"] = "replace-immediately"
    with pytest.raises(ArenyxaError):
        validate_root_transition_bundle(bundle)


def test_transition_trust_store_overlap_then_retirement() -> None:
    old_root, old_private = _root(1)
    new_root, new_private = _root(2)
    now = datetime.now(UTC).replace(microsecond=0)
    payload = {
        "schema": ROOT_ROTATION_SCHEMA,
        "old_root_key_id": old_root["key_id"],
        "new_root_key_id": new_root["key_id"],
        "old_root_sha256": artifact_sha256(old_root),
        "new_root_sha256": artifact_sha256(new_root),
        "old_generation": 1,
        "new_generation": 2,
        "reason": "Controlled trust overlap before old Root retirement",
        "created_at": now.isoformat(),
    }
    rotation = {
        **payload,
        "old_signature": _sign(old_private, payload, old_root["key_id"]),
        "new_signature": _sign(new_private, payload, new_root["key_id"]),
    }
    bundle = {
        "schema": ROOT_TRANSITION_BUNDLE_SCHEMA,
        "mode": "overlap-then-retire-old",
        "created_at": now.isoformat(),
        "old_root": old_root,
        "new_root": new_root,
        "rotation": rotation,
    }
    overlap = build_overlap_trust_store(bundle, [old_root])
    assert {root["key_id"] for root in overlap["roots"]} == {old_root["key_id"], new_root["key_id"]}
    retired = build_retired_trust_store(bundle, overlap["roots"])
    assert [root["key_id"] for root in retired["roots"]] == [new_root["key_id"]]
    with pytest.raises(ArenyxaError):
        build_retired_trust_store(bundle, [new_root])


def test_tpm_batch_signing_limit_is_hard_bounded_before_provider_access() -> None:
    provider = WindowsTPMEcdsaP256Provider()
    with pytest.raises(ValueError, match="max_items"):
        provider.sign_many_sha256("unused", (), machine_scope=True, max_items=257)
