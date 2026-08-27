from __future__ import annotations

import hashlib
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from arenyxa.compat import UTC
from arenyxa.security import SecurityKernel, TrustDomain
from arenyxa.security.developer_credentials import (
    HARDWARE_ROOT_PROTECTION_SCHEMA_V2,
    HARDWARE_ROOT_SCHEMA_V3,
    b64u_encode,
    canonical_json,
    key_fingerprint,
    validate_root_trust,
)
from arenyxa.security.developer_crypto import ECDSA_P256_SHA256
from arenyxa.security.developer_trust_anchors import EMBEDDED_DEVELOPER_ROOTS
from arenyxa.security.hardware_identity import HardwareKeyHealth, HardwareSigningStatus
from arenyxa.security.hardware_root_lifecycle import probe_root_integrity


def _sign(private: ec.EllipticCurvePrivateKey, payload: dict, key_id: str) -> dict[str, str]:
    der = private.sign(canonical_json(payload), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return {
        "algorithm": ECDSA_P256_SHA256,
        "signer_key_id": key_id,
        "value": b64u_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")),
    }


def _hardware_root() -> tuple[dict, bytes, str]:
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    generation = 7
    unique_name = "Arenyxa-Phase2-Test-Hardware-Root"
    key_id = "devroot_tpm_" + hashlib.sha256(public).hexdigest()[:20]
    unsigned = {
        "schema": HARDWARE_ROOT_SCHEMA_V3,
        "key_id": key_id,
        "generation": generation,
        "algorithm": ECDSA_P256_SHA256,
        "public_key": b64u_encode(public),
        "fingerprint": key_fingerprint(public),
        "owner_label": "Arenyxa Phase2 Hardware Root",
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "provider": "windows-tpm-cng",
        "key_name": f"Arenyxa.Developer.HardwareRoot.g{generation:04d}",
        "key_binding_sha256": hashlib.sha256(unique_name.encode("utf-8")).hexdigest(),
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
    return validate_root_trust({**unsigned, "signature": _sign(private, unsigned, key_id)}), public, unique_name


class _HealthyHardwareProvider:
    def __init__(self, public: bytes, unique_name: str) -> None:
        self.public = bytes(public)
        self.unique_name = str(unique_name)
        self.probe_calls = 0

    def status(self) -> HardwareSigningStatus:
        return HardwareSigningStatus(
            "windows-tpm-cng", True, True, True, (ECDSA_P256_SHA256,), ""
        )

    def inspect_key(self, key_name: str, *, machine_scope: bool = False):
        assert machine_scope is True
        return {
            "provider": "windows-tpm-cng",
            "provider_available": True,
            "hardware_backed": True,
            "algorithm": "ECDSA_P256",
            "key_name": key_name,
            "unique_name": self.unique_name,
            "machine_scope": True,
            "private_exportable": False,
            "signing_only": True,
            "high_protection": True,
            "public_key_uncompressed": self.public,
        }

    def probe_key(self, key_name: str, *, machine_scope: bool = False) -> HardwareKeyHealth:
        self.probe_calls += 1
        return HardwareKeyHealth(
            "windows-tpm-cng",
            key_name,
            True,
            True,
            True,
            True,
            0.1,
            hashlib.sha256(self.public).hexdigest(),
            "",
            hashlib.sha256(self.unique_name.encode("utf-8")).hexdigest(),
        )


def test_phase2_legacy_root_integrity_is_valid_without_replacing_root_key() -> None:
    state = probe_root_integrity(dict(EMBEDDED_DEVELOPER_ROOTS[0]))
    assert state.artifact_valid is True
    assert state.integrity_valid is True
    assert state.authority_ready is True
    assert state.hardware_required is False
    assert state.reason == "ROOT_ARTIFACT_VALID"


def test_phase2_hardware_root_startup_probe_is_passive_then_active_proof_unlocks_authority() -> None:
    root, public, unique_name = _hardware_root()
    provider = _HealthyHardwareProvider(public, unique_name)

    passive = probe_root_integrity(root, active_proof=False, provider=provider)
    assert passive.integrity_valid is True
    assert passive.authority_ready is False
    assert passive.hardware_required is True
    assert passive.key_present is True
    assert passive.policy_valid is True
    assert passive.public_key_match is True
    assert passive.key_binding_match is True
    assert passive.proof_of_possession is False
    assert provider.probe_calls == 0

    active = probe_root_integrity(root, active_proof=True, provider=provider)
    assert active.integrity_valid is True
    assert active.authority_ready is True
    assert active.proof_of_possession is True
    assert active.reason == "ROOT_HARDWARE_PROOF_VALID"
    assert provider.probe_calls == 1


def test_phase2_hardware_root_public_key_mismatch_fails_closed() -> None:
    root, _public, unique_name = _hardware_root()
    wrong_private = ec.generate_private_key(ec.SECP256R1())
    wrong_public = wrong_private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    state = probe_root_integrity(
        root, provider=_HealthyHardwareProvider(wrong_public, unique_name)
    )
    assert state.integrity_valid is False
    assert state.authority_ready is False
    assert state.reason == "ROOT_HARDWARE_PUBLIC_KEY_MISMATCH"


def test_phase2_security_kernel_rejects_platform_root_without_integrity_marker() -> None:
    kernel = SecurityKernel()
    identity = kernel.state.create_identity(
        TrustDomain.DEVELOPER,
        principal_id="root-phase2-test",
        display_name="Root Phase2 Test",
        kind="root_owner",
    )
    forged = kernel.issue_session(
        identity.id,
        capabilities=["runtime.debug", "platform.root"],
        metadata={"authentication": "synthetic"},
    )
    denied = kernel.authorize(forged, "runtime.debug", "developer:internal/test")
    assert denied.allowed is False
    assert denied.code == "ROOT_INTEGRITY_REQUIRED"

    verified = kernel.issue_session(
        identity.id,
        capabilities=["runtime.debug", "platform.root"],
        metadata={"root_integrity_verified": True},
    )
    allowed = kernel.authorize(verified, "runtime.debug", "developer:internal/test")
    assert allowed.allowed is True
    assert allowed.code == "PLATFORM_ROOT_ALLOW"
