from __future__ import annotations

from datetime import datetime

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from arenyxa.compat import UTC
from arenyxa.domain.errors import ArenyxaError
from arenyxa.security.developer_credentials import (
    HARDWARE_ROOT_PROTECTION_SCHEMA,
    HARDWARE_ROOT_SCHEMA,
    b64u_encode,
    canonical_json,
    key_fingerprint,
    validate_root_trust,
)
from arenyxa.security.developer_crypto import ECDSA_P256_SHA256


def _artifact() -> dict:
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    key_id = "devroot_tpm_" + __import__("hashlib").sha256(public).hexdigest()[:20]
    unsigned = {
        "schema": HARDWARE_ROOT_SCHEMA,
        "key_id": key_id,
        "algorithm": ECDSA_P256_SHA256,
        "public_key": b64u_encode(public),
        "fingerprint": key_fingerprint(public),
        "owner_label": "Hardware Root Verification Test",
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "provider": "windows-tpm-cng",
        "key_name": "Arenyxa.Developer.HardwareRoot.v1",
        "protection_profile": {
            "schema": HARDWARE_ROOT_PROTECTION_SCHEMA,
            "layers": ["tpm-platform-provider", "machine-scope-persistence", "private-export-disabled", "signing-only-key-usage", "high-protection-ui"],
            "machine_scope": True,
            "private_exportable": False,
            "signing_only": True,
            "high_protection": True,
        },
    }
    der = private.sign(canonical_json(unsigned), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return {**unsigned, "signature": {"algorithm": ECDSA_P256_SHA256, "signer_key_id": key_id, "value": b64u_encode(signature)}}


def test_public_runtime_verifies_hardware_root_without_private_authority_code() -> None:
    artifact = _artifact()
    assert validate_root_trust(artifact)["algorithm"] == ECDSA_P256_SHA256


def test_hardware_root_protection_profile_is_fail_closed() -> None:
    artifact = _artifact()
    artifact["protection_profile"] = {**artifact["protection_profile"], "private_exportable": True}
    with pytest.raises(ArenyxaError):
        validate_root_trust(artifact)
