from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import field
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from arenyxa.compat import dataclass
from arenyxa.domain.errors import ArenyxaError
from arenyxa.security.hardware_identity import WindowsTPMEcdsaP256Provider

ED25519 = "ED25519"
ECDSA_P256_SHA256 = "ECDSA_P256_SHA256"
SUPPORTED_WORKER_IDENTITY_ALGORITHMS = (ED25519, ECDSA_P256_SHA256)


def _fail(code: str, message: str, **context: Any) -> ArenyxaError:
    return ArenyxaError(code, message, domain="ENTERPRISE_WORKER_IDENTITY", context=context)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(data)).decode("ascii").rstrip("=")


def b64u_decode(value: str, *, max_bytes: int = 4096) -> bytes:
    text = str(value).strip()
    if not text or "=" in text or len(text) > max_bytes * 2:
        raise _fail("WORKER_IDENTITY_ENCODING_INVALID", "Worker identity value is not canonical base64url.")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * ((4 - len(text) % 4) % 4))
    except (ValueError, TypeError) as exc:
        raise _fail("WORKER_IDENTITY_ENCODING_INVALID", "Worker identity value cannot be decoded.") from exc
    if len(raw) > max_bytes or not hmac.compare_digest(b64u(raw), text):
        raise _fail("WORKER_IDENTITY_ENCODING_INVALID", "Worker identity value is oversized or non-canonical.")
    return raw


def normalize_algorithm(value: str | None) -> str:
    text = str(value or ED25519).strip().upper().replace("-", "_")
    aliases = {
        "ED_25519": ED25519,
        "ECDSA_P256": ECDSA_P256_SHA256,
        "ECDSA_P_256_SHA256": ECDSA_P256_SHA256,
        "P256": ECDSA_P256_SHA256,
    }
    text = aliases.get(text, text)
    if text not in SUPPORTED_WORKER_IDENTITY_ALGORITHMS:
        raise _fail("WORKER_IDENTITY_ALGORITHM_UNSUPPORTED", "Worker identity algorithm is not supported.", algorithm=text)
    return text


def validate_public_key(algorithm: str, public_key_b64: str) -> bytes:
    normalized = normalize_algorithm(algorithm)
    raw = b64u_decode(public_key_b64, max_bytes=256)
    if normalized == ED25519:
        if len(raw) != 32:
            raise _fail("WORKER_IDENTITY_PUBLIC_KEY_INVALID", "Ed25519 worker public key must be 32 bytes.")
        Ed25519PublicKey.from_public_bytes(raw)
        return raw
    if len(raw) != 65 or raw[0] != 0x04:
        raise _fail("WORKER_IDENTITY_PUBLIC_KEY_INVALID", "P-256 worker public key must use 65-byte uncompressed SEC1 encoding.")
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError as exc:
        raise _fail("WORKER_IDENTITY_PUBLIC_KEY_INVALID", "P-256 worker public key is not on the expected curve.") from exc
    return raw


def verify_signature(algorithm: str, public_key_b64: str, signature_b64: str, message: bytes) -> None:
    normalized = normalize_algorithm(algorithm)
    public_raw = validate_public_key(normalized, public_key_b64)
    signature = b64u_decode(signature_b64, max_bytes=512)
    payload = bytes(message)
    try:
        if normalized == ED25519:
            if len(signature) != 64:
                raise InvalidSignature
            Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, payload)
            return
        # Windows CNG ECDSA signatures are represented by Arenyxa on the wire as
        # IEEE P1363 r||s (32 bytes each). Converting to DER is a verification-only
        # representation detail; the protocol stays deterministic and bounded.
        if len(signature) != 64:
            raise InvalidSignature
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        der = encode_dss_signature(r, s)
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_raw).verify(
            der, payload, ec.ECDSA(hashes.SHA256())
        )
    except (InvalidSignature, ValueError) as exc:
        raise _fail("WORKER_PROOF_INVALID", "Worker private-key proof failed.", algorithm=normalized) from exc


@dataclass(frozen=True, slots=True)
class WorkerIdentityProfile:
    algorithm: str
    public_key: str
    hardware_backed: bool = False
    provider: str = "software"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "algorithm": normalize_algorithm(self.algorithm),
            "public_key": self.public_key,
            "hardware_backed": bool(self.hardware_backed),
            "provider": str(self.provider),
            "metadata": dict(self.metadata),
        }


class TPMWorkerIdentitySigner:
    """Non-exportable Windows TPM Worker identity for protocol-v2 challenges."""

    identity_algorithm = ECDSA_P256_SHA256

    def __init__(self, key_name: str, provider: WindowsTPMEcdsaP256Provider | None = None) -> None:
        self.key_name = str(key_name).strip()
        if not self.key_name:
            raise ValueError("TPM worker identity key name is required")
        self.provider = provider or WindowsTPMEcdsaP256Provider()
        created = dict(self.provider.create_key(self.key_name))
        public = bytes(created["public_key_uncompressed"])
        self.profile = WorkerIdentityProfile(
            algorithm=self.identity_algorithm,
            public_key=b64u(public),
            hardware_backed=True,
            provider=self.provider.name,
            metadata={"key_name": self.key_name, "non_exportable": True},
        )

    def sign(self, message: bytes) -> bytes:
        digest = hashlib.sha256(bytes(message)).digest()
        signature = bytes(self.provider.sign_sha256(self.key_name, digest))
        if len(signature) != 64:
            raise _fail(
                "TPM_SIGNATURE_FORMAT_UNEXPECTED",
                "TPM ECDSA signature is not the expected P1363 r||s representation.",
                bytes=len(signature),
            )
        return signature

    def __call__(self, message: bytes) -> bytes:
        return self.sign(message)
