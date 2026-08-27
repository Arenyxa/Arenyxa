from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ED25519 = "Ed25519"
ECDSA_P256_SHA256 = "ECDSA_P256_SHA256"
SUPPORTED_DEVELOPER_SIGNATURE_ALGORITHMS = (ED25519, ECDSA_P256_SHA256)


def normalize_signature_algorithm(value: str) -> str:
    text = str(value).strip()
    aliases = {
        "ED25519": ED25519,
        "ed25519": ED25519,
        "ECDSA_P256": ECDSA_P256_SHA256,
        "ECDSA-P256-SHA256": ECDSA_P256_SHA256,
        "P256": ECDSA_P256_SHA256,
    }
    normalized = aliases.get(text, text)
    if normalized not in SUPPORTED_DEVELOPER_SIGNATURE_ALGORITHMS:
        raise ValueError("unsupported developer signature algorithm")
    return normalized


def validate_public_key_raw(algorithm: str, public_raw: bytes) -> bytes:
    normalized = normalize_signature_algorithm(algorithm)
    raw = bytes(public_raw)
    if normalized == ED25519:
        if len(raw) != 32:
            raise ValueError("Ed25519 public key must be exactly 32 bytes")
        Ed25519PublicKey.from_public_bytes(raw)
        return raw
    if len(raw) != 65 or raw[0] != 0x04:
        raise ValueError("P-256 public key must use 65-byte uncompressed SEC1 encoding")
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    return raw


def verify_signature_raw(algorithm: str, public_raw: bytes, signature: bytes, message: bytes) -> None:
    normalized = normalize_signature_algorithm(algorithm)
    public = validate_public_key_raw(normalized, public_raw)
    sig = bytes(signature)
    payload = bytes(message)
    try:
        if normalized == ED25519:
            if len(sig) != 64:
                raise InvalidSignature
            Ed25519PublicKey.from_public_bytes(public).verify(sig, payload)
            return
        if len(sig) != 64:
            raise InvalidSignature
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        if r <= 0 or s <= 0:
            raise InvalidSignature
        der = encode_dss_signature(r, s)
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public).verify(
            der,
            payload,
            ec.ECDSA(hashes.SHA256()),
        )
    except (InvalidSignature, ValueError) as exc:
        raise InvalidSignature from exc
