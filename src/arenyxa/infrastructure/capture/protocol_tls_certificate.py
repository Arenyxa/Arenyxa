from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import hashlib
from typing import Any


MAX_TLS_CERTIFICATES = 16
MAX_TLS_CERTIFICATE_BYTES = 1024 * 1024
MAX_TLS_CHAIN_BYTES = 4 * 1024 * 1024


def _certificate_metadata(der: bytes) -> dict[str, Any]:
    row: dict[str, Any] = {
        "der_bytes": len(der),
        "sha256": hashlib.sha256(der).hexdigest(),
        "sha1_compat": hashlib.sha1(der, usedforsecurity=False).hexdigest(),
    }
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
    except ImportError:
        row["x509_parser"] = "unavailable"
        return row

    try:
        certificate = x509.load_der_x509_certificate(der)
    except ValueError:
        row["x509_parser"] = "invalid-der"
        return row

    row.update({
        "x509_parser": "cryptography",
        "serial_hex": f"{certificate.serial_number:x}"[:256],
        "subject": certificate.subject.rfc4514_string()[:4096],
        "issuer": certificate.issuer.rfc4514_string()[:4096],
        "signature_algorithm_oid": certificate.signature_algorithm_oid.dotted_string,
        "signature_algorithm": getattr(certificate.signature_algorithm_oid, "_name", None) or "",
    })
    not_before = getattr(certificate, "not_valid_before_utc", None)
    not_after = getattr(certificate, "not_valid_after_utc", None)
    if not_before is None:  # compatibility with older cryptography releases
        not_before = certificate.not_valid_before
    if not_after is None:
        not_after = certificate.not_valid_after
    row["not_valid_before"] = not_before.isoformat()
    row["not_valid_after"] = not_after.isoformat()
    try:
        signature_hash = certificate.signature_hash_algorithm
        row["signature_hash"] = "" if signature_hash is None else str(signature_hash.name)
    except (ValueError, TypeError):
        row["signature_hash"] = ""

    public_key = certificate.public_key()
    key_type = type(public_key).__name__
    row["public_key_type"] = key_type
    if isinstance(public_key, rsa.RSAPublicKey):
        row["public_key_bits"] = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        row["public_key_bits"] = public_key.key_size
        row["public_key_curve"] = public_key.curve.name
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        row["public_key_bits"] = 256 if isinstance(public_key, ed25519.Ed25519PublicKey) else 456
    try:
        spki = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        row["spki_sha256"] = hashlib.sha256(spki).hexdigest()
    except (TypeError, ValueError):
        record_current_exception(__name__, '_certificate_metadata:67')

    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        row["san_dns"] = [str(value)[:253] for value in san.get_values_for_type(x509.DNSName)[:256]]
        row["san_ip"] = [str(value) for value in san.get_values_for_type(x509.IPAddress)[:128]]
    except x509.ExtensionNotFound:
        record_current_exception(__name__, '_certificate_metadata:74')
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        row["is_ca"] = bool(constraints.ca)
        row["path_length"] = constraints.path_length
    except x509.ExtensionNotFound:
        record_current_exception(__name__, '_certificate_metadata:80')
    try:
        usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        row["extended_key_usage"] = [oid.dotted_string for oid in list(usage)[:64]]
    except x509.ExtensionNotFound:
        record_current_exception(__name__, '_certificate_metadata:85')
    return row


def decode_tls12_certificate_list(body: bytes) -> list[dict[str, Any]]:
    """Decode a bounded TLS 1.0-1.2 Certificate handshake body.

    TLS 1.3 encrypts the Certificate flight in normal operation, so encrypted TLS 1.3
    traffic must be decrypted by a key-log/external dissector path before certificate
    bytes can be analyzed. This helper deliberately does not pretend otherwise.
    """

    if len(body) < 3:
        return []
    total = int.from_bytes(body[:3], "big")
    if total != len(body) - 3 or total > MAX_TLS_CHAIN_BYTES:
        return []
    cursor = 3
    rows: list[dict[str, Any]] = []
    while cursor < len(body) and len(rows) < MAX_TLS_CERTIFICATES:
        if cursor + 3 > len(body):
            return []
        size = int.from_bytes(body[cursor:cursor + 3], "big")
        cursor += 3
        if size <= 0 or size > MAX_TLS_CERTIFICATE_BYTES or cursor + size > len(body):
            return []
        rows.append(_certificate_metadata(body[cursor:cursor + size]))
        cursor += size
    return rows if cursor == len(body) else []
