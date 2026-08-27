from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from arenyxa.compat import UTC, dataclass
from arenyxa.domain.errors import ArenyxaError

ROOT_SCHEMA = "arenyxa.developer-root-trust/v1"
ISSUER_SCHEMA = "arenyxa.developer-issuer-certificate/v1"
DEVELOPER_SCHEMA = "arenyxa.developer-certificate/v1"
OWNER_SCHEMA = "arenyxa.developer-owner-certificate/v1"
REVOCATION_SCHEMA = "arenyxa.developer-revocation/v1"
LOGIN_BUNDLE_SCHEMA = "arenyxa.developer-login-bundle/v1"
OWNER_LOGIN_BUNDLE_SCHEMA = "arenyxa.developer-owner-login-bundle/v1"
TRUST_STORE_SCHEMA = "arenyxa.developer-trust-store/v1"
REVOCATION_SET_SCHEMA = "arenyxa.developer-revocation-set/v1"
SIGNATURE_ALGORITHM = "Ed25519"

DEVELOPER_CAPABILITIES: frozenset[str] = frozenset(
    {
        "runtime.debug",
        "profiler",
        "stress_test",
        "fault_injection",
        "internal_logs",
        "release.verify",
    }
)

MAX_ARTIFACT_BYTES = 512 * 1024
MAX_REVOCATIONS = 10_000


def _error(code: str, message: str, **context: Any) -> ArenyxaError:
    return ArenyxaError(code, message, domain="DEVELOPER_ACCESS", context=context)


def canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def artifact_sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def b64u_decode(value: str, *, max_bytes: int) -> bytes:
    text = str(value).strip()
    if not text or len(text) > max_bytes * 2:
        raise _error("DEVELOPER_ARTIFACT_INVALID", "base64url field is empty or too large")
                                                                                               
                                                                                                
                                                                                    
    if "=" in text or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for ch in text):
        raise _error("DEVELOPER_ARTIFACT_INVALID", "invalid base64url field")
    padding = "=" * ((4 - len(text) % 4) % 4)
    try:
        raw = base64.b64decode((text + padding).encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, UnicodeError) as exc:
        raise _error("DEVELOPER_ARTIFACT_INVALID", "invalid base64url field") from exc
    if len(raw) > max_bytes or b64u_encode(raw) != text:
        raise _error("DEVELOPER_ARTIFACT_INVALID", "decoded field exceeds its size limit or is non-canonical")
    return raw


def b64u_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(value)).decode("ascii").rstrip("=")


def key_fingerprint(public_raw: bytes) -> str:
    digest = hashlib.sha256(bytes(public_raw)).hexdigest().upper()
    return "ARYX-" + "-".join(digest[index : index + 8] for index in range(0, len(digest), 8))


def _public_from_artifact(value: str) -> bytes:
    raw = b64u_decode(value, max_bytes=64)
    if len(raw) != 32:
        raise _error("DEVELOPER_PUBLIC_KEY_INVALID", "Ed25519 public key must be exactly 32 bytes")
    return raw


def _parse_utc(value: str) -> datetime:
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except (TypeError, ValueError, OverflowError) as exc:
        raise _error("DEVELOPER_TIME_INVALID", "developer artifact timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise _error("DEVELOPER_TIME_INVALID", "developer artifact timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _normalize_now(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if not isinstance(value, datetime):
        raise TypeError("now must be datetime or None")
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _exact_fields(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise _error(
            "DEVELOPER_ARTIFACT_INVALID",
            f"{label} fields mismatch",
            missing=sorted(expected - actual),
            extra=sorted(actual - expected),
        )


def _validate_identifier(value: str, *, label: str) -> str:
    text = str(value).strip()
    if not 1 <= len(text) <= 128:
        raise _error("DEVELOPER_ARTIFACT_INVALID", f"{label} length is invalid")
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-:@"
    if any(ch not in allowed for ch in text):
        raise _error("DEVELOPER_ARTIFACT_INVALID", f"{label} contains unsupported characters")
    return text


def _validate_email(value: str) -> str:
    text = str(value).strip()
    if not 3 <= len(text) <= 254 or text.count("@") != 1 or any(ch.isspace() for ch in text):
        raise _error("DEVELOPER_ARTIFACT_INVALID", "developer email field is invalid")
    local, domain = text.rsplit("@", 1)
    if not local or not domain or "." not in domain:
        raise _error("DEVELOPER_ARTIFACT_INVALID", "developer email field is invalid")
    return text


def _validate_capabilities(values: Iterable[str], *, allowed: Iterable[str] = DEVELOPER_CAPABILITIES) -> tuple[str, ...]:
    result = tuple(sorted(set(str(item).strip() for item in values)))
    if not result:
        raise _error("DEVELOPER_CAPABILITY_INVALID", "developer credential grants no capabilities")
    if len(result) > 16:
        raise _error("DEVELOPER_CAPABILITY_INVALID", "developer credential grants too many capabilities")
    allowed_set = frozenset(str(item) for item in allowed)
    unknown = sorted(set(result) - allowed_set)
    if unknown:
        raise _error(
            "DEVELOPER_CAPABILITY_INVALID",
            "developer credential contains unsupported or out-of-domain capabilities",
            capabilities=unknown,
        )
    return result


def _unsigned(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in dict(value).items() if key != "signature"}


def _verify_signature(artifact: Mapping[str, Any], public_raw: bytes, expected_signer: str) -> None:
    block = artifact.get("signature")
    if not isinstance(block, dict):
        raise _error("DEVELOPER_SIGNATURE_INVALID", "signature block is missing")
    _exact_fields(block, {"algorithm", "signer_key_id", "value"}, "signature")
    if block.get("algorithm") != SIGNATURE_ALGORITHM or str(block.get("signer_key_id")) != str(expected_signer):
        raise _error("DEVELOPER_SIGNATURE_INVALID", "signature algorithm or signer key id is invalid")
    signature = b64u_decode(str(block.get("value")), max_bytes=128)
    if len(signature) != 64:
        raise _error("DEVELOPER_SIGNATURE_INVALID", "Ed25519 signature must be exactly 64 bytes")
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, canonical_json(_unsigned(artifact)))
    except (InvalidSignature, ValueError) as exc:
        raise _error("DEVELOPER_SIGNATURE_INVALID", "developer artifact signature verification failed") from exc


def validate_root_trust(artifact: Mapping[str, Any]) -> dict[str, Any]:
    _exact_fields(
        artifact,
        {"schema", "key_id", "algorithm", "public_key", "fingerprint", "owner_label", "created_at", "signature"},
        "Developer Root trust",
    )
    if artifact.get("schema") != ROOT_SCHEMA or artifact.get("algorithm") != SIGNATURE_ALGORITHM:
        raise _error("DEVELOPER_ROOT_INVALID", "Developer Root schema/algorithm is invalid")
    key_id = _validate_identifier(str(artifact.get("key_id")), label="root key id")
    public_raw = _public_from_artifact(str(artifact.get("public_key")))
    if key_fingerprint(public_raw) != artifact.get("fingerprint"):
        raise _error("DEVELOPER_ROOT_INVALID", "Developer Root fingerprint does not match public key")
    owner = str(artifact.get("owner_label", "")).strip()
    if not 1 <= len(owner) <= 128:
        raise _error("DEVELOPER_ROOT_INVALID", "Developer Root owner label is invalid")
    _parse_utc(str(artifact.get("created_at")))
    _verify_signature(artifact, public_raw, key_id)
    return dict(artifact)


def validate_issuer_certificate(
    artifact: Mapping[str, Any],
    root: Mapping[str, Any],
    *,
    at: datetime | None = None,
    allow_expired: bool = False,
) -> dict[str, Any]:
    _exact_fields(
        artifact,
        {
            "schema", "issuer_key_id", "root_key_id", "algorithm", "public_key", "fingerprint", "label",
            "allowed_capabilities", "not_before", "expires_at", "created_at", "signature",
        },
        "Developer Issuing certificate",
    )
    root = validate_root_trust(root)
    if artifact.get("schema") != ISSUER_SCHEMA or artifact.get("algorithm") != SIGNATURE_ALGORITHM:
        raise _error("DEVELOPER_ISSUER_INVALID", "Developer Issuing certificate schema/algorithm is invalid")
    if artifact.get("root_key_id") != root.get("key_id"):
        raise _error("DEVELOPER_ISSUER_INVALID", "Developer Issuing certificate belongs to another root")
    key_id = _validate_identifier(str(artifact.get("issuer_key_id")), label="issuer key id")
    public_raw = _public_from_artifact(str(artifact.get("public_key")))
    if key_fingerprint(public_raw) != artifact.get("fingerprint"):
        raise _error("DEVELOPER_ISSUER_INVALID", "Developer Issuing fingerprint does not match public key")
    label = str(artifact.get("label", "")).strip()
    if not 1 <= len(label) <= 128:
        raise _error("DEVELOPER_ISSUER_INVALID", "Developer Issuing label is invalid")
    capabilities = artifact.get("allowed_capabilities")
    if not isinstance(capabilities, list):
        raise _error("DEVELOPER_ISSUER_INVALID", "issuer capabilities must be an array")
    _validate_capabilities(capabilities)
    start = _parse_utc(str(artifact.get("not_before")))
    end = _parse_utc(str(artifact.get("expires_at")))
    if end <= start:
        raise _error("DEVELOPER_ISSUER_INVALID", "issuer validity interval is invalid")
    current = _normalize_now(at)
    if not allow_expired and (current < start - timedelta(minutes=5) or current >= end):
        raise _error("DEVELOPER_ISSUER_TIME_INVALID", "Developer Issuing certificate is not currently valid")
    _parse_utc(str(artifact.get("created_at")))
    _verify_signature(artifact, _public_from_artifact(str(root["public_key"])), str(root["key_id"]))
    return dict(artifact)


def validate_developer_certificate(
    artifact: Mapping[str, Any],
    issuer: Mapping[str, Any],
    root: Mapping[str, Any],
    *,
    at: datetime | None = None,
    allow_expired: bool = False,
) -> dict[str, Any]:
    _exact_fields(
        artifact,
        {
            "schema", "serial", "developer_id", "email", "public_key", "fingerprint", "capabilities",
            "issuer_key_id", "not_before", "expires_at", "issued_at", "signature",
        },
        "Developer certificate",
    )
    issuer = validate_issuer_certificate(issuer, root, at=at, allow_expired=allow_expired)
    if artifact.get("schema") != DEVELOPER_SCHEMA or artifact.get("issuer_key_id") != issuer.get("issuer_key_id"):
        raise _error("DEVELOPER_CERT_INVALID", "Developer certificate schema/issuer binding is invalid")
    serial = str(artifact.get("serial", ""))
    if len(serial) != 32 or any(ch not in "0123456789abcdef" for ch in serial):
        raise _error("DEVELOPER_CERT_INVALID", "Developer certificate serial is invalid")
    _validate_identifier(str(artifact.get("developer_id")), label="developer id")
    _validate_email(str(artifact.get("email")))
    public_raw = _public_from_artifact(str(artifact.get("public_key")))
    if key_fingerprint(public_raw) != artifact.get("fingerprint"):
        raise _error("DEVELOPER_CERT_INVALID", "Developer certificate fingerprint does not match public key")
    caps = artifact.get("capabilities")
    issuer_caps = issuer.get("allowed_capabilities")
    if not isinstance(caps, list) or not isinstance(issuer_caps, list):
        raise _error("DEVELOPER_CERT_INVALID", "Developer certificate capabilities are invalid")
    _validate_capabilities(caps, allowed=issuer_caps)
    start = _parse_utc(str(artifact.get("not_before")))
    end = _parse_utc(str(artifact.get("expires_at")))
    if end <= start:
        raise _error("DEVELOPER_CERT_INVALID", "Developer certificate validity interval is invalid")
    current = _normalize_now(at)
    if not allow_expired and (current < start - timedelta(minutes=5) or current >= end):
        raise _error("DEVELOPER_CERT_TIME_INVALID", "Developer certificate is not currently valid")
    _parse_utc(str(artifact.get("issued_at")))
    _verify_signature(artifact, _public_from_artifact(str(issuer["public_key"])), str(issuer["issuer_key_id"]))
    return dict(artifact)


def validate_owner_certificate(
    artifact: Mapping[str, Any],
    issuer: Mapping[str, Any],
    root: Mapping[str, Any],
    *,
    at: datetime | None = None,
    allow_expired: bool = False,
) -> dict[str, Any]:
    _exact_fields(
        artifact,
        {
            "schema", "serial", "owner_id", "email", "public_key", "fingerprint", "capabilities",
            "issuer_key_id", "not_before", "expires_at", "issued_at", "signature",
        },
        "Root Owner Authority certificate",
    )
    issuer = validate_issuer_certificate(issuer, root, at=at, allow_expired=allow_expired)
    if artifact.get("schema") != OWNER_SCHEMA or artifact.get("issuer_key_id") != issuer.get("issuer_key_id"):
        raise _error("DEVELOPER_OWNER_CERT_INVALID", "Root Owner Authority certificate schema/issuer binding is invalid")
    serial = str(artifact.get("serial", ""))
    if len(serial) != 32 or any(ch not in "0123456789abcdef" for ch in serial):
        raise _error("DEVELOPER_OWNER_CERT_INVALID", "Root Owner Authority certificate serial is invalid")
    _validate_identifier(str(artifact.get("owner_id")), label="owner id")
    _validate_email(str(artifact.get("email")))
    public_raw = _public_from_artifact(str(artifact.get("public_key")))
    if key_fingerprint(public_raw) != artifact.get("fingerprint"):
        raise _error("DEVELOPER_OWNER_CERT_INVALID", "Root Owner Authority certificate fingerprint does not match public key")
    caps = artifact.get("capabilities")
    issuer_caps = issuer.get("allowed_capabilities")
    if not isinstance(caps, list) or not isinstance(issuer_caps, list):
        raise _error("DEVELOPER_OWNER_CERT_INVALID", "Root Owner Authority capabilities are invalid")
    validated_caps = _validate_capabilities(caps, allowed=issuer_caps)
    if frozenset(validated_caps) != DEVELOPER_CAPABILITIES:
        raise _error(
            "DEVELOPER_OWNER_CERT_INVALID",
            "Root Owner Authority certificate must carry the complete Developer capability set",
        )
    start = _parse_utc(str(artifact.get("not_before")))
    end = _parse_utc(str(artifact.get("expires_at")))
    if end <= start:
        raise _error("DEVELOPER_OWNER_CERT_INVALID", "Root Owner Authority validity interval is invalid")
    current = _normalize_now(at)
    if not allow_expired and (current < start - timedelta(minutes=5) or current >= end):
        raise _error("DEVELOPER_OWNER_CERT_TIME_INVALID", "Root Owner Authority certificate is not currently valid")
    _parse_utc(str(artifact.get("issued_at")))
    _verify_signature(artifact, _public_from_artifact(str(issuer["public_key"])), str(issuer["issuer_key_id"]))
    return dict(artifact)


def validate_revocation(
    artifact: Mapping[str, Any],
    *,
    root: Mapping[str, Any],
    issuer: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    _exact_fields(
        artifact,
        {
            "schema", "revocation_id", "target_kind", "target_id", "target_sha256", "reason", "revoked_at",
            "signer_key_id", "signature",
        },
        "Developer revocation",
    )
    if artifact.get("schema") != REVOCATION_SCHEMA:
        raise _error("DEVELOPER_REVOCATION_INVALID", "Developer revocation schema is invalid")
    revocation_id = str(artifact.get("revocation_id", ""))
    if len(revocation_id) != 32 or any(ch not in "0123456789abcdef" for ch in revocation_id):
        raise _error("DEVELOPER_REVOCATION_INVALID", "revocation id is invalid")
    target_kind = str(artifact.get("target_kind"))
    target_id = str(artifact.get("target_id"))
    if target_kind in {"developer_certificate", "owner_certificate"}:
        if len(target_id) != 32 or any(ch not in "0123456789abcdef" for ch in target_id):
            raise _error("DEVELOPER_REVOCATION_INVALID", f"{target_kind} revocation target is invalid")
    elif target_kind == "issuing_key":
        _validate_identifier(target_id, label="revoked issuer key id")
    else:
        raise _error("DEVELOPER_REVOCATION_INVALID", "unsupported revocation target kind")
    digest = str(artifact.get("target_sha256", "")).lower()
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise _error("DEVELOPER_REVOCATION_INVALID", "revocation target SHA-256 is invalid")
    reason = str(artifact.get("reason", "")).strip()
    if not 1 <= len(reason) <= 512:
        raise _error("DEVELOPER_REVOCATION_INVALID", "revocation reason is invalid")
    revoked_at = _parse_utc(str(artifact.get("revoked_at")))
    root = validate_root_trust(root)
    signer = str(artifact.get("signer_key_id"))
    if target_kind == "issuing_key":
        if signer != root["key_id"]:
            raise _error("DEVELOPER_REVOCATION_INVALID", "Issuing Key revocation must be signed by the Developer Root")
        signer_public = _public_from_artifact(str(root["public_key"]))
    else:
        if issuer is None:
            raise _error("DEVELOPER_REVOCATION_INVALID", "Developer/Owner certificate revocation requires its Issuing certificate")
        issuer = validate_issuer_certificate(issuer, root, allow_expired=True)
        if signer != issuer["issuer_key_id"]:
            raise _error("DEVELOPER_REVOCATION_INVALID", "Developer/Owner certificate revocation signer is invalid")
        issuer_start = _parse_utc(str(issuer["not_before"]))
        issuer_end = _parse_utc(str(issuer["expires_at"]))
        if revoked_at < issuer_start - timedelta(minutes=5) or revoked_at >= issuer_end:
            raise _error("DEVELOPER_REVOCATION_INVALID", "Developer/Owner revocation was signed outside the issuer validity window")
        signer_public = _public_from_artifact(str(issuer["public_key"]))
    _verify_signature(artifact, signer_public, signer)
    return dict(artifact)


def _is_revoked(artifact: Mapping[str, Any], revocations: Sequence[Mapping[str, Any]], target_kind: str) -> bool:
    digest = artifact_sha256(artifact)
    target_id = str(artifact.get("serial") if target_kind in {"developer_certificate", "owner_certificate"} else artifact.get("issuer_key_id"))
    return any(
        str(item.get("target_kind")) == target_kind
        and str(item.get("target_id")) == target_id
        and str(item.get("target_sha256")) == digest
        for item in revocations
    )


@dataclass(frozen=True, slots=True)
class VerifiedDeveloperCredential:
    root_key_id: str
    root_fingerprint: str
    issuer_key_id: str
    issuer_fingerprint: str
    developer_id: str
    email: str
    developer_fingerprint: str
    certificate_serial: str
    certificate_sha256: str
    public_key: bytes = field(repr=False)
    capabilities: tuple[str, ...] = field(default_factory=tuple)
    expires_at: str = ""


@dataclass(frozen=True, slots=True)
class VerifiedOwnerCredential:
    root_key_id: str
    root_fingerprint: str
    issuer_key_id: str
    issuer_fingerprint: str
    owner_id: str
    email: str
    owner_fingerprint: str
    certificate_serial: str
    certificate_sha256: str
    public_key: bytes = field(repr=False)
    capabilities: tuple[str, ...] = field(default_factory=tuple)
    expires_at: str = ""


class DeveloperTrustStore:
    






    def __init__(self, roots: Iterable[Mapping[str, Any]] = ()) -> None:
        validated: dict[str, dict[str, Any]] = {}
        for raw in roots:
            root = validate_root_trust(raw)
            key_id = str(root["key_id"])
            previous = validated.get(key_id)
            if previous is not None and artifact_sha256(previous) != artifact_sha256(root):
                raise _error("DEVELOPER_TRUST_STORE_INVALID", "duplicate Root key id has conflicting public artifacts")
            validated[key_id] = root
        self._roots = validated

    @classmethod
    def load(cls, path: Path) -> "DeveloperTrustStore":
        raw = load_json_object(path, max_bytes=MAX_ARTIFACT_BYTES)
        _exact_fields(raw, {"schema", "roots"}, "Developer trust store")
        if raw.get("schema") != TRUST_STORE_SCHEMA or not isinstance(raw.get("roots"), list):
            raise _error("DEVELOPER_TRUST_STORE_INVALID", "Developer trust store schema is invalid")
        if len(raw["roots"]) > 16:
            raise _error("DEVELOPER_TRUST_STORE_INVALID", "Developer trust store contains too many Root keys")
        return cls(raw["roots"])

    def root(self, key_id: str) -> dict[str, Any] | None:
        item = self._roots.get(str(key_id))
        return None if item is None else dict(item)

    def roots(self) -> tuple[dict[str, Any], ...]:
        return tuple(dict(self._roots[key]) for key in sorted(self._roots))

    @property
    def ready(self) -> bool:
        return bool(self._roots)


class DeveloperRevocationSet:
    def __init__(self, revocations: Iterable[Mapping[str, Any]] = ()) -> None:
        values = [dict(item) for item in revocations]
        if len(values) > MAX_REVOCATIONS:
            raise _error("DEVELOPER_REVOCATION_SET_INVALID", "Developer revocation set is too large")
        self.values = tuple(values)

    @classmethod
    def load(cls, path: Path) -> "DeveloperRevocationSet":
        raw = load_json_object(path, max_bytes=8 * 1024 * 1024)
        _exact_fields(raw, {"schema", "revocations"}, "Developer revocation set")
        if raw.get("schema") != REVOCATION_SET_SCHEMA or not isinstance(raw.get("revocations"), list):
            raise _error("DEVELOPER_REVOCATION_SET_INVALID", "Developer revocation set schema is invalid")
        return cls(raw["revocations"])


def validate_login_bundle(bundle: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    _exact_fields(bundle, {"schema", "developer_certificate", "issuer_certificate"}, "Developer login bundle")
    if bundle.get("schema") != LOGIN_BUNDLE_SCHEMA:
        raise _error("DEVELOPER_BUNDLE_INVALID", "Developer login bundle schema is invalid")
    developer = bundle.get("developer_certificate")
    issuer = bundle.get("issuer_certificate")
    if not isinstance(developer, dict) or not isinstance(issuer, dict):
        raise _error("DEVELOPER_BUNDLE_INVALID", "Developer login bundle certificates must be JSON objects")
    return dict(developer), dict(issuer)


def verify_login_bundle(
    bundle: Mapping[str, Any],
    trust_store: DeveloperTrustStore,
    revocation_set: DeveloperRevocationSet | None = None,
    *,
    at: datetime | None = None,
) -> VerifiedDeveloperCredential:
    developer_raw, issuer_raw = validate_login_bundle(bundle)
    root_key_id = str(issuer_raw.get("root_key_id", ""))
    root = trust_store.root(root_key_id)
    if root is None:
        raise _error("DEVELOPER_ROOT_UNTRUSTED", "Developer credential chains to an untrusted Root", root_key_id=root_key_id)
    issuer = validate_issuer_certificate(issuer_raw, root, at=at)
    developer = validate_developer_certificate(developer_raw, issuer, root, at=at)

    validated_revocations: list[dict[str, Any]] = []
    for raw in (revocation_set or DeveloperRevocationSet()).values:
        kind = str(raw.get("target_kind"))
                                                                                              
                                                                                            
                                                                                    
        if kind == "developer_certificate" and str(raw.get("signer_key_id")) != str(issuer["issuer_key_id"]):
            continue
        if kind == "issuing_key" and str(raw.get("signer_key_id")) != str(root["key_id"]):
            continue
        validated_revocations.append(
            validate_revocation(raw, root=root, issuer=issuer if kind == "developer_certificate" else None)
        )
    if _is_revoked(issuer, validated_revocations, "issuing_key"):
        raise _error("DEVELOPER_ISSUER_REVOKED", "Developer Issuing Key has been revoked")
    if _is_revoked(developer, validated_revocations, "developer_certificate"):
        raise _error("DEVELOPER_CERT_REVOKED", "Developer certificate has been revoked")

    capabilities = _validate_capabilities(developer["capabilities"], allowed=issuer["allowed_capabilities"])
    return VerifiedDeveloperCredential(
        root_key_id=str(root["key_id"]),
        root_fingerprint=str(root["fingerprint"]),
        issuer_key_id=str(issuer["issuer_key_id"]),
        issuer_fingerprint=str(issuer["fingerprint"]),
        developer_id=str(developer["developer_id"]),
        email=str(developer["email"]),
        developer_fingerprint=str(developer["fingerprint"]),
        certificate_serial=str(developer["serial"]),
        certificate_sha256=artifact_sha256(developer),
        public_key=_public_from_artifact(str(developer["public_key"])),
        capabilities=capabilities,
        expires_at=str(developer["expires_at"]),
    )


def validate_owner_login_bundle(bundle: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    _exact_fields(bundle, {"schema", "owner_certificate", "issuer_certificate"}, "Root Owner login bundle")
    if bundle.get("schema") != OWNER_LOGIN_BUNDLE_SCHEMA:
        raise _error("DEVELOPER_OWNER_BUNDLE_INVALID", "Root Owner login bundle schema is invalid")
    owner = bundle.get("owner_certificate")
    issuer = bundle.get("issuer_certificate")
    if not isinstance(owner, dict) or not isinstance(issuer, dict):
        raise _error("DEVELOPER_OWNER_BUNDLE_INVALID", "Root Owner login bundle certificates must be JSON objects")
    return dict(owner), dict(issuer)


def verify_owner_login_bundle(
    bundle: Mapping[str, Any],
    trust_store: DeveloperTrustStore,
    revocation_set: DeveloperRevocationSet | None = None,
    *,
    at: datetime | None = None,
) -> VerifiedOwnerCredential:
    owner_raw, issuer_raw = validate_owner_login_bundle(bundle)
    root_key_id = str(issuer_raw.get("root_key_id", ""))
    root = trust_store.root(root_key_id)
    if root is None:
        raise _error("DEVELOPER_ROOT_UNTRUSTED", "Root Owner credential chains to an untrusted Root", root_key_id=root_key_id)
    issuer = validate_issuer_certificate(issuer_raw, root, at=at)
    owner = validate_owner_certificate(owner_raw, issuer, root, at=at)

    validated_revocations: list[dict[str, Any]] = []
    for raw in (revocation_set or DeveloperRevocationSet()).values:
        kind = str(raw.get("target_kind"))
        signer = str(raw.get("signer_key_id"))
        if kind == "issuing_key":
            if signer != str(root["key_id"]):
                continue
            validated_revocations.append(validate_revocation(raw, root=root, issuer=None))
        elif kind == "owner_certificate":
            if signer != str(issuer["issuer_key_id"]):
                continue
            validated_revocations.append(validate_revocation(raw, root=root, issuer=issuer))
    if _is_revoked(issuer, validated_revocations, "issuing_key"):
        raise _error("DEVELOPER_ISSUER_REVOKED", "Root Owner Authority Issuing Key has been revoked")
    if _is_revoked(owner, validated_revocations, "owner_certificate"):
        raise _error("DEVELOPER_OWNER_CERT_REVOKED", "Root Owner Authority certificate has been revoked")

    capabilities = _validate_capabilities(owner["capabilities"], allowed=issuer["allowed_capabilities"])
    return VerifiedOwnerCredential(
        root_key_id=str(root["key_id"]),
        root_fingerprint=str(root["fingerprint"]),
        issuer_key_id=str(issuer["issuer_key_id"]),
        issuer_fingerprint=str(issuer["fingerprint"]),
        owner_id=str(owner["owner_id"]),
        email=str(owner["email"]),
        owner_fingerprint=str(owner["fingerprint"]),
        certificate_serial=str(owner["serial"]),
        certificate_sha256=artifact_sha256(owner),
        public_key=_public_from_artifact(str(owner["public_key"])),
        capabilities=capabilities,
        expires_at=str(owner["expires_at"]),
    )


def _json_without_duplicate_keys(text: str) -> Any:
    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    return json.loads(text, object_pairs_hook=pairs_hook)


def load_json_object(path: Path, *, max_bytes: int = MAX_ARTIFACT_BYTES) -> dict[str, Any]:
    target = Path(path)
    limit = max(1, int(max_bytes))
    try:
        with target.open("rb") as stream:
            payload = stream.read(limit + 1)
    except OSError as exc:
        raise _error("DEVELOPER_ARTIFACT_READ_FAILED", "Developer artifact could not be read", path=str(target)) from exc
    if not payload or len(payload) > limit:
        raise _error("DEVELOPER_ARTIFACT_INVALID", "Developer artifact size is outside the allowed range", path=str(target))
    try:
        value = _json_without_duplicate_keys(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise _error("DEVELOPER_ARTIFACT_INVALID", "Developer artifact JSON is invalid", path=str(target)) from exc
    if not isinstance(value, dict):
        raise _error("DEVELOPER_ARTIFACT_INVALID", "Developer artifact must be a JSON object", path=str(target))
    return value
