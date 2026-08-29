from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import sys
from dataclasses import field
from arenyxa.compat import dataclass
from arenyxa.compat import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any

from arenyxa import __display_version__ as __version__
from arenyxa.branding import APP_NAME
from arenyxa.release_keys import OFFICIAL_RELEASE_KEYS
from arenyxa.infrastructure.atomic_io import read_bytes_limited, read_text_limited


class ProvenanceState(StrEnum):
    DEVELOPMENT = "development"
    VERIFIED_OFFICIAL = "verified_official"
    VERIFIED_COMMUNITY = "verified_community"
    MODIFIED = "modified"
    UNVERIFIED = "unverified"
    INVALID = "invalid"


@dataclass(slots=True)
class ProvenanceReport:
    state: ProvenanceState
    channel: str
    product: str = APP_NAME
    version: str = __version__
    build_id: str = ""
    signer_key_id: str = ""
    manifest_hash: str = ""
    signature_valid: bool | None = None
    trusted_signer: bool = False
    modified_files: list[str] = field(default_factory=list)
    unexpected_files: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def is_official(self) -> bool:
        return self.state == ProvenanceState.VERIFIED_OFFICIAL

    @property
    def is_modified(self) -> bool:
        return self.state == ProvenanceState.MODIFIED

    @property
    def display_name(self) -> str:
        mapping = {
            ProvenanceState.DEVELOPMENT: "Source / Development build",
            ProvenanceState.VERIFIED_OFFICIAL: "Verified official build",
            ProvenanceState.VERIFIED_COMMUNITY: "Verified community build",
            ProvenanceState.MODIFIED: "Modified build",
            ProvenanceState.UNVERIFIED: "Unverified distribution",
            ProvenanceState.INVALID: "Invalid release attestation",
        }
        return mapping[self.state]


TRUST_STORE_RESOURCE = Path(__file__).with_name("resources") / "release_trust_store.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _safe_relative(root: Path, relative: str) -> Path:
    normalized = relative.replace("\\", "/")
    if not normalized or normalized.startswith("/") or ":" in normalized.split("/", 1)[0]:
        raise ValueError(f"Unsafe release path: {relative}")
    candidate = (root / normalized).resolve()
    root_resolved = root.resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        raise ValueError(f"Release path escapes installation root: {relative}")
    return candidate


def load_trust_store(path: Path | None = None) -> dict[str, dict[str, str]]:
                                                                                        
                                                                                         
    result: dict[str, dict[str, str]] = {
        str(key_id): {**{str(k): str(v) for k, v in metadata.items()}, "anchor": "compiled"}
        for key_id, metadata in OFFICIAL_RELEASE_KEYS.items()
        if isinstance(metadata, dict) and isinstance(metadata.get("public_key"), str)
    }
    source = path or TRUST_STORE_RESOURCE
    try:
        raw = json.loads(read_text_limited(source, 4 * 1024 * 1024, encoding="utf-8"))
        keys = raw.get("keys", {})
        if not isinstance(keys, dict):
            return result
        for key_id, metadata in keys.items():
            if not isinstance(metadata, dict) or not isinstance(metadata.get("public_key"), str):
                continue
            normalized = {str(k): str(v) for k, v in metadata.items()}
            if str(key_id) in result:
                                                                                    
                continue
            normalized["anchor"] = "external"
            if normalized.get("role", "community").casefold() == "official":
                normalized["role"] = "community"
            result[str(key_id)] = normalized
        return result
    except (OSError, UnicodeError, ValueError, TypeError):
        return result


def _verify_ed25519(public_key_b64: str, signature_b64: str, payload: bytes) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64, validate=True))
        signature = base64.b64decode(signature_b64, validate=True)
        public_key.verify(signature, payload)
        return True
    except (ImportError, ValueError, InvalidSignature, binascii.Error):
        return False


def _read_manifest(manifest_path: Path) -> tuple[dict[str, Any], str]:
                                                                                         
    raw_bytes = read_bytes_limited(manifest_path, 32 * 1024 * 1024)
    parsed = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("Release manifest root must be an object")
    return parsed, hashlib.sha256(raw_bytes).hexdigest()


def _validate_install_manifest(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if int(manifest.get("schema_version", 0) or 0) != 2:
        raise ValueError("Unsupported installation manifest schema version")
    if str(manifest.get("product", "")) != APP_NAME:
        raise ValueError(f"Installation manifest product is not {APP_NAME}")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("Installation manifest files table is missing or empty")
    normalized: dict[str, dict[str, Any]] = {}
    for relative, metadata in files.items():
        if not isinstance(relative, str) or not isinstance(metadata, dict):
            raise ValueError("Installation manifest contains an invalid file entry")
        digest = str(metadata.get("sha256", "")).casefold()
        try:
            size = int(metadata.get("size", -1))
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"Invalid size for manifest file {relative}") from exc
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError(f"Invalid SHA-256 for manifest file {relative}")
        if size < 0:
            raise ValueError(f"Invalid size for manifest file {relative}")
        normalized_relative = relative.replace("\\", "/")
        parsed_path = PurePosixPath(normalized_relative)
        if (
            not normalized_relative
            or parsed_path.is_absolute()
            or ".." in parsed_path.parts
            or ":" in parsed_path.parts[0]
        ):
            raise ValueError(f"Unsafe installation manifest path: {relative}")
        if normalized_relative in normalized:
            raise ValueError(f"Duplicate normalized installation manifest path: {relative}")
        normalized[normalized_relative] = {"sha256": digest, "size": size}
    critical = manifest.get("critical_files", [])
    if not isinstance(critical, list) or any(not isinstance(item, str) for item in critical):
        raise ValueError("Installation manifest critical_files is invalid")
    if any(item.replace("\\", "/") not in normalized for item in critical):
        raise ValueError("Installation manifest references unknown critical files")
    recovery = manifest.get("recovery_payload")
    if not isinstance(recovery, dict):
        raise ValueError("Installation manifest recovery_payload is invalid")
    name = str(recovery.get("name", ""))
    digest = str(recovery.get("sha256", "")).casefold()
    try:
        size = int(recovery.get("size", -1))
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("Installation manifest recovery payload size is invalid") from exc
    if Path(name).name != name or not name:
        raise ValueError("Installation manifest recovery payload name is unsafe")
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest) or size < 0:
        raise ValueError("Installation manifest recovery payload metadata is invalid")
    return normalized


def _find_unexpected_loadable_files(install_root: Path, signed_files: set[str]) -> list[str]:
                                                                                        
                                                                                         
                             
    executable_suffixes = {".exe", ".dll", ".pyd", ".py", ".pyc", ".pth", ".so", ".dylib"}
    allowed_repair = {
        "repair/install_manifest.json",
        "repair/release_attestation.json",
        "repair/recovery_payload.zip",
    }
    unexpected: list[str] = []
    for path in install_root.rglob("*"):
        try:
            if not path.is_file():
                continue
            relative = path.relative_to(install_root).as_posix()
        except (OSError, ValueError):
            continue
        if relative in signed_files or relative in allowed_repair:
            continue
        name = path.name.casefold()
        if name.startswith("unins") and path.suffix.casefold() in {".exe", ".dat", ".msg"}:
            continue
        if path.suffix.casefold() in executable_suffixes:
            unexpected.append(relative)
    return sorted(unexpected)


def verify_release_attestation(
    install_root: Path,
    *,
    attestation_path: Path | None = None,
    manifest_path: Path | None = None,
    trust_store_path: Path | None = None,
    deep_files: bool = False,
) -> ProvenanceReport:
    






    if not bool(getattr(sys, "frozen", False)) and attestation_path is None:
        return ProvenanceReport(
            state=ProvenanceState.DEVELOPMENT,
            channel="source",
            notes=["Source trees are intentionally mutable; integrity enforcement is advisory only."],
        )

    repair_dir = install_root / "repair"
    attestation_path = attestation_path or repair_dir / "release_attestation.json"
    manifest_path = manifest_path or repair_dir / "install_manifest.json"
    if not attestation_path.is_file():
        return ProvenanceReport(
            state=ProvenanceState.UNVERIFIED,
            channel="unknown",
            notes=["No release attestation is present. The build remains usable but cannot claim verified official provenance."],
        )
    if not manifest_path.is_file():
        return ProvenanceReport(
            state=ProvenanceState.INVALID,
            channel="unknown",
            notes=["The signed release attestation exists but the installation manifest is missing."],
        )

    try:
        if attestation_path.stat().st_size > 1024 * 1024:
            raise ValueError("release attestation is unreasonably large")
        attestation = json.loads(read_text_limited(attestation_path, 4 * 1024 * 1024, encoding="utf-8"))
        if not isinstance(attestation, dict):
            raise ValueError("attestation must be an object")
        signed = attestation.get("signed")
        if not isinstance(signed, dict):
            raise ValueError("attestation.signed is missing")
        signature = str(attestation.get("signature", ""))
        manifest, manifest_hash = _read_manifest(manifest_path)
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return ProvenanceReport(
            state=ProvenanceState.INVALID,
            channel="unknown",
            notes=[f"Release attestation could not be parsed: {exc}"],
        )

    if str(attestation.get("signature_algorithm", "")) != "Ed25519":
        return ProvenanceReport(
            state=ProvenanceState.INVALID,
            channel=str(signed.get("channel", "unknown")),
            notes=["Unsupported or missing release signature algorithm."],
        )

    if int(signed.get("schema_version", 0) or 0) != 1:
        return ProvenanceReport(
            state=ProvenanceState.INVALID,
            channel=str(signed.get("channel", "unknown")),
            notes=["Unsupported release attestation schema version."],
        )

    channel = str(signed.get("channel", "unknown")).casefold()
    key_id = str(signed.get("key_id", ""))
    build_id = str(signed.get("build_id", ""))
    expected_manifest_hash = str(signed.get("manifest_sha256", ""))
    report = ProvenanceReport(
        state=ProvenanceState.UNVERIFIED,
        channel=channel,
        product=str(signed.get("product", APP_NAME)),
        version=str(signed.get("version", __version__)),
        build_id=build_id,
        signer_key_id=key_id,
        manifest_hash=manifest_hash,
    )

    if report.product != APP_NAME or report.version != __version__:
        report.state = ProvenanceState.INVALID
        report.notes.append("Attested product/version does not match the running application.")
        return report
    if channel not in {"official", "community"}:
        report.state = ProvenanceState.INVALID
        report.notes.append("Release channel must be either official or community.")
        return report
    if str(signed.get("license", "")) != "GPL-3.0-or-later":
        report.state = ProvenanceState.INVALID
        report.notes.append("Release attestation does not declare the expected GPL-3.0-or-later license identifier.")
        return report
    if not build_id.strip():
        report.state = ProvenanceState.INVALID
        report.notes.append("Release attestation is missing a non-empty build identifier.")
        return report
    if not key_id.strip():
        report.state = ProvenanceState.INVALID
        report.notes.append("Release attestation is missing a signer key identifier.")
        return report
    if not expected_manifest_hash or expected_manifest_hash != manifest_hash:
        report.state = ProvenanceState.MODIFIED
        report.notes.append("Installation manifest differs from the signed release manifest hash.")
        return report

    trust_store = load_trust_store(trust_store_path)
    trusted = trust_store.get(key_id)
    if trusted and str(trusted.get("status", "active")).casefold() in {"revoked", "disabled"}:
        report.state = ProvenanceState.INVALID
        report.notes.append("Release signer is revoked or disabled in the local trust store.")
        return report
    public_key = str((trusted or {}).get("public_key", ""))
    if not public_key:
                                                                                           
                                                                                            
        report.signature_valid = None
        report.notes.append("Signer key is not in the local Arenyxa trust store.")
        return report

    report.trusted_signer = True
    report.signature_valid = _verify_ed25519(public_key, signature, _canonical_json(signed))
    if not report.signature_valid:
        report.state = ProvenanceState.INVALID
        report.notes.append("Release attestation signature is invalid.")
        return report

    try:
        files = _validate_install_manifest(manifest)
    except (ValueError, TypeError, OverflowError) as exc:
        report.state = ProvenanceState.INVALID
        report.notes.append(f"Installation manifest is invalid: {exc}")
        return report

    if deep_files:
        modified: list[str] = []
        for relative, metadata in files.items():
            try:
                target = _safe_relative(install_root, relative)
                expected_hash = str(metadata["sha256"])
                expected_size = int(metadata["size"])
                if not target.is_file():
                    modified.append(relative)
                elif target.stat().st_size != expected_size:
                    modified.append(relative)
                elif _sha256(target) != expected_hash:
                    modified.append(relative)
            except (OSError, ValueError, TypeError):
                modified.append(relative)
        unexpected = _find_unexpected_loadable_files(install_root, set(files))
        recovery = manifest["recovery_payload"]
        recovery_path = install_root / "repair" / str(recovery["name"])
        try:
            if (
                not recovery_path.is_file()
                or recovery_path.stat().st_size != int(recovery["size"])
                or _sha256(recovery_path) != str(recovery["sha256"])
            ):
                modified.append(f"repair/{recovery['name']}")
        except (OSError, TypeError, ValueError, OverflowError):
            modified.append(f"repair/{recovery.get('name', 'recovery_payload.zip')}")
        if modified or unexpected:
            report.state = ProvenanceState.MODIFIED
            report.modified_files = sorted(set(modified))
            report.unexpected_files = unexpected
            if modified:
                report.notes.append(f"{len(set(modified))} installed/recovery file(s) differ from the signed release manifest.")
            if unexpected:
                report.notes.append(f"{len(unexpected)} unexpected executable/loadable file(s) are present in the installation.")
            return report

    signer_role = str((trusted or {}).get("role", "community")).casefold()
    signer_anchor = str((trusted or {}).get("anchor", "external")).casefold()
    if channel == "official":
        if signer_role != "official" or signer_anchor != "compiled":
            report.state = ProvenanceState.INVALID
            report.notes.append("An official-channel claim requires an official key embedded in the Arenyxa build.")
            return report
        report.state = ProvenanceState.VERIFIED_OFFICIAL
    else:
        report.state = ProvenanceState.VERIFIED_COMMUNITY
    return report


def build_identity_summary(report: ProvenanceReport) -> str:
    parts = [report.display_name]
    if report.build_id:
        parts.append(f"Build {report.build_id}")
    if report.signer_key_id:
        parts.append(f"Signer {report.signer_key_id}")
    return " · ".join(parts)


def commercialization_notice() -> str:
    return (
        "GPL-3.0-or-later 允许使用、修改、再分发和合法商业分发；“已验证官方版本”只表示发行来源可验证，并不是功能授权或 DRM。"
        "修改版与第三方版本应明确标识自身来源，并遵守适用的 GPL 许可证与对应源码义务。"
    )
