from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import utc_now
from arenyxa.enterprise.distributed import CURRENT_PROTOCOL, MIN_COMPATIBLE_PROTOCOL
from arenyxa.enterprise.identity import LocalEnterpriseIdentityService
from arenyxa.infrastructure.atomic_io import atomic_write_bytes, read_bytes_limited

MIGRATION_BUNDLE_SCHEMA = "arenyxa.enterprise-authority-migration/v1"
MAX_MIGRATION_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_BACKUP_MEMBER_BYTES = 48 * 1024 * 1024
MAX_MIGRATION_MANIFEST_BYTES = 1024 * 1024


def _fail(code: str, message: str, **context: Any) -> ArenyxaError:
    return ArenyxaError(code, message, domain="ENTERPRISE_MIGRATION", context=context)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64u(value: str, expected: int) -> bytes:
    text = str(value).strip()
    if not text or "=" in text:
        raise _fail("MIGRATION_SIGNATURE_INVALID", "Migration signature encoding is invalid")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * ((4 - len(text) % 4) % 4))
    except Exception as exc:
        raise _fail("MIGRATION_SIGNATURE_INVALID", "Migration signature cannot be decoded") from exc
    if len(raw) != expected or not hmac.compare_digest(_b64u(raw), text):
        raise _fail("MIGRATION_SIGNATURE_INVALID", "Migration signature encoding is non-canonical")
    return raw


class EnterpriseAuthorityMigrationService:
    





    def __init__(self, identity: LocalEnterpriseIdentityService) -> None:
        self.identity = identity

    def export_bundle(self, destination: Path, vault_passphrase: str, *, source_mode: str = "office") -> Path:
        self.identity.require("enterprise.server.manage", "enterprise:server")
        self.identity.require_recent_step_up()
        target = Path(destination)
        if target.exists() and target.is_symlink():
            raise _fail("MIGRATION_PATH_UNSAFE", "Migration bundle destination cannot be a symbolic link")
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="arenyxa-migration-") as folder:
            backup = Path(folder) / "enterprise.aryxbak"
            self.identity.backup(backup, vault_passphrase)
            backup_raw = read_bytes_limited(backup, MAX_BACKUP_MEMBER_BYTES)
            root = self.identity.root_public_identity()
            manifest = {
                "schema": MIGRATION_BUNDLE_SCHEMA,
                "enterprise_id": root["enterprise_id"],
                "root_public_key": root["public_key"],
                "root_fingerprint": root["fingerprint"],
                "source_mode": str(source_mode)[:32],
                "target_mode": "enterprise-server",
                "protocol_min": MIN_COMPATIBLE_PROTOCOL,
                "protocol_max": CURRENT_PROTOCOL,
                "backup_sha256": hashlib.sha256(backup_raw).hexdigest(),
                "backup_size": len(backup_raw),
                "created_at": utc_now(),
            }
            signed_fields = {key: value for key, value in manifest.items() if key not in {"root_public_key", "root_fingerprint"}}
            proof = self.identity.sign_enterprise_artifact(
                _canonical(signed_fields), capability="enterprise.server.manage", resource="enterprise:server", step_up=False,
            )
            manifest["signature"] = proof["signature"]
            temp = target.with_name(target.name + ".tmp")
            with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
                archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8"))
                archive.writestr("enterprise.aryxbak", backup_raw)
            if temp.stat().st_size > MAX_MIGRATION_BUNDLE_BYTES:
                temp.unlink(missing_ok=True)
                raise _fail("MIGRATION_BUNDLE_TOO_LARGE", "Migration bundle exceeds safety limit")
            os.replace(temp, target)
        return target

    @staticmethod
    def verify_bundle(source: Path, expected_root_fingerprint: str = "") -> dict[str, Any]:
        source = Path(source)
        try:
            raw_size = source.stat().st_size
        except OSError as exc:
            raise _fail("MIGRATION_BUNDLE_INVALID", "Migration bundle cannot be read") from exc
        if raw_size <= 0 or raw_size > MAX_MIGRATION_BUNDLE_BYTES or source.is_symlink():
            raise _fail("MIGRATION_BUNDLE_INVALID", "Migration bundle size/path is invalid")
        try:
            with zipfile.ZipFile(source, "r") as archive:
                names = set(archive.namelist())
                if names != {"manifest.json", "enterprise.aryxbak"}:
                    raise _fail("MIGRATION_BUNDLE_INVALID", "Migration bundle has unexpected members")
                total_uncompressed = 0
                for info in archive.infolist():
                    if info.filename.startswith(("/", "\\")) or ".." in Path(info.filename).parts:
                        raise _fail("MIGRATION_BUNDLE_INVALID", "Migration bundle member path is unsafe")
                    limit = MAX_MIGRATION_MANIFEST_BYTES if info.filename == "manifest.json" else MAX_BACKUP_MEMBER_BYTES
                    if info.file_size < 0 or info.file_size > limit:
                        raise _fail("MIGRATION_BUNDLE_TOO_LARGE", "Migration member exceeds safety limit")
                    total_uncompressed += int(info.file_size)
                    if total_uncompressed > MAX_MIGRATION_BUNDLE_BYTES:
                        raise _fail("MIGRATION_BUNDLE_TOO_LARGE", "Migration bundle expands beyond safety limit")
                manifest_raw = archive.read("manifest.json")
                backup_raw = archive.read("enterprise.aryxbak")
        except (zipfile.BadZipFile, OSError) as exc:
            raise _fail("MIGRATION_BUNDLE_INVALID", "Migration bundle is not a valid readable ZIP") from exc
        try:
            manifest = json.loads(manifest_raw.decode("utf-8"), object_pairs_hook=lambda pairs: _no_duplicates(pairs))
        except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise _fail("MIGRATION_BUNDLE_INVALID", "Migration manifest is invalid") from exc
        if not isinstance(manifest, dict) or manifest.get("schema") != MIGRATION_BUNDLE_SCHEMA:
            raise _fail("MIGRATION_BUNDLE_INVALID", "Migration manifest schema is invalid")
        required = {
            "schema", "enterprise_id", "root_public_key", "root_fingerprint", "source_mode", "target_mode",
            "protocol_min", "protocol_max", "backup_sha256", "backup_size", "created_at", "signature",
        }
        if set(manifest) != required or manifest.get("target_mode") != "enterprise-server":
            raise _fail("MIGRATION_BUNDLE_INVALID", "Migration manifest fields are invalid")
        if int(manifest["backup_size"]) != len(backup_raw) or not hmac.compare_digest(
            str(manifest["backup_sha256"]), hashlib.sha256(backup_raw).hexdigest()
        ):
            raise _fail("MIGRATION_BACKUP_TAMPERED", "Encrypted Vault backup checksum does not match the manifest")
        public_raw = _unb64u(str(manifest["root_public_key"]), 32)
        fingerprint = hashlib.sha256(public_raw).hexdigest()
        if not hmac.compare_digest(fingerprint, str(manifest["root_fingerprint"]).casefold()):
            raise _fail("MIGRATION_ROOT_INVALID", "Migration Root public-key fingerprint is invalid")
        expected = str(expected_root_fingerprint).strip().casefold()
        if expected and not hmac.compare_digest(expected, fingerprint):
            raise _fail("MIGRATION_ROOT_MISMATCH", "Migration bundle belongs to another Enterprise")
        signed_fields = {key: value for key, value in manifest.items() if key not in {"signature", "root_public_key", "root_fingerprint"}}
        try:
            Ed25519PublicKey.from_public_bytes(public_raw).verify(_unb64u(str(manifest["signature"]), 64), _canonical(signed_fields))
        except InvalidSignature as exc:
            raise _fail("MIGRATION_SIGNATURE_INVALID", "Migration manifest signature is invalid") from exc
        return {**manifest, "backup_bytes": backup_raw}

    def import_bundle(self, source: Path, vault_passphrase: str, *, expected_root_fingerprint: str = "") -> None:
        verified = self.verify_bundle(source, expected_root_fingerprint)
        if self.identity.unlocked:
            raise _fail("MIGRATION_TARGET_UNLOCKED", "Lock the Enterprise Vault before central authority migration")
        with tempfile.TemporaryDirectory(prefix="arenyxa-migration-import-") as folder:
            backup_path = Path(folder) / "enterprise.aryxbak"
            atomic_write_bytes(backup_path, bytes(verified["backup_bytes"]), mode=0o600)
            self.identity.restore(backup_path, vault_passphrase)


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value
