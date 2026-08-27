from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
from dataclasses import field
from pathlib import Path
from typing import Any, Callable, Mapping

from arenyxa import __compat_version__, __package_version__
from arenyxa.compat import StrEnum, dataclass
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import utc_now
from arenyxa.infrastructure.atomic_io import atomic_write_bytes, atomic_write_json, read_bytes_limited

RELEASE_HARDENING_SCHEMA = "arenyxa.release-hardening/v1"
MIGRATION_JOURNAL_SCHEMA = "arenyxa.migration-journal/v1"
BACKUP_MANIFEST_SCHEMA = "arenyxa.upgrade-backup/v1"
MAX_MIGRATION_FILE_BYTES = 32 * 1024 * 1024
MAX_UPGRADE_DATABASE_BYTES = 128 * 1024 * 1024 * 1024
MIN_UPGRADE_FREE_BYTES = 512 * 1024 * 1024


def _fail(code: str, message: str, **context: Any) -> ArenyxaError:
    return ArenyxaError(code, message, domain="RELEASE", context=context)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _json_object_no_duplicates(raw: bytes, *, code: str, message: str) -> dict[str, Any]:
    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=hook)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise _fail(code, message) from exc
    if not isinstance(value, dict):
        raise _fail(code, message)
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


class ReleaseChannel(StrEnum):
    STABLE = "stable"
    BETA = "beta"
    DEVELOPER = "developer"
    ENTERPRISE = "enterprise"


@dataclass(frozen=True, slots=True)
class ArtifactMigrationPolicy:
    artifact: str
    current_version: int
    minimum_supported_version: int
    rollback_supported: bool
    notes: str = ""


@dataclass(frozen=True, slots=True)
class ReleasePolicy:
    schema: str = RELEASE_HARDENING_SCHEMA
    lts_support_months: int = 24
    security_fix_months: int = 30
    deprecation_window_months: int = 12
    protocol_current: int = 2
    protocol_minimum: int = 1
    stable_to_enterprise_promotion_requires_native_windows_gate: bool = True
    rc_feature_freeze: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "lts_support_months": self.lts_support_months,
            "security_fix_months": self.security_fix_months,
            "deprecation_window_months": self.deprecation_window_months,
            "protocol_current": self.protocol_current,
            "protocol_minimum": self.protocol_minimum,
            "stable_to_enterprise_promotion_requires_native_windows_gate": self.stable_to_enterprise_promotion_requires_native_windows_gate,
            "rc_feature_freeze": self.rc_feature_freeze,
        }




@dataclass(frozen=True, slots=True)
class ReleaseGateReport:
    regression: bool
    integrity: bool
    migration_rollback: bool
    security_review: bool
    native_windows: bool
    distributed_failure_drill: bool

    def can_promote(self, channel: ReleaseChannel) -> bool:
        channel = ReleaseChannel(channel)
        if channel is ReleaseChannel.DEVELOPER:
            return self.regression and self.integrity
        if channel is ReleaseChannel.BETA:
            return self.regression and self.integrity and self.migration_rollback
                                                                                               
                                                                                                
        return all((
            self.regression, self.integrity, self.migration_rollback, self.security_review,
            self.native_windows, self.distributed_failure_drill,
        ))

    def missing(self, channel: ReleaseChannel) -> list[str]:
        required = {
            ReleaseChannel.DEVELOPER: ("regression", "integrity"),
            ReleaseChannel.BETA: ("regression", "integrity", "migration_rollback"),
            ReleaseChannel.STABLE: ("regression", "integrity", "migration_rollback", "security_review", "native_windows", "distributed_failure_drill"),
            ReleaseChannel.ENTERPRISE: ("regression", "integrity", "migration_rollback", "security_review", "native_windows", "distributed_failure_drill"),
        }[ReleaseChannel(channel)]
        return [name for name in required if not bool(getattr(self, name))]


@dataclass(frozen=True, slots=True)
class MigrationStep:
    artifact: str
    from_version: int
    to_version: int
    upgrade: Callable[[dict[str, Any]], dict[str, Any]]
    downgrade: Callable[[dict[str, Any]], dict[str, Any]] | None = None


class MigrationRegistry:
    






    def __init__(self) -> None:
        self._steps: dict[tuple[str, int], MigrationStep] = {}
        self._policies: dict[str, ArtifactMigrationPolicy] = {}

    def define_policy(self, policy: ArtifactMigrationPolicy) -> None:
        if policy.current_version < policy.minimum_supported_version or policy.minimum_supported_version < 0:
            raise ValueError("invalid migration policy")
        self._policies[policy.artifact] = policy

    def register(self, step: MigrationStep) -> None:
        if step.to_version != step.from_version + 1:
            raise ValueError("migration steps must advance exactly one version")
        key = (step.artifact, step.from_version)
        if key in self._steps:
            raise ValueError("duplicate migration step")
        self._steps[key] = step

    def policy(self, artifact: str) -> ArtifactMigrationPolicy:
        try:
            return self._policies[str(artifact)]
        except KeyError as exc:
            raise _fail("MIGRATION_ARTIFACT_UNKNOWN", "Artifact is not registered for migration", artifact=artifact) from exc

    def plan(self, artifact: str, from_version: int, to_version: int | None = None) -> list[MigrationStep]:
        policy = self.policy(artifact)
        start = int(from_version)
        target = policy.current_version if to_version is None else int(to_version)
        if start < policy.minimum_supported_version or target > policy.current_version or target < start:
            raise _fail(
                "MIGRATION_VERSION_UNSUPPORTED", "Artifact version is outside the supported migration window",
                artifact=artifact, from_version=start, to_version=target,
                minimum=policy.minimum_supported_version, current=policy.current_version,
            )
        steps: list[MigrationStep] = []
        version = start
        while version < target:
            step = self._steps.get((artifact, version))
            if step is None:
                raise _fail("MIGRATION_PATH_MISSING", "No migration path exists for this artifact version", artifact=artifact, version=version)
            steps.append(step)
            version = step.to_version
        return steps

    def migrate(self, artifact: str, payload: Mapping[str, Any], from_version: int, to_version: int | None = None) -> tuple[dict[str, Any], list[MigrationStep]]:
        current = dict(payload)
        steps = self.plan(artifact, from_version, to_version)
        for step in steps:
            current = step.upgrade(current)
            if not isinstance(current, dict):
                raise _fail("MIGRATION_OUTPUT_INVALID", "Migration step returned an invalid artifact", artifact=artifact)
        return current, steps

    def rollback(self, payload: Mapping[str, Any], steps: list[MigrationStep]) -> dict[str, Any]:
        current = dict(payload)
        for step in reversed(steps):
            if step.downgrade is None:
                raise _fail("MIGRATION_ROLLBACK_UNAVAILABLE", "Migration step cannot be reversed", artifact=step.artifact, version=step.to_version)
            current = step.downgrade(current)
        return current


def _settings_8_to_9(payload: dict[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    result.setdefault("adaptive_request_concurrency", True)
    result.setdefault("resource_governor_enabled", True)
    result.setdefault("resource_cpu_soft_percent", 88)
    result.setdefault("resource_memory_soft_percent", 82)
    result.setdefault("resource_min_free_disk_mb", 512)
    result.setdefault("resource_max_browser_instances", 4)
    result.setdefault("experience_profile", "")
    result.setdefault("experience_setup_completed", False)
    result["schema_version"] = 9
    return result


def _settings_9_to_8(payload: dict[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    for key in (
        "adaptive_request_concurrency", "resource_governor_enabled", "resource_cpu_soft_percent",
        "resource_memory_soft_percent", "resource_min_free_disk_mb", "resource_max_browser_instances",
        "experience_profile", "experience_setup_completed",
    ):
        result.pop(key, None)
    result["schema_version"] = 8
    return result


def _workflow_0_to_1(payload: dict[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    result["schema"] = "arenyxa.workflow/v1"
    result.setdefault("metadata", {"portable": True, "secrets": "references-only"})
    result.pop("sha256", None)
    result["sha256"] = hashlib.sha256(_canonical(result)).hexdigest()
    return result


def _workflow_1_to_0(payload: dict[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    result.pop("sha256", None)
    result["schema"] = "arenyxa.workflow/v0"
    return result


def _plugin_0_to_1(payload: dict[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    result.setdefault("api_version", "1")
    result.setdefault("min_app_version", "6.0.0")
    return result


def _plugin_1_to_0(payload: dict[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    result.pop("api_version", None)
    result.pop("min_app_version", None)
    return result


def default_migration_registry() -> MigrationRegistry:
    registry = MigrationRegistry()
    registry.define_policy(ArtifactMigrationPolicy("settings", 9, 8, True, "Explicit v8->v9 settings defaults migration"))
    registry.define_policy(ArtifactMigrationPolicy("workflow_definition", 1, 0, True, "Portable arenyxa.workflow/v0->v1 migration tool"))
    registry.define_policy(ArtifactMigrationPolicy("plugin_api", 1, 0, True, "Legacy manifest metadata -> Plugin API v1"))
                                                                                             
                                                                                               
    registry.define_policy(ArtifactMigrationPolicy("enterprise_vault", 1, 1, True, "v1 authenticated-encryption envelope; older undocumented formats rejected"))
    registry.define_policy(ArtifactMigrationPolicy("distributed_queue", 1, 1, True, "v1 durable queue; migration occurs under database backup/journal"))
    registry.register(MigrationStep("settings", 8, 9, _settings_8_to_9, _settings_9_to_8))
    registry.register(MigrationStep("workflow_definition", 0, 1, _workflow_0_to_1, _workflow_1_to_0))
    registry.register(MigrationStep("plugin_api", 0, 1, _plugin_0_to_1, _plugin_1_to_0))
    return registry


@dataclass(slots=True)
class UpgradePreflightResult:
    allowed: bool
    reasons: list[str] = field(default_factory=list)
    free_bytes: int = 0
    required_bytes: int = 0
    database_integrity: str = "not_checked"

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reasons": list(self.reasons),
            "free_bytes": self.free_bytes,
            "required_bytes": self.required_bytes,
            "database_integrity": self.database_integrity,
        }


class UpgradeTransaction:
    

    def __init__(self, data_root: Path, backup_root: Path) -> None:
        self.data_root = Path(data_root).resolve()
        self.backup_root = Path(backup_root).resolve()
        self.manifest_path = self.backup_root / "manifest.json"
        self.journal_path = self.backup_root / "migration_journal.json"
        self._manifest: dict[str, Any] | None = None

    def preflight(self, paths: list[Path], database_path: Path | None = None) -> UpgradePreflightResult:
        reasons: list[str] = []
        required = MIN_UPGRADE_FREE_BYTES
        total = 0
        for path in paths:
            item = Path(path)
            try:
                resolved = item.resolve(strict=True)
                resolved.relative_to(self.data_root)
            except (OSError, ValueError):
                reasons.append(f"outside_or_missing:{item}")
                continue
            if item.is_symlink() or not resolved.is_file():
                reasons.append(f"unsafe:{item}")
                continue
            size = resolved.stat().st_size
            if size > MAX_MIGRATION_FILE_BYTES:
                reasons.append(f"oversized:{item}")
            total += size
        database_resolved: Path | None = None
        if database_path is not None:
            requested_database = Path(database_path)
            if not requested_database.exists():
                reasons.append("database_path_missing")
            else:
                try:
                    database_resolved = requested_database.resolve(strict=True)
                    database_resolved.relative_to(self.data_root)
                    if requested_database.is_symlink() or not database_resolved.is_file():
                        raise ValueError("unsafe database")
                except (OSError, ValueError):
                    reasons.append("database_path_unsafe")
                    database_resolved = None
                if database_resolved is not None:
                    db_size = database_resolved.stat().st_size
                    if db_size > MAX_UPGRADE_DATABASE_BYTES:
                        reasons.append("database_oversized")
                    total += db_size
        required += total * 3
        target_parent = self.backup_root.parent
        target_parent.mkdir(parents=True, exist_ok=True)
        usage = shutil.disk_usage(target_parent)
        if usage.free < required:
            reasons.append("insufficient_free_space")
        db_status = "not_checked"
        if database_resolved is not None:
            try:
                connection = sqlite3.connect(database_resolved, timeout=10.0)
                try:
                    row = connection.execute("PRAGMA quick_check").fetchone()
                    db_status = "" if row is None else str(row[0])
                finally:
                    connection.close()
                if db_status.casefold() != "ok":
                    reasons.append("database_integrity_failed")
            except sqlite3.DatabaseError:
                db_status = "error"
                reasons.append("database_integrity_failed")
        return UpgradePreflightResult(not reasons, reasons, usage.free, required, db_status)

    def backup(self, paths: list[Path], *, database_paths: list[Path] | None = None) -> dict[str, Any]:
        





        parent = self.backup_root.parent
        parent.mkdir(parents=True, exist_ok=True)
        if self.backup_root.exists() and any(self.backup_root.iterdir()):
            raise _fail("UPGRADE_BACKUP_EXISTS", "Upgrade backup destination is not empty")
        staging = Path(tempfile.mkdtemp(prefix=f".{self.backup_root.name}.staging-", dir=str(parent)))
        try:
            entries: list[dict[str, Any]] = []
            for source in paths:
                requested_source = Path(source)
                if requested_source.is_symlink() or not requested_source.is_file():
                    raise _fail("UPGRADE_PATH_UNSAFE", "Upgrade source must be a regular non-symlink file", path=str(requested_source))
                source = requested_source.resolve(strict=True)
                try:
                    relative = source.relative_to(self.data_root)
                except ValueError as exc:
                    raise _fail("UPGRADE_PATH_OUTSIDE_DATA_ROOT", "Upgrade path is outside the Arenyxa data root", path=str(source)) from exc
                if source.stat().st_size > MAX_MIGRATION_FILE_BYTES:
                    raise _fail("UPGRADE_FILE_TOO_LARGE", "Upgrade control file exceeds the migration safety limit", path=str(source))
                destination = staging / "files" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                payload = read_bytes_limited(source, MAX_MIGRATION_FILE_BYTES)
                atomic_write_bytes(destination, payload)
                entries.append({
                    "relative_path": relative.as_posix(), "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                })
            databases: list[dict[str, Any]] = []
            for source_db in database_paths or []:
                requested_db = Path(source_db)
                if requested_db.is_symlink() or not requested_db.is_file():
                    raise _fail("UPGRADE_DATABASE_INVALID", "Upgrade database must be a regular non-symlink file", path=str(requested_db))
                source_db = requested_db.resolve(strict=True)
                try:
                    relative = source_db.relative_to(self.data_root)
                except ValueError as exc:
                    raise _fail("UPGRADE_PATH_OUTSIDE_DATA_ROOT", "Upgrade database is outside the Arenyxa data root", path=str(source_db)) from exc
                if source_db.stat().st_size > MAX_UPGRADE_DATABASE_BYTES:
                    raise _fail("UPGRADE_DATABASE_INVALID", "Upgrade database exceeds the safety limit", path=str(source_db))
                destination = staging / "databases" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                source_conn = sqlite3.connect(f"file:{source_db.as_posix()}?mode=ro", uri=True, timeout=10.0)
                try:
                    backup_conn = sqlite3.connect(destination, timeout=10.0)
                    try:
                        source_conn.backup(backup_conn)
                        backup_conn.commit()
                        row = backup_conn.execute("PRAGMA quick_check").fetchone()
                        if row is None or str(row[0]).casefold() != "ok":
                            raise _fail("UPGRADE_DATABASE_BACKUP_INVALID", "SQLite backup integrity check failed", path=str(source_db))
                    finally:
                        backup_conn.close()
                finally:
                    source_conn.close()
                databases.append({
                    "relative_path": relative.as_posix(), "size": destination.stat().st_size,
                    "sha256": _sha256(destination),
                })
            manifest = {
                "schema": BACKUP_MANIFEST_SCHEMA,
                "created_at": utc_now(),
                "data_root_sha256": hashlib.sha256(str(self.data_root).encode("utf-8")).hexdigest(),
                "files": entries,
                "databases": databases,
            }
            atomic_write_json(staging / "manifest.json", manifest, ensure_ascii=False, indent=2)
            atomic_write_json(
                staging / "migration_journal.json",
                {
                    "schema": MIGRATION_JOURNAL_SCHEMA,
                    "events": [{
                        "at": utc_now(), "state": "backup_complete",
                        "details": {"file_count": len(entries), "database_count": len(databases)},
                    }],
                },
                ensure_ascii=False, indent=2,
            )
                                                                                                  
                                                                                               
                                
            if self.backup_root.exists():
                self.backup_root.rmdir()
            os.replace(staging, self.backup_root)
            self._manifest = manifest
            return manifest
        except Exception:
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)
            raise

    def _load_manifest(self) -> dict[str, Any]:
        if self._manifest is not None:
            return self._manifest
        try:
            raw = read_bytes_limited(self.manifest_path, 4 * 1024 * 1024)
            payload = _json_object_no_duplicates(
                raw, code="UPGRADE_BACKUP_INVALID", message="Upgrade backup manifest cannot be read",
            )
        except ArenyxaError:
            raise
        except Exception as exc:
            raise _fail("UPGRADE_BACKUP_INVALID", "Upgrade backup manifest cannot be read") from exc
        if payload.get("schema") != BACKUP_MANIFEST_SCHEMA:
            raise _fail("UPGRADE_BACKUP_INVALID", "Upgrade backup manifest schema is invalid")
        required = {"schema", "created_at", "data_root_sha256", "files", "databases"}
        if set(payload) != required:
            raise _fail("UPGRADE_BACKUP_INVALID", "Upgrade backup manifest fields are invalid")
        expected_root = hashlib.sha256(str(self.data_root).encode("utf-8")).hexdigest()
        if not hmac_compare_hex(expected_root, str(payload.get("data_root_sha256", ""))):
            raise _fail("UPGRADE_BACKUP_ROOT_MISMATCH", "Upgrade backup belongs to another Arenyxa data root")
        self._manifest = payload
        return payload

    def verify_backup(self) -> None:
        manifest = self._load_manifest()
        files = manifest.get("files")
        if not isinstance(files, list) or len(files) > 10_000:
            raise _fail("UPGRADE_BACKUP_INVALID", "Upgrade backup file list is invalid")
        for item in files:
            if not isinstance(item, dict):
                raise _fail("UPGRADE_BACKUP_INVALID", "Upgrade backup entry is invalid")
            relative = Path(str(item.get("relative_path", "")))
            if relative.is_absolute() or ".." in relative.parts:
                raise _fail("UPGRADE_BACKUP_INVALID", "Upgrade backup path is unsafe")
            path = self.backup_root / "files" / relative
            payload = read_bytes_limited(path, MAX_MIGRATION_FILE_BYTES)
            if len(payload) != int(item.get("size", -1)) or not hmac_compare_hex(hashlib.sha256(payload).hexdigest(), str(item.get("sha256", ""))):
                raise _fail("UPGRADE_BACKUP_INVALID", "Upgrade backup checksum verification failed", path=relative.as_posix())
        databases = manifest.get("databases", [])
        if not isinstance(databases, list) or len(databases) > 128:
            raise _fail("UPGRADE_BACKUP_INVALID", "Upgrade backup database list is invalid")
        for item in databases:
            if not isinstance(item, dict):
                raise _fail("UPGRADE_BACKUP_INVALID", "Upgrade database backup entry is invalid")
            relative = Path(str(item.get("relative_path", "")))
            if relative.is_absolute() or ".." in relative.parts:
                raise _fail("UPGRADE_BACKUP_INVALID", "Upgrade database backup path is unsafe")
            path = self.backup_root / "databases" / relative
            if not path.is_file() or path.stat().st_size != int(item.get("size", -1)) or not hmac_compare_hex(_sha256(path), str(item.get("sha256", ""))):
                raise _fail("UPGRADE_BACKUP_INVALID", "Upgrade database backup checksum verification failed", path=relative.as_posix())
            connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, timeout=10.0)
            try:
                row = connection.execute("PRAGMA quick_check").fetchone()
                if row is None or str(row[0]).casefold() != "ok":
                    raise _fail("UPGRADE_BACKUP_INVALID", "Upgrade database backup integrity check failed", path=relative.as_posix())
            finally:
                connection.close()

    def restore(self) -> None:
        self.verify_backup()
        manifest = self._load_manifest()
        for item in manifest["files"]:
            relative = Path(str(item["relative_path"]))
            source = self.backup_root / "files" / relative
            destination = self.data_root / relative
            payload = read_bytes_limited(source, MAX_MIGRATION_FILE_BYTES)
            atomic_write_bytes(destination, payload)
        databases = manifest.get("databases", [])
        for item in databases:
            relative = Path(str(item["relative_path"]))
            source = self.backup_root / "databases" / relative
            destination = self.data_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(destination.name + ".restore.tmp")
            temporary.unlink(missing_ok=True)
            source_conn = sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True, timeout=10.0)
            try:
                target_conn = sqlite3.connect(temporary, timeout=10.0)
                try:
                    source_conn.backup(target_conn)
                    target_conn.commit()
                    row = target_conn.execute("PRAGMA quick_check").fetchone()
                    if row is None or str(row[0]).casefold() != "ok":
                        raise _fail("UPGRADE_ROLLBACK_FAILED", "Restored SQLite database failed integrity check", path=relative.as_posix())
                finally:
                    target_conn.close()
            finally:
                source_conn.close()
            os.replace(temporary, destination)
            Path(str(destination) + "-wal").unlink(missing_ok=True)
            Path(str(destination) + "-shm").unlink(missing_ok=True)
        self._journal("rollback_complete", {"file_count": len(manifest["files"]), "database_count": len(databases)})

    def apply_json_migration(
        self,
        path: Path,
        registry: MigrationRegistry,
        artifact: str,
        from_version: int,
        to_version: int | None = None,
    ) -> dict[str, Any]:
        requested = Path(path)
        try:
            target = requested.resolve(strict=True)
            target.relative_to(self.data_root)
        except (OSError, ValueError) as exc:
            raise _fail("MIGRATION_PATH_UNSAFE", "Migration input is outside the Arenyxa data root", path=str(requested)) from exc
        if requested.is_symlink():
            raise _fail("MIGRATION_PATH_UNSAFE", "Migration input cannot be a symbolic link", path=str(requested))
        try:
            raw = read_bytes_limited(target, MAX_MIGRATION_FILE_BYTES)
            payload = _json_object_no_duplicates(
                raw, code="MIGRATION_INPUT_INVALID", message="Migration input JSON is invalid",
            )
        except ArenyxaError:
            raise
        except Exception as exc:
            raise _fail("MIGRATION_INPUT_INVALID", "Migration input JSON is invalid", path=str(target)) from exc
        migrated, steps = registry.migrate(artifact, payload, from_version, to_version)
        atomic_write_json(target, migrated, ensure_ascii=False, indent=2)
        self._journal("artifact_migrated", {
            "artifact": artifact, "path": str(target), "from_version": from_version,
            "to_version": steps[-1].to_version if steps else from_version,
        })
        return migrated

    def execute(self, action: Callable[[], Any]) -> Any:
        
        self.verify_backup()
        self._journal("upgrade_started", {})
        try:
            result = action()
            self._journal("upgrade_committed", {})
            return result
        except Exception as original:
            try:
                self.restore()
            except Exception as rollback_error:
                self._journal("rollback_failed", {"error": type(rollback_error).__name__})
                raise _fail("UPGRADE_ROLLBACK_FAILED", "Upgrade failed and rollback could not restore the verified backup") from rollback_error
            self._journal("upgrade_failed_rolled_back", {"error": type(original).__name__})
            raise

    def _journal(self, state: str, details: Mapping[str, Any]) -> None:
        rows: list[dict[str, Any]] = []
        if self.journal_path.exists():
            try:
                value = _json_object_no_duplicates(
                    read_bytes_limited(self.journal_path, 2 * 1024 * 1024),
                    code="MIGRATION_JOURNAL_INVALID",
                    message="Existing migration journal is unreadable; refusing to fork release history",
                )
            except ArenyxaError:
                raise
            except Exception as exc:
                raise _fail("MIGRATION_JOURNAL_INVALID", "Existing migration journal is unreadable; refusing to fork release history") from exc
            if set(value) != {"schema", "events"} or value.get("schema") != MIGRATION_JOURNAL_SCHEMA or not isinstance(value.get("events"), list):
                raise _fail("MIGRATION_JOURNAL_INVALID", "Existing migration journal schema is invalid; refusing to fork release history")
            validated_rows: list[dict[str, Any]] = []
            for item in value["events"]:
                if not isinstance(item, dict) or set(item) != {"at", "state", "details"} or not isinstance(item.get("details"), dict):
                    raise _fail(
                        "MIGRATION_JOURNAL_INVALID",
                        "Existing migration journal contains a malformed event; refusing to fork release history",
                    )
                if not isinstance(item.get("at"), str) or not isinstance(item.get("state"), str):
                    raise _fail(
                        "MIGRATION_JOURNAL_INVALID",
                        "Existing migration journal contains invalid event fields; refusing to fork release history",
                    )
                validated_rows.append(dict(item))
            rows = validated_rows[-255:]
        rows.append({"at": utc_now(), "state": str(state)[:96], "details": dict(details)})
        atomic_write_json(self.journal_path, {"schema": MIGRATION_JOURNAL_SCHEMA, "events": rows}, ensure_ascii=False, indent=2)


def hmac_compare_hex(left: str, right: str) -> bool:
    import hmac
    return hmac.compare_digest(str(left), str(right))


def compatibility_matrix() -> dict[str, Any]:
    
    policies = default_migration_registry()._policies
    return {
        "schema": "arenyxa.compatibility-matrix/v1",
        "product_release_version": __package_version__,
        "runtime_compatibility_identity": __compat_version__,
        "channels": [channel.value for channel in ReleaseChannel],
        "enterprise_protocol": {
            "current": 2,
            "minimum": 1,
            "strategy": "server accepts N and N-1; worker negotiates the highest common version",
        },
        "plugin_api": {"current": "1", "supported": ["1"], "deprecation_window_months": 12},
        "workflow_portable": {"current": "arenyxa.workflow/v1", "migration_tool_accepts": ["arenyxa.workflow/v0"]},
        "artifacts": {
            key: {
                "current": policy.current_version,
                "minimum_supported": policy.minimum_supported_version,
                "rollback_supported": policy.rollback_supported,
            }
            for key, policy in sorted(policies.items())
        },
        "windows_lanes": {
            "modern": {"python": "3.11-3.13", "qt": "PySide6"},
            "legacy_enterprise": {"python": "3.8", "qt": "PySide2", "browser_recorder": False},
        },
    }
