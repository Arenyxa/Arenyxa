from __future__ import annotations

from arenyxa.console_io import console_write
from arenyxa.infrastructure.process_safety import validated_argv
import hashlib
import importlib.util
import json
import math
import os
import secrets
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
import zipfile
from dataclasses import asdict, field
from arenyxa.compat import dataclass
from datetime import datetime, timezone
from arenyxa.compat import StrEnum
from pathlib import Path
from typing import Any, Iterable, Optional

from arenyxa.branding import (
    APP_NAME,
    DATA_DIR_ENV,
    LEGACY_DATA_DIR_ENV,
    SOURCE_INTEGRITY_ENV,
    LEGACY_SOURCE_INTEGRITY_ENV,
    EXECUTABLE_NAME,
)
from arenyxa.config import AppPaths, AppSettings
from arenyxa.provenance import ProvenanceState, verify_release_attestation
from arenyxa.platform_compat import select_runtime, validate_python_for_runtime
from arenyxa.qt_compat import available_binding_name
from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.atomic_io import atomic_write_bytes, atomic_write_json, read_text_limited
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.data_root_lock import DataRootLease
from arenyxa.infrastructure.plugins import PLUGIN_COMPATIBILITY_ERROR_CODES, PluginManifest
from arenyxa.application.runtime_recovery import RuntimeRecoveryService


REPAIR_LEASE_WAIT_SECONDS = 8.0
REPAIR_MARKER_NAME = "repair_in_progress.json"
REPAIR_HANDOFF_GRACE_SECONDS = 30.0
REPAIR_PIP_TIMEOUT_SECONDS = 900.0
REPAIR_OPTIONAL_PIP_TIMEOUT_SECONDS = 300.0


def _repair_marker_path(data_root: Path) -> Path:
    return Path(data_root).resolve() / "repair" / REPAIR_MARKER_NAME


def _windows_process_running(pid: int, wait_milliseconds: int = 0) -> bool | None:
    










    try:
        import ctypes
        from ctypes import wintypes

        synchronize = 0x00100000
        wait_object_0 = 0x00000000
        wait_timeout = 0x00000102
        error_access_denied = 5
        error_invalid_parameter = 87

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL

        ctypes.set_last_error(0)
        handle = kernel32.OpenProcess(synchronize, False, int(pid))
        if not handle:
            error = ctypes.get_last_error()
            if error == error_invalid_parameter:
                return False
            if error == error_access_denied:
                                                                                     
                return True
            return None
        try:
            result = int(
                kernel32.WaitForSingleObject(handle, max(0, int(wait_milliseconds)))
            )
        finally:
            kernel32.CloseHandle(handle)
        if result == wait_object_0:
            return False
        if result == wait_timeout:
            return True
        return None
    except Exception:                                                                           
        return None


def _process_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if os.name == "nt":
        state = _windows_process_running(pid)
                                                                                            
                                                                                             
        return True if state is None else state
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
                                                               
        return True
    except OSError:
        return False
    return True


def _load_repair_marker(data_root: Path) -> Optional[dict[str, Any]]:
    path = _repair_marker_path(data_root)
    try:
        payload = json.loads(read_text_limited(path, 64 * 1024, encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def repair_worker_active(data_root: Path) -> bool:
    





    path = _repair_marker_path(data_root)
    marker = _load_repair_marker(data_root)
    if marker is None:
        return False
    try:
        owner_pid = int(marker.get("owner_pid", 0))
    except (TypeError, ValueError):
        owner_pid = 0
    state = str(marker.get("state", "active"))
    if _process_is_running(owner_pid):
        return True

                                                                                             
                                                                                            
                                                                           
    if state == "handoff":
        try:
            age = max(0.0, time.time() - float(marker.get("created_epoch", 0.0)))
        except (TypeError, ValueError):
            age = REPAIR_HANDOFF_GRACE_SECONDS + 1.0
        if age <= REPAIR_HANDOFF_GRACE_SECONDS:
            return True

                                                                                          
                                                                                         
    latest = _load_repair_marker(data_root)
    if latest == marker:
        try:
            path.unlink(missing_ok=True)
        except OSError:
                                                                                               
                                                                                              
            return True
    else:
        return repair_worker_active(data_root)
    return False


def _write_repair_marker(data_root: Path, owner_pid: int, token: str, state: str) -> Path:
    path = _repair_marker_path(data_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(
        path,
        {
            "owner_pid": int(owner_pid),
            "token": str(token),
            "state": str(state),
            "created_epoch": time.time(),
        },
        mode=stat.S_IRUSR | stat.S_IWUSR,
    )
    return path


def clear_repair_marker(data_root: Path, token: Optional[str] = None) -> None:
    path = _repair_marker_path(data_root)
    if token is not None:
        marker = _load_repair_marker(data_root)
        if marker is None or str(marker.get("token", "")) != str(token):
            return
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


class RepairCategory(StrEnum):
    ENCODING_UI = "encoding_ui"
    STARTUP_CRASH = "startup_crash"
    PROGRAM_FILES = "program_files"
    DEPENDENCIES = "dependencies"
    DATABASE_INDEX = "database_index"
    SETTINGS_UI = "settings_ui"
    PLUGINS = "plugins"
    CAPTURE_STACK = "capture_stack"
    PERMISSIONS_PATHS = "permissions_paths"
    CACHE_TEMP = "cache_temp"
    SERVER_RUNTIME = "server_runtime"
    PERFORMANCE_MOTION = "performance_motion"
    FEATURE_INTEGRATION = "feature_integration"
    RUNTIME_STATE = "runtime_state"
    OTHER = "other"


CATEGORY_LABELS: dict[RepairCategory, str] = {
    RepairCategory.ENCODING_UI: "乱码 / 语言 / 字体显示异常",
    RepairCategory.STARTUP_CRASH: "启动失败 / 崩溃 / 闪退 / 崩溃循环",
    RepairCategory.PROGRAM_FILES: "程序文件缺失 / 损坏 / 被意外修改",
    RepairCategory.DEPENDENCIES: "Python / Qt / 模块依赖加载异常",
    RepairCategory.DATABASE_INDEX: "数据库 / FTS 索引 / WAL 异常",
    RepairCategory.SETTINGS_UI: "设置 / 主题 / 窗口布局异常",
    RepairCategory.PLUGINS: "插件加载 / 插件权限 / 插件崩溃异常",
    RepairCategory.CAPTURE_STACK: "抓包 / tshark / dumpcap / 进程监控异常",
    RepairCategory.PERMISSIONS_PATHS: "目录 / 权限 / 写入 / 存储路径异常",
    RepairCategory.CACHE_TEMP: "缓存 / 临时文件 / 残留状态异常",
    RepairCategory.SERVER_RUNTIME: "本地服务 / 端口 / 运行时异常",
    RepairCategory.PERFORMANCE_MOTION: "动画 / 渲染 / 卡顿 / 性能配置异常",
    RepairCategory.FEATURE_INTEGRATION: "高级功能 / 模块接线 / 能力完整性异常",
    RepairCategory.RUNTIME_STATE: "运行状态 / 中断任务 / 恢复点异常",
    RepairCategory.OTHER: "其他 / 无法确定的问题",
}


def fault_fingerprint(code: str, category: RepairCategory | str) -> str:
    




    category_value = category.value if isinstance(category, RepairCategory) else str(category)
    digest = hashlib.sha256(f"arenyxa-repair-v1\0{category_value}\0{str(code).strip().upper()}".encode("utf-8")).hexdigest()
    return f"NXF-{digest[:12].upper()}"


@dataclass(slots=True)
class RepairFinding:
    code: str
    category: RepairCategory
    severity: str
    title: str
    detail: str
    evidence: str = ""
    fingerprint: str = ""

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = fault_fingerprint(self.code, self.category)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["category"] = self.category.value
        return payload


@dataclass(slots=True)
class HealthReport:
    generated_at: str
    install_root: str
    data_root: str
    source_mode: bool
    findings: list[RepairFinding] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return not self.findings

    @property
    def categories(self) -> list[RepairCategory]:
        result: list[RepairCategory] = []
        for finding in self.findings:
            if finding.category not in result:
                result.append(finding.category)
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "install_root": self.install_root,
            "data_root": self.data_root,
            "source_mode": self.source_mode,
            "healthy": self.healthy,
            "findings": [item.to_dict() for item in self.findings],
        }


def append_feature_integration_findings(report: HealthReport, context: object) -> HealthReport:
    





    from arenyxa.application.feature_audit import audit_advanced_features

    existing_codes = {item.code for item in report.findings}
    feature_report = audit_advanced_features(context)
    for issue in feature_report.issues:
        code = f"FEATURE_WIRING_{issue.feature_id.upper().replace('.', '_')}"
        if code in existing_codes:
            continue
        report.findings.append(
            RepairFinding(
                code=code,
                category=RepairCategory.FEATURE_INTEGRATION,
                severity="critical",
                title=f"高级功能接线异常：{issue.label}",
                detail=issue.detail or "高级界面存在，但对应运行时能力不完整。",
                evidence=", ".join(issue.missing),
            )
        )
        existing_codes.add(code)
    return report


@dataclass(slots=True)
class RepairPlan:
    install_root: str
    data_root: str
    categories: list[str]
    detected_findings: list[dict[str, Any]] = field(default_factory=list)
    parent_pid: int = 0
    relaunch: bool = True
    source_mode: bool = True
    created_at: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = _utc_now()

    @classmethod
    def load(cls, path: Path) -> "RepairPlan":
        raw = json.loads(read_text_limited(path, 4 * 1024 * 1024, encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Repair plan root must be a JSON object")
        allowed_fields = set(cls.__dataclass_fields__)
        if set(raw) - allowed_fields:
            raise ValueError("Repair plan contains unsupported fields")
        plan = cls(**raw)
        plan.validate()
        return plan

    def validate(self) -> None:
        if not isinstance(self.install_root, str) or not self.install_root.strip():
            raise ValueError("Repair plan install_root is invalid")
        if not isinstance(self.data_root, str) or not self.data_root.strip():
            raise ValueError("Repair plan data_root is invalid")
        if not isinstance(self.categories, list) or not all(isinstance(item, str) for item in self.categories):
            raise ValueError("Repair plan categories are invalid")
        allowed_categories = {item.value for item in RepairCategory}
        unknown = set(self.categories) - allowed_categories
        if unknown:
            raise ValueError(f"Repair plan contains unknown categories: {sorted(unknown)}")
        if not isinstance(self.detected_findings, list) or not all(isinstance(item, dict) for item in self.detected_findings):
            raise ValueError("Repair plan findings are invalid")
        if not isinstance(self.parent_pid, int) or self.parent_pid < 0:
            raise ValueError("Repair plan parent_pid is invalid")
        if not isinstance(self.relaunch, bool) or not isinstance(self.source_mode, bool):
            raise ValueError("Repair plan flags are invalid")

    def save(self, path: Path) -> Path:
        self.validate()
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(path, asdict(self), mode=stat.S_IRUSR | stat.S_IWUSR)
        return path


@dataclass(slots=True)
class RepairActionResult:
    action: str
    status: str
    detail: str


@dataclass(slots=True)
class RepairResult:
    started_at: str
    finished_at: str
    success: bool
    categories: list[str]
    backup_dir: str
    actions: list[RepairActionResult]
    unresolved: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "success": self.success,
            "categories": self.categories,
            "backup_dir": self.backup_dir,
            "actions": [asdict(item) for item in self.actions],
            "unresolved": self.unresolved,
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def installation_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def source_mode() -> bool:
    return not bool(getattr(sys, "frozen", False))


def repair_resource(name: str) -> Path:
    
    candidates = [Path(__file__).resolve().parent / "resources" / name]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / "arenyxa" / "resources" / name)
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).resolve().parent / "_internal" / "arenyxa" / "resources" / name)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def _packaged_repair_artifacts(install_root: Path, data_root: Path | None = None) -> tuple[Path, Path]:
    installed_manifest = install_root / "repair" / "install_manifest.json"
    installed_payload = install_root / "repair" / "recovery_payload.zip"
    if installed_manifest.is_file() and installed_payload.is_file():
        return installed_manifest, installed_payload
    if data_root is not None:
        known_good = data_root / "repair" / "known_good"
        return known_good / "install_manifest.json", known_good / "recovery_payload.zip"
    return installed_manifest, installed_payload


def _validate_packaged_recovery(manifest_path: Path, payload_path: Path, *, deep: bool = True) -> dict[str, Any]:
    if not manifest_path.is_file():
        raise FileNotFoundError(f"install_manifest.json 缺失: {manifest_path}")
    if not payload_path.is_file():
        raise FileNotFoundError(f"recovery_payload.zip 缺失: {payload_path}")
    manifest = json.loads(read_text_limited(manifest_path, 32 * 1024 * 1024, encoding="utf-8"))
    recovery = dict(manifest.get("recovery_payload", {}))
    expected = str(recovery.get("sha256", ""))
    expected_size = int(recovery.get("size", -1))
    if not expected:
        raise ValueError("recovery payload SHA-256 is missing from manifest")
    if expected_size >= 0 and payload_path.stat().st_size != expected_size:
        raise ValueError("recovery_payload.zip size mismatch")
    if deep:
        if _sha256(payload_path) != expected:
            raise ValueError("recovery_payload.zip SHA-256 不匹配")
        with zipfile.ZipFile(payload_path, "r") as archive:
            bad = archive.testzip()
            if bad is not None:
                raise zipfile.BadZipFile(f"recovery payload CRC failed: {bad}")
    return manifest


def ensure_known_good_seed(paths: AppPaths) -> None:
    
    known_good = paths.root / "repair" / "known_good"
    try:
        known_good.mkdir(parents=True, exist_ok=True)
        if getattr(sys, "frozen", False):
            install_root = installation_root()
            attestation_path = install_root / "repair" / "release_attestation.json"
            if attestation_path.is_file():
                provenance = verify_release_attestation(install_root, deep_files=False)
                if provenance.state not in {ProvenanceState.VERIFIED_OFFICIAL, ProvenanceState.VERIFIED_COMMUNITY}:
                                                                                                    
                    return
            manifest_path, payload_path = _packaged_repair_artifacts(install_root)
            manifest = _validate_packaged_recovery(manifest_path, payload_path, deep=False)
            recovery = dict(manifest.get("recovery_payload", {}))
            expected = str(recovery.get("sha256", ""))
            expected_size = int(recovery.get("size", -1))
            target = known_good / "recovery_payload.zip"
            cached_manifest = known_good / "install_manifest.json"
            cache_current = False
            if target.is_file() and cached_manifest.is_file():
                try:
                    cached = json.loads(read_text_limited(cached_manifest, 32 * 1024 * 1024, encoding="utf-8"))
                    cached_hash = str(dict(cached.get("recovery_payload", {})).get("sha256", ""))
                    cache_current = cached_hash == expected and (expected_size < 0 or target.stat().st_size == expected_size)
                except (OSError, ValueError, TypeError, json.JSONDecodeError):
                    cache_current = False
            if not cache_current:
                                                                                            
                _validate_packaged_recovery(manifest_path, payload_path, deep=True)
                temporary = target.with_suffix(".tmp")
                shutil.copy2(payload_path, temporary)
                temporary.replace(target)
                shutil.copy2(manifest_path, cached_manifest)
            attestation_path = install_root / "repair" / "release_attestation.json"
            if attestation_path.is_file():
                                                                                                
                shutil.copy2(attestation_path, known_good / "release_attestation.json")
            return

        seed = repair_resource("repair_seed.zip")
        manifest_path = repair_resource("repair_manifest.json")
        if not seed.is_file() or not manifest_path.is_file():
            return
        manifest = json.loads(read_text_limited(manifest_path, 32 * 1024 * 1024, encoding="utf-8"))
        expected = str(manifest.get("seed_sha256", ""))
        if not expected or _sha256(seed) != expected:
            return
        with zipfile.ZipFile(seed, "r") as archive:
            if archive.testzip() is not None:
                return
        target = known_good / "repair_seed.zip"
        if not target.is_file() or _sha256(target) != expected:
            temporary = target.with_suffix(".tmp")
            shutil.copy2(seed, temporary)
            temporary.replace(target)
        shutil.copy2(manifest_path, known_good / "repair_manifest.json")
    except (OSError, ValueError, zipfile.BadZipFile, json.JSONDecodeError):
        return

def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    base = root.resolve()
    try:
        return resolved.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"Path escapes repair root: {resolved}") from exc


def _directory_size(root: Path, limit: int = 3 * 1024 * 1024 * 1024) -> int:
    total = 0
    if not root.exists():
        return 0
    try:
        for path in root.rglob("*"):
            try:
                if path.is_file() and not path.is_symlink():
                    total += path.stat().st_size
                    if total >= limit:
                        return total
            except OSError:
                continue
    except OSError:
        return total
    return total


class StartupHealthScanner:
    

    REQUIRED_MODULES = {
        "lxml": "lxml",
        "cssselect": "cssselect",
        "dns": "dnspython",
        "openpyxl": "openpyxl",
        "tzdata": "tzdata",
        "cryptography": "cryptography",
    }
    SUPPORTED_LOCALES = {"system", "zh_CN", "zh_TW", "en_US", "fr_FR", "ru_RU", "de_DE", "ja_JP", "ko_KR", "ar_SA", "la_VA"}
    SUPPORTED_THEMES = {"modern_dark", "aurora_glass", "clean_light", "terminal_green", "professional_graphite", "blue_productivity"}

    def __init__(self, paths: AppPaths, install_root: Path | None = None, *, ignore_current_session: bool = False) -> None:
        self.paths = paths
        self.install_root = (install_root or installation_root()).resolve()
        self.source_mode = source_mode()
        self.ignore_current_session = bool(ignore_current_session)
        self.findings: list[RepairFinding] = []
        self._category_codes: set[tuple[RepairCategory, str]] = set()

    def scan(self) -> HealthReport:
        self.findings.clear()
        self._category_codes.clear()
        self._check_previous_crash()
        self._check_settings()
        self._check_paths()
        self._check_database()
        self._check_runtime_state()
        self._check_plugin_manifests()
        self._check_runtime_compatibility()
        self._check_dependencies()
        self._check_program_integrity()
        self._check_logs()
        self._check_cache_pressure()
        report = HealthReport(
            generated_at=_utc_now(),
            install_root=str(self.install_root),
            data_root=str(self.paths.root),
            source_mode=self.source_mode,
            findings=list(self.findings),
        )
        repair_dir = self.paths.root / "repair"
        repair_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(repair_dir / "last_health_report.json", report.to_dict())
        return report

    def _add(
        self,
        code: str,
        category: RepairCategory,
        severity: str,
        title: str,
        detail: str,
        evidence: str = "",
    ) -> None:
        key = (category, code)
        if key in self._category_codes:
            return
        self._category_codes.add(key)
        self.findings.append(RepairFinding(code, category, severity, title, detail, evidence))

    def _check_runtime_compatibility(self) -> None:
        try:
            runtime = select_runtime()
            validate_python_for_runtime(runtime)
        except ArenyxaError as exc:
            self._add(
                exc.code,
                RepairCategory.DEPENDENCIES,
                "critical",
                "Python / Windows 运行时不受支持",
                exc.message,
                f"python={sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}",
            )
        try:
            SQLiteStore.validate_runtime()
        except ArenyxaError as exc:
            self._add(
                exc.code,
                RepairCategory.DATABASE_INDEX,
                "critical",
                "SQLite 运行时不兼容",
                exc.message,
                f"sqlite={sqlite3.sqlite_version}",
            )

    def _check_previous_crash(self) -> None:
        marker = self.paths.root / "crash.marker"
        if not marker.exists():
            return
        if self.ignore_current_session:
            try:
                payload = json.loads(read_text_limited(marker, 64 * 1024, encoding="utf-8"))
                if (
                    isinstance(payload, dict)
                    and int(payload.get("pid", -1)) == os.getpid()
                    and str(payload.get("phase", "")).casefold() == "running"
                ):
                    return
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                                                                                     
                pass
        self._add(
            "PREVIOUS_UNCLEAN_EXIT",
            RepairCategory.STARTUP_CRASH,
            "warning",
            "检测到上次异常退出",
            "上一次 Arenyxa 没有完成正常关闭流程。修复中心可以检查程序文件、设置、数据库与插件状态。",
            str(marker),
        )

    def _check_settings(self) -> None:
        path = self.paths.root / "settings.json"
        if not path.exists():
            return
        try:
            text = read_text_limited(path, 2 * 1024 * 1024, encoding="utf-8")
            raw = json.loads(text)
            if not isinstance(raw, dict):
                self._add(
                    "SETTINGS_ROOT_INVALID",
                    RepairCategory.SETTINGS_UI,
                    "critical",
                    "设置文件结构无效",
                    "settings.json 的根节点必须是 JSON object。修复时会先备份原文件，再重建安全设置。",
                    type(raw).__name__,
                )
                return
        except UnicodeDecodeError as exc:
            self._add(
                "SETTINGS_ENCODING_INVALID",
                RepairCategory.ENCODING_UI,
                "critical",
                "设置文件编码异常",
                "settings.json 不是有效 UTF-8，可能造成乱码、语言切换异常或启动失败。",
                str(exc),
            )
            return
        except (OSError, ValueError) as exc:
            self._add(
                "SETTINGS_JSON_INVALID",
                RepairCategory.SETTINGS_UI,
                "critical",
                "设置文件损坏",
                "settings.json 无法解析。修复会先备份原文件，再保留可恢复信息并重建有效配置。",
                str(exc),
            )
            return
        locale = str(raw.get("locale", "system"))
        if locale not in self.SUPPORTED_LOCALES:
            self._add(
                "LOCALE_UNSUPPORTED",
                RepairCategory.ENCODING_UI,
                "warning",
                "语言配置无效",
                f"当前 locale={locale!r} 不在 Arenyxa 支持列表中。",
                locale,
            )
        theme = str(raw.get("theme", "modern_dark"))
        if theme not in self.SUPPORTED_THEMES:
            self._add(
                "THEME_UNSUPPORTED",
                RepairCategory.SETTINGS_UI,
                "warning",
                "主题配置无效",
                f"当前 theme={theme!r} 不存在。",
                theme,
            )
        numeric_rules = {
            "max_workers": (1, 64),
            "request_concurrency": (1, 64),
            "per_host_concurrency": (1, 32),
            "max_response_bytes": (1024 * 1024, 1024 * 1024 * 1024),
            "default_timeout_seconds": (1.0, 600.0),
            "glass_strength": (0.0, 1.0),
            "motion_strength": (0.0, 1.0),
            "blur_strength": (0.0, 64.0),
        }
        for key, (low, high) in numeric_rules.items():
            if key not in raw:
                continue
            try:
                value = float(raw[key])
            except (TypeError, ValueError):
                value = low - 1
            if not low <= value <= high:
                self._add(
                    f"SETTING_RANGE_{key.upper()}", RepairCategory.SETTINGS_UI, "warning",
                    "设置参数超出安全范围", f"{key}={raw.get(key)!r} 不在允许范围 {low}..{high}。"
                )
        if raw.get("performance_mode", "auto") not in {"auto", "quality", "balanced", "efficiency"}:
            self._add(
                "SETTING_PERFORMANCE_MODE_INVALID", RepairCategory.SETTINGS_UI, "warning",
                "性能模式配置无效", f"performance_mode={raw.get('performance_mode')!r}。"
            )
        try:
            request_concurrency = int(raw.get("request_concurrency", 8))
            per_host_concurrency = int(raw.get("per_host_concurrency", 4))
        except (TypeError, ValueError, OverflowError):
            request_concurrency = per_host_concurrency = 0
        if request_concurrency > 0 and per_host_concurrency > request_concurrency:
            self._add(
                "PER_HOST_CONCURRENCY_EXCEEDS_GLOBAL",
                RepairCategory.SETTINGS_UI,
                "warning",
                "单域名并发高于全局并发",
                "per_host_concurrency 不能高于 request_concurrency；加载时会安全收敛。",
                f"{per_host_concurrency}>{request_concurrency}",
            )

        boolean_names = (
            "reduce_motion", "high_contrast", "edge_flow", "live_data_motion",
            "left_sidebar_collapsed", "advanced_nav_expanded", "developer_nav_expanded",
            "inspector_collapsed", "diagnostics_include_paths", "developer_mode",
            "adaptive_request_concurrency",
        )
        for key in boolean_names:
            if key in raw and not isinstance(raw[key], bool):
                self._add(
                    f"SETTING_BOOL_{key.upper()}", RepairCategory.SETTINGS_UI, "warning",
                    "设置布尔值类型无效", f"{key} 应为 true/false，当前为 {raw.get(key)!r}。"
                )
        if raw.get("developer_mode") is False and raw.get("developer_nav_expanded") is True:
            self._add(
                "DEVELOPER_NAV_STATE_INCONSISTENT", RepairCategory.SETTINGS_UI, "info",
                "开发者导航状态不一致", "Developer Mode 已关闭，但开发者导航仍记录为展开；修复时会安全折叠。"
            )
        if "\ufffd" in text:
            self._add(
                "SETTINGS_REPLACEMENT_CHARACTER",
                RepairCategory.ENCODING_UI,
                "warning",
                "设置文本包含替换字符",
                "检测到 Unicode replacement character，可能是历史编码损坏造成的乱码。",
            )

    def _check_paths(self) -> None:
        for label, path in {
            "应用数据": self.paths.root,
            "日志": self.paths.logs,
            "缓存": self.paths.cache,
            "导出": self.paths.exports,
            "抓包": self.paths.captures,
            "项目": self.paths.projects,
            "插件": self.paths.plugins,
            "浏览器 Profile": self.paths.profiles,
        }.items():
            try:
                path.mkdir(parents=True, exist_ok=True)
                probe = path / f".arenyxa-write-test-{os.getpid()}"
                probe.write_bytes(b"ok")
                probe.unlink(missing_ok=True)
            except OSError as exc:
                self._add(
                    f"PATH_NOT_WRITABLE_{label}",
                    RepairCategory.PERMISSIONS_PATHS,
                    "critical",
                    f"{label}目录不可写",
                    f"Arenyxa 需要写入 {path}，当前权限或路径状态不正常。",
                    str(exc),
                )
        try:
            free = shutil.disk_usage(self.paths.root).free
            if free < 512 * 1024 * 1024:
                self._add(
                    "LOW_DISK_SPACE",
                    RepairCategory.PERMISSIONS_PATHS,
                    "warning",
                    "可用磁盘空间过低",
                    "Arenyxa 数据目录所在磁盘不足 512 MiB，可能导致数据库、日志、抓包或导出失败。",
                    f"free={free}",
                )
        except OSError:
            pass

    def _check_database(self) -> None:
        path = self.paths.database
        if not path.exists() or path.stat().st_size == 0:
            return
        try:
            uri = f"file:{path.as_posix()}?mode=ro"
            connection = sqlite3.connect(uri, uri=True, timeout=1.0)
            try:
                result = connection.execute("PRAGMA quick_check(1)").fetchone()
            finally:
                connection.close()
            if not result or str(result[0]).lower() != "ok":
                self._add(
                    "DATABASE_QUICK_CHECK_FAILED",
                    RepairCategory.DATABASE_INDEX,
                    "critical",
                    "数据库完整性检查失败",
                    "arenyxa.db 的 SQLite quick_check 未通过。修复会先创建完整备份，再尝试安全恢复。",
                    str(result[0] if result else "no result"),
                )
        except sqlite3.DatabaseError as exc:
            self._add(
                "DATABASE_OPEN_FAILED",
                RepairCategory.DATABASE_INDEX,
                "critical",
                "数据库无法正常打开",
                "SQLite 报告数据库错误。修复中心会保留原始数据库后再尝试恢复。",
                str(exc),
            )
        except OSError as exc:
            self._add(
                "DATABASE_IO_FAILED",
                RepairCategory.PERMISSIONS_PATHS,
                "critical",
                "数据库文件访问失败",
                str(path),
                str(exc),
            )

    def _check_runtime_state(self) -> None:
        if not self.paths.database.exists() or self.paths.database.stat().st_size == 0:
            return
        try:
            audit = RuntimeRecoveryService(SQLiteStore(self.paths.database)).audit()
        except (sqlite3.DatabaseError, OSError, ValueError) as exc:
                                                                                                
            return
        if audit.has_stale_active_state:
            evidence = (
                f"runs={len(audit.active_runs)},captures={len(audit.active_captures)},"
                f"workflows={len(audit.active_workflows)},revisions={len(audit.building_revisions)}"
            )
            self._add(
                "STALE_RUNTIME_OWNERSHIP", RepairCategory.RUNTIME_STATE, "warning",
                "检测到没有当前进程所有者的运行状态",
                "Run/Capture/Workflow/Dataset 中仍存在活动状态。自愈会保留数据，并把它们关闭或转换为可恢复的 interrupted 状态。",
                evidence,
            )
        if audit.invalid_schedules:
            self._add(
                "INVALID_PERSISTED_SCHEDULE", RepairCategory.RUNTIME_STATE, "warning",
                "检测到无效的自动化计划",
                "无效计划不会被删除；修复中心只会将其禁用，保留原规则供用户检查。",
                ", ".join(audit.invalid_schedules[:12]),
            )
        if audit.invalid_revision_states or audit.broken_interrupted_revisions:
            ids = [*audit.invalid_revision_states, *audit.broken_interrupted_revisions]
            self._add(
                "DATASET_RECOVERY_STATE_INVALID", RepairCategory.RUNTIME_STATE, "warning",
                "Dataset Revision 恢复状态异常",
                "Revision 生命周期或恢复元数据不合法。修复会把不可恢复项标记为 failed，但不会删除已写入记录。",
                ", ".join(ids[:12]),
            )
        if audit.invalid_workflow_states or audit.broken_interrupted_workflows:
            ids = [*audit.invalid_workflow_states, *audit.broken_interrupted_workflows]
            self._add(
                "WORKFLOW_RECOVERY_STATE_INVALID", RepairCategory.RUNTIME_STATE, "warning",
                "Workflow 恢复点异常",
                "执行状态、工作流定义、输入 Revision 或输出 Revision 无法组成安全恢复链。修复会终止不可恢复执行并保留检查点/输出证据。",
                ", ".join(ids[:12]),
            )

    def _check_plugin_manifests(self) -> None:
        root = self.paths.plugins
        if not root.exists():
            return
        invalid: list[str] = []
        incompatible: list[str] = []
        for manifest in root.glob("*/plugin.json"):
            if "quarantine" in manifest.parts:
                continue
            try:
                                                                                          
                                                                                           
                                                                               
                parsed = PluginManifest.load(manifest)
                parsed.validate_compatibility()
            except ArenyxaError as exc:
                if exc.code in PLUGIN_COMPATIBILITY_ERROR_CODES:
                    incompatible.append(manifest.parent.name)
                else:
                    invalid.append(manifest.parent.name)
            except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
                invalid.append(manifest.parent.name)
        if invalid:
            self._add(
                "PLUGIN_MANIFEST_INVALID", RepairCategory.PLUGINS, "warning",
                "检测到无效插件清单",
                "修复中心会把无效插件目录移动到 quarantine，而不是删除。",
                ", ".join(invalid[:12]),
            )
        if incompatible:
            self._add(
                "PLUGIN_INCOMPATIBLE", RepairCategory.PLUGINS, "warning",
                "检测到与当前版本不兼容的插件",
                "插件文件本身未损坏；Arenyxa 会保持其停用状态，升级应用或插件后可再次使用。",
                ", ".join(incompatible[:12]),
            )

    def _check_dependencies(self) -> None:
        missing: list[str] = []
        try:
            expected_qt = select_runtime().qt_binding
        except ArenyxaError:
            expected_qt = "PySide6"
        if available_binding_name() != expected_qt:
            missing.append(expected_qt)
        if expected_qt == "PySide2":
            try:
                backport = importlib.util.find_spec("backports.zoneinfo")
            except (ImportError, AttributeError, ValueError):
                backport = None
            if backport is None:
                missing.append("backports.zoneinfo")
        for module, package in self.REQUIRED_MODULES.items():
            try:
                found = importlib.util.find_spec(module)
            except (ImportError, AttributeError, ValueError):
                found = None
            if found is None:
                missing.append(package)
        if missing:
            self._add(
                "REQUIRED_DEPENDENCIES_MISSING",
                RepairCategory.DEPENDENCIES,
                "critical",
                "核心依赖缺失",
                "缺少 Arenyxa 必需模块：" + ", ".join(missing),
                ",".join(missing),
            )

    def _check_program_integrity(self) -> None:
        if not self.source_mode:
            attestation_path = self.install_root / "repair" / "release_attestation.json"
            if attestation_path.is_file():
                provenance = verify_release_attestation(self.install_root, deep_files=False)
                if provenance.state in {ProvenanceState.INVALID, ProvenanceState.MODIFIED}:
                    self._add(
                        "RELEASE_ATTESTATION_INVALID", RepairCategory.PROGRAM_FILES, "critical",
                        "发行版身份或签名验证失败",
                        "官方/签名发行版的发布证明、完整性清单或签名链已发生异常。修复中心不会把该副本提升为已知良好源。",
                        "; ".join(provenance.notes[:4]),
                    )
                    return
            manifest_path, payload_path = _packaged_repair_artifacts(self.install_root, self.paths.root)
            try:
                manifest = _validate_packaged_recovery(manifest_path, payload_path, deep=False)
                files = dict(manifest.get("files", {}))
            except (OSError, ValueError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
                self._add(
                    "PACKAGED_RECOVERY_INVALID", RepairCategory.PROGRAM_FILES, "critical",
                    "安装修复资源不可用", "离线恢复包或安装完整性清单缺失/损坏。", str(exc)
                )
                return

                                                                                         
                                                                                        
                                                     
            critical = {str(item) for item in manifest.get("critical_files", [])}
            state_path = self.paths.root / "repair" / "integrity_state.json"
            deep_due = any(item.code == "PREVIOUS_UNCLEAN_EXIT" for item in self.findings)
            try:
                state = json.loads(read_text_limited(state_path, 1024 * 1024, encoding="utf-8"))
                last = float(state.get("last_deep_check_epoch", 0.0))
                deep_due = deep_due or (time.time() - last >= 24 * 60 * 60)
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                deep_due = True

            if deep_due:
                try:
                    if attestation_path.is_file():
                                                                                              
                                                                                              
                                                                                            
                        deep_provenance = verify_release_attestation(self.install_root, deep_files=True)
                        if deep_provenance.state in {ProvenanceState.INVALID, ProvenanceState.MODIFIED}:
                            evidence = [*deep_provenance.modified_files, *deep_provenance.unexpected_files]
                            self._add(
                                "RELEASE_DEEP_INTEGRITY_FAILED",
                                RepairCategory.PROGRAM_FILES,
                                "critical",
                                "发行版深度完整性校验失败",
                                "签名安装内容、恢复包或额外可加载代码与可信发行状态不一致。",
                                ", ".join(evidence[:12]) or "; ".join(deep_provenance.notes[:4]),
                            )
                            return
                    else:
                        _validate_packaged_recovery(manifest_path, payload_path, deep=True)
                except (OSError, ValueError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
                    self._add(
                        "PACKAGED_RECOVERY_INVALID", RepairCategory.PROGRAM_FILES, "critical",
                        "离线恢复包完整性异常", "recovery_payload.zip 未通过每日深度校验。", str(exc)
                    )
                    return

            broken: list[str] = []
            for relative, meta in files.items():
                target = self.install_root / relative
                try:
                    _safe_relative(target, self.install_root)
                    metadata = dict(meta) if isinstance(meta, dict) else {}
                    expected_size = int(metadata.get("size", -1))
                    expected_hash = str(metadata.get("sha256", ""))
                    if not target.is_file():
                        broken.append(relative)
                        continue
                    if expected_size >= 0 and target.stat().st_size != expected_size:
                        broken.append(relative)
                        continue
                    if expected_hash and (deep_due or relative in critical) and _sha256(target) != expected_hash:
                        broken.append(relative)
                except (OSError, ValueError, TypeError):
                    broken.append(relative)
            if deep_due and not broken:
                try:
                    state_path.parent.mkdir(parents=True, exist_ok=True)
                    atomic_write_json(state_path, {
                        "last_deep_check_epoch": time.time(),
                        "manifest_generated_at": manifest.get("generated_at", ""),
                    })
                except OSError:
                    pass
            if broken:
                preview = ", ".join(broken[:8])
                self._add(
                    "PROGRAM_FILE_HASH_MISMATCH", RepairCategory.PROGRAM_FILES, "critical",
                    "安装程序文件完整性异常", f"检测到 {len(broken)} 个安装文件缺失、尺寸或哈希异常。", preview
                )
            return
        manifest_path = repair_resource("repair_manifest.json")
        seed_path = repair_resource("repair_seed.zip")
        if not manifest_path.exists() and not seed_path.exists():
            return
        if not manifest_path.exists():
            self._add(
                "REPAIR_MANIFEST_MISSING", RepairCategory.PROGRAM_FILES, "critical",
                "程序完整性清单缺失", "repair_manifest.json 缺失，无法验证安装文件。"
            )
            return
        try:
            manifest = json.loads(read_text_limited(manifest_path, 32 * 1024 * 1024, encoding="utf-8"))
            files = dict(manifest.get("files", {}))
            expected_seed = str(manifest.get("seed_sha256", ""))
            if expected_seed and (not seed_path.is_file() or _sha256(seed_path) != expected_seed):
                self._add(
                    "REPAIR_SEED_INVALID", RepairCategory.PROGRAM_FILES, "critical",
                    "离线修复副本损坏", "repair_seed.zip 缺失或 SHA-256 不匹配；将优先尝试用户数据中的已知良好副本。"
                )
        except (OSError, ValueError) as exc:
            self._add(
                "REPAIR_MANIFEST_INVALID",
                RepairCategory.PROGRAM_FILES,
                "critical",
                "程序完整性清单损坏",
                "Arenyxa 无法读取内置 SHA-256 清单。",
                str(exc),
            )
            return
                                                                                               
                                                                                                
                                                                                      
        if (os.getenv(SOURCE_INTEGRITY_ENV) or os.getenv(LEGACY_SOURCE_INTEGRITY_ENV, "")).strip().casefold() not in {"1", "true", "yes", "on"}:
            return
        broken: list[str] = []
        for relative, expected in files.items():
            target = self.install_root / relative
            try:
                _safe_relative(target, self.install_root)
                if not target.is_file() or _sha256(target) != str(expected):
                    broken.append(relative)
            except (OSError, ValueError):
                broken.append(relative)
        if broken:
            preview = ", ".join(broken[:5])
            if len(broken) > 5:
                preview += f" 等 {len(broken)} 个文件"
            self._add(
                "PROGRAM_FILE_HASH_MISMATCH",
                RepairCategory.PROGRAM_FILES,
                "critical",
                "源码完整性校验异常",
                f"严格源码校验检测到 {len(broken)} 个文件缺失或 SHA-256 不匹配。",
                preview,
            )

    def _check_logs(self) -> None:
        path = self.paths.readable_log_file
        if not path.exists():
            return
        try:
            with path.open("rb") as stream:
                size = path.stat().st_size
                stream.seek(max(0, size - 512 * 1024))
                text = stream.read().decode("utf-8", errors="replace")
        except OSError:
            return
        problem_texts: list[str] = []
        for line in text.splitlines():
            try:
                payload = json.loads(line)
            except ValueError:
                                                                                                 
                lowered_line = line.casefold()
                if any(token in lowered_line for token in ("traceback", "error", "exception", "failed")):
                    problem_texts.append(line)
                continue
            level = str(payload.get("level", "")).casefold()
            if level in {"warning", "error", "critical", "fatal"}:
                problem_texts.append(json.dumps(payload, ensure_ascii=False, default=str))
        lowered = "\n".join(problem_texts).casefold()
        patterns: list[tuple[tuple[str, ...], str, RepairCategory, str, str]] = [
            (("unicodedecodeerror", "unicodeencodeerror", "codec can't decode", "\ufffd"), "RECENT_ENCODING_ERROR", RepairCategory.ENCODING_UI, "warning", "近期日志出现编码错误"),
            (("modulenotfounderror", "no module named", "importerror"), "RECENT_IMPORT_ERROR", RepairCategory.DEPENDENCIES, "warning", "近期日志出现模块加载错误"),
            (("database disk image is malformed", "database is locked", "sqlite"), "RECENT_DATABASE_ERROR", RepairCategory.DATABASE_INDEX, "warning", "近期日志出现数据库异常"),
            (("plugin_execution_failed", "plugin_", "插件"), "RECENT_PLUGIN_ERROR", RepairCategory.PLUGINS, "warning", "近期日志出现插件异常"),
            (("tshark", "dumpcap", "pcap", "capture_adapter"), "RECENT_CAPTURE_ERROR", RepairCategory.CAPTURE_STACK, "warning", "近期日志出现抓包组件异常"),
            (("permissionerror", "access is denied", "errno 13"), "RECENT_PERMISSION_ERROR", RepairCategory.PERMISSIONS_PATHS, "warning", "近期日志出现权限错误"),
            (("address already in use", "winerror 10048"), "RECENT_SERVER_ERROR", RepairCategory.SERVER_RUNTIME, "warning", "近期日志出现本地服务端口异常"),
            (("dropped frame", "frame budget", "render error", "qpaint", "qpropertyanimation"), "RECENT_RENDER_ERROR", RepairCategory.PERFORMANCE_MOTION, "warning", "近期日志出现渲染或动画异常"),
        ]
        for needles, code, category, severity, title in patterns:
            if any(needle in lowered for needle in needles):
                self._add(code, category, severity, title, "修复中心将结合当前状态执行对应的安全修复。")

    def _check_cache_pressure(self) -> None:
        size = _directory_size(self.paths.cache)
        if size >= 2 * 1024 * 1024 * 1024:
            self._add(
                "CACHE_OVERSIZED",
                RepairCategory.CACHE_TEMP,
                "warning",
                "缓存目录异常膨胀",
                "缓存已超过约 2 GiB，可安全清理后重新生成。",
                f"bytes={size}",
            )


class RepairEngine:
    

    def __init__(self, plan: RepairPlan) -> None:
        self.plan = plan
        self.install_root = Path(plan.install_root).resolve()
        self.data_root = Path(plan.data_root).resolve()
        self.paths = AppPaths.discover(self.data_root)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.repair_root = self.data_root / "repair"
        self.backup_root = self.repair_root / "backups" / stamp
        self.log_dir = self.repair_root / "logs"
        self.actions: list[RepairActionResult] = []
        self.unresolved: list[str] = []
        self.finding_codes = {str(item.get("code", "")) for item in plan.detected_findings if isinstance(item, dict)}
        self.started_at = _utc_now()
                                                                                           
                                                                                              
                                                  
        self.log_path = self.log_dir / f"repair-{stamp}.log"

    def log(self, text: str) -> None:
        line = f"[{datetime.now().strftime('%H:%M:%S')}] {text}"
        if sys.stdout is not None:
            try:
                console_write(line, flush=True)
            except (OSError, AttributeError):
                pass
                                                                                             
                                                                                               
                                  
        self.log_dir.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")

    def action(self, name: str, func) -> None:
        self.log(f"▶ {name}")
        try:
            detail = func()
            detail_text = "完成" if detail is None else str(detail)
            self.actions.append(RepairActionResult(name, "ok", detail_text))
            self.log(f"✓ {name}: {detail_text}")
        except Exception as exc:                                                      
            self.actions.append(RepairActionResult(name, "failed", str(exc)))
            self.unresolved.append(f"{name}: {exc}")
            self.log(f"✗ {name}: {exc}")

    def run(self) -> RepairResult:
                                                                                            
                                                                                                
                                                                                               
                                                                              
        console_write("Arenyxa Repair Center: waiting for the main process to exit safely...", flush=True)
        _wait_for_parent(self.plan.parent_pid, timeout_seconds=20.0)
        lease = DataRootLease(self.data_root)
        deadline = time.monotonic() + max(0.0, float(REPAIR_LEASE_WAIT_SECONDS))
        acquired = False
        while True:
            try:
                acquired = lease.acquire()
            except OSError:
                acquired = False
            if acquired or time.monotonic() >= deadline:
                break
            time.sleep(0.15)
        if not acquired:
            message = (
                "数据目录仍被另一个 Arenyxa Desktop/Server 使用；为避免并发修改，修复已安全取消。"
            )
            console_write(f"Arenyxa Repair Center: {message}", flush=True)
            return RepairResult(
                started_at=self.started_at,
                finished_at=_utc_now(),
                success=False,
                categories=list(self.plan.categories),
                backup_dir=str(self.backup_root),
                actions=[],
                unresolved=[message],
            )
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            self.backup_root.mkdir(parents=True, exist_ok=True)
            self.log("Arenyxa Repair Center / 自愈修复中心")
            self.log(f"安装目录: {self.install_root}")
            self.log(f"数据目录: {self.data_root}")
            self.log("已取得数据目录独占锁；开始执行修复。")
            return self._run_with_data_root_lease()
        finally:
            lease.release()

    def _run_with_data_root_lease(self) -> RepairResult:
        self.paths.initialize()

        categories = [RepairCategory(item) for item in self.plan.categories if item in RepairCategory._value2member_map_]
        if not categories:
            categories = [RepairCategory.OTHER]

                                                                                             
                                                                                    
        if RepairCategory.PROGRAM_FILES in categories or RepairCategory.OTHER in categories:
            self.action("校验并恢复程序文件", self._repair_program_files)
        if RepairCategory.DEPENDENCIES in categories or RepairCategory.OTHER in categories:
            self.action("检查并修复核心依赖", self._repair_dependencies)
        if RepairCategory.ENCODING_UI in categories:
            self.action("修复语言与编码配置", self._repair_language)
        if RepairCategory.SETTINGS_UI in categories or RepairCategory.OTHER in categories:
            self.action("校验并修复设置", self._repair_settings)
        if RepairCategory.STARTUP_CRASH in categories:
            self.action("清理崩溃残留并恢复启动状态", self._repair_crash_state)
        if RepairCategory.RUNTIME_STATE in categories or RepairCategory.STARTUP_CRASH in categories or RepairCategory.OTHER in categories:
            self.action("恢复中断运行状态与检查点", self._repair_runtime_state)
        if RepairCategory.DATABASE_INDEX in categories or RepairCategory.OTHER in categories:
            self.action("检查并修复 SQLite / FTS", self._repair_database)
        if RepairCategory.PLUGINS in categories:
            self.action("隔离异常插件", self._repair_plugins)
        if RepairCategory.CAPTURE_STACK in categories:
            self.action("检查抓包运行环境", self._repair_capture_stack)
        if RepairCategory.PERMISSIONS_PATHS in categories or RepairCategory.OTHER in categories:
            self.action("修复应用数据目录与可写状态", self._repair_permissions)
        if RepairCategory.CACHE_TEMP in categories or RepairCategory.OTHER in categories:
            self.action("清理安全缓存与临时状态", self._repair_cache)
        if RepairCategory.SERVER_RUNTIME in categories:
            self.action("检查本地服务运行环境", self._repair_server_runtime)
        if RepairCategory.PERFORMANCE_MOTION in categories:
            self.action("恢复稳定动画与性能配置", self._repair_performance_motion)
        if RepairCategory.FEATURE_INTEGRATION in categories:
            self.action("复核高级功能模块接线", self._verify_feature_integration_files)

        self.action("归档修复前应用日志", self._archive_pre_repair_logs)
        self.action("最终健康验证", self._final_verify)
        success = not self.unresolved
        result = RepairResult(
            started_at=self.started_at,
            finished_at=_utc_now(),
            success=success,
            categories=[item.value for item in categories],
            backup_dir=str(self.backup_root),
            actions=list(self.actions),
            unresolved=list(self.unresolved),
        )
        report_path = self.repair_root / "last_repair_report.json"
        atomic_write_json(report_path, result.to_dict())
        self.log("修复流程完成。" if success else "修复流程完成，但仍有未解决项目。")
        return result

    def _backup(self, path: Path, group: str) -> None:
        if not path.exists():
            return
        destination = self.backup_root / group / path.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        if path.is_dir():
            shutil.copytree(path, destination, dirs_exist_ok=True)
        else:
            shutil.copy2(path, destination)

    def _repair_program_files(self) -> str:
        if not self.plan.source_mode:
            manifest_path, payload_path = _packaged_repair_artifacts(self.install_root, self.data_root)
            manifest = _validate_packaged_recovery(manifest_path, payload_path)
            bad: list[str] = []
            for relative, meta in dict(manifest.get("files", {})).items():
                target = self.install_root / relative
                _safe_relative(target, self.install_root)
                metadata = dict(meta) if isinstance(meta, dict) else {}
                expected = str(metadata.get("sha256", ""))
                if not target.is_file() or (expected and _sha256(target) != expected):
                    bad.append(relative)
            if bad:
                raise RuntimeError(f"外部恢复后仍有 {len(bad)} 个安装文件异常: {bad[:8]}")
            return "当前安装目录已由独立修复终端恢复，并完成逐文件 SHA-256 验证。"
        seed_path = repair_resource("repair_seed.zip")
        if not seed_path.is_file():
            seed_path = self.data_root / "repair" / "known_good" / "repair_seed.zip"
        else:
            try:
                with zipfile.ZipFile(seed_path, "r") as probe:
                    if probe.testzip() is not None:
                        raise zipfile.BadZipFile("seed CRC failed")
            except zipfile.BadZipFile:
                seed_path = self.data_root / "repair" / "known_good" / "repair_seed.zip"
        if not seed_path.exists():
            raise FileNotFoundError("离线 repair_seed.zip 与已知良好副本均不可用，无法恢复程序文件。")
        restored = 0
        with zipfile.ZipFile(seed_path, "r") as archive:
            archive.testzip()
            manifest = json.loads(archive.read("MANIFEST.json").decode("utf-8"))
            files: dict[str, str] = dict(manifest.get("files", {}))
            for relative, expected_hash in files.items():
                target = self.install_root / relative
                _safe_relative(target, self.install_root)
                current_hash = _sha256(target) if target.is_file() else ""
                if current_hash == expected_hash:
                    continue
                if target.exists():
                    backup_target = self.backup_root / "program_files" / relative
                    backup_target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(target, backup_target)
                payload = archive.read(relative)
                if hashlib.sha256(payload).hexdigest() != expected_hash:
                    raise ValueError(f"repair seed 内部哈希不匹配: {relative}")
                target.parent.mkdir(parents=True, exist_ok=True)
                atomic_write_bytes(target, payload)
                restored += 1
        self._remove_pycache(self.install_root / "src")
        return f"恢复 {restored} 个缺失/损坏文件；未改动文件保持原样。"

    def _repair_dependencies(self) -> str:
        missing: list[str] = []
                                                                                           
                                                                                             
                                       
        try:
            expected_qt = select_runtime().qt_binding
        except ArenyxaError:
            expected_qt = "PySide6"
        if available_binding_name() != expected_qt:
            missing.append(expected_qt)
        if expected_qt == "PySide2":
            try:
                legacy_zoneinfo = importlib.util.find_spec("backports.zoneinfo")
            except (ImportError, AttributeError, ValueError):
                legacy_zoneinfo = None
            if legacy_zoneinfo is None:
                missing.append("backports.zoneinfo")
        for module, package in StartupHealthScanner.REQUIRED_MODULES.items():
            try:
                spec = importlib.util.find_spec(module)
            except (ImportError, ValueError):
                spec = None
            if spec is None:
                missing.append(package)
        if not missing:
            return "核心依赖均可加载。"
        if not self.plan.source_mode:
            raise RuntimeError("打包版本检测到内部依赖缺失，需要使用安装包 Repair/Reinstall 恢复。")
        try:
            runtime = select_runtime()
        except ArenyxaError:
            runtime = None
        requirements_name = "requirements-win7.txt" if runtime is not None and runtime.legacy else "requirements.txt"
        requirements = self.install_root / requirements_name
        if not requirements.exists():
            raise FileNotFoundError(f"{requirements_name} 不存在。")
        command = [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--upgrade-strategy",
            "only-if-needed",
            "-r",
            str(requirements),
        ]
        self.log("  执行: " + " ".join(command))
        completed = subprocess.run(
            validated_argv(command),
            cwd=self.install_root,
            check=False,
            timeout=REPAIR_PIP_TIMEOUT_SECONDS,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"pip 修复依赖失败，返回码 {completed.returncode}")
        return f"缺失依赖已通过 {requirements.name} 自动恢复。"

    def _load_settings_resilient(self) -> dict[str, Any]:
        defaults = asdict(AppSettings())
        path = self.data_root / "settings.json"
        if not path.exists():
            return defaults
        try:
            raw = json.loads(read_text_limited(path, 2 * 1024 * 1024, encoding="utf-8"))
            if isinstance(raw, dict):
                for key, value in raw.items():
                    if key in defaults:
                        defaults[key] = value
        except (OSError, UnicodeError, ValueError):
            pass
        return defaults

    def _write_settings(self, data: dict[str, Any]) -> None:
        path = self.data_root / "settings.json"
        self._backup(path, "settings")
        allowed = AppSettings.__dataclass_fields__.keys()
        normalized = {key: value for key, value in data.items() if key in allowed}
                                                                                                       
        defaults = asdict(AppSettings())
        defaults.update(normalized)
        if defaults.get("locale") not in StartupHealthScanner.SUPPORTED_LOCALES:
            defaults["locale"] = "system"
        if defaults.get("theme") not in StartupHealthScanner.SUPPORTED_THEMES:
            defaults["theme"] = "modern_dark"
        if defaults.get("performance_mode") not in {"auto", "quality", "balanced", "efficiency"}:
            defaults["performance_mode"] = "auto"
        def number(name: str, fallback: float, low: float, high: float) -> float:
            try:
                value = float(defaults.get(name, fallback))
            except (TypeError, ValueError, OverflowError):
                value = fallback
            if not math.isfinite(value):
                value = fallback
            return max(low, min(high, value))

        defaults["glass_strength"] = number("glass_strength", 0.82, 0.0, 1.0)
        defaults["motion_strength"] = number("motion_strength", 0.88, 0.0, 1.0)
        defaults["blur_strength"] = number("blur_strength", 22.0, 0.0, 64.0)
        defaults["default_timeout_seconds"] = number("default_timeout_seconds", 30.0, 1.0, 600.0)
        try:
            defaults["max_workers"] = max(1, min(64, int(defaults.get("max_workers", 4))))
        except (TypeError, ValueError, OverflowError):
            defaults["max_workers"] = 4
        try:
            defaults["request_concurrency"] = max(1, min(64, int(defaults.get("request_concurrency", 8))))
        except (TypeError, ValueError, OverflowError):
            defaults["request_concurrency"] = 8
        try:
            defaults["per_host_concurrency"] = max(1, min(32, int(defaults.get("per_host_concurrency", 4))))
        except (TypeError, ValueError, OverflowError):
            defaults["per_host_concurrency"] = 4
        defaults["per_host_concurrency"] = min(defaults["per_host_concurrency"], defaults["request_concurrency"])
        try:
            defaults["max_response_bytes"] = max(1024 * 1024, min(1024 * 1024 * 1024, int(defaults.get("max_response_bytes", 32 * 1024 * 1024))))
        except (TypeError, ValueError, OverflowError):
            defaults["max_response_bytes"] = 32 * 1024 * 1024
        for boolean_name in (
            "reduce_motion", "high_contrast", "edge_flow", "live_data_motion",
            "left_sidebar_collapsed", "advanced_nav_expanded", "developer_nav_expanded",
            "inspector_collapsed", "diagnostics_include_paths", "developer_mode",
            "adaptive_request_concurrency",
        ):
            if not isinstance(defaults.get(boolean_name), bool):
                defaults[boolean_name] = bool(asdict(AppSettings())[boolean_name])
        if not defaults.get("developer_mode", False):
            defaults["developer_nav_expanded"] = False
        AppSettings(**defaults).save(path)

    def _repair_language(self) -> str:
        settings = self._load_settings_resilient()
        settings["locale"] = "system"
        self._write_settings(settings)
                                                                                         
                                                                                           
                                                                          
        return "语言已恢复为“跟随系统”；源码/开发构建不会因语言修复覆盖开发者修改。"

    def _repair_settings(self) -> str:
        settings = self._load_settings_resilient()
        self._write_settings(settings)
        return "设置结构已校验；无效 locale/theme/performance 值已安全归一化。"

    def _repair_crash_state(self) -> str:
        marker = self.data_root / "crash.marker"
        self._backup(marker, "crash")
        marker.unlink(missing_ok=True)
        window_state = self.data_root / "window.ini"
        if window_state.exists():
            self._backup(window_state, "window_state")
            window_state.unlink(missing_ok=True)
        return "移除异常退出标记并重置窗口几何状态；任务、项目和结果数据未改动。"

    def _database_quick_check(self, path: Path) -> str:
        connection = sqlite3.connect(path, timeout=5.0)
        try:
            row = connection.execute("PRAGMA quick_check(1)").fetchone()
            return str(row[0] if row else "no result")
        finally:
            connection.close()

    def _repair_database(self) -> str:
        path = self.paths.database
        if not path.exists():
            return "数据库尚未创建，无需修复。"
        self._backup(path, "database")
        for suffix in ("-wal", "-shm"):
            self._backup(Path(str(path) + suffix), "database")
        try:
            current = self._database_quick_check(path)
        except sqlite3.DatabaseError:
            current = "failed"
        if current.lower() == "ok":
            connection = sqlite3.connect(path, timeout=10.0)
            try:
                try:
                    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.DatabaseError:
                    pass
                connection.execute("REINDEX")
                try:
                    connection.execute("INSERT INTO local_search(local_search) VALUES('rebuild')")
                except sqlite3.DatabaseError:
                    pass
                connection.execute("ANALYZE")
                connection.execute("PRAGMA optimize")
                connection.commit()
            finally:
                connection.close()
            return "SQLite quick_check=ok；已执行 WAL checkpoint、REINDEX、FTS rebuild/optimize。"

                                                                                    
                                                                                     
                                                                                   
                                                                                     
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        recovered = path.with_name(f".{path.name}.recovered-{os.getpid()}-{stamp}.tmp")
        recovered.unlink(missing_ok=True)
        source = None
        destination = None
        try:
            source = sqlite3.connect(path, timeout=10.0)
            destination = sqlite3.connect(recovered, timeout=10.0)
            destination.execute("PRAGMA foreign_keys=OFF")
            for statement in source.iterdump():
                statement = statement.strip()
                if statement:
                    destination.execute(statement)
            destination.commit()
        except Exception:
            if destination is not None:
                try:
                    destination.rollback()
                except sqlite3.DatabaseError:
                    pass
            recovered.unlink(missing_ok=True)
            raise
        finally:
            if destination is not None:
                destination.close()
            if source is not None:
                source.close()

        try:
            check = self._database_quick_check(recovered)
            if check.lower() != "ok":
                raise sqlite3.DatabaseError(f"自动恢复后的数据库仍未通过 quick_check: {check}")

                                                                                     
                                                                                       
                                                                                     
            preserved = path.with_name(f"{path.stem}.corrupt-preserved-{stamp}{path.suffix}")
            counter = 1
            while preserved.exists():
                preserved = path.with_name(
                    f"{path.stem}.corrupt-preserved-{stamp}-{counter}{path.suffix}"
                )
                counter += 1
            path.replace(preserved)
            try:
                recovered.replace(path)
            except Exception:
                                                                                       
                                                                                      
                                           
                if not path.exists() and preserved.exists():
                    preserved.replace(path)
                raise
            Path(str(path) + "-wal").unlink(missing_ok=True)
            Path(str(path) + "-shm").unlink(missing_ok=True)
        except Exception:
            recovered.unlink(missing_ok=True)
            raise
        return (
            "原数据库已使用唯一文件名完整保留；通过流式 SQLite iterdump 重建并通过 quick_check。"
        )

    def _repair_runtime_state(self) -> str:
        store = SQLiteStore(self.paths.database)
        store.initialize()
        service = RuntimeRecoveryService(store)
        before = service.audit()
        result = service.recover()
        after = service.audit()
        if after.has_stale_active_state or after.has_invalid_state:
            raise RuntimeError(
                "运行状态修复后仍存在异常: "
                f"active={after.has_stale_active_state}, invalid={after.has_invalid_state}"
            )
        history_path = self.repair_root / "runtime_recovery_history.json"
        history: list[dict[str, Any]] = []
        try:
            raw = json.loads(read_text_limited(history_path, 2 * 1024 * 1024, encoding="utf-8"))
            if isinstance(raw, list):
                history = [item for item in raw if isinstance(item, dict)][-99:]
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            history = []
        history.append({
            "recovered_at": result.recovered_at,
            "source": "repair_center",
            "before": before.to_dict(),
            "result": result.to_dict(),
        })
        atomic_write_json(history_path, history)
        return (
            f"Run {result.recovered_runs} / Capture {result.recovered_captures} 已关闭；"
            f"已完成 Workflow 对账 {result.reconciled_completed_workflows}；"
            f"Workflow {result.interrupted_workflows} / Revision {result.interrupted_revisions} 转为 interrupted；"
            f"禁用无效计划 {result.disabled_invalid_schedules}；终止不可恢复 Workflow "
            f"{result.failed_invalid_workflows + result.failed_broken_workflows}；"
            f"不可恢复 Revision {result.failed_invalid_revisions + result.failed_broken_revisions}；"
            f"当前仍可恢复 Workflow {result.resumable_workflows} / Revision {result.resumable_revisions}。"
        )

    def _repair_plugins(self) -> str:
        root = self.paths.plugins
        quarantine = root / "quarantine" / datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        quarantined = 0
        incompatible = 0
        if root.exists():
            for manifest in root.glob("*/plugin.json"):
                if "quarantine" in manifest.parts:
                    continue
                should_quarantine = False
                try:
                    parsed = PluginManifest.load(manifest)
                    parsed.validate_compatibility()
                except ArenyxaError as exc:
                    if exc.code in PLUGIN_COMPATIBILITY_ERROR_CODES:
                                                                                            
                                                                                          
                        incompatible += 1
                        continue
                    should_quarantine = True
                except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
                    should_quarantine = True
                if should_quarantine:
                    quarantine.mkdir(parents=True, exist_ok=True)
                    destination = quarantine / manifest.parent.name
                    counter = 1
                    while destination.exists():
                        destination = quarantine / f"{manifest.parent.name}-{counter}"
                        counter += 1
                    shutil.move(str(manifest.parent), str(destination))
                    quarantined += 1
        if self.paths.database.exists():
            try:
                connection = sqlite3.connect(self.paths.database, timeout=5.0)
                try:
                    connection.execute("UPDATE plugins SET enabled=0 WHERE last_error IS NOT NULL")
                    connection.commit()
                finally:
                    connection.close()
            except sqlite3.DatabaseError:
                pass
        return (
            f"隔离 {quarantined} 个无效插件目录；保留 {incompatible} 个版本不兼容插件；"
            "数据库中有错误记录的插件已禁用，未删除插件数据。"
        )

    def _repair_capture_stack(self) -> str:
        details: list[str] = []
        if self.plan.source_mode and importlib.util.find_spec("psutil") is None:
            command = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--no-input", "psutil>=6,<8"]
            try:
                completed = subprocess.run(
                    validated_argv(command),
                    cwd=self.install_root,
                    check=False,
                    timeout=REPAIR_OPTIONAL_PIP_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired:
                self.unresolved.append("自动安装 psutil 超时；进程网络归因功能可能不可用。")
            else:
                if completed.returncode != 0:
                    self.unresolved.append("无法自动安装 psutil；进程网络归因功能可能不可用。")
                else:
                    details.append("psutil 已恢复")
        tshark = shutil.which("tshark")
        dumpcap = shutil.which("dumpcap")
        if not tshark and not dumpcap:
            self.unresolved.append("未检测到 tshark/dumpcap。Arenyxa 不会静默安装第三方抓包驱动；Browser Capture 仍可使用。")
            details.append("tshark/dumpcap 未安装")
        else:
            details.append(f"capture tool={tshark or dumpcap}")
                                                                                            
        removed = 0
        for pattern in ("*.part", "*.tmp"):
            for path in self.paths.captures.rglob(pattern):
                try:
                    path.unlink()
                    removed += 1
                except OSError:
                    continue
        details.append(f"清理临时抓包文件 {removed} 个")
        return "；".join(details)

    def _repair_permissions(self) -> str:
        self.paths.initialize()
        changed = 0
        for path in (self.paths.root, self.paths.logs, self.paths.cache, self.paths.exports, self.paths.captures, self.paths.projects, self.paths.plugins, self.paths.profiles):
            try:
                mode = path.stat().st_mode
                if not mode & stat.S_IWUSR:
                    path.chmod(mode | stat.S_IWUSR)
                    changed += 1
                probe = path / f".repair-write-test-{os.getpid()}"
                probe.write_bytes(b"ok")
                probe.unlink(missing_ok=True)
            except OSError as exc:
                raise PermissionError(f"{path} 仍不可写: {exc}") from exc
        return f"数据目录结构已补齐；修正 {changed} 个用户写权限标记。"

    def _repair_cache(self) -> str:
        removed = 0
        self.paths.cache.mkdir(parents=True, exist_ok=True)
        for path in list(self.paths.cache.iterdir()):
            try:
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path)
                else:
                    path.unlink()
                removed += 1
            except OSError:
                continue
        if self.plan.source_mode:
            removed += self._remove_pycache(self.install_root / "src")
        for temp in self.data_root.glob("*.tmp"):
            try:
                temp.unlink()
                removed += 1
            except OSError:
                pass
        return f"清理 {removed} 个安全缓存/临时项；Projects/Captures/Exports/数据库未删除。"

    def _remove_pycache(self, root: Path) -> int:
        removed = 0
        if not root.exists():
            return 0
        for cache in root.rglob("__pycache__"):
            try:
                shutil.rmtree(cache)
                removed += 1
            except OSError:
                continue
        return removed

    def _repair_server_runtime(self) -> str:
                                                                       
        return "已保留安全边界：不终止未知进程；Arenyxa Server 默认继续使用 loopback，重启后重新绑定。"

    def _verify_feature_integration_files(self) -> str:
        





        required = (
            "src/arenyxa/application/advanced.py",
            "src/arenyxa/application/nextgen.py",
            "src/arenyxa/application/autopilot.py",
            "src/arenyxa/application/workflows.py",
            "src/arenyxa/application/workflow_runtime.py",
            "src/arenyxa/application/data_lineage.py",
            "src/arenyxa/application/feature_audit.py",
        )
        missing = [relative for relative in required if not (self.install_root / relative).is_file()]
        if missing:
            raise FileNotFoundError("高级功能实现模块缺失: " + ", ".join(missing))
                                                                                               
        import py_compile
        for relative in required:
            py_compile.compile(str(self.install_root / relative), doraise=True)
        return f"{len(required)} 个高级功能实现模块存在且可编译；运行时接线将在重启后再次自动审计。"

    def _archive_pre_repair_logs(self) -> str:
        path = self.paths.readable_log_file
        if not path.exists() or path.stat().st_size == 0:
            return "没有需要归档的应用日志。"
        destination = self.backup_root / "logs" / "arenyxa-pre-repair.jsonl"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        atomic_write_bytes(path, b"")
        return f"修复前日志已保留到 {destination}，新启动将使用干净日志。"

    def _repair_performance_motion(self) -> str:
        settings = self._load_settings_resilient()
        settings.update(
            {
                "performance_mode": "auto",
                "request_concurrency": 8,
                "per_host_concurrency": 4,
                "motion_strength": 0.88,
                "blur_strength": 22.0,
                "glass_strength": 0.82,
                "live_data_motion": True,
                "reduce_motion": False,
                "edge_flow": False,
            }
        )
        self._write_settings(settings)
        return "Motion/Glass 参数恢复到稳定 Balanced 基线；未启用屏幕跑马灯或电源键呼出效果。"

    def _final_verify(self) -> str:
        scanner = StartupHealthScanner(self.paths, self.install_root)
        report = scanner.scan()
        remaining = [
            item for item in report.findings
            if item.code != "PREVIOUS_UNCLEAN_EXIT" and not item.code.startswith("RECENT_")
        ]
        if remaining:
            summary = "; ".join(f"{item.code}: {item.title}" for item in remaining[:8])
            raise RuntimeError("修复后仍检测到: " + summary)
        return "启动健康扫描通过。"


def create_repair_plan(
    paths: AppPaths,
    report: HealthReport,
    categories: Iterable[RepairCategory],
    *,
    parent_pid: int | None = None,
    relaunch: bool = True,
) -> Path:
    repair_dir = paths.root / "repair"
    repair_dir.mkdir(parents=True, exist_ok=True)
    plan = RepairPlan(
        install_root=str(installation_root()),
        data_root=str(paths.root),
        categories=[item.value for item in categories],
        detected_findings=[item.to_dict() for item in report.findings],
        parent_pid=parent_pid or os.getpid(),
        relaunch=relaunch,
        source_mode=source_mode(),
    )
    return plan.save(repair_dir / "pending_repair_plan.json")


def _validate_repair_plan_origin(plan: RepairPlan, plan_path: Path) -> None:
    expected_install = installation_root().resolve()
    declared_install = Path(plan.install_root).expanduser().resolve()
    if declared_install != expected_install:
        raise ValueError("Repair plan install_root does not match the running Arenyxa installation")
    declared_data = Path(plan.data_root).expanduser().resolve()
    expected_plan_dir = (declared_data / "repair").resolve()
    resolved_plan = plan_path.expanduser().resolve()
    if resolved_plan.parent != expected_plan_dir:
        raise ValueError("Repair plan must reside in the declared Arenyxa data repair directory")
    if plan.source_mode != source_mode():
        raise ValueError("Repair plan source/install mode does not match the running Arenyxa mode")


def launch_repair_worker(plan_path: Path) -> subprocess.Popen[Any]:
    plan = RepairPlan.load(plan_path)
    _validate_repair_plan_origin(plan, plan_path)
    environment = os.environ.copy()
    data_root = Path(plan.data_root).resolve()
    marker_token = secrets.token_hex(16)

                                                                                         
                                                                                            
                                                                                             
                     
    _write_repair_marker(data_root, os.getpid(), marker_token, "handoff")

    process: Optional[subprocess.Popen[Any]] = None
    try:
        if os.name == "nt" and not plan.source_mode:
            repair_dir = data_root / "repair"
            repair_dir.mkdir(parents=True, exist_ok=True)
            script_source = repair_resource("repair/repair_worker.ps1")
            if not script_source.is_file():
                raise FileNotFoundError(f"Repair worker resource missing: {script_source}")
            script_copy = repair_dir / "repair_worker.ps1"
            shutil.copy2(script_source, script_copy)
            command = [
                "powershell.exe", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(script_copy),
                "-InstallRoot", plan.install_root,
                "-DataRoot", plan.data_root,
                "-PlanPath", str(plan_path),
                "-WaitPid", str(plan.parent_pid or os.getpid()),
            ]
            process = subprocess.Popen(
                validated_argv(command),
                cwd=plan.data_root,
                env=environment,
                close_fds=True,
                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
            )
        else:
            if plan.source_mode:
                src = str(Path(plan.install_root) / "src")
                existing = environment.get("PYTHONPATH", "")
                environment["PYTHONPATH"] = src + (os.pathsep + existing if existing else "")
                command = [sys.executable, "-m", "arenyxa", "--repair-worker", str(plan_path)]
            else:
                command = [sys.executable, "--repair-worker", str(plan_path)]
            creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0) if os.name == "nt" else 0
            process = subprocess.Popen(
                validated_argv(command),
                cwd=plan.install_root,
                env=environment,
                close_fds=True,
                creationflags=creationflags,
            )
        _write_repair_marker(data_root, process.pid, marker_token, "active")
        return process
    except Exception:
        if process is not None:
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5.0)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5.0)
            except (AttributeError, OSError, subprocess.SubprocessError):
                pass
        clear_repair_marker(data_root, marker_token)
        raise

def run_repair_worker(plan_path: Path) -> int:
    try:
        plan = RepairPlan.load(plan_path)
        _validate_repair_plan_origin(plan, plan_path)
    except Exception as exc:
        console_write(f"Arenyxa Repair Center: 无法读取修复计划: {exc}", flush=True)
        time.sleep(2)
        return 2
    if os.name == "nt":
        try:
            import ctypes

            ctypes.windll.kernel32.SetConsoleTitleW("Arenyxa Repair Center · 自动修复")
        except Exception:
            pass
    engine = RepairEngine(plan)
    result = engine.run()
    plan_path.unlink(missing_ok=True)
                                                                                              
                                                                                                
                                                                                            
    clear_repair_marker(Path(plan.data_root))
    if plan.relaunch:
        try:
            _relaunch_arenyxa(plan)
            engine.log("已重新启动 Arenyxa，修复终端将在 1 秒后自动退出。")
        except Exception as exc:
            engine.log(f"重新启动 Arenyxa 失败: {exc}")
    time.sleep(1.0)
    return 0 if result.success else 1


def _source_gui_python_executable() -> str:
    







    executable = Path(sys.executable)
    if os.name == "nt":
        pythonw = executable.with_name("pythonw.exe")
        if pythonw.is_file():
            return str(pythonw)
    return str(executable)


def _relaunch_arenyxa(plan: RepairPlan) -> None:
    environment = os.environ.copy()
    environment[DATA_DIR_ENV] = plan.data_root
    environment[LEGACY_DATA_DIR_ENV] = plan.data_root
    if plan.source_mode:
        src = str(Path(plan.install_root) / "src")
        existing = environment.get("PYTHONPATH", "")
        environment["PYTHONPATH"] = src + (os.pathsep + existing if existing else "")
        command = [_source_gui_python_executable(), "-m", "arenyxa", "--post-repair"]
        cwd = plan.install_root
    else:
        command = [sys.executable, "--post-repair"]
        cwd = plan.install_root
    popen_kwargs: dict[str, Any] = {"cwd": cwd, "env": environment, "close_fds": True}
    if os.name == "nt":
                                                                                             
                                                                                                 
                                                                                                
                                                                                                 
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        if plan.source_mode:
            creationflags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
        else:
            creationflags |= getattr(subprocess, "DETACHED_PROCESS", 0)
        popen_kwargs.update(
            creationflags=creationflags,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    subprocess.Popen(validated_argv(command), **popen_kwargs)


def _wait_for_parent(pid: int, timeout_seconds: float) -> None:
    if pid <= 0 or pid == os.getpid():
        return
    deadline = time.monotonic() + timeout_seconds
    if os.name == "nt":
        remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
        state = _windows_process_running(pid, remaining_ms)
        if state is False:
            return
                                                                                                
                                                                                                 
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        return
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except (OSError, ProcessLookupError):
            return
        time.sleep(0.15)
