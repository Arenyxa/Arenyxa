from __future__ import annotations
from arenyxa.recoverable import record_current_exception

from arenyxa.console_io import console_write
from arenyxa.infrastructure.process_safety import validated_argv
import hashlib
import importlib
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

from arenyxa.repair_common import (
    REPAIR_LEASE_WAIT_SECONDS,
    REPAIR_MARKER_NAME,
    REPAIR_HANDOFF_GRACE_SECONDS,
    REPAIR_PIP_TIMEOUT_SECONDS,
    REPAIR_OPTIONAL_PIP_TIMEOUT_SECONDS,
    _repair_marker_path,
    _windows_process_running,
    _process_is_running,
    _load_repair_marker,
    repair_worker_active,
    _write_repair_marker,
    clear_repair_marker,
    RepairCategory,
    CATEGORY_LABELS,
    fault_fingerprint,
    RepairFinding,
    HealthReport,
    append_feature_integration_findings,
    RepairPlan,
    RepairActionResult,
    RepairResult,
    _utc_now,
    installation_root,
    source_mode,
    repair_resource,
    _packaged_repair_artifacts,
    _validate_packaged_recovery,
    ensure_known_good_seed,
    _sha256,
    _safe_relative,
    _directory_size,
    _wait_for_parent,
)


def _module_importable(module: str) -> bool:
    try:
        if importlib.util.find_spec(module) is None:
            return False
        importlib.import_module(module)
        return True
    except (ImportError, AttributeError, OSError, RuntimeError, ValueError):
        return False

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
                                                                                     
                record_current_exception(__name__, 'StartupHealthScanner._check_previous_crash:179')
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
            "adaptive_request_concurrency", "experience_setup_completed",
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
            record_current_exception(__name__, 'StartupHealthScanner._check_paths:352')

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
            if not _module_importable(module):
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
                    record_current_exception(__name__, 'StartupHealthScanner._check_program_integrity:595')
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

