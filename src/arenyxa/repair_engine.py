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

from arenyxa.repair_scanner import StartupHealthScanner


def _module_importable(module: str) -> bool:
    try:
        if importlib.util.find_spec(module) is None:
            return False
        importlib.import_module(module)
        return True
    except (ImportError, AttributeError, OSError, RuntimeError, ValueError):
        return False

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
                record_current_exception(__name__, 'RepairEngine.log:106')
                                                                                             
                                                                                               
                                  
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
            if not _module_importable(module):
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
            record_current_exception(__name__, 'RepairEngine._load_settings_resilient:357')
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
            "adaptive_request_concurrency", "experience_setup_completed",
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
                    record_current_exception(__name__, 'RepairEngine._repair_database:465')
                connection.execute("REINDEX")
                try:
                    connection.execute("INSERT INTO local_search(local_search) VALUES('rebuild')")
                except sqlite3.DatabaseError:
                    record_current_exception(__name__, 'RepairEngine._repair_database:470')
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
                    record_current_exception(__name__, 'RepairEngine._repair_database:501')
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
                record_current_exception(__name__, 'RepairEngine._repair_plugins:621')
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
                record_current_exception(__name__, 'RepairEngine._repair_cache:699')
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

