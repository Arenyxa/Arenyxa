from __future__ import annotations

from arenyxa.console_io import console_write
import argparse
import faulthandler
import json
import logging
import os
import sys
import threading
from pathlib import Path

from arenyxa import __version__
from arenyxa.branding import (
    APP_NAME,
    PROJECT_EXTENSION,
    LEGACY_PROJECT_EXTENSIONS,
    preferred_window_icon_path,
)
from arenyxa.config import AppPaths, AppSettings
from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.atomic_io import atomic_write_json, read_text_limited
from arenyxa.platform_compat import (
    apply_legacy_environment,
    select_runtime,
    validate_python_for_runtime,
    windows_reduced_motion_requested,
)
from arenyxa.qt_compat import available_binding_name
from arenyxa.provenance import ProvenanceState, verify_release_attestation
from arenyxa.repair import (
    HealthReport,
    RepairCategory,
    RepairFinding,
    StartupHealthScanner,
    append_feature_integration_findings,
    create_repair_plan,
    ensure_known_good_seed,
    installation_root,
    launch_repair_worker,
    repair_worker_active,
    run_repair_worker,
)


LOGGER = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=f"{APP_NAME} V{__version__}")
    parser.add_argument(
        "project",
        nargs="?",
        type=Path,
        help=f"Optional {PROJECT_EXTENSION} project to open (legacy {LEGACY_PROJECT_EXTENSIONS[0]} is supported)",
    )
    parser.add_argument("--data-dir", type=Path, help="Override local application data directory")
    parser.add_argument(
        "--safe-mode", action="store_true", help="Disable plugins and enhanced visual effects"
    )
    parser.add_argument("--smoke-test", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--repair-worker", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--post-repair", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--verify-installation", action="store_true", help="Verify release provenance and installed-file integrity, then exit")
    parser.add_argument("--provenance-json", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    return parser


def _native_repair_question(report: HealthReport) -> bool:
    
    text = (
        "Arenyxa detected a startup problem before the Qt interface could load.\n\n"
        f"Detected issues: {len(report.findings)}\n"
        "Would you like Arenyxa Repair Center to repair the installation automatically?\n\n"
        "A separate repair terminal will open. No commands are required."
    )
    if os.name == "nt":
        try:
            import ctypes

            MB_YESNO = 0x00000004
            MB_ICONWARNING = 0x00000030
            IDYES = 6
            result = ctypes.windll.user32.MessageBoxW(
                None, text, "Arenyxa Repair Center", MB_YESNO | MB_ICONWARNING
            )
            return result == IDYES
        except Exception:
            LOGGER.debug("Native Repair question dialog failed; falling back to stderr", exc_info=True)
    console_write(text, file=sys.stderr)
                                                                                                  
    return False


def _native_repair_busy_notice() -> None:
    text = (
        "Arenyxa Repair Center is currently repairing this installation/data directory.\n\n"
        "Wait for the repair terminal to finish before starting another Desktop/Server runtime."
    )
    if os.name == "nt":
        try:
            import ctypes

            MB_OK = 0x00000000
            MB_ICONINFORMATION = 0x00000040
            ctypes.windll.user32.MessageBoxW(None, text, "Arenyxa Repair Center", MB_OK | MB_ICONINFORMATION)
            return
        except Exception:
            LOGGER.debug("Native Repair busy dialog failed; falling back to stderr", exc_info=True)
    console_write(text, file=sys.stderr)


def _startup_locale(paths: AppPaths) -> str:
    requested = "system"
    settings_path = paths.root / "settings.json"
    try:
        raw = json.loads(read_text_limited(settings_path, 2 * 1024 * 1024, encoding="utf-8"))
        if isinstance(raw, dict):
            requested = str(raw.get("locale", "system"))
    except (OSError, UnicodeError, ValueError, TypeError):
        pass
    from arenyxa.presentation.language import LOCALES, resolve_system_locale

    if requested not in LOCALES:
        requested = "system"
    return resolve_system_locale() if requested == "system" else requested


def _bootstrap_failure_report(paths: AppPaths, exc: Exception) -> HealthReport:
    code = "BOOTSTRAP_FAILED"
    category = RepairCategory.STARTUP_CRASH
    title = "Arenyxa 初始化失败"
    detail = "核心上下文初始化时发生异常，建议运行自愈修复中心。"
    evidence = type(exc).__name__
    if isinstance(exc, ArenyxaError):
        code = exc.code
        detail = exc.message
        domain = str(exc.domain or "").upper()
        if domain in {"DATABASE", "STORAGE"}:
            category = RepairCategory.DATABASE_INDEX
            title = "数据库运行时不兼容或初始化失败"
        elif domain in {"DEPENDENCY", "RUNTIME"}:
            category = RepairCategory.DEPENDENCIES
            title = "运行时依赖不兼容"
        elif domain == "PLUGIN":
            category = RepairCategory.PLUGINS
            title = "插件初始化失败"
        elif domain == "CAPTURE":
            category = RepairCategory.CAPTURE_STACK
            title = "抓包运行时初始化失败"
        evidence = f"{exc.code} ({type(exc).__name__})"
    return HealthReport(
        generated_at="startup-bootstrap-failure",
        install_root=str(installation_root()),
        data_root=str(paths.root),
        source_mode=not bool(getattr(sys, "frozen", False)),
        findings=[
            RepairFinding(
                code=code,
                category=category,
                severity="critical",
                title=title,
                detail=detail,
                evidence=evidence,
            )
        ],
    )


def _write_crash_marker(path: Path, phase: str) -> None:
    
    try:
        atomic_write_json(path, {"pid": os.getpid(), "phase": phase})
    except OSError:
        LOGGER.warning("Unable to write crash marker", extra={"phase": phase, "path": str(path)}, exc_info=True)


def main(argv: list[str] | None = None) -> int:
    if getattr(sys, "frozen", False):
        import multiprocessing
        multiprocessing.freeze_support()
    effective_argv = list(sys.argv[1:] if argv is None else argv)
                                                                                           
                                                                                       
    if effective_argv and effective_argv[0] == "--internal-plugin-worker":
        if len(effective_argv) != 3:
            console_write("invalid internal plugin worker arguments", file=sys.stderr)
            return 2
        from arenyxa.infrastructure.plugin_worker import run as run_plugin_worker

        return run_plugin_worker(effective_argv[1], effective_argv[2])

                                                                                         
                                                                                            
                                                                             
    try:
        if not faulthandler.is_enabled():
            faulthandler.enable(all_threads=True)
    except (OSError, RuntimeError):
        pass

    arguments = build_parser().parse_args(effective_argv)
    if arguments.repair_worker is not None:
        return run_repair_worker(arguments.repair_worker)
    if arguments.verify_installation:
        report = verify_release_attestation(installation_root(), deep_files=True)
        if arguments.provenance_json:
            console_write(json.dumps({
                "state": report.state.value,
                "channel": report.channel,
                "product": report.product,
                "version": report.version,
                "build_id": report.build_id,
                "signer_key_id": report.signer_key_id,
                "signature_valid": report.signature_valid,
                "trusted_signer": report.trusted_signer,
                "modified_files": report.modified_files,
                "unexpected_files": getattr(report, "unexpected_files", []),
                "notes": report.notes,
            }, ensure_ascii=False, indent=2))
        else:
            console_write(f"Arenyxa provenance: {report.display_name}")
            if report.build_id:
                console_write(f"Build ID: {report.build_id}")
            if report.signer_key_id:
                console_write(f"Signer: {report.signer_key_id}")
            for note in report.notes:
                console_write(f"- {note}")
            if report.modified_files:
                for relative in report.modified_files[:20]:
                    console_write(f"  modified: {relative}")
            for relative in getattr(report, "unexpected_files", [])[:20]:
                console_write(f"  unexpected-loadable: {relative}")
        if report.state in {ProvenanceState.VERIFIED_OFFICIAL, ProvenanceState.VERIFIED_COMMUNITY, ProvenanceState.DEVELOPMENT}:
            return 0
        if report.state == ProvenanceState.UNVERIFIED:
            return 2
        return 3

                                                                                         
                                                                                         
    runtime = select_runtime()
    validate_python_for_runtime(runtime)
    apply_legacy_environment(runtime)
    system_reduce_motion = windows_reduced_motion_requested()
    os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")

    paths = AppPaths.discover(arguments.data_dir)
    paths.initialize()

                                                                                          
                                                                                            
    if repair_worker_active(paths.root):
        _native_repair_busy_notice()
        return 1

                                                                                                    
                                                                                                      
    active_qt_binding = available_binding_name()
    if active_qt_binding != runtime.qt_binding:
                                                                                             
                                                                                          
        from arenyxa.infrastructure.data_root_lock import DataRootLease

        bootstrap_lease = DataRootLease(paths.root)
        if not bootstrap_lease.acquire():
            _native_repair_busy_notice()
            return 1
        try:
            startup_report = StartupHealthScanner(paths, installation_root()).scan()
            if not any(item.category == RepairCategory.PROGRAM_FILES for item in startup_report.findings):
                ensure_known_good_seed(paths)
            if not any(item.category == RepairCategory.DEPENDENCIES for item in startup_report.findings):
                expected = runtime.qt_binding
                startup_report.findings.append(
                    RepairFinding(
                        "QT_BINDING_MISSING",
                        RepairCategory.DEPENDENCIES,
                        "critical",
                        f"{expected} 缺失",
                        f"{runtime.tier} Qt UI 无法启动。",
                        expected,
                    )
                )
            if _native_repair_question(startup_report):
                plan_path = create_repair_plan(
                    paths,
                    startup_report,
                    startup_report.categories or [RepairCategory.DEPENDENCIES],
                    parent_pid=os.getpid(),
                    relaunch=True,
                )
                launch_repair_worker(plan_path)
                return 0
            return 2
        finally:
            bootstrap_lease.release()

    from arenyxa.qt_compat.QtCore import QCoreApplication, QTimer, Qt
    from arenyxa.qt_compat.QtGui import QIcon
    from arenyxa.qt_compat.QtWidgets import QApplication, QLabel, QMainWindow, QMessageBox, QVBoxLayout, QWidget
    from arenyxa.infrastructure.single_instance import SingleInstance
    from arenyxa.infrastructure.data_root_lock import DataRootLease

    QCoreApplication.setOrganizationName(APP_NAME)
    QCoreApplication.setApplicationName(APP_NAME)
    QCoreApplication.setApplicationVersion(__version__)
    application = QApplication(sys.argv[:1])
    if hasattr(application, "setApplicationDisplayName"):
        application.setApplicationDisplayName(APP_NAME)
                                                                                              
                                                                                                  
    startup_icon_path = preferred_window_icon_path()
    if startup_icon_path.is_file():
        application.setWindowIcon(QIcon(str(startup_icon_path)))

                                                                                              
                                                                                                
    single_instance = SingleInstance(paths.root, application)
    if not single_instance.acquire():
        single_instance.notify(str(arguments.project or "activate"))
        return 0

                                                                                   
                                                                                 
    data_root_lease = DataRootLease(paths.root)
    if not data_root_lease.acquire():
        QMessageBox.critical(
            None,
            "Arenyxa",
            "当前数据目录正被另一个 Arenyxa Desktop/Server 运行时使用。\n"
            "请关闭另一个运行时，或为本实例选择不同的数据目录。",
        )
        return 1

                                                                                            
                                                                                               
                                                                                              
                                                                    
    locale = _startup_locale(paths)

                                                                                       
                                                                                              
                                                                                                 
                                                                              
    startup_settings = AppSettings.load(paths.root / "settings.json")
                                                                                                
                                                                                                
                                                                        
    from arenyxa.presentation.launch_geometry import resolve_launch_geometry

    launch_geometry = resolve_launch_geometry(paths.root / "window.ini")
    startup_splash = None
    try:
        from arenyxa.presentation.startup_splash import create_startup_splash

        startup_splash = create_startup_splash(
            preferred_window_icon_path(),
            reduce_motion=bool(startup_settings.reduce_motion or system_reduce_motion),
            safe_mode=arguments.safe_mode,
            smoke_test=arguments.smoke_test,
            reduced_visuals=runtime.reduced_visuals,
            performance_mode=startup_settings.performance_mode,
            geometry=launch_geometry.rect,
        )
        if startup_splash is not None:
            startup_splash.present()
    except Exception:
                                                                                              
                                                                                             
        LOGGER.exception("Startup splash failed; continuing with ordinary startup")
        if startup_splash is not None:
            try:
                startup_splash.abort()
            except Exception:
                LOGGER.debug("Startup splash cleanup also failed", exc_info=True)
        startup_splash = None

                                                                                                          
    crash_marker = paths.root / "crash.marker"
    _write_crash_marker(crash_marker, "bootstrap")

    try:
        from arenyxa.bootstrap import bootstrap

        context = bootstrap(arguments.data_dir, arguments.safe_mode)
    except Exception as exc:                                                                    
        if startup_splash is not None:
            startup_splash.abort()
        failure_report = _bootstrap_failure_report(paths, exc)
        if arguments.smoke_test:
            data_root_lease.release()
            raise
        from arenyxa.presentation.repair_dialog import RepairSelectionDialog, ask_startup_repair

                                                                                          
                                                                                             
                                                                                              
                                                                                                               
        recovery_window = QMainWindow()
        recovery_window.setWindowTitle("Arenyxa · Recovery Mode")
        recovery_width = min(760, max(1, int(launch_geometry.rect.width())))
        recovery_height = min(430, max(1, int(launch_geometry.rect.height())))
        recovery_x = int(launch_geometry.rect.x()) + max(0, (int(launch_geometry.rect.width()) - recovery_width) // 2)
        recovery_y = int(launch_geometry.rect.y()) + max(0, (int(launch_geometry.rect.height()) - recovery_height) // 2)
        recovery_window.setGeometry(recovery_x, recovery_y, recovery_width, recovery_height)
        recovery_root = QWidget(recovery_window)
        recovery_layout = QVBoxLayout(recovery_root)
        recovery_layout.setContentsMargins(38, 34, 38, 34)
        recovery_layout.setSpacing(14)
        recovery_title = QLabel("Arenyxa")
        recovery_title.setStyleSheet("font-size: 28px; font-weight: 750;")
        recovery_subtitle = QLabel("启动恢复模式 / Startup Recovery Mode")
        recovery_subtitle.setStyleSheet("font-size: 17px; font-weight: 650;")
        recovery_detail = QLabel(
            "主工作区初始化未完成。Arenyxa 已进入安全恢复界面，正在提供具体问题与修复选项。\n\n"
            f"{exc}"
        )
        recovery_detail.setWordWrap(True)
        recovery_detail.setTextInteractionFlags(recovery_detail.textInteractionFlags() | Qt.TextInteractionFlag.TextSelectableByMouse)
        recovery_layout.addWidget(recovery_title)
        recovery_layout.addWidget(recovery_subtitle)
        recovery_layout.addWidget(recovery_detail, 1)
        recovery_window.setCentralWidget(recovery_root)
        recovery_window.show()
        recovery_window.raise_()
        application.processEvents()

        if ask_startup_repair(failure_report, locale, recovery_window):
            selector = RepairSelectionDialog(failure_report, locale, recovery_window)
            if selector.exec() == selector.DialogCode.Accepted:
                plan_path = create_repair_plan(
                    paths,
                    failure_report,
                    selector.selected_categories(),
                    parent_pid=os.getpid(),
                    relaunch=True,
                )
                launch_repair_worker(plan_path)
                recovery_window.close()
                data_root_lease.release()
                return 0
        QMessageBox.critical(recovery_window, "Arenyxa", f"Arenyxa initialization failed:\n{exc}")
        recovery_window.close()
        data_root_lease.release()
        return 1

    from arenyxa.presentation.main_window import MainWindow

    try:
        window = MainWindow(context, project_path=arguments.project, launch_geometry=launch_geometry)
    except Exception as exc:
        if startup_splash is not None:
            startup_splash.abort()
        LOGGER.exception("Main window construction failed")
                                                                                               
                                                                                              
                                                                                      
        try:
            context.shutdown()
        except Exception:
            LOGGER.exception("Context shutdown failed after main-window construction failure")
        finally:
            data_root_lease.release()
        QMessageBox.critical(None, "Arenyxa", f"Arenyxa interface initialization failed:\n{exc}")
        return 1
    _write_crash_marker(crash_marker, "running")

                                                                                             
                                                                                               
                                                                                                
                                                                                                
                                                                                            
    finalization_lock = threading.Lock()
    runtime_finalized = False

    def finalize_runtime() -> None:
        nonlocal runtime_finalized
        with finalization_lock:
            if runtime_finalized:
                return
            runtime_finalized = True
        try:
            from arenyxa.presentation.background import begin_background_shutdown

            if not begin_background_shutdown(timeout_ms=2500):
                LOGGER.warning("UI background jobs did not fully quiesce during application finalization")
        except Exception:
            LOGGER.exception("UI background shutdown boundary failed")
        try:
            context.shutdown()
        finally:
            try:
                crash_marker.unlink(missing_ok=True)
            except OSError:
                LOGGER.exception("Failed to remove crash marker during application finalization")
                                                                                               
                                                                                        
                                                                     
            data_root_lease.release()

    application.aboutToQuit.connect(finalize_runtime)

    def activate_window(message: str) -> None:
        window.showNormal()
        window.raise_()
        window.activateWindow()
        if message not in {"", "activate"}:
            window.open_project(Path(message))

    single_instance.messageReceived.connect(activate_window)
                                                                                                
                                                                                                 
                                                                                                 
    if startup_splash is not None:
        startup_splash.prepare_handoff(window)
    if launch_geometry.maximized:
        window.showMaximized()
    else:
        window.show()
    if startup_splash is not None:
        application.processEvents()
        startup_splash.finish(window)
                                                                                                    
                                                                                           
    window.show_pending_welcome()
    if context.runtime_recovery.changed:
        recovery = context.runtime_recovery
        window.show_status(
            "已自动恢复上次中断状态："
            f"Run {recovery.recovered_runs} · Capture {recovery.recovered_captures} · "
            f"已完成 Workflow 对账 {recovery.reconciled_completed_workflows} · "
            f"Workflow {recovery.interrupted_workflows} · Revision {recovery.interrupted_revisions}",
            7000,
        )

    def deferred_startup_health_check() -> None:
        if arguments.smoke_test:
            return
        from arenyxa.presentation.background import run_background

        window.show_status("Arenyxa 正在后台执行启动健康检查…", 2800)

        def worker() -> HealthReport:
            report = StartupHealthScanner(
                paths, installation_root(), ignore_current_session=True
            ).scan()
                                                                                         
                                                            
            append_feature_integration_findings(report, context)
                                                                                            
                                                                                   
            atomic_write_json(paths.root / "repair" / "last_health_report.json", report.to_dict())
            if not any(item.category == RepairCategory.PROGRAM_FILES for item in report.findings):
                ensure_known_good_seed(paths)
            return report

        def completed(value: object) -> None:
            if not isinstance(value, HealthReport):
                window.show_status("启动健康检查返回了无效结果", 5000)
                return
            report = value
            window.set_startup_health_report(report)
            if not report.findings:
                window.show_status("启动健康检查完成：未发现异常", 3200)
                return
            window.show_status(f"启动健康检查发现 {len(report.findings)} 项需要关注的问题", 6500)
            if arguments.post_repair:
                                                                                           
                                                                                         
                                           
                return
            from arenyxa.presentation.repair_dialog import RepairSelectionDialog, ask_startup_repair

                                                                                          
                                                                                             
            if not ask_startup_repair(report, window.language.locale, window):
                return
            selector = RepairSelectionDialog(report, window.language.locale, window)
            if selector.exec() != selector.DialogCode.Accepted:
                return
            plan_path = create_repair_plan(
                paths,
                report,
                selector.selected_categories(),
                parent_pid=os.getpid(),
                relaunch=True,
            )
            launch_repair_worker(plan_path)
            window.request_repair_exit()

        def failed(message: str) -> None:
                                                                                             
                                                                                        
                                        
            window.show_status(f"启动健康检查未完成：{message}", 8000)

        run_background(worker, completed, failed)

    if arguments.post_repair and not arguments.smoke_test:
        from arenyxa.presentation.repair_dialog import show_post_repair_report

        report_path = context.paths.root / "repair" / "last_repair_report.json"
        QTimer.singleShot(650, lambda: show_post_repair_report(report_path, window.language.locale, window))
        QTimer.singleShot(1200, deferred_startup_health_check)
    elif not arguments.smoke_test:
                                                                                          
        QTimer.singleShot(700, deferred_startup_health_check)
    if arguments.smoke_test:
        QTimer.singleShot(1200, window.close)
    try:
        return application.exec()
    finally:
                                                                                               
                                                      
        finalize_runtime()


if __name__ == "__main__":
    raise SystemExit(main())
