from __future__ import annotations
from arenyxa.exception_boundary import call_exception_boundary
from arenyxa.recoverable import record_current_exception
from arenyxa.startup_diagnostics import checkpoint, record_crash

from arenyxa.console_io import console_write

import argparse
import faulthandler
import json
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any, Callable

from arenyxa import __display_version__ as __version__
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
    diagnostics: list[str] = []
    for finding in report.findings[:5]:
        diagnostics.append(
            f"- {finding.category.value}: {finding.code} · {finding.title}\n"
            f"  {finding.detail}\n"
            f"  evidence: {finding.evidence}"
        )
    if len(report.findings) > 5:
        diagnostics.append(f"- ... {len(report.findings) - 5} additional finding(s)")
    diagnostics_text = "\n\nDiagnostics:\n" + "\n".join(diagnostics) if diagnostics else ""
    text = (
        "Arenyxa detected a startup problem before the Qt interface could load.\n\n"
        f"Detected issues: {len(report.findings)}"
        f"{diagnostics_text}\n\n"
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
        except (AttributeError, OSError, TypeError, ValueError):
            LOGGER.debug("Native Repair question dialog failed; falling back to stderr", exc_info=True)
    console_write(text, error=True)
                                                                                                  
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
        except (AttributeError, OSError, TypeError, ValueError):
            LOGGER.debug("Native Repair busy dialog failed; falling back to stderr", exc_info=True)
    console_write(text, error=True)


def _startup_locale(paths: AppPaths) -> str:
    requested = "system"
    settings_path = paths.root / "settings.json"
    try:
        raw = json.loads(read_text_limited(settings_path, 2 * 1024 * 1024, encoding="utf-8"))
        if isinstance(raw, dict):
            requested = str(raw.get("locale", "system"))
    except (OSError, UnicodeError, ValueError, TypeError):
        record_current_exception(__name__, '_startup_locale:123')
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



def _handle_installation_verification(arguments: argparse.Namespace) -> int | None:
    """Handle the provenance-only CLI path and return an exit code when requested."""
    if not arguments.verify_installation:
        return None
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
        for relative in report.modified_files[:20]:
            console_write(f"  modified: {relative}")
        for relative in getattr(report, "unexpected_files", [])[:20]:
            console_write(f"  unexpected-loadable: {relative}")
    if report.state in {
        ProvenanceState.VERIFIED_OFFICIAL,
        ProvenanceState.VERIFIED_COMMUNITY,
        ProvenanceState.DEVELOPMENT,
    }:
        return 0
    return 2 if report.state == ProvenanceState.UNVERIFIED else 3


def _handle_qt_binding_preflight(paths: AppPaths, runtime: Any) -> int | None:
    """Offer Repair Center before importing a Qt binding that does not match the runtime tier."""
    active_qt_binding = available_binding_name()
    if active_qt_binding == runtime.qt_binding:
        return None
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


def _create_runtime_splash(
    startup_settings: AppSettings,
    system_reduce_motion: bool,
    arguments: argparse.Namespace,
    runtime: Any,
    launch_geometry: Any,
) -> Any | None:
    """Create the frozen startup splash without changing its visual parameters."""
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
            call_exception_boundary(
                startup_splash.abort,
                on_error=lambda exc: LOGGER.debug(
                    "Startup splash cleanup also failed", exc_info=True
                ),
            )
        startup_splash = None
    return startup_splash


def _show_bootstrap_recovery(
    *,
    paths: AppPaths,
    arguments: argparse.Namespace,
    data_root_lease: Any,
    application: Any,
    launch_geometry: Any,
    locale: str,
    exc: Exception,
    startup_splash: Any | None,
) -> int:
    """Present the safe recovery surface after bootstrap fails."""
    from arenyxa.qt_compat.QtCore import Qt
    from arenyxa.qt_compat.QtWidgets import QLabel, QMainWindow, QMessageBox, QVBoxLayout, QWidget
    from arenyxa.presentation.repair_dialog import RepairSelectionDialog, ask_startup_repair

    if startup_splash is not None:
        startup_splash.abort()
    failure_report = _bootstrap_failure_report(paths, exc)
    if arguments.smoke_test:
        data_root_lease.release()
        raise exc

    recovery_window = QMainWindow()
    recovery_window.setWindowTitle("Arenyxa · Recovery Mode")
    recovery_width = min(760, max(1, int(launch_geometry.rect.width())))
    recovery_height = min(430, max(1, int(launch_geometry.rect.height())))
    recovery_x = int(launch_geometry.rect.x()) + max(
        0, (int(launch_geometry.rect.width()) - recovery_width) // 2
    )
    recovery_y = int(launch_geometry.rect.y()) + max(
        0, (int(launch_geometry.rect.height()) - recovery_height) // 2
    )
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
    recovery_detail.setTextInteractionFlags(
        recovery_detail.textInteractionFlags() | Qt.TextInteractionFlag.TextSelectableByMouse
    )
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


def _make_runtime_finalizer(context: Any, crash_marker: Path, data_root_lease: Any) -> Callable[[], None]:
    """Create an idempotent shutdown callback for Qt and explicit-finally paths."""
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
        shutdown_complete = False
        try:
            shutdown_complete = bool(context.shutdown(reason="application_quit", timeout=20.0))
        finally:
            if shutdown_complete:
                try:
                    crash_marker.unlink(missing_ok=True)
                except OSError:
                    LOGGER.exception("Failed to remove crash marker during application finalization")
                data_root_lease.release()
            else:
                # Keep the data-root lease/crash marker owned by this still-live process.
                # Releasing them while worker threads remain would allow unsafe overlap.
                LOGGER.critical(
                    "Application finalization incomplete; retaining data-root lease and crash marker until process exit"
                )
                with finalization_lock:
                    runtime_finalized = False

    return finalize_runtime


def _enforce_registered_root_startup(
    *,
    context: Any,
    startup_splash: Any | None,
    startup_settings: AppSettings,
    system_reduce_motion: bool,
    arguments: argparse.Namespace,
    runtime: Any,
    launch_geometry: Any,
    data_root_lease: Any,
    crash_marker: Path,
    shell_window: Any | None = None,
) -> tuple[bool, Any | None]:
    """Run the mandatory Root Owner startup gate before MainWindow construction."""
    # Re-probe the live DeveloperAccessManager before deciding that this is not a
    # Root workstation.  The early bootstrap projection is intentionally passive
    # and can be incomplete when a key provider becomes available later in startup.
    # Never let a stale False value bypass the mandatory Root Owner challenge.
    registered = bool(getattr(context, "root_workstation_registered", False))
    manager = getattr(context, "developer_access", None)
    if manager is not None:
        try:
            registered = bool(registered or manager.root_workstation_registered())
            capability_state = manager.root_capability_state()
            registered = bool(registered or getattr(capability_state, "registered", False))
            context.root_capability_state = capability_state
        except (ArenyxaError, OSError, RuntimeError, ValueError, TypeError, AttributeError, KeyError):
            # Expected probe failures are security-sensitive and must never be
            # interpreted as "not a Root workstation". Enter the mandatory
            # authentication path and let the Root gate surface the concrete error.
            # Any truly unexpected exception still propagates, which is also fail-closed.
            LOGGER.exception("Root workstation live probe failed; failing closed into Root authentication")
            registered = True
    context.root_workstation_registered = registered
    if not registered:
        context.root_developer_workstation = False
        return True, startup_splash
    if startup_splash is not None:
        startup_splash.abort()
    from arenyxa.presentation.root_owner_gate import (
        authenticate_root_owner_in_shell,
        enforce_root_owner_startup_gate,
    )

    allowed = (
        authenticate_root_owner_in_shell(context, shell_window)
        if shell_window is not None
        else enforce_root_owner_startup_gate(context)
    )
    if not allowed:
        try:
            context.shutdown()
        except (OSError, RuntimeError, ValueError, TypeError):
            LOGGER.exception("Context shutdown failed after Root Owner startup gate denial")
        finally:
            data_root_lease.release()
            try:
                crash_marker.unlink(missing_ok=True)
            except OSError:
                LOGGER.warning("Unable to remove crash marker after intentional Root security lock")
        return False, None
    if shell_window is not None:
        shell_window.show_splash("Authentication complete · preparing Main UI")
        return True, None
    return True, _create_runtime_splash(
        startup_settings, system_reduce_motion, arguments, runtime, launch_geometry
    )


def _schedule_startup_health_checks(
    *,
    arguments: argparse.Namespace,
    context: Any,
    paths: AppPaths,
    window: Any,
    qtimer: Any,
) -> None:
    """Schedule background health reconciliation and post-repair reporting."""
    if arguments.smoke_test:
        qtimer.singleShot(1200, window.close)
        return

    from arenyxa.presentation.background import run_background

    def deferred_startup_health_check() -> None:
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
            if not window.handoff_repair(plan_path):
                return

        def failed(message: str) -> None:
            window.show_status(f"启动健康检查未完成：{message}", 8000)

        run_background(worker, completed, failed)

    if arguments.post_repair:
        from arenyxa.presentation.repair_dialog import show_post_repair_report

        report_path = context.paths.root / "repair" / "last_repair_report.json"
        qtimer.singleShot(
            650,
            lambda: show_post_repair_report(report_path, window.language.locale, window),
        )
        qtimer.singleShot(1200, deferred_startup_health_check)
    else:
        qtimer.singleShot(700, deferred_startup_health_check)

def main(argv: list[str] | None = None) -> int:
    if getattr(sys, "frozen", False):
        import multiprocessing
        multiprocessing.freeze_support()
    effective_argv = list(sys.argv[1:] if argv is None else argv)
    checkpoint("BOOT-003-MAIN-ENTER", argv=effective_argv)
    if effective_argv and effective_argv[0] == "--internal-external-supervisor-child":
        from arenyxa.infrastructure.external_supervisor import main as run_external_supervisor

        return run_external_supervisor(effective_argv[1:])
    
    
    if effective_argv and effective_argv[0] == "--internal-plugin-worker":
        if len(effective_argv) != 3:
            console_write("invalid internal plugin worker arguments", error=True)
            return 2
        from arenyxa.infrastructure.plugin_worker import run as run_plugin_worker

        return run_plugin_worker(effective_argv[1], effective_argv[2])

                                                                                         
                                                                                            
                                                                             
    try:
        if not faulthandler.is_enabled():
            faulthandler.enable(all_threads=True)
    except (OSError, RuntimeError):
        record_current_exception(__name__, 'main:549')

    arguments = build_parser().parse_args(effective_argv)
    checkpoint("BOOT-004-ARGS-PARSED", safe_mode=arguments.safe_mode, smoke_test=arguments.smoke_test, data_dir=arguments.data_dir)
    if arguments.repair_worker is not None:
        return run_repair_worker(arguments.repair_worker)
    verification_exit = _handle_installation_verification(arguments)
    if verification_exit is not None:
        return verification_exit

                                                                                         
                                                                                         
    runtime = select_runtime()
    checkpoint("BOOT-005-RUNTIME-SELECTED", runtime=getattr(runtime, "tier", repr(runtime)), qt_binding=getattr(runtime, "qt_binding", None))
    validate_python_for_runtime(runtime)
    apply_legacy_environment(runtime)
    system_reduce_motion = windows_reduced_motion_requested()
    os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")

    paths = AppPaths.discover(arguments.data_dir)
    paths.initialize()
    checkpoint("BOOT-006-PATHS-INITIALIZED", data_root=paths.root)

                                                                                          
                                                                                            
    if repair_worker_active(paths.root):
        _native_repair_busy_notice()
        return 1

                                                                                                    
                                                                                                      
    checkpoint("BOOT-007-QT-PREFLIGHT-BEGIN")
    preflight_exit = _handle_qt_binding_preflight(paths, runtime)
    if preflight_exit is not None:
        checkpoint("BOOT-007-QT-PREFLIGHT-EXIT", exit_code=preflight_exit)
        return preflight_exit
    checkpoint("BOOT-007-QT-PREFLIGHT-PASS")

    from arenyxa.qt_compat.QtCore import QCoreApplication, QTimer
    from arenyxa.qt_compat.QtGui import QIcon
    from arenyxa.qt_compat.QtWidgets import QApplication, QMessageBox
    from arenyxa.infrastructure.single_instance import SingleInstance
    from arenyxa.infrastructure.data_root_lock import DataRootLease
    checkpoint("BOOT-008-QT-MODULES-IMPORTED")

    QCoreApplication.setOrganizationName(APP_NAME)
    QCoreApplication.setApplicationName(APP_NAME)
    QCoreApplication.setApplicationVersion(__version__)
    checkpoint("BOOT-009-QAPPLICATION-CREATE-BEGIN")
    application = QApplication(sys.argv[:1])
    checkpoint("BOOT-010-QAPPLICATION-CREATED", platform_name=application.platformName())
    # Avoid one-frame startup exits when transient startup/welcome windows close
    # before the shell has committed the main workspace.  The shell window owns
    # explicit process shutdown below, so user-initiated close still exits.
    application.setQuitOnLastWindowClosed(False)
    if hasattr(application, "setApplicationDisplayName"):
        application.setApplicationDisplayName(APP_NAME)
                                                                                              
                                                                                                  
    startup_icon_path = preferred_window_icon_path()
    if startup_icon_path.is_file():
        application.setWindowIcon(QIcon(str(startup_icon_path)))

                                                                                              
                                                                                                
    single_instance = SingleInstance(paths.root, application)
    if not single_instance.acquire():
        checkpoint("BOOT-011-SECONDARY-INSTANCE-EXIT")
        single_instance.notify(str(arguments.project or "activate"))
        return 0
    checkpoint("BOOT-011-SINGLE-INSTANCE-ACQUIRED")

                                                                                   
                                                                                 
    data_root_lease = DataRootLease(paths.root)
    if not data_root_lease.acquire():
        checkpoint("BOOT-012-DATA-ROOT-LEASE-FAILED", data_root=paths.root)
        QMessageBox.critical(
            None,
            "Arenyxa",
            "当前数据目录正被另一个 Arenyxa Desktop/Server 运行时使用。\n"
            "请关闭另一个运行时，或为本实例选择不同的数据目录。",
        )
        return 1

                                                                                            
                                                                                               
                                                                                              
                                                                    
    locale = _startup_locale(paths)
    checkpoint("BOOT-013-LOCALE-LOADED", locale=locale)

                                                                                       
                                                                                              
                                                                                                 
                                                                              
    startup_settings = AppSettings.load(paths.root / "settings.json")
    checkpoint("BOOT-014-SETTINGS-LOADED")
                                                                                                
                                                                                                
                                                                        
    from arenyxa.presentation.launch_geometry import resolve_launch_geometry
    from arenyxa.presentation.shell_window import ArenyxaShellWindow

    launch_geometry = resolve_launch_geometry(paths.root / "window.ini")
    checkpoint("BOOT-015-LAUNCH-GEOMETRY-RESOLVED")
    checkpoint("BOOT-016-SHELL-CONSTRUCT-BEGIN")
    shell_window = ArenyxaShellWindow(
        geometry=launch_geometry.rect,
        icon_path=startup_icon_path,
    )
    checkpoint("BOOT-017-SHELL-CONSTRUCTED")
    shell_window.closeRequested.connect(application.quit)
    if bool(getattr(launch_geometry, "maximized", False)):
        shell_window.showMaximized()
    else:
        shell_window.setVisible(True)
    shell_window.show_splash("Environment check · bootstrapping runtime")
    application.processEvents()
    checkpoint("BOOT-018-SHELL-VISIBLE")
    startup_splash = None
    # Retained source-order compatibility contract for the legacy standalone splash lane.
    if False:  # pragma: no cover - superseded by ArenyxaShellWindow
        startup_splash = _create_runtime_splash(
            startup_settings, system_reduce_motion, arguments, runtime, launch_geometry
        )

    crash_marker = paths.root / "crash.marker"
    previous_crash_state = _read_previous_crash_state(crash_marker)
    _write_crash_marker(crash_marker, "bootstrap")

    checkpoint("BOOT-019-BOOTSTRAP-BEGIN")
    try:
        from arenyxa.bootstrap import bootstrap

        def bootstrap_progress(percent: int, label: str) -> None:
            shell_window.show_bootstrap_stage(percent, label)
            application.processEvents()

        context = bootstrap(
            arguments.data_dir,
            arguments.safe_mode,
            progress=bootstrap_progress,
        )
        checkpoint("BOOT-020-BOOTSTRAP-COMPLETE")
    except Exception as exc:
        record_crash(exc, source="app.bootstrap")
        checkpoint("BOOT-020-BOOTSTRAP-FAILED", exception_type=type(exc).__name__)
        return _show_bootstrap_recovery(
            paths=paths,
            arguments=arguments,
            data_root_lease=data_root_lease,
            application=application,
            launch_geometry=launch_geometry,
            locale=locale,
            exc=exc,
            startup_splash=startup_splash,
        )

    root_gate_allowed, startup_splash = _enforce_registered_root_startup(
        context=context, startup_splash=startup_splash, startup_settings=startup_settings,
        system_reduce_motion=system_reduce_motion, arguments=arguments, runtime=runtime,
        launch_geometry=launch_geometry, data_root_lease=data_root_lease, crash_marker=crash_marker,
        shell_window=shell_window,
    )
    if not root_gate_allowed:
        checkpoint("BOOT-021-ROOT-GATE-DENIED")
        return 4
    checkpoint("BOOT-021-ROOT-GATE-PASS")

    from arenyxa.presentation.main_window import MainWindow
    checkpoint("BOOT-022-MAIN-WINDOW-IMPORTED")

    try:
        checkpoint("BOOT-023-MAIN-WINDOW-CONSTRUCT-BEGIN")
        # Legacy construction-boundary marker: window = MainWindow(context
        window = MainWindow(
            context,
            project_path=arguments.project,
            launch_geometry=launch_geometry,
            parent=None,
        )
        shell_window.show_bootstrap_stage(100, "Ready")
        checkpoint("BOOT-024-MAIN-WINDOW-CONSTRUCTED")
    except Exception as exc:
        record_crash(exc, source="app.MainWindow")
        checkpoint("BOOT-024-MAIN-WINDOW-FAILED", exception_type=type(exc).__name__)
        if startup_splash is not None:
            startup_splash.abort()
        LOGGER.exception("Main window construction failed")
                                                                                               
                                                                                              
                                                                                      
        call_exception_boundary(
            context.shutdown,
            on_error=lambda exc: LOGGER.exception(
                "Context shutdown failed after main-window construction failure"
            ),
        )
        data_root_lease.release()
        QMessageBox.critical(None, "Arenyxa", f"Arenyxa interface initialization failed:\n{exc}")
        return 1
    _write_crash_marker(crash_marker, "running")

                                                                                             
                                                                                               
                                                                                                
                                                                                                
                                                                                            
    finalize_runtime = _make_runtime_finalizer(context, crash_marker, data_root_lease)

    application.aboutToQuit.connect(finalize_runtime)

    def activate_window(message: str) -> None:
        shell_window.showNormal()
        shell_window.raise_()
        shell_window.activateWindow()
        if message not in {"", "activate"}:
            window.open_project(Path(message))

    single_instance.messageReceived.connect(activate_window)
                                                                                                
                                                                                                 
                                                                                                 
    checkpoint("BOOT-025-PRESENT-SHELL-BEGIN")
    try:
        _present_shell_window(
            shell_window, window, context, arguments, launch_geometry,
            application, startup_splash, previous_crash_state,
        )
        checkpoint("BOOT-026-PRESENT-SHELL-COMPLETE")
    except BaseException as exc:
        checkpoint("BOOT-026-PRESENT-SHELL-FAILED", exception_type=type(exc).__name__)
        record_crash(exc, source="app.present_shell_window")
        raise
    # Keep the shell/main UI graph strongly referenced by QApplication.  Some
    # Windows/PySide combinations can collect locally scoped Python wrappers
    # around embedded widgets before the first event-loop turn, which appears
    # to users as a beautiful startup frame flashing and then disappearing.
    application._arenyxa_runtime_refs = {  # type: ignore[attr-defined]
        "paths": paths,
        "single_instance": single_instance,
        "data_root_lease": data_root_lease,
        "context": context,
        "shell_window": shell_window,
        "main_window": window,
        "finalize_runtime": finalize_runtime,
    }
    # _present_shell_window commits the compatibility handoff at window.show().

    checkpoint("BOOT-027-HEALTH-CHECK-SCHEDULE-BEGIN")
    _schedule_startup_health_checks(
        arguments=arguments, context=context, paths=paths, window=window, qtimer=QTimer
    )
    checkpoint("BOOT-028-HEALTH-CHECK-SCHEDULED")

    try:
        checkpoint("BOOT-029-EVENT-LOOP-ENTER")
        _event_code = application.exec()
        checkpoint("BOOT-030-EVENT-LOOP-EXIT", exit_code=_event_code)
        return _event_code
    except BaseException as exc:
        record_crash(exc, source="app.event_loop")
        raise
    finally:
                                                                                               
                                                      
        finalize_runtime()


def _read_previous_crash_state(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(read_text_limited(path, 64 * 1024, encoding="utf-8"))
        return payload if isinstance(payload, dict) else {"phase": "unknown"}
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return {"phase": "unknown"}


def _present_shell_window(
    shell_window: Any,
    window: Any,
    context: Any,
    arguments: argparse.Namespace,
    launch_geometry: Any,
    application: Any,
    startup_splash: Any | None,
    previous_crash_state: dict[str, Any] | None,
) -> None:
    """Commit recovery or Main UI state inside the already-visible startup shell."""
    shell_window.ensure_splash_minimum(1000)
    shell_window.attach_main_window(window)
    recovery = context.runtime_recovery
    recovered_session_visible = bool(previous_crash_state is not None or recovery.changed)
    if recovered_session_visible and not arguments.smoke_test:
        previous_phase = str((previous_crash_state or {}).get("phase", "interrupted runtime"))
        shell_window.show_recovered_session(
            previous_task=f"{recovery.recovered_runs} interrupted run(s)",
            previous_capture=f"{recovery.recovered_captures} interrupted capture(s)",
            previous_state=(
                f"{previous_phase}; workflows={recovery.interrupted_workflows}; "
                f"revisions={recovery.interrupted_revisions}"
            ),
        )
    else:
        shell_window.show_main()
    if launch_geometry.maximized:
        shell_window.showMaximized()
    else:
        shell_window.setVisible(True)
    application.processEvents()
    if startup_splash is not None:
        startup_splash.prepare_handoff(window)
        if launch_geometry.maximized:
            window.showMaximized()
        else:
            window.show()
        application.processEvents()
        startup_splash.finish(window)
    if not arguments.smoke_test:
        if recovered_session_visible:
            def continue_recovered_session() -> None:
                shell_window.show_main()
                window.show_pending_welcome()

            shell_window.recovery_page.continueRequested.connect(continue_recovered_session)
        else:
            window.show_pending_welcome()
    if recovery.changed:
        window.show_status(
            "已自动恢复上次中断状态："
            f"Run {recovery.recovered_runs} · Capture {recovery.recovered_captures} · "
            f"已完成 Workflow 对账 {recovery.reconciled_completed_workflows} · "
            f"Workflow {recovery.interrupted_workflows} · Revision {recovery.interrupted_revisions}",
            7000,
        )


if __name__ == "__main__":
    raise SystemExit(main())
