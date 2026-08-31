from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from arenyxa.qt_compat.QtCore import QSettings, QSize, Qt, QThreadPool, QTimer, QUrl, Signal
from arenyxa.qt_compat.QtGui import QAction, QColor, QCloseEvent, QDesktopServices, QFont, QIcon, QKeySequence, QPainter, QPixmap, QShortcut
from arenyxa.qt_compat.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QBoxLayout,
    QButtonGroup,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QProgressBar,
    QScrollArea,
    QStackedWidget,
    QStatusBar,
    QSystemTrayIcon,
    QMenu,
    QVBoxLayout,
    QWidget,
)
from arenyxa import __display_version__ as __version__
from arenyxa.branding import preferred_window_icon_path
from arenyxa.bootstrap import ApplicationContext
from arenyxa.application.experience import apply_experience_profile
from arenyxa.application.future_callbacks import WeakMethodFutureCallback
from arenyxa.application.general_user import GeneralUserIntentRouter, RuntimeCapabilityService, is_general_user, summarize_network_events
from arenyxa.domain.enums import CaptureSource, MotionIntent
from arenyxa.domain.models import MotionProfile
from arenyxa.presentation.background import begin_background_shutdown, run_background
from arenyxa.presentation.glass import GlassPanel
from arenyxa.presentation.language import LanguageManager
from arenyxa.presentation.launch_geometry import LaunchGeometryPlan
from arenyxa.presentation.motion import MotionOrchestrator
from arenyxa.presentation.pages.base import WorkspacePage
from arenyxa.presentation.pages.dashboard import DashboardPage
from arenyxa.presentation.pages.data import DataPage, SearchPage, VersionPage
from arenyxa.presentation.pages.network import NetworkPage
from arenyxa.presentation.pages.proxy import ProxyPage
from arenyxa.presentation.pages.mitm_proxy import MitmInterceptionPage
from arenyxa.presentation.pages.recovery import RecoveryCenterPage
from arenyxa.presentation.pages.settings import AboutPage, SettingsPage
from arenyxa.presentation.pages.personalization import PersonalizationPage
from arenyxa.presentation.pages.enterprise import EnterprisePage
from arenyxa.presentation.pages.server_ops import ServerOperationsPage
from arenyxa.presentation.pages.welcome import WelcomeCenterDialog
from arenyxa.presentation.pages.tasks import TasksPage
from arenyxa.presentation.pages.task_center import TaskCenterPage
from arenyxa.presentation.pages.tools import (
    AdvancedPlatformPage,
    AutomationPage,
    ConsolePage,
    LogsPage,
    PluginsPage,
    WorkflowPage,
)
from arenyxa.presentation.pages.visualization import VisualizationPage
from arenyxa.presentation.pages.studio import IntelligenceStudioPage
from arenyxa.presentation.pages.extraction import ExtractionStudioPage
from arenyxa.presentation.taskbar import WindowsTaskbarProgress
from arenyxa.presentation.themes import ThemeManager
from arenyxa.presentation.ui_scale import InterfaceScaleManager

from arenyxa.presentation.command_palette import CommandPalette
from arenyxa.presentation.main_window_registry import DEVELOPER_SHORTCUTS, PAGE_DEFINITIONS

LOGGER = logging.getLogger(__name__)

class MainWindowOperationsMixin:
    def show_status(self, message: str, duration: int = 5000) -> None:
        localized = self.language.literal(message)
        self.status_text.setText(localized)
        self._status_generation += 1
        generation = self._status_generation
                                                                                  
        lowered = message.casefold()
        if any(token in message for token in ("失败", "错误")) or any(token in lowered for token in ("failed", "error")):
            self.motion.emphasize(self.status_text, MotionIntent.ERROR)
        elif any(token in message for token in ("完成", "成功")) or any(token in lowered for token in ("completed", "success")):
            self.motion.emphasize(self.status_text, MotionIntent.SUCCESS)

        def clear_if_current() -> None:
            if generation == self._status_generation:
                self.status_text.setText(self.language.text("status.ready"))

        QTimer.singleShot(duration, clear_if_current)

    def update_operation_progress(self, label: str, completed: int, total: int, state: str) -> None:
        state = str(state or "normal").casefold()
        if state == "clear":
            self._aux_progress = None
        else:
            self._aux_progress = (str(label), max(0, int(completed)), max(0, int(total)), state)
        self.refresh_global_status()

    def refresh_global_status(self) -> None:
        handles = self.context.runner.active_handles()
        capture = self.context.capture.session
        capture_text = capture.state.value if capture else "idle"
        if is_general_user(self.context.settings):
            self.worker_status.setText(f"{len(handles)} background · capture {capture_text} · ready")
        else:
            frame = self.motion.profiler.snapshot()
            self.worker_status.setText(
                f"{len(handles)} background · capture {capture_text} · DB ready · "
                f"{self.motion.refresh_hz:.0f}Hz · {self.motion.effective_quality()} · p95 {float(frame['p95_ms']):.1f}ms"
            )
        active = [handle for handle in handles if not handle.future.done()]
        if active:
            completed = sum(max(0, int(handle.run.completed_units)) for handle in active)
            totals = [int(handle.run.total_units or 0) for handle in active]
            total = sum(value for value in totals if value > 0)
            paused = any(handle.run.status.value == "paused" for handle in active)
            failed = any(handle.run.status.value == "failed" for handle in active)
            if total > 0:
                percent = max(0, min(100, round(completed / total * 100)))
                self.live_progress.setRange(0, 100)
                self.live_progress.setValue(percent)
                self.live_progress.setFormat(f"{len(active)} runs · {percent}%")
                state = self.taskbar_progress.TBPF_PAUSED if paused else (self.taskbar_progress.TBPF_ERROR if failed else self.taskbar_progress.TBPF_NORMAL)
                self.taskbar_progress.set_progress(completed, total, state)
            else:
                self.live_progress.setRange(0, 0)
                self.live_progress.setFormat(f"{len(active)} runs")
                self.taskbar_progress.set_state(self.taskbar_progress.TBPF_INDETERMINATE)
            self.live_progress.setVisible(True)
        elif capture and capture_text in {"preparing", "capturing", "finalizing"}:
            self.live_progress.setVisible(True)
            self.live_progress.setRange(0, 0)
            self.live_progress.setFormat(f"Capture · {capture_text}")
            self.taskbar_progress.set_state(self.taskbar_progress.TBPF_INDETERMINATE)
        elif self._aux_progress is not None:
            label, completed, total, state_name = self._aux_progress
            self.live_progress.setVisible(True)
            if total > 0:
                percent = max(0, min(100, round(completed / total * 100)))
                self.live_progress.setRange(0, 100)
                self.live_progress.setValue(percent)
                self.live_progress.setFormat(f"{label} · {percent}%")
                taskbar_state = {
                    "paused": self.taskbar_progress.TBPF_PAUSED,
                    "error": self.taskbar_progress.TBPF_ERROR,
                }.get(state_name, self.taskbar_progress.TBPF_NORMAL)
                self.taskbar_progress.set_progress(completed, total, taskbar_state)
            else:
                self.live_progress.setRange(0, 0)
                self.live_progress.setFormat(label)
                self.taskbar_progress.set_state(self.taskbar_progress.TBPF_INDETERMINATE)
        else:
            self.live_progress.setVisible(False)
            self.live_progress.setRange(0, 100)
            self.live_progress.setValue(0)
            self.live_progress.setFormat("Idle")
            self.taskbar_progress.clear()
        if self.tray is not None:
            aux = f" · {self._aux_progress[0]}" if self._aux_progress else ""
            self.tray.setToolTip(f"Arenyxa · {len(active)} active · capture {capture_text}{aux}")

    def global_search_action(self) -> None:
        text = self.global_search.text().strip()
        if not text:
            self.show_command_palette()
            return
        search_page = self._ensure_page("search")
        assert isinstance(search_page, SearchPage)
        search_page.query.setText(text)
        self.navigate("search")
        search_page.search()

    def show_command_palette(self) -> None:
        commands: list[tuple[str, str, Callable[[], None]]] = []
        if is_general_user(self.context.settings):
            for workflow in GeneralUserIntentRouter().workflows():
                commands.append((
                    f"simple.{workflow.id} {' '.join(workflow.aliases)}",
                    f"{workflow.title} · {workflow.summary}",
                    lambda workflow_id=workflow.id: self.run_general_user_workflow(workflow_id),
                ))
        for page_id, _symbol, _key, _page_type, _group in PAGE_DEFINITIONS:
            if not self._page_allowed(page_id):
                continue
            button = self.nav_buttons.get(page_id)
            label = button.toolTip() if button is not None else page_id
            commands.append((f"nav.{page_id}", label, lambda page_id=page_id: self.navigate(page_id)))
        if is_general_user(self.context.settings):
            commands.extend([
                ("action.open_data", self.language.text("top.open_data"), self.open_data_folder),
                ("action.diagnostics", self.language.text("action.diagnostics"), self._run_diagnostics_command),
                ("action.repair", self.language.text("action.repair"), self.launch_repair_center),
            ])
            palette = CommandPalette(commands, self)
            QTimer.singleShot(0, lambda: self.language.translate_tree(palette))
            QTimer.singleShot(0, lambda: self.motion.reveal(palette, MotionIntent.EXPAND))
            palette.exec()
            return
        if self._developer_surface_enabled():
            for action_id, _symbol, key in DEVELOPER_SHORTCUTS:
                commands.append((f"dev.{action_id}", self.language.text(key), lambda action_id=action_id: self.open_developer_tool(action_id)))
        commands.extend(
            [
                ("action.run", self.language.text("top.run"), self.run_selected_task),
                ("action.capture", self.language.text("top.capture"), lambda: self.navigate("network")),
                ("action.open_data", self.language.text("top.open_data"), self.open_data_folder),
                ("action.diagnostics", self.language.text("action.diagnostics"), self._run_diagnostics_command),
                ("action.repair", self.language.text("action.repair"), self.launch_repair_center),
                ("studio.smartpath", "SmartPath 2.0 / Data Sources", lambda: self.open_studio_section("smartpath")),
                ("studio.blueprint", "Explainable Web Intelligence Blueprint", lambda: self.open_studio_section("blueprint")),
                ("studio.autopilot", "Autopilot Learning / Experience Store", lambda: self.open_studio_section("autopilot")),
                ("studio.compatibility", "Compatibility Lab", lambda: self.open_studio_section("compatibility")),
                ("studio.portability", "Open Workflow Portability", lambda: self.open_studio_section("portability")),
                ("studio.selector", "Selector Studio / Self-Heal", lambda: self.open_studio_section("selector")),
                ("studio.http", "HTTP Request Builder", lambda: self.open_studio_section("http")),
                ("studio.live", "Live Run & Activity Center", lambda: self.open_studio_section("live")),
                ("studio.secrets", "Secrets Vault", lambda: self.open_studio_section("secrets")),
                ("studio.profiles", "Browser Profiles & Marketplace", lambda: self.open_studio_section("profiles")),
                ("studio.workers", "Distributed Workers", lambda: self.open_studio_section("workers")),
                ("studio.recorder", "Browser Recorder 2.0", lambda: self.open_studio_section("recorder")),
                ("studio.debugger", "Workflow Debugger", lambda: self.open_studio_section("debugger")),
            ]
        )
        palette = CommandPalette(commands, self)
        QTimer.singleShot(0, lambda: self.language.translate_tree(palette))
        QTimer.singleShot(0, lambda: self.motion.reveal(palette, MotionIntent.EXPAND))
        palette.exec()

    def run_general_user_assistant(self, text: str) -> None:
        if not is_general_user(self.context.settings):
            return
        workflow = GeneralUserIntentRouter().resolve(text)
        if workflow is not None:
            self.show_status(f"简单模式已识别：{workflow.title}")

    def _general_user_task_center(self) -> TaskCenterPage | None:
        try:
            page = self._ensure_page("task_center")
        except (KeyError, RuntimeError, TypeError, ValueError):
            return None
        return page if isinstance(page, TaskCenterPage) else None

    def _simple_prepare_pcap(self, caps: dict[str, Any]) -> None:
        self.navigate("network")
        page = self._ensure_page("network")
        if isinstance(page, NetworkPage):
            index = page.source.findData(CaptureSource.PCAP_IMPORT)
            if index >= 0:
                page.source.setCurrentIndex(index)
            backend = "Arenyxa Native" if not caps["packet.deep"].executable else "Native + TShark Deep"
            self.show_status(f"PCAP 分析已准备 · {backend}")
            QTimer.singleShot(0, page.start_capture)

    def _simple_prepare_capture(self, caps: dict[str, Any], task_center: TaskCenterPage | None) -> None:
        self.navigate("network")
        page = self._ensure_page("network")
        if not isinstance(page, NetworkPage):
            return
        source = CaptureSource.SYSTEM if caps["capture.system"].state in {"ready", "degraded"} else CaptureSource.BROWSER
        if source is CaptureSource.BROWSER and caps["browser.automation"].state == "unavailable":
            self.show_status("实时抓包组件不可用；仍可使用 PCAP/HAR 离线分析。")
            if task_center:
                task_center.show_result("运行能力", {key: value.snapshot() for key, value in caps.items()})
            return
        index = page.source.findData(source)
        if index >= 0:
            page.source.setCurrentIndex(index)
        self.show_status("已自动选择当前可用的捕获方式；点击开始即可继续。")

    def _simple_security_check(self, task_center: TaskCenterPage | None) -> None:
        captures = self.context.store.list_captures(limit=1)
        if not captures:
            self.show_status("还没有可分析的流量；请先抓包或导入 PCAP/HAR。")
            return
        session_id = str(captures[0].get("id") or "")
        rows = list(self.context.store.iter_network_events(session_id, 50_000))
        summary = summarize_network_events(rows)
        payload: dict[str, Any] = summary.snapshot()
        pipeline = getattr(self.context, "network_intelligence", None)
        if pipeline is not None:
            try:
                payload["threat_intelligence"] = pipeline.analyze_events(session_id, rows, limit=50_000)
            except (RuntimeError, TypeError, ValueError, OSError) as exc:
                payload["intelligence_note"] = f"高级关联分析未完成：{type(exc).__name__}"
        self.navigate("task_center")
        if task_center:
            task_center.show_result("Security Check", payload)
        self.show_status(f"安全检查完成 · Risk {summary.risk} · Score {summary.score}/100")

    def _simple_network_diagnose(self, caps: dict[str, Any], task_center: TaskCenterPage | None) -> None:
        payload = {
            "capabilities": {key: value.snapshot() for key, value in caps.items()},
            "capture_session": getattr(getattr(self.context, "capture", None), "session", None),
            "recommendation": "优先使用 Arenyxa native PCAP analysis；实时系统抓包、浏览器自动化和高级 MITM 才需要对应可选运行时。",
        }
        self.navigate("task_center")
        if task_center:
            task_center.show_result("Network Diagnosis", payload)
        self.show_status("网络诊断完成")

    def run_general_user_workflow(self, workflow_id: str) -> None:
        """Run a task-oriented workflow only for the Personal/Simple profile."""
        if not is_general_user(self.context.settings):
            self.show_status("Guided Workflow 仅用于一般用户 · 简单模式。")
            return
        try:
            workflow = GeneralUserIntentRouter().get(workflow_id)
        except ValueError as exc:
            self.show_status(str(exc))
            return
        caps = RuntimeCapabilityService().snapshot()
        task_center = self._general_user_task_center()
        if workflow.auto_action == "import_pcap":
            self._simple_prepare_pcap(caps)
            return
        if workflow.auto_action == "prepare_capture":
            self._simple_prepare_capture(caps, task_center)
            return
        if workflow.auto_action == "security_check":
            self._simple_security_check(task_center)
            return
        if workflow.auto_action == "open_project":
            path, _ = QFileDialog.getOpenFileName(self, "打开 Arenyxa 项目", "", "Arenyxa Project (*.arenyxa *.zip);;All Files (*)")
            if path:
                self.open_project(Path(path))
            return
        if workflow.auto_action == "network_diagnose":
            self._simple_network_diagnose(caps, task_center)
            return
        route = {"open_api": "network", "open_extraction": "tasks"}.get(workflow.auto_action, workflow.page_id)
        if self._page_allowed(route):
            self.navigate(route)
            self.show_status(f"{workflow.title} · 已打开简化入口")
        else:
            self.navigate("task_center")
            if task_center:
                task_center.show_result(workflow.title, {
                    "steps": list(workflow.steps), "note": workflow.fallback_note,
                    "advanced_workbench": workflow.page_id,
                    "message": "简单模式隐藏高级工作台；切换到 Professional Profile 后可访问完整控制面。"})

    def _run_diagnostics_command(self) -> None:
        page = self._ensure_page("settings")
        if isinstance(page, SettingsPage):
            page.run_diagnostics()

    def set_startup_health_report(self, report: object) -> None:
        
        self._startup_health_report = report

    def prepare_for_repair_shutdown(self) -> bool:
        """Apply the one canonical Repair pre-shutdown policy before worker handoff."""
        if not self.context.prepare_for_repair_shutdown(timeout=8.0):
            self._enter_repair_terminal_failure(
                "Repair 已停止：仍有运行中的任务未能在安全期限内退出。请查看 shutdown 日志。",
            )
            return False
        if not begin_background_shutdown(timeout_ms=2500):
            self._enter_repair_terminal_failure(
                "Repair 已停止：仍有 UI 后台任务未退出；未启动外部 Repair Worker。",
            )
            return False
        return True

    def _enter_repair_terminal_failure(self, message: str) -> None:
        self.context.mark_repair_shutdown_failed()
        self.setEnabled(False)
        self.show_status(message, 9000)
        self.request_repair_exit()

    def handoff_repair(self, plan_path: Path) -> bool:
        """Quiesce owned work, launch Repair Worker, then request canonical application exit."""
        from arenyxa.repair import launch_repair_worker

        if not self.prepare_for_repair_shutdown():
            try:
                Path(plan_path).unlink(missing_ok=True)
            except OSError:
                LOGGER.warning("Unable to remove unused Repair plan after shutdown preparation failure")
            return False
        try:
            launch_repair_worker(Path(plan_path))
            self.context.mark_repair_handoff_committed()
        except Exception:
            self._enter_repair_terminal_failure(
                "Repair Worker 启动失败；Arenyxa 已进入安全终止状态。",
            )
            raise
        self.request_repair_exit()
        return True

    def request_repair_exit(self) -> None:
        self._repair_exit_requested = True
        # MainWindow is embedded as a child widget inside ArenyxaShellWindow. Closing
        # only this child does not terminate QApplication because the application uses
        # setQuitOnLastWindowClosed(False). After the child has closed successfully,
        # explicitly ask its top-level shell owner to close as well.
        if self.close():
            self.shellCloseRequested.emit()

    def launch_repair_center(self) -> None:
        from arenyxa.presentation.repair_dialog import RepairSelectionDialog
        from arenyxa.repair import StartupHealthScanner, create_repair_plan, installation_root

        if self._repair_scan_in_progress:
            self.show_status("Repair Center 正在后台检查安装与运行状态…")
            return

                                                                                       
                                                                                         
                                               
        self._repair_scan_in_progress = True
        self.show_status("Repair Center 正在后台检查安装与运行状态…")

        def worker() -> object:
            from arenyxa.repair import append_feature_integration_findings

            report = StartupHealthScanner(
                self.context.paths, installation_root(), ignore_current_session=True
            ).scan()
            return append_feature_integration_findings(report, self.context)

        def completed(value: object) -> None:
            self._repair_scan_in_progress = False
            report = value
            self.set_startup_health_report(report)
            try:
                selector = RepairSelectionDialog(report, self.language.locale, self)
                if selector.exec() != selector.DialogCode.Accepted:
                    self.show_status("Repair Center 已取消")
                    return
                active = self.context.runner.active_handles()
                if active:
                    choice = QMessageBox.question(
                        self,
                        "Repair Center",
                        f"仍有 {len(active)} 个后台任务。执行修复将停止任务并退出 Arenyxa。继续？",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                    )
                    if choice != QMessageBox.StandardButton.Yes:
                        self.show_status("Repair Center 已取消；后台任务保持运行")
                        return
                plan_path = create_repair_plan(
                    self.context.paths,
                    report,
                    selector.selected_categories(),
                    parent_pid=__import__("os").getpid(),
                    relaunch=True,
                )
                if not self.handoff_repair(plan_path):
                    return
            except Exception as exc:                                                                   
                QMessageBox.critical(self, "Repair Center", str(exc))
                return

        def failed(message: str) -> None:
            self._repair_scan_in_progress = False
            QMessageBox.critical(self, "Repair Center", message)
            self.show_status("Repair Center 诊断失败")

                                                                                            
        run_background(worker, completed, failed)

    def _emit_runner_progress(self) -> None:
                                                                                            
                                                                                             
        interval = max(0.15, self.context.performance.status_refresh_ms / 1000.0 * 0.5)
        now = time.monotonic()
        with self._progress_emit_lock:
            if now - self._last_progress_emit < interval:
                return
            self._last_progress_emit = now
        self.runnerProgress.emit()

    def run_selected_task(self) -> None:
        tasks = self.context.store.list_tasks(limit=1)
        if not tasks:
            self.navigate("tasks")
            self.show_status("请先创建任务")
            return
        try:
            handle = self.context.runner.submit(
                tasks[0], lambda _run: self._emit_runner_progress()
            )
            self.context.nextgen.activity.publish("run", f"Started {tasks[0].name}", details={"run_id": handle.run.id, "task_id": tasks[0].id})
            handle.future.add_done_callback(
                WeakMethodFutureCallback(
                    self,
                    "_publish_main_run_completion",
                    prefix=(handle.run, tasks[0].name),
                )
            )
            self.show_status(f"已启动 {tasks[0].name} · {handle.run.id}")
        except Exception as exc:                                          
            QMessageBox.warning(self, "运行失败", str(exc))

    def _publish_main_run_completion(self, run: Any, task_name: str, _future: Any) -> None:
        level = (
            "error"
            if run.status.value == "failed"
            else ("warning" if run.status.value == "cancelled" else "info")
        )
        self.context.nextgen.activity.publish(
            "run-complete",
            f"{task_name}: {run.status.value}",
            level=level,
            details={
                "run_id": run.id,
                "success": run.success_count,
                "failure": run.failure_count,
                "retry": run.retry_count,
            },
        )

    def pause_active(self) -> None:
        handles = self.context.runner.active_handles()
        for handle in handles:
            if handle.run.status.value == "paused":
                handle.resume()
            else:
                handle.pause()
        self.show_status("活动任务暂停/恢复状态已更新")

    def stop_active(self) -> None:
        self.context.runner.cancel_all()
        self.show_status("已请求协作式取消所有活动任务")

    def open_data_folder(self) -> None:
        target = QUrl.fromLocalFile(str(self.context.paths.root.resolve()))
        if not QDesktopServices.openUrl(target):
            QMessageBox.warning(self, "无法打开文件夹", str(self.context.paths.root))
