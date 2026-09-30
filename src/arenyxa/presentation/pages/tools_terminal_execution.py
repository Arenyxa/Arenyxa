from __future__ import annotations

import json
import logging
import os
import threading
from collections import deque
from dataclasses import asdict
from datetime import datetime
from arenyxa.compat import UTC
from typing import ClassVar
from arenyxa.qt_compat.QtCore import Qt, QTimer, Signal
from arenyxa.qt_compat.QtGui import QFont, QKeyEvent, QTextCursor
from arenyxa.qt_compat.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QCompleter,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)
from arenyxa import __display_version__ as __version__
from arenyxa.application.advanced import (
    ApiMapper,
    CompatibilityAnalyzer,
    PerformanceProfiler,
    SecurityAnalyzer,
    SmartExecutionPlanner,
    WebsiteIntelligenceMapper,
)
from arenyxa.application.scheduler import ScheduleRule
from arenyxa.application.developer_safety import authorization_from_settings
from arenyxa.application.developer_validation import DeveloperFaultInjectionSuite, DeveloperStressSuite, DeveloperValidationSuite, STRESS_PROFILES
from arenyxa.application.terminal import TerminalMode, TerminalResult
from arenyxa.application.command_runtime import ArenyxaCommandRuntime, CommandRuntimeError
from arenyxa.application.workflow_inspector import WorkflowExecutionInspector
from arenyxa.application.workflow_trace import WorkflowRuntimeTrace
from arenyxa.application.workflow_graph import WorkflowGraphModel
from arenyxa.domain.models import RequestSpec, Workflow, WorkflowNode, new_id
from arenyxa.infrastructure.http_client import HttpFetcher
from arenyxa.presentation.background import run_background
from arenyxa.presentation.flow_graph import FlowGraphCanvas
from arenyxa.presentation.i18n_runtime import current_text
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import MiniBars, PageHeader, set_table_header_stretch_last, ScrollSafeComboBox

LOGGER = logging.getLogger(__name__)

class ConsoleValidationMixin:
    def _run_full_validation(self) -> None:
        if not self._developer_validation_authorized():
            return
        self._developer_test_running = True
        self.output.appendPlainText(
            current_text("terminal.validation.test_all_started")
        )

        def worker() -> object:
            suite = DeveloperValidationSuite(self.context)
            return suite.run_all(progress=lambda message: self.outputReady.emit(f"\n[validate] {message}"))

        def completed(value: object) -> None:
            self._developer_test_running = False
            payload = value.to_dict() if hasattr(value, "to_dict") else {"result": str(value)}
            self.output.appendPlainText("\n[test-all completed]\n" + json.dumps(payload, ensure_ascii=False, indent=2, default=str))

        def failed(message: str) -> None:
            self._developer_test_running = False
            self.output.appendPlainText(f"\n[test-all internal failure] {message}")

        run_background(worker, completed, failed)

    def _official_developer_high_risk_gate(self, capability: str, action: str, title: str, detail: str) -> bool:
        manager = getattr(self.context, "developer_access", None)
        if manager is None:
            self.output.appendPlainText(current_text("terminal.developer.backend_unavailable"))
            return False
        try:
            manager.require(capability, action)
        except Exception as exc:
            code = getattr(exc, "code", type(exc).__name__)
            self.output.appendPlainText(
                current_text("terminal.developer.capability_required").format(capability=capability, code=code)
            )
            return False
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setText(detail)
        box.setInformativeText(
            current_text("terminal.developer.audit_warning")
        )
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            try:
                manager.require(capability, action, high_risk=True, risk_confirmed=False)
            except Exception:
                                                                                                  
                                                                
                LOGGER.exception("Failed to persist cancelled high-risk Developer operation audit")
            self.output.appendPlainText(current_text("terminal.developer.high_risk_cancelled"))
            return False
        try:
            manager.require(capability, action, high_risk=True, risk_confirmed=True)
        except Exception as exc:
            self.output.appendPlainText(current_text("terminal.developer.authorization_expired").format(code=getattr(exc, "code", type(exc).__name__)))
            return False
        return True

    def _run_stress_validation(self, profile: str) -> None:
        if profile not in STRESS_PROFILES:
            self.output.appendPlainText(current_text("terminal.validation.profile_invalid"))
            return
        if self._developer_test_running:
            self.output.appendPlainText(current_text("terminal.validation.already_running"))
            return
        if profile == "quick":
            manager = getattr(self.context, "developer_access", None)
            if manager is None:
                self.output.appendPlainText("官方开发者授权组件当前不可用。")
                return
            try:
                manager.require("stress_test", "stress-test/quick")
            except Exception as exc:
                code = getattr(exc, "code", type(exc).__name__)
                self.output.appendPlainText(
                    current_text("terminal.validation.stress_capability_required").format(code=code)
                )
                return
        elif not self._official_developer_high_risk_gate(
            "stress_test", f"stress-test/{profile}", current_text("terminal.validation.stress_title").format(profile=profile),
            current_text("terminal.validation.stress_detail").format(profile=profile),
        ):
            return
        self._developer_test_running = True
        self.output.appendPlainText(
            current_text("terminal.validation.stress_started").format(profile=profile)
        )

        def worker() -> object:
            return DeveloperStressSuite(self.context).run(
                profile, progress=lambda message: self.outputReady.emit(f"\n[stress] {message}")
            )

        def completed(value: object) -> None:
            self._developer_test_running = False
            payload = value.to_dict() if hasattr(value, "to_dict") else {"result": str(value)}
            self.output.appendPlainText("\n[stress-test completed]\n" + json.dumps(payload, ensure_ascii=False, indent=2, default=str))

        def failed(message: str) -> None:
            self._developer_test_running = False
            self.output.appendPlainText(f"\n[stress-test internal failure] {message}")

        run_background(worker, completed, failed)

    def _run_fault_injection(self, scenario: str) -> None:
        allowed = {"transient", "recoverable", "configuration", "permission", "corruption", "fatal", "all"}
        if scenario not in allowed:
            self.output.appendPlainText(
                current_text("terminal.validation.scenario_invalid")
            )
            return
        if self._developer_test_running:
            self.output.appendPlainText("已有开发者验证任务正在运行，请等待完成后再启动新的测试。")
            return
        if not self._official_developer_high_risk_gate(
            "fault_injection", f"fault-injection/{scenario}", current_text("terminal.validation.fault_title"),
            current_text("terminal.validation.fault_detail"),
        ):
            return
        self._developer_test_running = True
        self.output.appendPlainText(
            f"[fault-injection started · scenario={scenario}] synthetic-only; no production data mutation."
        )

        def worker() -> object:
            return DeveloperFaultInjectionSuite(self.context).run(scenario)

        def completed(value: object) -> None:
            self._developer_test_running = False
            payload = value.to_dict() if hasattr(value, "to_dict") else {"result": str(value)}
            self.output.appendPlainText(
                "\n[fault-injection completed]\n" + json.dumps(payload, ensure_ascii=False, indent=2, default=str)
            )

        def failed(message: str) -> None:
            self._developer_test_running = False
            self.output.appendPlainText(f"\n[fault-injection internal failure] {message}")

        run_background(worker, completed, failed)

class ConsoleExternalProcessMixin:
    @staticmethod
    def _strip_outer_quotes(value: str) -> str:
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            return value[1:-1]
        return value

    def _bounded_int(self, raw: str, low: int, high: int, command_name: str) -> int | None:
        try:
            value = int(raw)
        except ValueError:
            self.output.appendPlainText(current_text("terminal.argument.integer_required").format(command=command_name))
            return None
        if not low <= value <= high:
            self.output.appendPlainText(current_text("terminal.argument.range").format(command=command_name, low=low, high=high))
            return None
        return value

    def _run_readonly_sql(self, query: str) -> None:
        if not query:
            self.output.appendPlainText(current_text("terminal.sql.usage"))
            return

        def worker() -> object:
            return self.context.terminal.readonly_sql(self.context.paths.database, query, limit=500)

        self._background_json(worker)

    def _background_json(self, producer) -> None:
        def worker() -> str:
            text = json.dumps(producer(), ensure_ascii=False, indent=2, default=str)
            limit = 250_000
            if len(text) > limit:
                omitted = len(text) - limit
                text = text[:limit] + "\n" + current_text("terminal.output.truncated").format(omitted=omitted)
            return text

        run_background(
            worker,
            lambda value: self.output.appendPlainText(str(value)),
            lambda message: self.output.appendPlainText(current_text("terminal.command.failed").format(message=message)),
        )

    def _execute_external(self, command: str, mode: TerminalMode) -> None:
        if not command:
            self.output.appendPlainText(current_text("terminal.external.empty"))
            return
        authorization = authorization_from_settings(self.context.settings)
        if not (authorization.valid or self._root_workstation_active()):
            if not authorization.developer_mode:
                self.output.appendPlainText(current_text("terminal.external.developer_mode_required"))
            else:
                self.output.appendPlainText(current_text("terminal.external.terms_required"))
            return
        shell_modes = {TerminalMode.POWERSHELL, TerminalMode.CMD, TerminalMode.POWERSHELL_SESSION, TerminalMode.CMD_SESSION}
        if mode in shell_modes and not (bool(getattr(self.context.settings, "developer_direct_shell_enabled", False)) or self._root_workstation_active()):
            self.output.appendPlainText(current_text("terminal.external.direct_shell_required"))
            return
        if self.context.terminal.is_running:
            self.output.appendPlainText(current_text("terminal.external.already_running"))
            return
        try:
            launch = self.context.terminal.build_launch(command, mode)
        except (OSError, ValueError) as exc:
            self.output.appendPlainText(current_text("terminal.external.launch_failed").format(error=exc))
            return

        details = [
            current_text("terminal.confirm.mode").format(mode=mode.value),
            current_text("terminal.confirm.cwd").format(cwd=launch.cwd),
            current_text("terminal.confirm.timeout").format(seconds=f"{self.context.terminal.timeout_seconds:g}"),
            "",
            self.context.terminal.redact_command(command),
        ]
        if mode in {TerminalMode.POWERSHELL, TerminalMode.CMD, TerminalMode.POWERSHELL_SESSION, TerminalMode.CMD_SESSION}:
            details.insert(3, current_text("terminal.confirm.shell_warning"))
        if mode == TerminalMode.PYTHON:
            details.insert(3, current_text("terminal.confirm.python_warning"))
        if launch.risk_reason:
            details.insert(3, current_text("terminal.confirm.risk").format(reason=launch.risk_reason))
        box = QMessageBox(self)
        box.setWindowTitle(current_text("terminal.confirm.title"))
        box.setIcon(
            QMessageBox.Icon.Warning
            if launch.risk_reason or mode in {TerminalMode.POWERSHELL, TerminalMode.CMD, TerminalMode.PYTHON, TerminalMode.POWERSHELL_SESSION, TerminalMode.CMD_SESSION, TerminalMode.PYTHON_SESSION}
            else QMessageBox.Icon.Question
        )
        box.setText("\n".join(details))
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            self.output.appendPlainText(current_text("terminal.common.cancelled"))
            return
        try:
            self.context.terminal.start(launch, self.outputReady.emit, self.processFinished.emit)
        except (OSError, RuntimeError, ValueError) as exc:
            self.output.appendPlainText(current_text("terminal.external.start_failed").format(error=exc))
            return
        self.stop_button.setEnabled(True)
        self.output.appendPlainText(f"[process started · mode={mode.value}]")
        if launch.persistent and command:
            if not self.context.terminal.send_input(command):
                self.output.appendPlainText("Persistent shell started but initial command could not be delivered.")

    def _append_stream(self, text: str) -> None:
        if not text:
            return
        cursor = self.output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text)
        self.output.setTextCursor(cursor)
        self.output.ensureCursorVisible()

    def _process_finished(self, value: object) -> None:
        self.stop_button.setEnabled(False)
        if not isinstance(value, TerminalResult):
            self.output.appendPlainText("\n[process finished]")
            return
        flags = []
        if value.timed_out:
            flags.append("timeout")
        if value.cancelled:
            flags.append("cancelled")
        if value.output_truncated:
            flags.append("output-limit")
        suffix = "" if not flags else " · " + ", ".join(flags)
        self.output.appendPlainText(
            f"\n[process exited · code={value.exit_code} · {value.duration_seconds:.2f}s{suffix}]"
        )
        if value.output_truncated:
            self.output.appendPlainText(
                current_text("terminal.output.process_limit")
            )

    def _interrupt_from_keyboard(self) -> None:
        if self.context.terminal.is_running:
            self._stop_process()

    def _stop_process(self) -> None:
        if self.context.terminal.request_stop():
            self.output.appendPlainText("\n" + current_text("terminal.external.stopping"))
            self.stop_button.setEnabled(False)
        else:
            self.output.appendPlainText(current_text("terminal.external.none_running"))
