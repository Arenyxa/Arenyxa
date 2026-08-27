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
from arenyxa import __version__
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
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import MiniBars, PageHeader, set_table_header_stretch_last, ScrollSafeComboBox

LOGGER = logging.getLogger(__name__)

class ConsoleValidationMixin:
    def _run_full_validation(self) -> None:
        if not self._developer_validation_authorized():
            return
        self._developer_test_running = True
        self.output.appendPlainText(
            "[test-all started] 使用隔离临时目录与 127.0.0.1 回环服务；不会主动访问公网目标或修改正式项目数据。"
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
            self.output.appendPlainText("官方开发者授权组件当前不可用。")
            return False
        try:
            manager.require(capability, action)
        except Exception as exc:
            code = getattr(exc, "code", type(exc).__name__)
            self.output.appendPlainText(
                f"命令已锁定：需要官方开发者证书授予 capability '{capability}'（{code}）。"
                " Developer Profile 或 Enterprise 管理员身份不能替代此授权。"
            )
            return False
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setText(detail)
        box.setInformativeText(
            "该操作会写入 Developer Audit。确认只在隔离/受控测试范围内执行，并理解资源或故障注入风险。"
        )
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            try:
                manager.require(capability, action, high_risk=True, risk_confirmed=False)
            except Exception:
                                                                                                  
                                                                
                LOGGER.exception("Failed to persist cancelled high-risk Developer operation audit")
            self.output.appendPlainText("高风险操作已取消。")
            return False
        try:
            manager.require(capability, action, high_risk=True, risk_confirmed=True)
        except Exception as exc:
            self.output.appendPlainText(f"授权在确认后失效：{getattr(exc, 'code', type(exc).__name__)}")
            return False
        return True

    def _run_stress_validation(self, profile: str) -> None:
        if profile not in STRESS_PROFILES:
            self.output.appendPlainText("profile 必须是 quick、standard 或 extreme。")
            return
        if self._developer_test_running:
            self.output.appendPlainText("已有开发者验证任务正在运行，请等待完成后再启动新的测试。")
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
                    f"命令已锁定：stress-test quick 也需要官方开发者证书授予 capability 'stress_test'（{code}）。"
                    " Developer Profile 不能运行内部压力测试。"
                )
                return
        elif not self._official_developer_high_risk_gate(
            "stress_test", f"stress-test/{profile}", f"官方开发者 · stress-test {profile}",
            f"即将运行 {profile} 有界稳定性压力测试。它会逐级提高本地并发并在安全上限、异常或时间预算处停止。",
        ):
            return
        self._developer_test_running = True
        self.output.appendPlainText(
            f"[stress-test started · profile={profile}] 仅使用隔离临时数据和本地计算；"
            "逐级提高并发，检测到错误或达到安全上限即停止，不以拖垮操作系统为目标。"
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
                "scenario 必须是 transient、recoverable、configuration、permission、corruption、fatal 或 all。"
            )
            return
        if self._developer_test_running:
            self.output.appendPlainText("已有开发者验证任务正在运行，请等待完成后再启动新的测试。")
            return
        if not self._official_developer_high_risk_gate(
            "fault_injection", f"fault-injection/{scenario}", "官方开发者 · Fault Injection",
            "即将执行合成故障注入。当前实现只向 RecoveryTaxonomy 注入内存中的合成异常/错误码，不触碰正式项目、网络目标或系统资源。",
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
            self.output.appendPlainText(f"{command_name} 参数必须是整数。")
            return None
        if not low <= value <= high:
            self.output.appendPlainText(f"{command_name} 参数范围：{low}-{high}。")
            return None
        return value

    def _run_readonly_sql(self, query: str) -> None:
        if not query:
            self.output.appendPlainText("用法：sql <SELECT/PRAGMA/EXPLAIN/WITH...>；sql tables 列表。")
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
                text = text[:limit] + f"\n… 输出已截断，省略 {omitted} 个字符。请使用专用页面筛选/导出完整数据。"
            return text

        run_background(
            worker,
            lambda value: self.output.appendPlainText(str(value)),
            lambda message: self.output.appendPlainText(f"命令失败：{message}"),
        )

    def _execute_external(self, command: str, mode: TerminalMode) -> None:
        if not command:
            self.output.appendPlainText("外部命令为空。")
            return
        authorization = authorization_from_settings(self.context.settings)
        if not (authorization.valid or self._root_workstation_active()):
            if not authorization.developer_mode:
                self.output.appendPlainText("外部命令已禁用。请在设置 → 高级设置中启用 Developer Mode。")
            else:
                self.output.appendPlainText(
                    "外部命令已锁定：Developer Mode 尚未完成有效的风险协议与免责协议授权。"
                    "请关闭 Developer Mode 后重新启用并完成双协议确认。"
                )
            return
        shell_modes = {TerminalMode.POWERSHELL, TerminalMode.CMD, TerminalMode.POWERSHELL_SESSION, TerminalMode.CMD_SESSION}
        if mode in shell_modes and not (bool(getattr(self.context.settings, "developer_direct_shell_enabled", False)) or self._root_workstation_active()):
            self.output.appendPlainText("完整 Shell 已锁定：请在 Settings → Advanced 启用 Direct Shell。")
            return
        if self.context.terminal.is_running:
            self.output.appendPlainText("已有外部进程正在运行。请先等待结束或点击“停止”。")
            return
        try:
            launch = self.context.terminal.build_launch(command, mode)
        except (OSError, ValueError) as exc:
            self.output.appendPlainText(f"无法启动命令：{exc}")
            return

        details = [
            f"执行模式：{mode.value}",
            f"工作目录：{launch.cwd}",
            f"超时：{self.context.terminal.timeout_seconds:g} 秒",
            "",
            self.context.terminal.redact_command(command),
        ]
        if mode in {TerminalMode.POWERSHELL, TerminalMode.CMD, TerminalMode.POWERSHELL_SESSION, TerminalMode.CMD_SESSION}:
            details.insert(3, "完整 Shell 模式会解释管道、重定向、变量展开和命令连接符。")
        if mode == TerminalMode.PYTHON:
            details.insert(3, "Python 代码将拥有当前用户权限，并可访问文件、网络和子进程。")
        if launch.risk_reason:
            details.insert(3, f"⚠ 风险提示：{launch.risk_reason}")
        box = QMessageBox(self)
        box.setWindowTitle("确认执行开发者命令")
        box.setIcon(
            QMessageBox.Icon.Warning
            if launch.risk_reason or mode in {TerminalMode.POWERSHELL, TerminalMode.CMD, TerminalMode.PYTHON, TerminalMode.POWERSHELL_SESSION, TerminalMode.CMD_SESSION, TerminalMode.PYTHON_SESSION}
            else QMessageBox.Icon.Question
        )
        box.setText("\n".join(details))
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            self.output.appendPlainText("已取消。")
            return
        try:
            self.context.terminal.start(launch, self.outputReady.emit, self.processFinished.emit)
        except (OSError, RuntimeError, ValueError) as exc:
            self.output.appendPlainText(f"系统命令启动失败：{exc}")
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
                "输出超过终端单进程安全上限，已停止继续接收并终止该进程；请改用文件或专用导出功能。"
            )

    def _interrupt_from_keyboard(self) -> None:
        if self.context.terminal.is_running:
            self._stop_process()

    def _stop_process(self) -> None:
        if self.context.terminal.request_stop():
            self.output.appendPlainText("\n[正在停止外部进程…]")
            self.stop_button.setEnabled(False)
        else:
            self.output.appendPlainText("当前没有正在运行的外部进程。")

