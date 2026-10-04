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
from arenyxa import __display_version__, __display_version__ as __version__
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
from arenyxa.presentation.language import resolve_system_locale
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import MiniBars, PageHeader, set_table_header_stretch_last, ScrollSafeComboBox

LOGGER = logging.getLogger(__name__)

class TerminalWorkspaceMixin:
    def _build_terminal_workspace(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        layout.setContentsMargins(0, 0, 0, 0)
        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("Session"))
        self.workspace_mode = ScrollSafeComboBox()
        self.workspace_mode.addItem("PowerShell", TerminalMode.POWERSHELL_SESSION.value)
        if os.name == "nt":
            self.workspace_mode.addItem("CMD", TerminalMode.CMD_SESSION.value)
        self.workspace_mode.addItem("Python REPL", TerminalMode.PYTHON_SESSION.value)
        self.workspace_pane = ScrollSafeComboBox()
        self.workspace_pane.addItem("Primary", "primary")
        self.workspace_pane.addItem("Secondary", "secondary")
        self.workspace_pane.addItem("Bottom", "bottom")
        self.workspace_new = QPushButton("New Session")
        self.workspace_new.setProperty("primary", True)
        self.workspace_interrupt = QPushButton("Interrupt")
        self.workspace_rename = QPushButton("Rename")
        self.workspace_move = QPushButton("Move Pane")
        self.workspace_resize = QPushButton("Resize")
        self.workspace_stop = QPushButton("Stop")
        self.workspace_close = QPushButton("Close")
        toolbar.addWidget(self.workspace_mode)
        toolbar.addWidget(self.workspace_pane)
        toolbar.addWidget(self.workspace_new)
        toolbar.addStretch()
        toolbar.addWidget(self.workspace_interrupt)
        toolbar.addWidget(self.workspace_rename)
        toolbar.addWidget(self.workspace_move)
        toolbar.addWidget(self.workspace_resize)
        toolbar.addWidget(self.workspace_stop)
        toolbar.addWidget(self.workspace_close)
        layout.addLayout(toolbar)
        self.workspace_primary_tabs = QTabWidget()
        self.workspace_secondary_tabs = QTabWidget()
        self.workspace_bottom_tabs = QTabWidget()
        self._workspace_hosts = {
            "primary": self.workspace_primary_tabs,
            "secondary": self.workspace_secondary_tabs,
            "bottom": self.workspace_bottom_tabs,
        }
        self._active_workspace_pane = "primary"
        for pane_name, host in self._workspace_hosts.items():
            host.setTabsClosable(False)
            host.currentChanged.connect(lambda _index, pane=pane_name: setattr(self, "_active_workspace_pane", pane))
        top_split = QSplitter(Qt.Orientation.Horizontal)
        top_split.addWidget(self.workspace_primary_tabs)
        top_split.addWidget(self.workspace_secondary_tabs)
        top_split.setSizes([720, 480])
        workspace_split = QSplitter(Qt.Orientation.Vertical)
        workspace_split.addWidget(top_split)
        workspace_split.addWidget(self.workspace_bottom_tabs)
        workspace_split.setSizes([620, 260])
        layout.addWidget(workspace_split, 1)
        note = QLabel(
            "Arenyxa Shell Sessions are isolated persistent processes. They share the Projects boundary, "
            "Developer authorization, output budgets and process-tree shutdown policy."
        )
        note.setWordWrap(True)
        note.setProperty("muted", True)
        layout.addWidget(note)
        self._workspace_views: dict[str, tuple[QPlainTextEdit, QLineEdit, QWidget, int]] = {}
        self.workspace_new.clicked.connect(self._new_terminal_workspace_session)
        self.workspace_interrupt.clicked.connect(self._interrupt_terminal_workspace_session)
        self.workspace_rename.clicked.connect(self._rename_terminal_workspace_session)
        self.workspace_move.clicked.connect(self._move_terminal_workspace_session)
        self.workspace_resize.clicked.connect(self._resize_terminal_workspace_session)
        self.workspace_stop.clicked.connect(self._stop_terminal_workspace_session)
        self.workspace_close.clicked.connect(self._close_terminal_workspace_session)
        return holder

    def _terminal_workspace_authorized(self) -> bool:
        if self._root_workstation_active():
            return True
        return bool(authorization_from_settings(self.context.settings).valid)

    def _new_terminal_workspace_session(self) -> None:
        if not self._terminal_workspace_authorized():
            QMessageBox.warning(self, "Developer Mode", "Enable Developer Mode and accept the Developer risk agreement first.")
            return
        mode = str(self.workspace_mode.currentData())
        if mode in {TerminalMode.POWERSHELL_SESSION.value, TerminalMode.CMD_SESSION.value} and not bool(
            getattr(self.context.settings, "developer_direct_shell_enabled", False)
        ):
            QMessageBox.warning(self, "Direct Shell", "PowerShell/CMD sessions require the Developer Mode Direct Shell setting.")
            return
        pane = str(self.workspace_pane.currentData() or "primary")
        try:
            state = self.context.terminal_workspace.create(
                title=self.workspace_mode.currentText(), mode=mode, pane=pane
            )
            session_id = str(state["id"])
            self.context.terminal_workspace.start(session_id)
        except (OSError, RuntimeError, ValueError) as exc:
            QMessageBox.warning(self, "Shell Session", str(exc))
            return
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        output = QPlainTextEdit()
        output.setReadOnly(True)
        output.setFont(QFont("Cascadia Mono"))
        output.setMaximumBlockCount(self._log_tail_lines)
        send_row = QHBoxLayout()
        command = QLineEdit()
        command.setPlaceholderText("Persistent session command")
        send = QPushButton("Send")
        send.setProperty("primary", True)
        send_row.addWidget(command, 1)
        send_row.addWidget(send)
        tab_layout.addWidget(output, 1)
        tab_layout.addLayout(send_row)
        host = self._workspace_hosts.get(pane, self.workspace_primary_tabs)
        index = host.addTab(tab, f"{state['title']} · {session_id}")
        self._workspace_views[session_id] = (output, command, tab, -1)
        send.clicked.connect(lambda _checked=False, sid=session_id: self._send_terminal_workspace_command(sid))
        command.returnPressed.connect(lambda sid=session_id: self._send_terminal_workspace_command(sid))
        host.setCurrentIndex(index)
        self._active_workspace_pane = pane
        self.statusMessage.emit(f"Shell session created: {session_id}")

    def _current_terminal_workspace_id(self) -> str | None:
        host = self._workspace_hosts.get(self._active_workspace_pane, self.workspace_primary_tabs)
        current = host.currentWidget()
        if current is None:
            for candidate in self._workspace_hosts.values():
                if candidate.currentWidget() is not None:
                    current = candidate.currentWidget()
                    break
        if current is None:
            return None
        for session_id, (_output, _command, widget, _size) in self._workspace_views.items():
            if widget is current:
                return session_id
        return None

    def _send_terminal_workspace_command(self, session_id: str) -> None:
        view = self._workspace_views.get(session_id)
        if view is None:
            return
        _output, command, _widget, _size = view
        text = command.text()
        command.clear()
        if not text.strip():
            return
        safe = self.context.terminal.redact_command(text)
        try:
            self.context.terminal_workspace.send(session_id, text)
            self.statusMessage.emit(f"{session_id}> {safe}")
        except (KeyError, OSError, RuntimeError, ValueError) as exc:
            QMessageBox.warning(self, "Shell Session", str(exc))

    def _refresh_terminal_workspace(self) -> None:
        live_ids = {str(item["id"]) for item in self.context.terminal_workspace.list()}
        for session_id in list(self._workspace_views):
            if session_id not in live_ids:
                self._remove_workspace_tab(session_id)
                continue
            output, command, widget, previous_size = self._workspace_views[session_id]
            text = self.context.terminal_workspace.output(session_id, tail_chars=500_000)
            if len(text) != previous_size:
                output.setPlainText(text)
                cursor = output.textCursor()
                cursor.movePosition(QTextCursor.MoveOperation.End)
                output.setTextCursor(cursor)
                self._workspace_views[session_id] = (output, command, widget, len(text))

    def _interrupt_terminal_workspace_session(self) -> None:
        session_id = self._current_terminal_workspace_id()
        if not session_id:
            return
        try:
            self.context.terminal_workspace.interrupt(session_id)
            self.statusMessage.emit(f"Interrupt sent to {session_id}")
        except (KeyError, OSError, RuntimeError, ValueError) as exc:
            QMessageBox.warning(self, "Shell Session", str(exc))

    def _rename_terminal_workspace_session(self) -> None:
        session_id = self._current_terminal_workspace_id()
        if not session_id:
            return
        title, ok = QInputDialog.getText(self, "Rename Shell Session", "Session title")
        if not ok or not title.strip():
            return
        try:
            state = self.context.terminal_workspace.rename(session_id, title)
            widget = self._workspace_views[session_id][2]
            for host in self._workspace_hosts.values():
                index = host.indexOf(widget)
                if index >= 0:
                    host.setTabText(index, f"{state['title']} · {session_id}")
                    break
        except (KeyError, ValueError) as exc:
            QMessageBox.warning(self, "Shell Session", str(exc))

    def _move_terminal_workspace_session(self) -> None:
        session_id = self._current_terminal_workspace_id()
        if not session_id:
            return
        panes = ["primary", "secondary", "bottom"]
        pane, ok = QInputDialog.getItem(self, "Move Shell Session", "Pane", panes, 0, False)
        if ok and pane:
            try:
                self.context.terminal_workspace.move(session_id, pane)
                widget = self._workspace_views[session_id][2]
                title = session_id
                for host in self._workspace_hosts.values():
                    index = host.indexOf(widget)
                    if index >= 0:
                        title = host.tabText(index)
                        host.removeTab(index)
                        break
                destination = self._workspace_hosts[str(pane)]
                index = destination.addTab(widget, title)
                destination.setCurrentIndex(index)
                self._active_workspace_pane = str(pane)
                self.statusMessage.emit(f"{session_id} moved to {pane} pane")
            except (KeyError, ValueError) as exc:
                QMessageBox.warning(self, "Shell Session", str(exc))

    def _resize_terminal_workspace_session(self) -> None:
        session_id = self._current_terminal_workspace_id()
        if not session_id:
            return
        columns, ok = QInputDialog.getInt(self, "Resize Shell Session", "Columns", 120, 20, 1000)
        if not ok:
            return
        rows, ok = QInputDialog.getInt(self, "Resize Shell Session", "Rows", 32, 5, 400)
        if not ok:
            return
        try:
            self.context.terminal_workspace.resize(session_id, columns, rows)
        except (KeyError, OSError, RuntimeError, ValueError) as exc:
            QMessageBox.warning(self, "Shell Session", str(exc))

    def _stop_terminal_workspace_session(self) -> None:
        session_id = self._current_terminal_workspace_id()
        if not session_id:
            return
        try:
            self.context.terminal_workspace.stop(session_id)
        except KeyError:
            self._remove_workspace_tab(session_id)

    def _close_terminal_workspace_session(self) -> None:
        session_id = self._current_terminal_workspace_id()
        if not session_id:
            return
        self.context.terminal_workspace.close(session_id)
        self._remove_workspace_tab(session_id)

    def _remove_workspace_tab(self, session_id: str) -> None:
        view = self._workspace_views.pop(session_id, None)
        if view is None:
            return
        widget = view[2]
        for host in self._workspace_hosts.values():
            index = host.indexOf(widget)
            if index >= 0:
                host.removeTab(index)
                break
        widget.deleteLater()

class ConsoleCommandMixin:
    def _root_workstation_active(self) -> bool:
        manager = getattr(self.context, "developer_access", None)
        if manager is None:
            return False
        try:
            if bool(getattr(self.context, "root_developer_workstation", False)):
                manager.ensure_root_workstation_session()
            status = manager.status()
        except Exception:
            return False
        return bool(status.authenticated and "platform.root" in status.capabilities)

    def activated(self) -> None:
        self._refresh_cwd()
        self.stop_button.setEnabled(self.context.terminal.is_running)

    def _mode_changed(self) -> None:
        value = str(self.mode.currentData())
        prompts = {
            "arenyxa": "Arenyxa>",
            TerminalMode.DIRECT.value: "Exec>",
            TerminalMode.POWERSHELL.value: "PS>",
            TerminalMode.CMD.value: "CMD>",
            TerminalMode.PYTHON.value: "Py>",
            TerminalMode.POWERSHELL_SESSION.value: "PS*>",
            TerminalMode.CMD_SESSION.value: "CMD*>",
            TerminalMode.PYTHON_SESSION.value: "Py*>",
        }
        placeholders = {
            "arenyxa": "task list / proxy status / fleet workers --json / help",
            TerminalMode.DIRECT.value: "python --version / git status / curl --version",
            TerminalMode.POWERSHELL.value: "Get-ChildItem | Select-Object -First 20",
            TerminalMode.CMD.value: "dir /b /a",
            TerminalMode.PYTHON.value: "print('hello from Arenyxa')",
            TerminalMode.POWERSHELL_SESSION.value: "$PSVersionTable / Get-Process / cd D:\\Project",
            TerminalMode.CMD_SESSION.value: "set / dir / cd /d D:\\Project",
            TerminalMode.PYTHON_SESSION.value: "import sys; print(sys.version)",
        }
        self.prompt.setText(prompts.get(value, "Arenyxa>"))
        self.command.setPlaceholderText(placeholders.get(value, "输入命令"))

    def _complete_command(self) -> None:
        if bool(getattr(self, "_secret_stdin_pending", False)):
            return
        runtime = self.context.command_runtime
        if runtime is None:
            return
        text = self.command.text()
        candidates = runtime.complete(text)
        if not candidates:
            return
        if len(candidates) == 1:
            candidate = candidates[0]
            stripped = text.rstrip()
            if not stripped or " " not in stripped:
                prefix = "arenyxa " if stripped.casefold() in {"arenyxa", "arenyxa-cli"} else ""
                completed = prefix + candidate if prefix else candidate
            else:
                head, _space, _tail = stripped.rpartition(" ")
                completed = f"{head} {candidate}"
            self.command.setText(completed + " ")
            self.command.setCursorPosition(len(self.command.text()))
            return
        common = os.path.commonprefix(candidates)
        stripped = text.rstrip()
        tail = stripped.rsplit(" ", 1)[-1] if stripped else ""
        if common and len(common) > len(tail):
            if " " in stripped:
                head, _space, _old = stripped.rpartition(" ")
                self.command.setText(f"{head} {common}")
            else:
                self.command.setText(common)
            self.command.setCursorPosition(len(self.command.text()))
        self.output.appendPlainText("Completions: " + "  ".join(candidates[:32]))

    def _refresh_cwd(self) -> None:
        cwd = self.context.terminal.cwd
        try:
            relative = cwd.relative_to(self.context.terminal.root)
            shown = "." if str(relative) == "." else f".\\{relative}"
        except ValueError:
            shown = str(cwd)
        self.cwd_label.setText(f"工作目录：{shown}  ·  Timeout {self.context.terminal.timeout_seconds:g}s")
        self.cwd_label.setToolTip(str(cwd))

    def _history_step(self, delta: int) -> None:
        if bool(getattr(self, "_secret_stdin_pending", False)):
            return
        history = self.context.terminal.history()
        if not history:
            return
        if self._history_cursor < 0 or self._history_cursor > len(history):
            self._history_cursor = len(history)
        self._history_cursor = max(0, min(len(history), self._history_cursor + int(delta)))
        if self._history_cursor == len(history):
            self.command.clear()
        else:
            self.command.setText(history[self._history_cursor])
            self.command.setCursorPosition(len(self.command.text()))

    def _update_secret_input_mode(self, text: str) -> None:
        """Mask secret stdin values while they are being typed, not only after submission."""
        secure = bool(getattr(self, "_secret_stdin_pending", False)) or str(text).casefold().startswith("stdin-secret ")
        if hasattr(QLineEdit, "EchoMode"):
            mode = QLineEdit.EchoMode.Password if secure else QLineEdit.EchoMode.Normal
        else:
            mode = QLineEdit.Password if secure else QLineEdit.Normal
        if self.command.echoMode() != mode:
            self.command.setEchoMode(mode)

    def _finish_secret_stdin(self, payload: str) -> None:
        try:
            sent = self.context.terminal.send_input(payload)
        except ValueError as exc:
            self.output.appendPlainText(f"stdin-secret failed: {exc}")
        else:
            self.output.appendPlainText("[secret stdin sent]" if sent else "The active process cannot receive standard input.")
        finally:
            self._secret_stdin_pending = False
            self.prompt.setText("Arenyxa>")
            self._update_secret_input_mode("")

    def execute(self) -> None:
        raw_input = self.command.text()
        self.command.clear()
        if bool(getattr(self, "_secret_stdin_pending", False)):
            self._finish_secret_stdin(raw_input)
            return
        command = raw_input.strip()
        if not command:
            return
        if command.casefold() == "stdin-secret":
            self._secret_stdin_pending = True
            self.prompt.setText("Secret stdin>")
            self._update_secret_input_mode("")
            self.output.appendPlainText("[secure stdin mode: next input is masked and is not stored in history]")
            return
        if command.casefold().startswith("stdin-secret "):
            safe_command = "stdin-secret <redacted>"
            self.context.terminal.remember(safe_command)
        else:
            safe_command = self.context.terminal.redact_command(command)
            self.context.terminal.remember(command)
        self._history_cursor = len(self.context.terminal.history())
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.output.appendPlainText(f"\n[{timestamp}] {self.prompt.text()} {safe_command}")

                                                                                    
        if command.startswith("!!"):
            self._execute_external(command[2:].strip(), TerminalMode.POWERSHELL)
            return
        if command.startswith("!"):
            self._execute_external(command[1:].strip(), TerminalMode.DIRECT)
            return

        first = command.split(maxsplit=1)[0].casefold()
        runtime = self.context.command_runtime
        if first == "arenyxa" or (runtime is not None and first in runtime.COMMAND_TREE):
            self._execute_control_plane(command)
            return
        if first in self.BUILTIN:
            self._execute_builtin(first, command)
            return

        selected = str(self.mode.currentData())
        if selected == "arenyxa":
            self._execute_control_plane(command)
            return
        mode = TerminalMode(selected)
        if mode in {TerminalMode.POWERSHELL_SESSION, TerminalMode.CMD_SESSION, TerminalMode.PYTHON_SESSION} and self.context.terminal.active_persistent:
            self._send_persistent_command(command, mode)
            return
        self._execute_external(command, mode)

    def _execute_builtin(self, name: str, command: str) -> None:
        """Dispatch one local terminal builtin to a bounded command family."""
        parts = command.split()
        handlers = (
            self._execute_builtin_core,
            self._execute_builtin_environment,
            self._execute_builtin_status,
            self._execute_builtin_data,
            self._execute_builtin_validation,
        )
        for handler in handlers:
            if handler(name, command, parts):
                return

    def _terminal_locale(self) -> str:
        configured = str(getattr(getattr(self.context, "settings", None), "locale", "system") or "system")
        if configured == "system":
            environment = os.environ.get("ARENYXA_LANGUAGE", "").strip()
            return environment or resolve_system_locale()
        return configured

    def _builtin_help_text(self) -> str:
        """Return terminal help in the same locale selected by the application."""
        english = self._terminal_locale().casefold().startswith("en")
        if english:
            return (
                "Arenyxa Terminal-First Control Plane:\n"
                "  task list/show/run                         Task query and execution (--json supported)\n"
                "  run list/show/cancel/pause/resume/export  Run control and export\n"
                "  capture start/browser/har-import/pcap-import  Live, browser, HAR and PCAP capture\n"
                "  capture status/events/intelligence/alerts/stream-stats  Live intelligence and alerts\n"
                "  packet summary/conversations/analytics    Packet Intelligence session analysis\n"
                "  packet detect/hunt/protocols/fields       Detection, hunting and dynamic field discovery\n"
                "  packet build                               Offline packet fixture/PCAP construction\n"
                "  extraction analyze/dry-run/pick            Extraction Lab and web picking\n"
                "  dataset list/show/revisions                Dataset queries\n"
                "  flow list/show/executions/inspect-execution Flow Designer analysis\n"
                "  proxy status/history/inspect/summary       Proxy control and Session analysis\n"
                "  mitm flows/pending/resolve/export/replay-current  MITM Proxy control\n"
                "  fleet status/workers/jobs/health           Fleet Control\n"
                "  plugin list/health                          Plugin Runtime\n"
                "  terminal capabilities/session-*             Shell capability and multi-session control\n"
                "  Tab                                         Arenyxa command completion\n"
                "  Append --json to professional commands for machine-readable output\n\n"
                "Compatibility / Session Commands:\n"
                "  help                              Show help\n"
                "  clear                             Clear output\n"
                "  history [n]                       Show session command history\n"
                "  pwd / cd <path> / ls [path]       Project navigation\n"
                "  status / paths / version          Runtime information\n"
                "  stdin <text> / stdin-secret       Send process input; secure mode masks and omits secrets from history\n"
                "  tasks [n] / runs [n] / captures [n]  Stored records\n"
                "  test-all                          Isolated full feature validation\n"
                "  stress-test [profile]             Performance stress validation\n"
            )
        return (
            "Arenyxa Terminal-First Control Plane：\n"
            "  task list/show/run                         任务查询与启动（支持 --json）\n"
            "  run list/show/cancel/pause/resume/export  Run 控制与导出\n"
            "  capture start/browser/har-import/pcap-import  实时、浏览器、HAR 与 PCAP 捕获\n"
            "  capture status/events/intelligence/alerts/stream-stats  实时情报与告警\n"
            "  packet summary/conversations/analytics    Packet Intelligence 会话分析\n"
            "  packet detect/hunt/protocols/fields       检测、威胁狩猎与动态字段发现\n"
            "  packet build                               离线数据包/PCAP 测试构造\n"
            "  extraction analyze/dry-run/pick            Extraction Lab 与网页点选\n"
            "  dataset list/show/revisions                Dataset 查询\n"
            "  flow list/show/executions/inspect-execution Flow Designer 查询与执行分析\n"
            "  proxy status/history/inspect/summary       Proxy 控制与 Session 分析\n"
            "  mitm flows/pending/resolve/export/replay-current  MITM Proxy 控制\n"
            "  fleet status/workers/jobs/health           Fleet Control\n"
            "  plugin list/health                          Plugin Runtime\n"
            "  terminal capabilities/session-*             Shell 能力探测与多会话控制\n"
            "  Tab                                         Arenyxa 命令组/动作补全\n"
            "  任意专业命令追加 --json 可输出机器可读 JSON\n\n"
            "兼容 / 会话命令：\n"
            "  help                              显示帮助\n"
            "  clear                             清空输出\n"
            "  history [n]                       显示命令历史\n"
            "  pwd / cd <path> / ls [path]       项目目录导航\n"
            "  status / paths / version          运行时信息\n"
            "  stdin <text> / stdin-secret       发送进程输入；安全模式会隐藏且不记录密钥\n"
            "  tasks [n] / runs [n] / captures [n]  已保存记录\n"
            "  test-all                          隔离完整功能验证\n"
            "  stress-test [profile]             性能压力验证\n"
        )

    def _execute_builtin_core(self, name: str, command: str, parts: list[str]) -> bool:
        """Handle help, navigation, history, and process-input builtins."""
        if name == "help":
            self.output.appendPlainText(self._builtin_help_text())
            return True
        if name == "clear":
            self.output.clear()
            return True
        if name == "stop":
            self._stop_process()
            return True
        if name in {"stdin", "stdin-secret"}:
            payload = command[len(parts[0]):].lstrip()
            if not payload:
                self.output.appendPlainText(f"用法：{name} <text>")
                return True
            try:
                sent = self.context.terminal.send_input(payload)
            except ValueError as exc:
                self.output.appendPlainText(f"{name} 失败：{exc}")
            else:
                label = "[secret stdin sent]" if name == "stdin-secret" else "[stdin sent]"
                self.output.appendPlainText(label if sent else "当前进程无法接收标准输入。")
            return True
        if name == "eof":
            self.output.appendPlainText(
                "[stdin closed]" if self.context.terminal.close_input() else "当前进程没有可关闭的标准输入。"
            )
            return True
        if name == "history":
            limit = self._bounded_int(parts[1] if len(parts) > 1 else "30", 1, 200, "history")
            if limit is not None:
                rows = self.context.terminal.history(limit)
                self.output.appendPlainText("\n".join(f"{idx + 1:>3}  {value}" for idx, value in enumerate(rows)))
            return True
        if name == "pwd":
            self.output.appendPlainText(str(self.context.terminal.cwd))
            return True
        if name == "cd":
            raw = self._strip_outer_quotes(command[len(parts[0]):].strip() or ".")
            try:
                changed = self.context.terminal.set_cwd(raw)
            except (OSError, ValueError) as exc:
                self.output.appendPlainText(f"cd 失败：{exc}")
            else:
                self.output.appendPlainText(str(changed))
                self._refresh_cwd()
            return True
        if name == "ls":
            raw = self._strip_outer_quotes(command[len(parts[0]):].strip() or ".")
            try:
                rows = self.context.terminal.list_directory(raw)
            except (OSError, ValueError) as exc:
                self.output.appendPlainText(f"ls 失败：{exc}")
                return True
            if not rows:
                self.output.appendPlainText("<empty>")
                return True
            lines = []
            for row in rows:
                kind = "<DIR>" if row["type"] == "dir" else "     "
                size = "" if row["size"] is None else f"{int(row['size']):>12,}"
                lines.append(f"{kind} {size:>12}  {row['name']}")
            self.output.appendPlainText("\n".join(lines))
            return True
        return False

    def _execute_builtin_environment(self, name: str, command: str, parts: list[str]) -> bool:
        """Handle session environment, executable lookup, and timeout builtins."""
        if name == "env":
            needle = parts[1] if len(parts) > 1 else ""
            rows = self.context.terminal.environment_items(needle)
            self.output.appendPlainText("没有匹配的环境变量。" if not rows else "\n".join(f"{key}={value}" for key, value in rows))
            return True
        if name == "setenv":
            payload = command[len(parts[0]):].strip()
            key, separator, value = payload.partition("=")
            if not separator:
                self.output.appendPlainText("用法：setenv NAME=VALUE")
                return True
            try:
                self.context.terminal.set_environment(key.strip(), value)
            except ValueError as exc:
                self.output.appendPlainText(f"setenv 失败：{exc}")
            else:
                shown = "<redacted>" if (
                    self.context.terminal.is_sensitive_environment_name(key.strip())
                    or self.context.terminal.is_sensitive_environment_value(value)
                ) else value
                self.output.appendPlainText(f"{key.strip()}={shown}")
            return True
        if name == "unsetenv":
            if len(parts) != 2:
                self.output.appendPlainText("用法：unsetenv NAME")
                return True
            try:
                removed = self.context.terminal.unset_environment(parts[1])
            except ValueError as exc:
                self.output.appendPlainText(f"unsetenv 失败：{exc}")
            else:
                self.output.appendPlainText("已删除。" if removed else "变量不存在。")
            return True
        if name == "which":
            if len(parts) != 2:
                self.output.appendPlainText("用法：which <program>")
            else:
                self.output.appendPlainText(self.context.terminal.which(parts[1]) or "未找到。")
            return True
        if name == "timeout":
            if len(parts) == 1:
                self.output.appendPlainText(f"{self.context.terminal.timeout_seconds:g} seconds")
                return True
            if len(parts) != 2:
                self.output.appendPlainText("用法：timeout [1-3600]")
                return True
            try:
                value = self.context.terminal.set_timeout(float(parts[1]))
            except (TypeError, ValueError) as exc:
                self.output.appendPlainText(f"timeout 失败：{exc}")
            else:
                self.output.appendPlainText(f"外部命令超时设置为 {value:g} 秒。")
                self._refresh_cwd()
            return True
        return False

    def _execute_builtin_status(self, name: str, _command: str, _parts: list[str]) -> bool:
        """Handle version, path, and runtime-status builtins."""
        if name == "version":
            self.output.appendPlainText(f"Arenyxa {__display_version__}")
            return True
        if name == "paths":
            payload = {
                "data_root": str(self.context.paths.root), "database": str(self.context.paths.database),
                "projects": str(self.context.paths.projects), "captures": str(self.context.paths.captures),
                "exports": str(self.context.paths.exports), "plugins": str(self.context.paths.plugins),
                "logs": str(self.context.paths.logs),
            }
            self.output.appendPlainText(json.dumps(payload, ensure_ascii=False, indent=2))
            return True
        if name == "status":
            capture = self.context.capture.session
            payload = {
                "version": __version__, "developer_mode": bool(self.context.settings.developer_mode),
                "root_developer_workstation": self._root_workstation_active(),
                "performance_mode": self.context.performance.mode, "terminal_mode": str(self.mode.currentData()),
                "cwd": str(self.context.terminal.cwd), "timeout_seconds": self.context.terminal.timeout_seconds,
                "external_process_running": self.context.terminal.is_running,
                "resource_governance": self.context.runner.resource_snapshot(),
                "performance_intelligence": self.context.runner.performance_explanation(),
                "plugin_health": [asdict(item) for item in self.context.plugin_sandbox.health_snapshot()],
                "capture_session": None if capture is None else {"id": capture.id, "state": capture.state.value},
            }
            self.output.appendPlainText(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
            return True
        return False

    def _execute_builtin_data(self, name: str, command: str, parts: list[str]) -> bool:
        """Handle bounded task, run, capture, event, and SQL queries."""
        if name in {"tasks", "runs", "captures"}:
            defaults = {"tasks": ("100", 500), "runs": ("100", 1000), "captures": ("100", 1000)}
            default, maximum = defaults[name]
            limit = self._bounded_int(parts[1] if len(parts) > 1 else default, 1, maximum, name)
            if limit is None:
                return True
            if name == "tasks":
                self._background_json(lambda: [task.to_dict() for task in self.context.store.list_tasks(True, limit=limit)])
            elif name == "runs":
                self._background_json(lambda: self.context.store.list_runs(limit=limit))
            else:
                self._background_json(lambda: self.context.store.list_captures(limit=limit))
            return True
        if name == "events":
            if len(parts) not in {2, 3}:
                self.output.appendPlainText("用法：events <session_id> [1-10000]")
                return True
            limit = self._bounded_int(parts[2] if len(parts) == 3 else "1000", 1, 10000, "events")
            if limit is not None:
                session_id = parts[1]
                self._background_json(lambda: list(self.context.store.iter_network_events(session_id, limit)))
            return True
        if name == "sql":
            self._run_readonly_sql(command[len(parts[0]):].strip())
            return True
        return False

    def _execute_builtin_validation(self, name: str, _command: str, parts: list[str]) -> bool:
        """Handle developer validation, stress, and synthetic fault builtins."""
        if name == "test-all":
            if len(parts) != 1:
                self.output.appendPlainText("用法：test-all")
            else:
                self._run_full_validation()
            return True
        if name == "stress-test":
            if len(parts) > 2:
                self.output.appendPlainText("用法：stress-test [quick|standard|extreme]")
            else:
                self._run_stress_validation(parts[1].casefold() if len(parts) == 2 else "standard")
            return True
        if name == "fault-injection":
            if len(parts) > 2:
                self.output.appendPlainText("用法：fault-injection [transient|recoverable|configuration|permission|corruption|fatal|all]")
            else:
                self._run_fault_injection(parts[1].casefold() if len(parts) == 2 else "all")
            return True
        return False

    def _execute_control_plane(self, command: str) -> None:
        runtime = self.context.command_runtime or ArenyxaCommandRuntime(self.context)
        self.context.command_runtime = runtime
        def worker() -> object:
            return runtime.execute(command)
        def completed(value: object) -> None:
            if isinstance(value, dict):
                self.output.appendPlainText(runtime.render(value))
            else:
                self.output.appendPlainText(str(value))
        def failed(message: str) -> None:
            self.output.appendPlainText(f"Arenyxa CLI failed: {message}")
        run_background(worker, completed, failed)

    def _send_persistent_command(self, command: str, mode: TerminalMode) -> None:
        if self.context.terminal.active_mode != mode:
            self.output.appendPlainText("当前已有另一个 Persistent Shell 正在运行；请先 stop。")
            return
        risk = self.context.terminal.detect_risk(command, mode)
        if risk:
            box = QMessageBox(self)
            box.setWindowTitle("确认 Persistent Shell 高风险命令")
            box.setIcon(QMessageBox.Icon.Warning)
            box.setText(f"⚠ {risk}\n\n{self.context.terminal.redact_command(command)}")
            box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            box.setDefaultButton(QMessageBox.StandardButton.No)
            if box.exec() != QMessageBox.StandardButton.Yes:
                self.output.appendPlainText("已取消。")
                return
        try:
            sent = self.context.terminal.send_input(command)
        except ValueError as exc:
            self.output.appendPlainText(f"Shell input failed: {exc}")
            return
        self.output.appendPlainText("[sent to persistent shell]" if sent else "Persistent shell is not accepting input.")

    def _developer_validation_authorized(self) -> bool:
        if self._root_workstation_active():
            if self._developer_test_running:
                self.output.appendPlainText("已有开发者验证任务正在运行，请等待完成后再启动新的测试。")
                return False
            return True
        authorization = authorization_from_settings(self.context.settings)
        if not authorization.developer_mode:
            self.output.appendPlainText("命令已锁定：请先在设置 → 高级设置中启用 Developer Mode。")
            return False
        if not authorization.valid:
            self.output.appendPlainText(
                "命令已锁定：当前 Developer Mode 没有有效的风险协议与免责协议授权。"
                "请关闭 Developer Mode 后重新启用，并完成双协议确认。"
            )
            return False
        if self._developer_test_running:
            self.output.appendPlainText("已有开发者验证任务正在运行，请等待完成后再启动新的测试。")
            return False
        return True
