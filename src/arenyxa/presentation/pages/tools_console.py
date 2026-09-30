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
from arenyxa.qt_compat.QtGui import QColor, QFont, QKeyEvent, QPalette, QTextCursor
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

from arenyxa import __display_version__
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
from arenyxa.application.workflow_debugger import WorkflowSafeDebugger
from arenyxa.application.workflow_graph import WorkflowGraphModel
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import RequestSpec, Workflow, WorkflowNode, new_id
from arenyxa.infrastructure.http_client import HttpFetcher
from arenyxa.presentation.background import run_background
from arenyxa.presentation.i18n_runtime import current_text, source_text
from arenyxa.presentation.flow_graph import FlowGraphCanvas
from arenyxa.presentation.pages.tools_terminal_workspace import ConsoleCommandMixin, TerminalWorkspaceMixin
from arenyxa.presentation.pages.tools_terminal_execution import ConsoleExternalProcessMixin, ConsoleValidationMixin
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import MiniBars, PageHeader, set_table_header_stretch_last, ScrollSafeComboBox


LOGGER = logging.getLogger(__name__)


class ConsoleCommandEdit(QLineEdit):
    historyStepRequested = Signal(int)
    interruptRequested = Signal()
    clearRequested = Signal()
    completionRequested = Signal()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() == Qt.Key.Key_Tab:
            self.completionRequested.emit()
            event.accept()
            return
        if event.key() == Qt.Key.Key_Up:
            self.historyStepRequested.emit(-1)
            event.accept()
            return
        if event.key() == Qt.Key.Key_Down:
            self.historyStepRequested.emit(1)
            event.accept()
            return
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            if event.key() == Qt.Key.Key_L:
                self.clearRequested.emit()
                event.accept()
                return
            if event.key() == Qt.Key.Key_C and not self.hasSelectedText():
                self.interruptRequested.emit()
                event.accept()
                return
        super().keyPressEvent(event)


class ConsolePage(TerminalWorkspaceMixin, ConsoleCommandMixin, ConsoleValidationMixin, ConsoleExternalProcessMixin, WorkspacePage):
    outputReady = Signal(str)
    processFinished = Signal(object)
    BUILTIN: ClassVar[set[str]] = {
        "help", "clear", "history", "pwd", "cd", "ls", "env", "setenv", "unsetenv",
        "which", "timeout", "status", "paths", "version", "tasks", "runs", "captures",
        "events", "sql", "stdin", "stdin-secret", "eof", "stop", "test-all", "stress-test", "fault-injection",
    }

    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        layout = page_layout(self)
        layout.addWidget(
            PageHeader(
                source_text("tools_console.page.title"),
                source_text("tools_console.page.subtitle"),
                title_key="tools_console.page.title",
                subtitle_key="tools_console.page.subtitle",
            )
        )

        toolbar = QHBoxLayout()
        mode_label = QLabel(source_text("tools_console.mode.label")); mode_label.setProperty("i18n_key_text", "tools_console.mode.label"); toolbar.addWidget(mode_label)
        self.mode = ScrollSafeComboBox()
        mode_items = [
            ("tools_console.mode.arenyxa", "arenyxa"),
            ("tools_console.mode.direct", TerminalMode.DIRECT.value),
            ("tools_console.mode.powershell", TerminalMode.POWERSHELL.value),
            ("tools_console.mode.powershell_session", TerminalMode.POWERSHELL_SESSION.value),
        ]
        if os.name == "nt":
            mode_items.extend((
                ("tools_console.mode.cmd", TerminalMode.CMD.value),
                ("tools_console.mode.cmd_session", TerminalMode.CMD_SESSION.value),
            ))
        mode_items.extend((
            ("tools_console.mode.python", TerminalMode.PYTHON.value),
            ("tools_console.mode.python_repl", TerminalMode.PYTHON_SESSION.value),
        ))
        for index, (key, value) in enumerate(mode_items):
            self.mode.addItem(source_text(key), value)
            self.mode.setProperty(f"i18n_item_key_{index}", key)
        toolbar.addWidget(self.mode)
        self.cwd_label = QLabel()
        self.cwd_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        toolbar.addWidget(self.cwd_label, 1)
        self.stop_button = QPushButton(source_text("tools_console.action.stop")); self.stop_button.setProperty("i18n_key_text", "tools_console.action.stop")
        self.stop_button.setEnabled(False)
        self.clear_button = QPushButton(source_text("tools_console.action.clear")); self.clear_button.setProperty("i18n_key_text", "tools_console.action.clear")
        toolbar.addWidget(self.stop_button)
        toolbar.addWidget(self.clear_button)
        layout.addLayout(toolbar)

        self.console_tabs = QTabWidget()
        main_console = QWidget()
        main_layout = QVBoxLayout(main_console)
        main_layout.setContentsMargins(0, 0, 0, 0)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Cascadia Mono"))
        log_blocks = (
            1000
            if context.performance.mode == "efficiency"
            else 2000
            if context.performance.mode == "balanced"
            else 3000
        )
        self.output.setMaximumBlockCount(log_blocks)
        self._log_tail_lines = log_blocks
        main_layout.addWidget(self.output, 1)

        row = QHBoxLayout()
        self.prompt = QLabel("Arenyxa>")
        self.command = ConsoleCommandEdit()
        runtime = self.context.command_runtime or ArenyxaCommandRuntime(self.context)
        self.context.command_runtime = runtime
        completion_words = sorted(self.BUILTIN | {"!", "!!", "arenyxa"} | set(runtime.COMMAND_TREE))
        completer = QCompleter(completion_words, self.command)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.command.setCompleter(completer)
        self._command_completer = completer
        self._refresh_completion_popup_theme()
        self.theme.changed.connect(self._refresh_completion_popup_theme)
        self.execute_button = QPushButton(source_text("tools_console.action.execute")); self.execute_button.setProperty("i18n_key_text", "tools_console.action.execute")
        self.execute_button.setProperty("primary", True)
        row.addWidget(self.prompt)
        row.addWidget(self.command, 1)
        row.addWidget(self.execute_button)
        main_layout.addLayout(row)
        self.console_tabs.addTab(main_console, source_text("tools_console.tab.control_plane"))
        self.console_tabs.setProperty("i18n_tab_key_0", "tools_console.tab.control_plane")
        self.console_tabs.addTab(self._build_terminal_workspace(), source_text("tools_console.tab.shell_sessions"))
        self.console_tabs.setProperty("i18n_tab_key_1", "tools_console.tab.shell_sessions")
        layout.addWidget(self.console_tabs, 1)

        self._workspace_timer = QTimer(self)
        self._workspace_timer.setInterval(180)
        self._workspace_timer.timeout.connect(self._refresh_terminal_workspace)
        self._workspace_timer.start()
        self._history_cursor = len(self.context.terminal.history())
        self._developer_test_running = False
        self._secret_stdin_pending = False
        self.execute_button.clicked.connect(self.execute)
        self.command.returnPressed.connect(self.execute)
        self.command.textChanged.connect(self._update_secret_input_mode)
        self.command.historyStepRequested.connect(self._history_step)
        self.command.interruptRequested.connect(self._interrupt_from_keyboard)
        self.command.clearRequested.connect(self.output.clear)
        self.command.completionRequested.connect(self._complete_command)
        self.stop_button.clicked.connect(self._stop_process)
        self.clear_button.clicked.connect(self.output.clear)
        self.mode.currentIndexChanged.connect(self._mode_changed)
        self.outputReady.connect(self._append_stream)
        self.processFinished.connect(self._process_finished)
        self._mode_changed()
        self._refresh_cwd()
        self.output.appendPlainText(
            current_text("tools_console.intro").format(version=__display_version__)
        )


    def _refresh_completion_popup_theme(self, *_args: object) -> None:
        """Synchronize QCompleter's top-level popup with the active visual preset."""
        completer = getattr(self, "_command_completer", None)
        if completer is None:
            return
        popup = completer.popup()
        tokens = self.theme.current
        palette = popup.palette()
        palette.setColor(QPalette.ColorRole.Base, QColor(tokens.background_alt))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(tokens.surface))
        palette.setColor(QPalette.ColorRole.Text, QColor(tokens.text))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(tokens.selection))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor(tokens.text))
        popup.setPalette(palette)
        popup.setStyleSheet(
            "QAbstractItemView {"
            f"background-color:{tokens.background_alt}; color:{tokens.text}; "
            f"border:1px solid {tokens.border}; selection-background-color:{tokens.selection}; "
            f"selection-color:{tokens.text}; outline:0; padding:2px;"
            "}"
        )
        popup.style().unpolish(popup)
        popup.style().polish(popup)
        popup.viewport().update()


class LogsPage(WorkspacePage):
    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        layout = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(PageHeader(source_text("tools_logs.page.title"), source_text("tools_logs.page.subtitle"), title_key="tools_logs.page.title", subtitle_key="tools_logs.page.subtitle"), 1)
        refresh = QPushButton(source_text("tools_logs.action.refresh")); refresh.setProperty("i18n_key_text", "tools_logs.action.refresh")
        header.addWidget(refresh)
        layout.addLayout(header)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Cascadia Mono"))
        log_blocks = (
            1000
            if context.performance.mode == "efficiency"
            else 2000
            if context.performance.mode == "balanced"
            else 3000
        )
        self.output.setMaximumBlockCount(log_blocks)
        self._log_tail_lines = log_blocks
        layout.addWidget(self.output, 1)
        refresh.clicked.connect(self.activated)

    def activated(self) -> None:
        path = self.context.paths.readable_log_file
        if not path.exists():
            self.output.setPlainText(current_text("tools_logs.empty"))
            return
        self.output.setPlainText(current_text("tools_logs.loading"))

        def worker() -> tuple[str, int]:

            with path.open("r", encoding="utf-8", errors="replace") as stream:
                lines = deque(stream, maxlen=self._log_tail_lines)
            return "".join(lines), len(lines)

        def completed(value: object) -> None:
            text, count = value if isinstance(value, tuple) and len(value) == 2 else ("", 0)
            self.output.setPlainText(str(text))
            self.output.moveCursor(self.output.textCursor().MoveOperation.End)
            self.inspectorChanged.emit(current_text("tools_logs.inspector"), {"path": str(path), "visible_lines": int(count)})

        run_background(
            worker,
            completed,
            lambda message: self.output.setPlainText(current_text("tools_logs.failed").format(message=message)),
        )
