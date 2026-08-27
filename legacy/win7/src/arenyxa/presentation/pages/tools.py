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

from arenyxa.qt_compat.QtCore import Qt, Signal
from arenyxa.qt_compat.QtGui import QFont, QKeyEvent, QTextCursor
from arenyxa.qt_compat.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QCompleter,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
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
from arenyxa.domain.models import RequestSpec, Workflow, WorkflowNode, new_id
from arenyxa.infrastructure.http_client import HttpFetcher
from arenyxa.presentation.background import run_background
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import MiniBars, PageHeader, set_table_header_stretch_last, ScrollSafeComboBox


LOGGER = logging.getLogger(__name__)

class AutomationPage(WorkspacePage):
    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        layout = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(PageHeader("自动化计划", "时区明确、启停可恢复、失败策略可追踪"), 1)
        add = QPushButton("新建计划")
        add.setProperty("primary", True)
        header.addWidget(add)
        layout.addLayout(header)
        self.table = QTableWidget(0, 6)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.table.setHorizontalHeaderLabels(["任务", "规则", "时区", "下一次", "启用", "ID"])
        set_table_header_stretch_last(self.table, True)
        layout.addWidget(self.table, 1)
        self._schedule_run_lock = threading.Lock()
        self._schedule_run_handles = {}
        add.clicked.connect(self.add_schedule)

    def activated(self) -> None:
        self.refresh()

    def refresh(self) -> None:
        rows = self.context.store.list_schedules()
        self.table.setRowCount(len(rows))
        for row, schedule in enumerate(rows):
            values = [
                schedule["task_name"],
                json.dumps(schedule["rule"], ensure_ascii=False),
                schedule["timezone"],
                schedule.get("next_run_at") or "",
                "是" if schedule["enabled"] else "否",
                schedule["id"],
            ]
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(str(value)))
        self.inspectorChanged.emit("自动化", {"schedule_count": len(rows)})

    def add_schedule(self) -> None:
        tasks = self.context.store.list_tasks()
        if not tasks:
            QMessageBox.information(self, "自动化", "请先创建任务。")
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("新建计划")
        form = QFormLayout(dialog)
        task_box = QComboBox()
        for task in tasks:
            task_box.addItem(task.name, task.id)
        interval = QSpinBox()
        interval.setRange(1, 10080)
        interval.setValue(1440)
        timezone = QComboBox()
        timezone.addItems(["Asia/Shanghai", "UTC", "Europe/Berlin", "America/New_York", "Asia/Tokyo"])
        controls = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        controls.accepted.connect(dialog.accept)
        controls.rejected.connect(dialog.reject)
        form.addRow("任务", task_box)
        form.addRow("间隔（分钟）", interval)
        form.addRow("时区", timezone)
        form.addRow(controls)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        rule = ScheduleRule(
            kind="interval", interval_minutes=interval.value(), timezone=timezone.currentText()
        )
        schedule_id = new_id("schedule")
        next_run = rule.next_after(datetime.now(UTC))
        self.context.store.save_schedule(
            {
                "id": schedule_id,
                "task_id": task_box.currentData(),
                "rule": asdict(rule),
                "timezone": rule.timezone,
                "enabled": True,
                "next_run_at": next_run.isoformat(),
            }
        )
        task_id = task_box.currentData()
        self.context.scheduler.add(
            schedule_id,
            rule,
            lambda task_id=task_id, schedule_id=schedule_id: self._scheduled_run(task_id, schedule_id),
            next_run=next_run,
        )
        self.refresh()

    def _scheduled_run(self, task_id: str, schedule_id: str) -> None:
                                                                                           
                                                                                             
                                                                                        
        with self._schedule_run_lock:
            previous = self._schedule_run_handles.get(schedule_id)
            if previous is not None and not previous.future.done():
                return
            operations = getattr(self.context, "enterprise_operations", None)
            if operations is not None:
                operations.authorize_if_bound(
                    "schedule", schedule_id, "schedule.manage",
                    correlation_id=f"schedule-run:{schedule_id}",
                )
            task = self.context.store.get_task(task_id)
            if task:
                self._schedule_run_handles[schedule_id] = self.context.runner.submit(task)


class WorkflowPage(WorkspacePage):
    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        layout = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(
            PageHeader(
                "Workflow & Pipeline 2.0",
                "HTTP/Browser/API → Parse → Clean → Validate → Database/Search/Visualization",
            ),
            1,
        )
        save = QPushButton("保存工作流")
        run = QPushButton("运行")
        run.setProperty("primary", True)
        header.addWidget(save)
        header.addWidget(run)
        layout.addLayout(header)
        splitter = QSplitter()
        self.definition = QPlainTextEdit()
        self.definition.setPlainText(
            json.dumps(
                {
                    "name": "Data Quality Pipeline",
                    "nodes": [
                        {"id": "source", "kind": "source", "config": {}, "next_ids": ["validate"]},
                        {
                            "id": "validate",
                            "kind": "validate",
                            "config": {"required": ["title"]},
                            "next_ids": ["sink"],
                            "failure_ids": ["errors"],
                        },
                        {"id": "sink", "kind": "sink", "config": {}, "next_ids": []},
                        {"id": "errors", "kind": "sink", "config": {}, "next_ids": []},
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self.inputs = QPlainTextEdit('[{"title":"Arenyxa","status":200},{"title":"","status":404}]')
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        right_layout.addWidget(QLabel("输入 JSON 数组"))
        right_layout.addWidget(self.inputs)
        right_layout.addWidget(QLabel("执行结果"))
        right_layout.addWidget(self.output)
        splitter.addWidget(self.definition)
        splitter.addWidget(right)
        layout.addWidget(splitter, 1)
        save.clicked.connect(self.save_workflow)
        run.clicked.connect(self.run_workflow)

    def _workflow(self) -> Workflow:
        raw = json.loads(self.definition.toPlainText())
        nodes = [WorkflowNode(**node) for node in raw["nodes"]]
        return Workflow(name=raw["name"], nodes=nodes, id=raw.get("id", new_id("workflow")))

    def save_workflow(self) -> None:
        try:
            workflow = self._workflow()
            operations = getattr(self.context, "enterprise_operations", None)
            if operations is not None and operations.binding("workflow", workflow.id) is not None:
                approval_id, ok = QInputDialog.getText(
                    self, "Enterprise 变更审批",
                    "该 Workflow 已纳入 Enterprise Governance。请输入已批准的 Approval ID：",
                )
                if not ok:
                    return
                operations.authorize_if_bound(
                    "workflow", workflow.id, "workflow.publish", approval_id=approval_id.strip(),
                    correlation_id=f"workflow-publish:{workflow.id}",
                )
            self.context.store.save_workflow(asdict(workflow))
            self.statusMessage.emit(f"工作流已保存：{workflow.name}")
        except Exception as exc:                                               
            QMessageBox.warning(self, "工作流无效", str(exc))

    def run_workflow(self) -> None:
        try:
            workflow = self._workflow()
            inputs = json.loads(self.inputs.toPlainText())
            operations = getattr(self.context, "enterprise_operations", None)
            if operations is not None:
                operations.authorize_if_bound(
                    "workflow", workflow.id, "workflow.execute",
                    correlation_id=f"workflow-direct:{workflow.id}",
                )
            result = self.context.workflows.execute(workflow, inputs)
            self.output.setPlainText(json.dumps(asdict(result), ensure_ascii=False, indent=2, default=str))
            self.statusMessage.emit(
                f"Workflow 完成：{len(result.outputs)} outputs · {len(result.errors)} errors"
            )
        except Exception as exc:                                                              
            QMessageBox.warning(self, "Workflow 失败", str(exc))


class AdvancedPlatformPage(WorkspacePage):
    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        layout = page_layout(self)
        layout.addWidget(
            PageHeader("Advanced Platform", "确定性执行规划、站点地图、API Map、性能与安全配置分析")
        )
        controls = QHBoxLayout()
        self.session = QComboBox()
        self.session.setMinimumWidth(300)
        self.url = QLineEdit("https://example.com")
        self.url.setPlaceholderText("授权分析 URL")
        self.analyze_button = QPushButton("运行分析")
        self.analyze_button.setProperty("primary", True)
        controls.addWidget(QLabel("Capture"))
        controls.addWidget(self.session)
        controls.addWidget(self.url, 1)
        controls.addWidget(self.analyze_button)
        layout.addLayout(controls)
        self.tabs = QTabWidget()
        self.tab_indices: dict[str, int] = {}
        self.outputs: dict[str, QPlainTextEdit] = {}
        for key, label in (
            ("planner", "Execution Planner"),
            ("map", "Website Intelligence"),
            ("api", "API Map"),
            ("performance", "Performance"),
            ("security", "Security Center"),
            ("compatibility", "Compatibility"),
        ):
            editor = QPlainTextEdit()
            editor.setReadOnly(True)
            self.outputs[key] = editor
            self.tab_indices[key] = self.tabs.addTab(editor, label)
        database_tab = QWidget()
        database_layout = QVBoxLayout(database_tab)
        database_form = QHBoxLayout()
        self.database_dsn = QLineEdit(str(context.paths.root / "external-data.db"))
        self.database_dsn.setPlaceholderText("SQLite path or SQLAlchemy URL")
        self.database_test_button = QPushButton("测试连接与能力")
        database_form.addWidget(self.database_dsn, 1)
        database_form.addWidget(self.database_test_button)
        self.database_output = QPlainTextEdit()
        self.database_output.setReadOnly(True)
        database_layout.addLayout(database_form)
        database_layout.addWidget(self.database_output, 1)
        self.tab_indices["database"] = self.tabs.addTab(database_tab, "Database Adapter")
        visualization = QWidget()
        visual_layout = QVBoxLayout(visualization)
        self.bars = MiniBars(theme)
        visual_layout.addWidget(QLabel("Traffic by domain"))
        visual_layout.addWidget(self.bars, 1)
        self.tab_indices["visualization"] = self.tabs.addTab(visualization, "Visualization Studio")
        layout.addWidget(self.tabs, 1)
        self.analyze_button.clicked.connect(self.analyze)
        self.database_test_button.clicked.connect(self.test_database)

    def open_section(self, key: str) -> None:
        index = self.tab_indices.get(key)
        if index is not None:
            self.tabs.setCurrentIndex(index)

    def activated(self) -> None:
        selected = self.session.currentData()
        self.session.clear()
        for capture in self.context.store.list_captures():
            self.session.addItem(
                f"{capture['created_at'][:19]} · {capture['source_type']} · {capture['event_count']}",
                capture["id"],
            )
            if capture["id"] == selected:
                self.session.setCurrentIndex(self.session.count() - 1)

    def analyze(self) -> None:
        session_id = self.session.currentData()
        target_url = self.url.text().strip()
        self.analyze_button.setEnabled(False)
        self.statusMessage.emit("高级平台正在后台分析…")

        def analyze_data() -> dict:
            from arenyxa.domain.enums import CaptureSource
            from arenyxa.domain.models import NetworkEvent

            events = []
            if session_id:
                for raw in self.context.store.iter_network_events(session_id):
                    normalized = dict(raw)
                    normalized["source_type"] = CaptureSource(normalized["source_type"])
                    normalized["sensitivity_flags"] = normalized.pop("sensitivity", [])
                    events.append(
                        NetworkEvent(
                            **{
                                key: value
                                for key, value in normalized.items()
                                if key in NetworkEvent.__dataclass_fields__
                            }
                        )
                    )
            response = (
                HttpFetcher(self.context.settings.max_response_bytes).fetch(RequestSpec(target_url))
                if target_url
                else None
            )
            plan = SmartExecutionPlanner().plan(response, events)
            site_map = WebsiteIntelligenceMapper().build(events)
            if session_id:
                from arenyxa.application.api_map import ApiMapService
                from arenyxa.infrastructure.capture.replay import CapturedBodyResolver

                exchanges = list(self.context.store.iter_http_exchanges(session_id, limit=100_000))
                resolver = CapturedBodyResolver(self.context.store, self.context.paths.captures)
                api_snapshot = ApiMapService().build(
                    session_id, exchanges, body_loader=resolver.load_for_schema
                )
                self.context.store.save_api_map_snapshot(api_snapshot.to_dict())
                api = api_snapshot.to_dict()
            else:
                api = {
                    "id": None,
                    "session_id": None,
                    "endpoint_count": 0,
                    "source_event_count": len(events),
                    "endpoints": ApiMapper().analyze(events),
                    "warnings": ["未选择捕获会话；当前 API Map 仅使用临时 NetworkEvent。"],
                }
            performance = PerformanceProfiler().summarize(events)
            security = SecurityAnalyzer().analyze(response) if response else []
            compatibility = CompatibilityAnalyzer().analyze_html(response) if response else []
            safe_performance = {key: value for key, value in performance.items() if key != "slowest"}
            safe_performance["slowest"] = [asdict(item) for item in performance["slowest"]]
            return {
                "planner": asdict(plan),
                "map": asdict(site_map),
                "api": api,
                "performance": safe_performance,
                "security": security,
                "compatibility": compatibility,
                "hosts": performance["hosts"],
            }

        def completed(result: object) -> None:
            self.analyze_button.setEnabled(True)
            for key in ("planner", "map", "api", "performance", "security", "compatibility"):
                self.outputs[key].setPlainText(
                    json.dumps(result[key], ensure_ascii=False, indent=2, default=str)
                )
            hosts = result["hosts"]
            self.bars.set_values([(str(host), float(count)) for host, count in list(hosts.items())[:12]])
            self.statusMessage.emit("高级平台分析完成")

        def failed(message: str) -> None:
            self.analyze_button.setEnabled(True)
            QMessageBox.warning(self, "分析失败", message)

        run_background(analyze_data, completed, failed)

    def test_database(self) -> None:
        from arenyxa.infrastructure.database_adapters import SQLAlchemyDatabaseAdapter, SQLiteDatabaseAdapter

        dsn = self.database_dsn.text().strip()
        self.database_test_button.setEnabled(False)

        def probe() -> dict:
            adapter = SQLAlchemyDatabaseAdapter() if "://" in dsn else SQLiteDatabaseAdapter()
            adapter.open({"url": dsn} if "://" in dsn else {"path": dsn}, {})
            try:
                return {
                    "connected": True,
                    "capabilities": asdict(adapter.describe_capabilities()),
                    "probe": list(adapter.query("SELECT 1 AS probe")),
                }
            finally:
                adapter.close()

        def completed(result: object) -> None:
            self.database_test_button.setEnabled(True)
            self.database_output.setPlainText(json.dumps(result, ensure_ascii=False, indent=2))

        def failed(message: str) -> None:
            self.database_test_button.setEnabled(True)
            self.database_output.setPlainText(
                json.dumps({"connected": False, "error": message}, ensure_ascii=False, indent=2)
            )

        run_background(probe, completed, failed)


class PluginsPage(WorkspacePage):
    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        layout = page_layout(self)
        layout.addWidget(PageHeader("插件与沙箱", "Manifest、显式授权、子进程隔离、超时与输出预算"))
        splitter = QSplitter()
        self.list = QListWidget()
        self.list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        splitter.addWidget(self.list)
        splitter.addWidget(self.detail)
        splitter.setSizes([360, 760])
        layout.addWidget(splitter, 1)
        self.list.currentRowChanged.connect(self.show_plugin)
        self._plugins = []

    def activated(self) -> None:
        self._plugins = self.context.plugins.discover()
        self._plugin_health = {item.plugin_id: item for item in self.context.plugin_sandbox.health_snapshot()}
        self.list.clear()
        for manifest, path in self._plugins:
            health = self._plugin_health.get(manifest.id)
            state = "healthy" if health is None else health.state
            self.list.addItem(f"{manifest.name}\n{manifest.id} · {manifest.version} · {state}")
        self.inspectorChanged.emit(
            "插件", {"count": len(self._plugins), "root": str(self.context.paths.plugins)}
        )

    def show_plugin(self, row: int) -> None:
        if 0 <= row < len(self._plugins):
            manifest, path = self._plugins[row]
            self.detail.setPlainText(
                json.dumps(
                    {
                        "manifest": asdict(manifest),
                        "path": str(path),
                        "default": "disabled until explicit grant",
                        "health": None if self._plugin_health.get(manifest.id) is None else asdict(self._plugin_health[manifest.id]),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )


class ConsoleCommandEdit(QLineEdit):
    historyStepRequested = Signal(int)
    interruptRequested = Signal()
    clearRequested = Signal()

    def keyPressEvent(self, event: QKeyEvent) -> None:
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


class ConsolePage(WorkspacePage):
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
                "Terminal & Packet Console",
                "实时输出 · 可停止进程 · 项目工作目录 · Direct/PowerShell/CMD/Python 多模式",
            )
        )

        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("模式"))
        self.mode = ScrollSafeComboBox()
        self.mode.addItem("Arenyxa Console", "arenyxa")
        self.mode.addItem("Direct Process", TerminalMode.DIRECT.value)
        self.mode.addItem("PowerShell", TerminalMode.POWERSHELL.value)
        if os.name == "nt":
            self.mode.addItem("CMD", TerminalMode.CMD.value)
        self.mode.addItem("Python", TerminalMode.PYTHON.value)
        toolbar.addWidget(self.mode)
        self.cwd_label = QLabel()
        self.cwd_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        toolbar.addWidget(self.cwd_label, 1)
        self.stop_button = QPushButton("停止")
        self.stop_button.setEnabled(False)
        self.clear_button = QPushButton("清屏")
        toolbar.addWidget(self.stop_button)
        toolbar.addWidget(self.clear_button)
        layout.addLayout(toolbar)

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

        row = QHBoxLayout()
        self.prompt = QLabel("Arenyxa>")
        self.command = ConsoleCommandEdit()
        completion_words = sorted(self.BUILTIN | {"!", "!!"})
        completer = QCompleter(completion_words, self.command)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.command.setCompleter(completer)
        self.execute_button = QPushButton("执行")
        self.execute_button.setProperty("primary", True)
        row.addWidget(self.prompt)
        row.addWidget(self.command, 1)
        row.addWidget(self.execute_button)
        layout.addLayout(row)

        self._history_cursor = len(self.context.terminal.history())
        self._developer_test_running = False
        self.execute_button.clicked.connect(self.execute)
        self.command.returnPressed.connect(self.execute)
        self.command.historyStepRequested.connect(self._history_step)
        self.command.interruptRequested.connect(self._interrupt_from_keyboard)
        self.command.clearRequested.connect(self.output.clear)
        self.stop_button.clicked.connect(self._stop_process)
        self.clear_button.clicked.connect(self.output.clear)
        self.mode.currentIndexChanged.connect(self._mode_changed)
        self.outputReady.connect(self._append_stream)
        self.processFinished.connect(self._process_finished)
        self._mode_changed()
        self._refresh_cwd()
        self.output.appendPlainText(
            f"Arenyxa V{__version__} Developer Console\n"
            "输入 help 查看命令。外部执行模式需要 Developer Mode，并且每条命令都会确认。\n"
            "工作目录可用 cd 持久切换，但被限制在 Arenyxa Projects 根目录内。"
        )

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
        }
        placeholders = {
            "arenyxa": "help / tasks 50 / events <session_id> 1000 / sql SELECT ...",
            TerminalMode.DIRECT.value: "python --version / git status / curl --version",
            TerminalMode.POWERSHELL.value: "Get-ChildItem | Select-Object -First 20",
            TerminalMode.CMD.value: "dir /b /a",
            TerminalMode.PYTHON.value: "print('hello from Arenyxa')",
        }
        self.prompt.setText(prompts.get(value, "Arenyxa>"))
        self.command.setPlaceholderText(placeholders.get(value, "输入命令"))

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

    def execute(self) -> None:
        command = self.command.text().strip()
        self.command.clear()
        if not command:
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
        if first in self.BUILTIN:
            self._execute_builtin(first, command)
            return

        selected = str(self.mode.currentData())
        if selected == "arenyxa":
            self.output.appendPlainText("未知 Arenyxa 命令；输入 help。也可以切换到 Direct/PowerShell/CMD/Python 模式。")
            return
        self._execute_external(command, TerminalMode(selected))

    def _execute_builtin(self, name: str, command: str) -> None:
        parts = command.split()
        if name == "help":
            self.output.appendPlainText(
                "Arenyxa 内置命令：\n"
                "  help                         查看帮助\n"
                "  clear                        清空输出\n"
                "  history [n]                  查看本次会话命令历史\n"
                "  pwd / cd <path> / ls [path]  项目目录导航（禁止越出 Projects 根目录）\n"
                "  env [filter]                 查看会话环境变量；敏感值自动脱敏\n"
                "  setenv NAME=VALUE            设置仅本会话有效的环境变量\n"
                "  unsetenv NAME                删除会话环境变量\n"
                "  which <program>              查找可执行程序\n"
                "  timeout [1-3600]             查看/设置外部命令超时秒数\n"
                "  status / paths / version     查看运行状态、路径与版本\n"
                "  tasks [n] / runs [n]         查看任务与运行记录\n"
                "  captures [n]                 查看抓包会话\n"
                "  events <session> [n]         查看网络事件，最大 10000\n"
                "  sql <SELECT...>               只读 SQLite 查询，最多返回 500 行\n"
                "  sql tables                   列出数据库表/视图\n"
                "  stdin <text>                  向正在运行的外部进程发送一行标准输入\n"
                "  stdin-secret <text>           发送不回显、不进入明文历史的敏感输入\n"
                "  eof                           关闭当前外部进程的标准输入\n"
                "  stop                          停止当前外部进程\n"
                "  test-all                      隔离执行完整功能验证（需 Developer Mode + 双协议授权）\n"
                "  stress-test [profile]         quick/standard/extreme 均需要 Official stress_test capability\n"
                "  fault-injection [scenario]    Official fault_injection capability；仅合成故障，不修改正式数据\n\n"
                "外部模式：Direct 不经过 Shell；PowerShell/CMD 支持管道和重定向；"
                "Python 为一次性 -c 执行。\n"
                "兼容前缀：!command = Direct，!!command = PowerShell。"
            )
            return
        if name == "clear":
            self.output.clear()
            return
        if name == "stop":
            self._stop_process()
            return
        if name in {"stdin", "stdin-secret"}:
            payload = command[len(parts[0]):].lstrip()
            if not payload:
                self.output.appendPlainText(f"用法：{name} <text>")
                return
            try:
                sent = self.context.terminal.send_input(payload)
            except ValueError as exc:
                self.output.appendPlainText(f"{name} 失败：{exc}")
            else:
                label = "[secret stdin sent]" if name == "stdin-secret" else "[stdin sent]"
                self.output.appendPlainText(label if sent else "当前进程无法接收标准输入。")
            return
        if name == "eof":
            self.output.appendPlainText(
                "[stdin closed]" if self.context.terminal.close_input() else "当前进程没有可关闭的标准输入。"
            )
            return
        if name == "history":
            limit = self._bounded_int(parts[1] if len(parts) > 1 else "30", 1, 200, "history")
            if limit is None:
                return
            rows = self.context.terminal.history(limit)
            self.output.appendPlainText("\n".join(f"{idx + 1:>3}  {value}" for idx, value in enumerate(rows)))
            return
        if name == "pwd":
            self.output.appendPlainText(str(self.context.terminal.cwd))
            return
        if name == "cd":
            raw = command[len(parts[0]):].strip() or "."
            raw = self._strip_outer_quotes(raw)
            try:
                changed = self.context.terminal.set_cwd(raw)
            except (OSError, ValueError) as exc:
                self.output.appendPlainText(f"cd 失败：{exc}")
            else:
                self.output.appendPlainText(str(changed))
                self._refresh_cwd()
            return
        if name == "ls":
            raw = command[len(parts[0]):].strip() or "."
            raw = self._strip_outer_quotes(raw)
            try:
                rows = self.context.terminal.list_directory(raw)
            except (OSError, ValueError) as exc:
                self.output.appendPlainText(f"ls 失败：{exc}")
                return
            if not rows:
                self.output.appendPlainText("<empty>")
                return
            lines = []
            for row in rows:
                kind = "<DIR>" if row["type"] == "dir" else "     "
                size = "" if row["size"] is None else f"{int(row['size']):>12,}"
                lines.append(f"{kind} {size:>12}  {row['name']}")
            self.output.appendPlainText("\n".join(lines))
            return
        if name == "env":
            needle = parts[1] if len(parts) > 1 else ""
            rows = self.context.terminal.environment_items(needle)
            if not rows:
                self.output.appendPlainText("没有匹配的环境变量。")
            else:
                self.output.appendPlainText("\n".join(f"{key}={value}" for key, value in rows))
            return
        if name == "setenv":
            payload = command[len(parts[0]):].strip()
            key, separator, value = payload.partition("=")
            if not separator:
                self.output.appendPlainText("用法：setenv NAME=VALUE")
                return
            try:
                self.context.terminal.set_environment(key.strip(), value)
            except ValueError as exc:
                self.output.appendPlainText(f"setenv 失败：{exc}")
            else:
                shown = (
                    "<redacted>"
                    if (
                        self.context.terminal.is_sensitive_environment_name(key.strip())
                        or self.context.terminal.is_sensitive_environment_value(value)
                    )
                    else value
                )
                self.output.appendPlainText(f"{key.strip()}={shown}")
            return
        if name == "unsetenv":
            if len(parts) != 2:
                self.output.appendPlainText("用法：unsetenv NAME")
                return
            try:
                removed = self.context.terminal.unset_environment(parts[1])
            except ValueError as exc:
                self.output.appendPlainText(f"unsetenv 失败：{exc}")
            else:
                self.output.appendPlainText("已删除。" if removed else "变量不存在。")
            return
        if name == "which":
            if len(parts) != 2:
                self.output.appendPlainText("用法：which <program>")
                return
            found = self.context.terminal.which(parts[1])
            self.output.appendPlainText(found or "未找到。")
            return
        if name == "timeout":
            if len(parts) == 1:
                self.output.appendPlainText(f"{self.context.terminal.timeout_seconds:g} seconds")
                return
            if len(parts) != 2:
                self.output.appendPlainText("用法：timeout [1-3600]")
                return
            try:
                value = self.context.terminal.set_timeout(float(parts[1]))
            except (TypeError, ValueError) as exc:
                self.output.appendPlainText(f"timeout 失败：{exc}")
            else:
                self.output.appendPlainText(f"外部命令超时设置为 {value:g} 秒。")
                self._refresh_cwd()
            return
        if name == "version":
            self.output.appendPlainText(f"Arenyxa {__version__}")
            return
        if name == "paths":
            payload = {
                "data_root": str(self.context.paths.root),
                "database": str(self.context.paths.database),
                "projects": str(self.context.paths.projects),
                "captures": str(self.context.paths.captures),
                "exports": str(self.context.paths.exports),
                "plugins": str(self.context.paths.plugins),
                "logs": str(self.context.paths.logs),
            }
            self.output.appendPlainText(json.dumps(payload, ensure_ascii=False, indent=2))
            return
        if name == "status":
            capture = self.context.capture.session
            payload = {
                "version": __version__,
                "developer_mode": bool(self.context.settings.developer_mode),
                "root_developer_workstation": self._root_workstation_active(),
                "performance_mode": self.context.performance.mode,
                "terminal_mode": str(self.mode.currentData()),
                "cwd": str(self.context.terminal.cwd),
                "timeout_seconds": self.context.terminal.timeout_seconds,
                "external_process_running": self.context.terminal.is_running,
                "resource_governance": self.context.runner.resource_snapshot(),
                "performance_intelligence": self.context.runner.performance_explanation(),
                "plugin_health": [asdict(item) for item in self.context.plugin_sandbox.health_snapshot()],
                "capture_session": (
                    None if capture is None else {"id": capture.id, "state": capture.state.value}
                ),
            }
            self.output.appendPlainText(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
            return
        if name == "tasks":
            limit = self._bounded_int(parts[1] if len(parts) > 1 else "100", 1, 500, "tasks")
            if limit is not None:
                self._background_json(
                    lambda: [task.to_dict() for task in self.context.store.list_tasks(True, limit=limit)]
                )
            return
        if name == "runs":
            limit = self._bounded_int(parts[1] if len(parts) > 1 else "100", 1, 1000, "runs")
            if limit is not None:
                self._background_json(lambda: self.context.store.list_runs(limit=limit))
            return
        if name == "captures":
            limit = self._bounded_int(parts[1] if len(parts) > 1 else "100", 1, 1000, "captures")
            if limit is not None:
                self._background_json(lambda: self.context.store.list_captures(limit=limit))
            return
        if name == "events":
            if len(parts) not in {2, 3}:
                self.output.appendPlainText("用法：events <session_id> [1-10000]")
                return
            limit = self._bounded_int(parts[2] if len(parts) == 3 else "1000", 1, 10000, "events")
            if limit is not None:
                session_id = parts[1]
                self._background_json(
                    lambda: list(self.context.store.iter_network_events(session_id, limit))
                )
            return
        if name == "sql":
            query = command[len(parts[0]):].strip()
            self._run_readonly_sql(query)
            return
        if name == "test-all":
            if len(parts) != 1:
                self.output.appendPlainText("用法：test-all")
                return
            self._run_full_validation()
            return
        if name == "stress-test":
            if len(parts) > 2:
                self.output.appendPlainText("用法：stress-test [quick|standard|extreme]")
                return
            profile = parts[1].casefold() if len(parts) == 2 else "standard"
            self._run_stress_validation(profile)
            return
        if name == "fault-injection":
            if len(parts) > 2:
                self.output.appendPlainText("用法：fault-injection [transient|recoverable|configuration|permission|corruption|fatal|all]")
                return
            scenario = parts[1].casefold() if len(parts) == 2 else "all"
            self._run_fault_injection(scenario)
            return

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
            self.output.appendPlainText("Official Developer Access 后端不可用。")
            return False
        try:
            manager.require(capability, action)
        except Exception as exc:
            code = getattr(exc, "code", type(exc).__name__)
            self.output.appendPlainText(
                f"命令已锁定：需要 Official Developer capability '{capability}'（{code}）。"
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
                self.output.appendPlainText("Official Developer Access 后端不可用。")
                return
            try:
                manager.require("stress_test", "stress-test/quick")
            except Exception as exc:
                code = getattr(exc, "code", type(exc).__name__)
                self.output.appendPlainText(
                    f"命令已锁定：stress-test quick 也需要 Official Developer capability 'stress_test'（{code}）。"
                    " Developer Profile 不能运行内部压力测试。"
                )
                return
        elif not self._official_developer_high_risk_gate(
            "stress_test", f"stress-test/{profile}", f"Official Developer · stress-test {profile}",
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
            "fault_injection", f"fault-injection/{scenario}", "Official Developer · Fault Injection",
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
        if not (self.context.settings.developer_mode or self._root_workstation_active()):
            self.output.appendPlainText("外部命令已禁用。请在设置 → 高级设置中启用 Developer Mode。")
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
        if mode in {TerminalMode.POWERSHELL, TerminalMode.CMD}:
            details.insert(3, "完整 Shell 模式会解释管道、重定向、变量展开和命令连接符。")
        if mode == TerminalMode.PYTHON:
            details.insert(3, "Python 代码将拥有当前用户权限，并可访问文件、网络和子进程。")
        if launch.risk_reason:
            details.insert(3, f"⚠ 风险提示：{launch.risk_reason}")
        box = QMessageBox(self)
        box.setWindowTitle("确认执行开发者命令")
        box.setIcon(
            QMessageBox.Icon.Warning
            if launch.risk_reason or mode in {TerminalMode.POWERSHELL, TerminalMode.CMD, TerminalMode.PYTHON}
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


class LogsPage(WorkspacePage):
    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        layout = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(PageHeader("日志与诊断", "结构化 JSONL、轮转、稳定错误码、统一秘密脱敏"), 1)
        refresh = QPushButton("刷新")
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
            self.output.setPlainText("尚无日志事件。")
            return
        self.output.setPlainText("正在后台读取最近日志…")

        def worker() -> tuple[str, int]:
                                                                                
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                lines = deque(stream, maxlen=self._log_tail_lines)
            return "".join(lines), len(lines)

        def completed(value: object) -> None:
            text, count = value if isinstance(value, tuple) and len(value) == 2 else ("", 0)
            self.output.setPlainText(str(text))
            self.output.moveCursor(self.output.textCursor().MoveOperation.End)
            self.inspectorChanged.emit("日志", {"path": str(path), "visible_lines": int(count)})

        run_background(
            worker,
            completed,
            lambda message: self.output.setPlainText(f"日志读取失败：{message}"),
        )
