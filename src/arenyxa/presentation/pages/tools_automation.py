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
from arenyxa.presentation.flow_graph import FlowGraphCanvas
from arenyxa.presentation.pages.tools_terminal_workspace import ConsoleCommandMixin, TerminalWorkspaceMixin
from arenyxa.presentation.pages.tools_terminal_execution import ConsoleExternalProcessMixin, ConsoleValidationMixin
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import MiniBars, PageHeader, set_table_header_stretch_last, ScrollSafeComboBox


LOGGER = logging.getLogger(__name__)


class AutomationPage(WorkspacePage):
    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        layout = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(PageHeader("Automation Center", "Timezone-aware schedules, resumable enablement and traceable failure policy"), 1)
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
                "Flow Designer",
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
        self.flow_tabs = QTabWidget()
        direct_tab = QWidget()
        direct_layout = QVBoxLayout(direct_tab)
        direct_layout.setContentsMargins(0, 0, 0, 0)
        self.inputs = QPlainTextEdit('[{"title":"Arenyxa","status":200},{"title":"","status":404}]')
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        direct_layout.addWidget(QLabel("输入 JSON 数组"))
        direct_layout.addWidget(self.inputs)
        direct_layout.addWidget(QLabel("执行结果"))
        direct_layout.addWidget(self.output)
        self.flow_tabs.addTab(direct_tab, "Direct Test")

        graph_tab = QWidget()
        graph_layout = QVBoxLayout(graph_tab)
        graph_layout.setContentsMargins(0, 0, 0, 0)
        graph_controls = QHBoxLayout()
        self.graph_sync_button = QPushButton("Sync Raw → Graph")
        self.graph_add_button = QPushButton("Add Node")
        self.graph_remove_button = QPushButton("Remove Node")
        self.graph_connect_button = QPushButton("Connect")
        self.graph_disconnect_button = QPushButton("Disconnect")
        self.graph_auto_layout_button = QPushButton("Auto Layout")
        for button in (
            self.graph_sync_button, self.graph_add_button, self.graph_remove_button,
            self.graph_connect_button, self.graph_disconnect_button, self.graph_auto_layout_button,
        ):
            graph_controls.addWidget(button)
        graph_controls.addStretch(1)
        graph_layout.addLayout(graph_controls)
        graph_split = QSplitter(Qt.Orientation.Vertical)
        graph_scroll = QScrollArea()
        graph_scroll.setWidgetResizable(True)
        self.graph_canvas = FlowGraphCanvas()
        graph_scroll.setWidget(self.graph_canvas)
        self.graph_node_detail = QPlainTextEdit()
        self.graph_node_detail.setReadOnly(True)
        self.graph_node_detail.setPlaceholderText("Select a node to inspect its Arenyxa graph definition.")
        graph_split.addWidget(graph_scroll)
        graph_split.addWidget(self.graph_node_detail)
        graph_split.setSizes([520, 180])
        graph_layout.addWidget(graph_split, 1)
        self.flow_tabs.addTab(graph_tab, "Visual Graph")

        inspector_tab = QWidget()
        inspector_layout = QVBoxLayout(inspector_tab)
        inspector_layout.setContentsMargins(0, 0, 0, 0)
        inspect_row = QHBoxLayout()
        self.execution_id = QLineEdit()
        self.execution_id.setPlaceholderText("Persisted workflow execution ID")
        self.inspect_execution_button = QPushButton("Inspect Execution")
        self.inspect_execution_button.setProperty("primary", True)
        self.trace_execution_button = QPushButton("Runtime Trace")
        self.step_plan_button = QPushButton("Step Plan")
        inspect_row.addWidget(self.execution_id, 1)
        inspect_row.addWidget(self.inspect_execution_button)
        inspect_row.addWidget(self.trace_execution_button)
        inspect_row.addWidget(self.step_plan_button)
        debug_row = QHBoxLayout()
        self.debug_breakpoints = QLineEdit()
        self.debug_breakpoints.setPlaceholderText("Safe debugger breakpoints, comma-separated node IDs")
        self.safe_debug_button = QPushButton("Safe Debug")
        self.safe_debug_button.setProperty("primary", True)
        debug_row.addWidget(self.debug_breakpoints, 1)
        debug_row.addWidget(self.safe_debug_button)
        self.execution_inspector_output = QPlainTextEdit()
        self.execution_inspector_output.setReadOnly(True)
        self.execution_inspector_output.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        inspector_layout.addLayout(inspect_row)
        inspector_layout.addLayout(debug_row)
        self.execution_trace_table = QTableWidget(0, 9)
        self.execution_trace_table.setHorizontalHeaderLabels(["Node", "Kind", "State", "Lane", "Input", "Output", "Errors", "Pressure", "Health"])
        self.execution_trace_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.execution_trace_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        set_table_header_stretch_last(self.execution_trace_table, True)
        trace_split = QSplitter(Qt.Orientation.Vertical)
        trace_split.addWidget(self.execution_trace_table)
        trace_split.addWidget(self.execution_inspector_output)
        trace_split.setSizes([360, 300])
        inspector_layout.addWidget(trace_split, 1)
        self.flow_tabs.addTab(inspector_tab, "Execution Inspector")
        right_layout.addWidget(self.flow_tabs, 1)
        splitter.addWidget(self.definition)
        splitter.addWidget(right)
        layout.addWidget(splitter, 1)
        save.clicked.connect(self.save_workflow)
        run.clicked.connect(self.run_workflow)
        self.inspect_execution_button.clicked.connect(self.inspect_execution)
        self.trace_execution_button.clicked.connect(self.trace_execution)
        self.step_plan_button.clicked.connect(self.step_plan)
        self.safe_debug_button.clicked.connect(self.safe_debug)
        self.graph_sync_button.clicked.connect(self.sync_graph_from_raw)
        self.graph_add_button.clicked.connect(self.graph_add_node)
        self.graph_remove_button.clicked.connect(self.graph_remove_node)
        self.graph_connect_button.clicked.connect(self.graph_connect_nodes)
        self.graph_disconnect_button.clicked.connect(self.graph_disconnect_nodes)
        self.graph_auto_layout_button.clicked.connect(self.sync_graph_from_raw)
        self.graph_canvas.nodeSelected.connect(self.graph_node_selected)
        self._graph_model: WorkflowGraphModel | None = None
        self._graph_syncing = False
        self._graph_refresh_timer = QTimer(self)
        self._graph_refresh_timer.setSingleShot(True)
        self._graph_refresh_timer.setInterval(180)
        self._graph_refresh_timer.timeout.connect(self.sync_graph_from_raw)
        self.definition.textChanged.connect(self._schedule_graph_sync)
        self.sync_graph_from_raw()

    def _schedule_graph_sync(self) -> None:
        if not self._graph_syncing:
            self._graph_refresh_timer.start()

    def sync_graph_from_raw(self) -> None:
        if self._graph_syncing:
            return
        try:
            raw = json.loads(self.definition.toPlainText())
            self._graph_model = WorkflowGraphModel(raw)
            self.graph_canvas.set_graph(self._graph_model.layout())
            selected = self.graph_canvas.selected_node()
            if selected:
                self.graph_node_selected(selected)
            else:
                self.graph_node_detail.setPlainText(
                    json.dumps({"nodes": len(raw.get("nodes") or []), "status": "graph synchronized"}, ensure_ascii=False, indent=2)
                )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            self._graph_model = None
            self.graph_node_detail.setPlainText(f"Raw Workflow JSON is not graph-ready yet: {exc}")

    def _commit_graph_to_raw(self) -> None:
        if self._graph_model is None:
            raise RuntimeError("Visual Graph is not synchronized with a valid workflow")
        payload = self._graph_model.snapshot()
        self._graph_syncing = True
        try:
            self.definition.setPlainText(json.dumps(payload, ensure_ascii=False, indent=2))
        finally:
            self._graph_syncing = False
        self.graph_canvas.set_graph(self._graph_model.layout())

    def graph_node_selected(self, node_id: str) -> None:
        if self._graph_model is None:
            return
        row = next((item for item in self._graph_model.snapshot()["nodes"] if item["id"] == node_id), None)
        if row is not None:
            self.graph_node_detail.setPlainText(json.dumps(row, ensure_ascii=False, indent=2, default=str))

    def graph_add_node(self) -> None:
        if self._graph_model is None:
            self.sync_graph_from_raw()
        if self._graph_model is None:
            QMessageBox.warning(self, "Visual Graph", "Fix the Raw Workflow JSON before editing the graph.")
            return
        node_id, ok = QInputDialog.getText(self, "Add Node", "Node ID:")
        if not ok or not node_id.strip():
            return
        kind, ok = QInputDialog.getText(self, "Add Node", "Node kind:", text="map")
        if not ok or not kind.strip():
            return
        try:
            self._graph_model.add_node(node_id, kind)
            self._commit_graph_to_raw()
            self.graph_canvas.select_node(node_id.strip())
            self.graph_node_selected(node_id.strip())
        except (KeyError, RuntimeError, TypeError, ValueError) as exc:
            QMessageBox.warning(self, "Visual Graph", str(exc))

    def graph_remove_node(self) -> None:
        if self._graph_model is None:
            return
        node_id = self.graph_canvas.selected_node()
        if not node_id:
            QMessageBox.information(self, "Visual Graph", "Select a node first.")
            return
        try:
            self._graph_model.remove_node(node_id)
            self.graph_canvas.select_node("")
            self._commit_graph_to_raw()
            self.graph_node_detail.clear()
        except (KeyError, RuntimeError, TypeError, ValueError) as exc:
            QMessageBox.warning(self, "Visual Graph", str(exc))

    def _graph_edge_dialog(self, title: str) -> tuple[str, str, str] | None:
        if self._graph_model is None:
            return None
        node_ids = [str(row["id"]) for row in self._graph_model.snapshot()["nodes"]]
        if len(node_ids) < 2:
            QMessageBox.information(self, "Visual Graph", "At least two nodes are required.")
            return None
        source, ok = QInputDialog.getItem(self, title, "Source node:", node_ids, 0, False)
        if not ok:
            return None
        target_choices = [item for item in node_ids if item != source]
        target, ok = QInputDialog.getItem(self, title, "Target node:", target_choices, 0, False)
        if not ok:
            return None
        edge_type, ok = QInputDialog.getItem(self, title, "Edge type:", ["normal", "failure"], 0, False)
        if not ok:
            return None
        return str(source), str(target), str(edge_type)

    def graph_connect_nodes(self) -> None:
        edge = self._graph_edge_dialog("Connect Nodes")
        if edge is None or self._graph_model is None:
            return
        try:
            self._graph_model.connect(edge[0], edge[1], edge_type=edge[2])
            self._commit_graph_to_raw()
        except (KeyError, RuntimeError, TypeError, ValueError) as exc:
            QMessageBox.warning(self, "Visual Graph", str(exc))

    def graph_disconnect_nodes(self) -> None:
        edge = self._graph_edge_dialog("Disconnect Nodes")
        if edge is None or self._graph_model is None:
            return
        try:
            self._graph_model.disconnect(edge[0], edge[1], edge_type=edge[2])
            self._commit_graph_to_raw()
        except (KeyError, RuntimeError, TypeError, ValueError) as exc:
            QMessageBox.warning(self, "Visual Graph", str(exc))

    def inspect_execution(self) -> None:
        execution_id = self.execution_id.text().strip()
        if not execution_id:
            QMessageBox.information(self, "Flow Designer", "Enter a persisted workflow execution ID first.")
            return
        try:
            result = WorkflowExecutionInspector(self.context.store).inspect(execution_id)
            self.execution_inspector_output.setPlainText(
                json.dumps(result.snapshot(), ensure_ascii=False, indent=2, default=str)
            )
            self.statusMessage.emit(f"Flow execution inspected: {execution_id}")
        except (KeyError, RuntimeError, TypeError, ValueError) as exc:
            QMessageBox.warning(self, "Execution Inspector", str(exc))

    def trace_execution(self) -> None:
        execution_id = self.execution_id.text().strip()
        if not execution_id:
            QMessageBox.information(self, "Flow Designer", "Enter a persisted workflow execution ID first.")
            return
        try:
            payload = WorkflowRuntimeTrace(self.context.store).trace(execution_id)
            self.execution_inspector_output.setPlainText(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
            nodes = list(payload.get("nodes") or [])
            self.execution_trace_table.setRowCount(len(nodes))
            for row_index, node in enumerate(nodes):
                values = [
                    node.get("node_id", ""), node.get("kind", ""), node.get("state", ""), node.get("lane", 0),
                    node.get("input_count", 0), node.get("output_count", 0), node.get("error_count", 0),
                    node.get("pressure", 0.0), node.get("health", ""),
                ]
                for column, value in enumerate(values):
                    self.execution_trace_table.setItem(row_index, column, QTableWidgetItem(str(value)))
            self.statusMessage.emit(f"Flow runtime trace loaded: {execution_id}")
        except (KeyError, RuntimeError, TypeError, ValueError) as exc:
            QMessageBox.warning(self, "Runtime Trace", str(exc))

    def step_plan(self) -> None:
        execution_id = self.execution_id.text().strip()
        if not execution_id:
            QMessageBox.information(self, "Flow Designer", "Enter a persisted workflow execution ID first.")
            return
        try:
            payload = WorkflowRuntimeTrace(self.context.store).step_plan(execution_id)
            self.execution_inspector_output.setPlainText(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        except (KeyError, RuntimeError, TypeError, ValueError) as exc:
            QMessageBox.warning(self, "Step Plan", str(exc))


    def safe_debug(self) -> None:
        try:
            workflow = self._workflow()
            raw_inputs = json.loads(self.inputs.toPlainText())
            if not isinstance(raw_inputs, list) or any(not isinstance(item, dict) for item in raw_inputs):
                raise ValueError("Direct Test input must be a JSON array of objects")
            breakpoints = [
                value.strip() for value in self.debug_breakpoints.text().split(",") if value.strip()
            ]
            report = WorkflowSafeDebugger(self.context.workflows).simulate(
                workflow, raw_inputs, breakpoints=breakpoints, max_steps=5000
            ).snapshot()
            self.execution_inspector_output.setPlainText(
                json.dumps(report, ensure_ascii=False, indent=2, default=str)
            )
            self.statusMessage.emit(
                f"Safe Debug {report['state']}: {report['steps_executed']} steps"
            )
        except (ArenyxaError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            QMessageBox.warning(self, "Safe Debug", str(exc))

    def _workflow(self) -> Workflow:
        raw = json.loads(self.definition.toPlainText())
        nodes = [WorkflowNode(**node) for node in raw["nodes"]]
        return Workflow(name=raw["name"], nodes=nodes, id=raw.get("id", new_id("workflow")))

    def save_workflow(self) -> None:
        try:
            workflow = self._workflow()
            self.context.workflows.validate_executable(workflow)
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
