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
from arenyxa.presentation.i18n_runtime import current_text, source_text
from arenyxa.presentation.flow_graph import FlowGraphCanvas
from arenyxa.presentation.pages.tools_terminal_workspace import ConsoleCommandMixin, TerminalWorkspaceMixin
from arenyxa.presentation.pages.tools_terminal_execution import ConsoleExternalProcessMixin, ConsoleValidationMixin
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import MiniBars, PageHeader, set_table_header_stretch_last, ScrollSafeComboBox


LOGGER = logging.getLogger(__name__)


class AdvancedPlatformPage(WorkspacePage):
    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        layout = page_layout(self)
        layout.addWidget(
            PageHeader(source_text("tools_platform.page.title"), source_text("tools_platform.page.subtitle"), title_key="tools_platform.page.title", subtitle_key="tools_platform.page.subtitle")
        )
        controls = QHBoxLayout()
        self.session = QComboBox()
        self.session.setMinimumWidth(300)
        self.url = QLineEdit("https://example.com")
        self.url.setPlaceholderText(source_text("tools_platform.url_placeholder")); self.url.setProperty("i18n_key_placeholder", "tools_platform.url_placeholder")
        self.analyze_button = QPushButton(source_text("tools_platform.action.analyze")); self.analyze_button.setProperty("i18n_key_text", "tools_platform.action.analyze")
        self.analyze_button.setProperty("primary", True)
        capture_label = QLabel(source_text("tools_platform.capture")); capture_label.setProperty("i18n_key_text", "tools_platform.capture"); controls.addWidget(capture_label)
        controls.addWidget(self.session)
        controls.addWidget(self.url, 1)
        controls.addWidget(self.analyze_button)
        layout.addLayout(controls)
        self.tabs = QTabWidget()
        self.tab_indices: dict[str, int] = {}
        self.outputs: dict[str, QPlainTextEdit] = {}
        for key, label_key in (
            ("planner", "tools_platform.tab.planner"),
            ("map", "tools_platform.tab.website"),
            ("api", "tools_platform.tab.api_map"),
            ("performance", "tools_platform.tab.performance"),
            ("security", "tools_platform.tab.security"),
            ("compatibility", "tools_platform.tab.compatibility"),
        ):
            editor = QPlainTextEdit()
            editor.setReadOnly(True)
            self.outputs[key] = editor
            index = self.tabs.addTab(editor, source_text(label_key))
            self.tabs.setProperty(f"i18n_tab_key_{index}", label_key)
            self.tab_indices[key] = index
        database_tab = QWidget()
        database_layout = QVBoxLayout(database_tab)
        database_form = QHBoxLayout()
        self.database_dsn = QLineEdit(str(context.paths.root / "external-data.db"))
        self.database_dsn.setPlaceholderText(source_text("tools_platform.database.placeholder")); self.database_dsn.setProperty("i18n_key_placeholder", "tools_platform.database.placeholder")
        self.database_test_button = QPushButton(source_text("tools_platform.database.test")); self.database_test_button.setProperty("i18n_key_text", "tools_platform.database.test")
        database_form.addWidget(self.database_dsn, 1)
        database_form.addWidget(self.database_test_button)
        self.database_output = QPlainTextEdit()
        self.database_output.setReadOnly(True)
        database_layout.addLayout(database_form)
        database_layout.addWidget(self.database_output, 1)
        self.tab_indices["database"] = self.tabs.addTab(database_tab, source_text("tools_platform.tab.database")); self.tabs.setProperty(f"i18n_tab_key_{self.tab_indices['database']}", "tools_platform.tab.database")
        visualization = QWidget()
        visual_layout = QVBoxLayout(visualization)
        self.bars = MiniBars(theme)
        traffic_label = QLabel(source_text("tools_platform.traffic_by_domain")); traffic_label.setProperty("i18n_key_text", "tools_platform.traffic_by_domain"); visual_layout.addWidget(traffic_label)
        visual_layout.addWidget(self.bars, 1)
        self.tab_indices["visualization"] = self.tabs.addTab(visualization, source_text("tools_platform.tab.visualization")); self.tabs.setProperty(f"i18n_tab_key_{self.tab_indices['visualization']}", "tools_platform.tab.visualization")
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
        self.statusMessage.emit(current_text("tools_platform.status.analyzing"))
        api_warning = current_text("tools_platform.api_map.no_capture_warning")

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
                    "warnings": [api_warning],
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
            self.statusMessage.emit(current_text("tools_platform.status.completed"))

        def failed(message: str) -> None:
            self.analyze_button.setEnabled(True)
            QMessageBox.warning(self, current_text("tools_platform.error.analysis_failed"), message)

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
        layout.addWidget(PageHeader(source_text("tools_plugins.page.title"), source_text("tools_plugins.page.subtitle"), title_key="tools_plugins.page.title", subtitle_key="tools_plugins.page.subtitle"))
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
            current_text("tools_plugins.inspector"), {"count": len(self._plugins), "root": str(self.context.paths.plugins)}
        )

    def show_plugin(self, row: int) -> None:
        if 0 <= row < len(self._plugins):
            manifest, path = self._plugins[row]
            self.detail.setPlainText(
                json.dumps(
                    {
                        "manifest": asdict(manifest),
                        "path": str(path),
                        "default": current_text("tools_plugins.default_disabled"),
                        "health": None if self._plugin_health.get(manifest.id) is None else asdict(self._plugin_health[manifest.id]),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
