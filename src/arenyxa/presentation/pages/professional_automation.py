from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from arenyxa.application.traffic_automation import (
    TrafficAutomationEngine,
    configure_default_traffic_handlers,
)
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.pages.tools import AutomationPage
from arenyxa.presentation.widgets import PageHeader
from arenyxa.qt_compat.QtWidgets import (
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)


class TrafficAutomationRulesPage(WorkspacePage):
    def __init__(self, context: Any, theme: Any, motion: Any, parent: QWidget | None = None) -> None:
        super().__init__(context, theme, motion, parent)
        engine = context.traffic_automation
        if engine is None:
            engine = TrafficAutomationEngine(Path(context.paths.captures) / "automation" / "traffic-rules.json")
            configure_default_traffic_handlers(engine, Path(context.paths.captures) / "automation")
            context.traffic_automation = engine
        self.engine = engine
        self._rule_ids: list[str] = []
        root = page_layout(self)
        root.addWidget(PageHeader(
            "Traffic Automation Rules",
            "HTTP request/response, TLS and WebSocket event actions: record, modify, export, alert and analyze",
        ))
        body = QHBoxLayout()
        self.rules = QListWidget()
        self.rules.setMinimumWidth(320)
        body.addWidget(self.rules, 1)
        editor = QWidget()
        editor_layout = QVBoxLayout(editor)
        form = QFormLayout()
        self.name = QLineEdit()
        self.name.setPlaceholderText("Rule name")
        self.event = QComboBox()
        self.event.addItems(["HTTP_REQUEST", "HTTP_RESPONSE", "TLS_ESTABLISHED", "WEBSOCKET_MESSAGE"])
        self.actions = QLineEdit("RECORD,ANALYZE")
        self.host = QLineEdit("*")
        self.url = QLineEdit("*")
        self.method = QLineEdit("*")
        self.status_pattern = QLineEdit("*")
        form.addRow("Name", self.name)
        form.addRow("Event", self.event)
        form.addRow("Actions", self.actions)
        form.addRow("Host", self.host)
        form.addRow("URL", self.url)
        form.addRow("Method", self.method)
        form.addRow("Status", self.status_pattern)
        editor_layout.addLayout(form)
        buttons = QHBoxLayout()
        add = QPushButton("Add Rule")
        add.setProperty("primary", True)
        remove = QPushButton("Remove Selected")
        refresh = QPushButton("Refresh")
        add.clicked.connect(self.add_rule)
        remove.clicked.connect(self.remove_rule)
        refresh.clicked.connect(self.refresh_rules)
        buttons.addWidget(add)
        buttons.addWidget(remove)
        buttons.addWidget(refresh)
        editor_layout.addLayout(buttons)
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        editor_layout.addWidget(self.preview, 1)
        body.addWidget(editor, 2)
        root.addLayout(body, 1)
        self.rules.currentRowChanged.connect(self.show_rule)
        self.refresh_rules()

    def activated(self) -> None:
        self.refresh_rules()

    def refresh_rules(self) -> None:
        rows = self.engine.list()
        self._rule_ids = [str(row["id"]) for row in rows]
        self.rules.clear()
        for row in rows:
            self.rules.addItem(
                f"{row['event']} · {','.join(row['actions'])} · {row['name']}"
            )
        if rows:
            self.rules.setCurrentRow(0)
        else:
            self.preview.setPlainText("No traffic automation rules.")

    def show_rule(self, row: int) -> None:
        rows = self.engine.list()
        if 0 <= row < len(rows):
            self.preview.setPlainText(json.dumps(rows[row], ensure_ascii=False, indent=2, default=str))

    def add_rule(self) -> None:
        try:
            self.engine.add(
                self.name.text().strip(),
                self.event.currentText(),
                [item.strip() for item in self.actions.text().split(",") if item.strip()],
                host_pattern=self.host.text() or "*",
                url_pattern=self.url.text() or "*",
                method_pattern=self.method.text() or "*",
                status_pattern=self.status_pattern.text() or "*",
            )
        except ValueError as exc:
            QMessageBox.warning(self, "Traffic Automation", str(exc))
            return
        self.name.clear()
        self.refresh_rules()

    def remove_rule(self) -> None:
        row = self.rules.currentRow()
        if not 0 <= row < len(self._rule_ids):
            return
        self.engine.remove(self._rule_ids[row])
        self.refresh_rules()


class AutomationEnginePage(WorkspacePage):
    """Preserve schedule automation and add the traffic event engine."""

    def __init__(self, context: Any, theme: Any, motion: Any, parent: QWidget | None = None) -> None:
        super().__init__(context, theme, motion, parent)
        root = page_layout(self)
        self.tabs = QTabWidget()
        self.schedule_page = AutomationPage(context, theme, motion, self)
        self.traffic_page = TrafficAutomationRulesPage(context, theme, motion, self)
        self.tabs.addTab(self.schedule_page, "Schedules")
        self.tabs.addTab(self.traffic_page, "Traffic Rules")
        root.addWidget(self.tabs, 1)

    def activated(self) -> None:
        page = self.tabs.currentWidget()
        if hasattr(page, "activated"):
            page.activated()

    def deactivated(self) -> None:
        for page in (self.schedule_page, self.traffic_page):
            if hasattr(page, "deactivated"):
                page.deactivated()


__all__ = ["AutomationEnginePage", "TrafficAutomationRulesPage"]
