from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from arenyxa.application.api_security_lab import ApiSecurityLab
from arenyxa.application.traffic_intelligence import TrafficIntelligenceAnalyzer
from arenyxa.presentation.background import run_background
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader
from arenyxa.qt_compat.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QWidget,
)


class _ProxyAnalysisPage(WorkspacePage):
    title = "Professional Analysis"
    subtitle = "Bounded analysis of durable Proxy Suite history"

    def __init__(self, context: Any, theme: Any, motion: Any, parent: QWidget | None = None) -> None:
        super().__init__(context, theme, motion, parent)
        self._token = 0
        root = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(PageHeader(self.title, self.subtitle), 1)
        self.limit = QSpinBox()
        self.limit.setRange(100, 100_000)
        self.limit.setSingleStep(1_000)
        self.limit.setValue(10_000)
        self.analyze_button = QPushButton("Analyze Traffic")
        self.analyze_button.setProperty("primary", True)
        header.addWidget(self.limit)
        header.addWidget(self.analyze_button)
        root.addLayout(header)
        self.tabs = QTabWidget()
        self.summary = self._viewer()
        self.details = self._viewer()
        self.findings = self._viewer()
        self.tabs.addTab(self.summary, "Summary")
        self.tabs.addTab(self.details, "Details")
        self.tabs.addTab(self.findings, "Findings")
        root.addWidget(self.tabs, 1)
        self.status = QLabel("READY")
        self.status.setProperty("muted", True)
        root.addWidget(self.status)
        self.analyze_button.clicked.connect(self.analyze)

    @staticmethod
    def _viewer() -> QPlainTextEdit:
        viewer = QPlainTextEdit()
        viewer.setReadOnly(True)
        viewer.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        return viewer

    def _flows(self, limit: int) -> list[Any]:
        engine = self.context.proxy_engine
        if engine is None:
            return []
        rows: list[Any] = []
        page = 1
        while len(rows) < limit:
            result = engine.history_page(page=page, page_size=min(1000, limit - len(rows)))
            batch = list(result.get("items", []))
            rows.extend(batch)
            if not batch or not result.get("has_next"):
                break
            page += 1
        return rows

    def activated(self) -> None:
        engine = self.context.proxy_engine
        health = engine.history_health() if engine is not None else {"ok": False, "flows": 0}
        self.status.setText(
            f"READY · {int(health.get('flows') or 0):,} durable flows · WAL {str(health.get('journal_mode') or 'n/a').upper()}"
        )

    def deactivated(self) -> None:
        self._token += 1

    def analyze(self) -> None:
        self.status.setText("UNAVAILABLE")
        QMessageBox.warning(
            self,
            self.title,
            "This analysis page has no registered analysis operation.",
        )

    def _run(self, work: Any, completed: Any) -> None:
        self._token += 1
        token = self._token
        self.analyze_button.setEnabled(False)
        self.status.setText("ANALYZING…")

        def done(value: object) -> None:
            if token != self._token:
                return
            self.analyze_button.setEnabled(True)
            completed(value)

        def failed(message: str) -> None:
            if token != self._token:
                return
            self.analyze_button.setEnabled(True)
            self.status.setText("FAILED")
            QMessageBox.warning(self, self.title, message)

        run_background(work, done, failed)


class ApiSecurityLabPage(_ProxyAnalysisPage):
    title = "API Security Lab"
    subtitle = "REST, GraphQL, OpenAPI and Swagger endpoint discovery, authentication and token-lifecycle analysis"

    def __init__(self, context: Any, theme: Any, motion: Any, parent: QWidget | None = None) -> None:
        super().__init__(context, theme, motion, parent)
        self.import_button = QPushButton("Import OpenAPI / Swagger")
        self.layout().itemAt(0).layout().insertWidget(2, self.import_button)
        self.import_button.clicked.connect(self.import_openapi)

    def analyze(self) -> None:
        limit = self.limit.value()

        def work() -> dict[str, Any]:
            return ApiSecurityLab().analyze(self._flows(limit)).snapshot()

        def completed(value: object) -> None:
            if not isinstance(value, dict):
                return
            summary = {key: value.get(key) for key in (
                "flow_count", "endpoint_count", "rest_endpoint_count", "graphql_endpoint_count",
                "authenticated_endpoint_count", "token_lifecycle",
            )}
            self.summary.setPlainText(json.dumps(summary, ensure_ascii=False, indent=2, default=str))
            self.details.setPlainText(json.dumps(value.get("endpoints", []), ensure_ascii=False, indent=2, default=str))
            self.findings.setPlainText(json.dumps(value.get("findings", []), ensure_ascii=False, indent=2, default=str))
            self.status.setText(
                f"COMPLETE · {int(value.get('endpoint_count') or 0):,} endpoints · {len(value.get('findings', [])):,} findings"
            )

        self._run(work, completed)

    def import_openapi(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Import OpenAPI / Swagger",
            "",
            "API Documents (*.json);;All Files (*)",
        )
        if not path:
            return
        source = Path(path)
        try:
            if source.stat().st_size > 16 * 1024 * 1024:
                raise ValueError("OpenAPI document exceeds the 16 MiB safety limit")
            rows = ApiSecurityLab().import_openapi_json(source.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            QMessageBox.warning(self, "API Security Lab", str(exc))
            return
        self.details.setPlainText(json.dumps([asdict(item) for item in rows], ensure_ascii=False, indent=2))
        self.summary.setPlainText(json.dumps({"source": str(source), "endpoint_count": len(rows)}, ensure_ascii=False, indent=2))
        self.status.setText(f"OPENAPI IMPORTED · {len(rows):,} endpoints")


class AiTrafficIntelligencePage(_ProxyAnalysisPage):
    title = "AI Traffic Intelligence"
    subtitle = "Local deterministic recognition of API calls, authentication, uploads, anomalies and token-leak risk"

    def analyze(self) -> None:
        limit = self.limit.value()

        def work() -> dict[str, Any]:
            return TrafficIntelligenceAnalyzer().analyze(self._flows(limit)).snapshot()

        def completed(value: object) -> None:
            if not isinstance(value, dict):
                return
            summary = {key: value.get(key) for key in (
                "flow_count", "api_count", "authentication_flow_count", "upload_count",
                "anomaly_count", "token_leak_count",
            )}
            self.summary.setPlainText(json.dumps(summary, ensure_ascii=False, indent=2, default=str))
            self.details.setPlainText(json.dumps(value.get("hosts", []), ensure_ascii=False, indent=2, default=str))
            self.findings.setPlainText(json.dumps(value.get("findings", []), ensure_ascii=False, indent=2, default=str))
            self.status.setText(
                f"COMPLETE · {int(value.get('api_count') or 0):,} APIs · "
                f"{int(value.get('authentication_flow_count') or 0):,} authentication flows · "
                f"{int(value.get('anomaly_count') or 0):,} anomalies"
            )

        self._run(work, completed)


__all__ = ["AiTrafficIntelligencePage", "ApiSecurityLabPage"]
