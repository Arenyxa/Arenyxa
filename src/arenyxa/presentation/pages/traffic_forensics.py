from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from arenyxa.application.traffic_forensics import TrafficForensicsAnalyzer
from arenyxa.infrastructure.atomic_io import atomic_write_json
from arenyxa.presentation.background import run_background
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader
from arenyxa.qt_compat.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
)


class TrafficForensicsPage(WorkspacePage):
    def __init__(self, context: Any, theme: Any, motion: Any, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        self.analyzer = TrafficForensicsAnalyzer()
        self._analysis_token = 0
        self._snapshot: dict[str, Any] | None = None

        root = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(
            PageHeader(
                "Traffic Forensics",
                "Passive capture forensics, host/error/latency triage, evidence timeline and bounded export",
            ),
            1,
        )
        self.session = QComboBox()
        self.session.setMinimumWidth(300)
        self.refresh_button = QPushButton("Refresh Sessions")
        self.analyze_button = QPushButton("Analyze Capture")
        self.analyze_button.setProperty("primary", True)
        self.export_button = QPushButton("Export Snapshot")
        self.export_button.setEnabled(False)
        header.addWidget(self.session)
        header.addWidget(self.refresh_button)
        header.addWidget(self.analyze_button)
        header.addWidget(self.export_button)
        root.addLayout(header)

        note = QLabel(
            "Forensics is read-only: it analyzes evidence already stored by Arenyxa. Sensitive header values and body content are not copied into the forensic snapshot."
        )
        note.setWordWrap(True)
        note.setProperty("muted", True)
        root.addWidget(note)

        self.tabs = QTabWidget(self)
        self.summary = self._viewer("Select a capture session, then run analysis.")
        self.findings = self._viewer("No findings yet.")
        self.timeline = self._viewer("No evidence timeline yet.")
        self.tabs.addTab(self.summary, "Summary")
        self.tabs.addTab(self.findings, "Findings")
        self.tabs.addTab(self.timeline, "Evidence Timeline")
        root.addWidget(self.tabs, 1)

        self.status = QLabel("IDLE")
        self.status.setProperty("muted", True)
        root.addWidget(self.status)

        self.refresh_button.clicked.connect(self.refresh_sessions)
        self.analyze_button.clicked.connect(self.analyze_capture)
        self.export_button.clicked.connect(self.export_snapshot)

    @staticmethod
    def _viewer(placeholder: str) -> QPlainTextEdit:
        viewer = QPlainTextEdit()
        viewer.setReadOnly(True)
        viewer.setPlaceholderText(placeholder)
        viewer.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        return viewer

    def activated(self) -> None:
        self.refresh_sessions()

    def deactivated(self) -> None:
        self._analysis_token += 1

    def refresh_sessions(self) -> None:
        current = self.session.currentData()
        captures = self.context.store.list_captures(limit=500)
        self.session.blockSignals(True)
        self.session.clear()
        for capture in captures:
            label = (
                f"{capture.get('name') or capture.get('id')} · "
                f"{capture.get('source_type', '')} · {int(capture.get('event_count') or 0):,} events"
            )
            self.session.addItem(label, str(capture.get("id") or ""))
            if current and str(capture.get("id") or "") == str(current):
                self.session.setCurrentIndex(self.session.count() - 1)
        self.session.blockSignals(False)
        self.analyze_button.setEnabled(self.session.count() > 0)
        self.status.setText(f"READY · {self.session.count():,} capture sessions")

    def analyze_capture(self) -> None:
        session_id = str(self.session.currentData() or "")
        if not session_id:
            QMessageBox.information(self, "Traffic Forensics", "Select a capture session first.")
            return
        self._analysis_token += 1
        token = self._analysis_token
        self.analyze_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.status.setText("ANALYZING · loading captured evidence…")
        history_limit = max(1, int(self.context.performance.network_history_limit))

        def work() -> dict[str, Any]:
            rows = list(self.context.store.iter_network_events(session_id, limit=history_limit))
            snapshot = self.analyzer.analyze(rows, timeline_limit=min(2_000, history_limit)).as_dict()
            snapshot["session_id"] = session_id
            snapshot["analysis_limit"] = history_limit
            snapshot["truncated_by_limit"] = len(rows) >= history_limit
            return snapshot

        def completed(value: object) -> None:
            if token != self._analysis_token or not isinstance(value, dict):
                return
            self._snapshot = dict(value)
            summary = {key: value.get(key) for key in (
                "session_id", "event_count", "bytes_total", "host_count", "flow_count",
                "first_timestamp", "last_timestamp", "protocols", "status_families",
                "severity_counts", "duration_ms", "dns_queries", "dns_rcodes", "tls_servers", "tls_versions",
                "tcp_analysis", "top_hosts", "analysis_limit", "truncated_by_limit",
            )}
            self.summary.setPlainText(json.dumps(summary, ensure_ascii=False, indent=2, default=str))
            self.findings.setPlainText(json.dumps(value.get("findings", []), ensure_ascii=False, indent=2, default=str))
            self.timeline.setPlainText(json.dumps(value.get("timeline", []), ensure_ascii=False, indent=2, default=str))
            self.analyze_button.setEnabled(True)
            self.export_button.setEnabled(True)
            self.status.setText(
                f"COMPLETE · {int(value.get('event_count') or 0):,} events · "
                f"{len(value.get('findings', [])):,} findings"
            )
            self.statusMessage.emit("Traffic Forensics analysis complete")
            self.inspectorChanged.emit("Traffic Forensics", summary)

        def failed(message: str) -> None:
            if token != self._analysis_token:
                return
            self.analyze_button.setEnabled(True)
            self.status.setText("FAILED")
            QMessageBox.warning(self, "Traffic Forensics", message)

        run_background(work, completed, failed)

    def export_snapshot(self) -> None:
        if not self._snapshot:
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Traffic Forensics Snapshot",
            "arenyxa-traffic-forensics.json",
            "JSON (*.json);;All Files (*)",
        )
        if not path:
            return
        destination = Path(path)
        try:
            atomic_write_json(destination, self._snapshot, ensure_ascii=False, indent=2)
        except OSError as exc:
            QMessageBox.warning(self, "Traffic Forensics", f"Export failed: {exc}")
            return
        self.statusMessage.emit(f"Traffic Forensics exported · {destination.name}")
