from __future__ import annotations

import json
from typing import Any

from arenyxa.domain.errors import ArenyxaError
from arenyxa.enterprise.fleet_telemetry import FleetTelemetryAnalyzer
from arenyxa.enterprise.fleet_live import FleetLiveTelemetry
from arenyxa.qt_compat.QtCore import QTimer
from arenyxa.qt_compat.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader


class ServerOperationsPage(WorkspacePage):
    def __init__(self, context: Any, theme: Any, motion: Any, parent: QWidget | None = None) -> None:
        super().__init__(context, theme, motion, parent)
        root = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(PageHeader("Fleet Control", "Enterprise runtime health, distributed workers, jobs and storage topology"), 1)
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.setProperty("primary", True)
        self.export_button = QPushButton("Export Snapshot")
        header.addWidget(self.export_button)
        header.addWidget(self.refresh_button)
        root.addLayout(header)

        self.live_telemetry = FleetLiveTelemetry()
        self.summary = QLabel("Enterprise Server runtime status is not loaded yet.")
        self.telemetry = QLabel("Telemetry has not been sampled yet.")
        self.telemetry.setWordWrap(True)
        self.telemetry.setProperty("muted", True)
        self.summary.setProperty("muted", True)
        self.summary.setWordWrap(True)
        root.addWidget(self.summary)
        root.addWidget(self.telemetry)

        splitter = QSplitter()
        self.health_view = self._read_only_view()
        self.workers_view = self._read_only_view()
        self.jobs_view = self._read_only_view()
        splitter.addWidget(self._panel("Runtime / Storage Health", self.health_view))
        splitter.addWidget(self._panel("Workers", self.workers_view))
        splitter.addWidget(self._panel("Distributed Jobs", self.jobs_view))
        splitter.setSizes([420, 360, 520])
        self.live_view = self._read_only_view()
        self.live_tabs = QTabWidget()
        live_holder = QWidget()
        live_layout = QVBoxLayout(live_holder)
        live_layout.setContentsMargins(0, 0, 0, 0)
        live_layout.addWidget(self.live_view)
        self.live_tabs.addTab(live_holder, "Live Telemetry & Events")
        root.addWidget(splitter, 3)
        root.addWidget(self.live_tabs, 1)

        note = QLabel(
            "SQLite is a durable single-host backend. For high-concurrency or multi-host server deployments, "
            "configure the PostgreSQL distributed runtime backend. Server-side worker max_slots remains authoritative."
        )
        note.setWordWrap(True)
        note.setProperty("muted", True)
        root.addWidget(note)

        self.refresh_button.clicked.connect(self.refresh_runtime)
        self.export_button.clicked.connect(self.export_snapshot)
        self.timer = QTimer(self)
        self.timer.setInterval(1500)
        self.timer.timeout.connect(self.refresh_runtime)

    @staticmethod
    def _read_only_view() -> QPlainTextEdit:
        view = QPlainTextEdit()
        view.setReadOnly(True)
        view.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        return view

    @staticmethod
    def _panel(title: str, view: QPlainTextEdit) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        label = QLabel(title)
        label.setProperty("sectionTitle", True)
        layout.addWidget(label)
        layout.addWidget(view, 1)
        return panel

    @property
    def runtime(self) -> Any:
        return getattr(self.context, "enterprise_server", None)

    def refresh_runtime(self) -> None:
        runtime = self.runtime
        if runtime is None:
            self.summary.setText("Enterprise Server runtime is unavailable in this application context.")
            self.health_view.setPlainText("Unavailable")
            self.workers_view.clear()
            self.jobs_view.clear()
            return
        try:
            snapshot = runtime.remote_ops_snapshot()
        except (ArenyxaError, OSError, RuntimeError, ValueError) as exc:
            self.summary.setText(f"Fleet Control requires authorized Enterprise remote-ops access: {exc}")
            return
        queue = dict(snapshot.get("queue") or {})
        workers = list(snapshot.get("workers") or [])[:1000]
        jobs = list(snapshot.get("jobs") or [])[:1000]
        capabilities = dict(queue.get("storage_capabilities") or queue.get("storage") or {})
        capacity = dict(queue.get("capacity") or {})
        invariants = dict(queue.get("state_invariants") or {})
        self.summary.setText(
            f"backend={capabilities.get('backend', 'unknown')} · write={capabilities.get('write_model', 'unknown')} · "
            f"capacity={str(capacity.get('severity', 'unknown')).upper()} · "
            f"recommended-total-slots={capabilities.get('recommended_total_worker_slots', 0)} · "
            f"workers={len(workers)} · jobs={len(jobs)} · "
            f"integrity={queue.get('database_integrity', 'unknown')} · invariants={invariants}"
        )
        telemetry = FleetTelemetryAnalyzer().analyze(snapshot)
        live_snapshot = self.live_telemetry.ingest(snapshot)
        warning_text = " · ".join(telemetry.warnings[:3]) if telemetry.warnings else "no active warnings"
        self.telemetry.setText(
            f"{telemetry.severity.upper()} · slots={telemetry.active_slots}/{telemetry.total_slots} "
            f"({telemetry.slot_utilization * 100:.0f}%) · queued={telemetry.queued_jobs} · "
            f"stale-workers={telemetry.stale_workers} · retries={telemetry.retry_pressure} · {warning_text}"
        )
        self.health_view.setPlainText(json.dumps(queue, ensure_ascii=False, indent=2)[:50000])
        self.live_view.setPlainText(json.dumps(live_snapshot, ensure_ascii=False, indent=2, default=str)[-100000:])
        self.workers_view.setPlainText("\n".join(
            f"{row.get('worker_id', '')} · {row.get('state', '')} · "
            f"slots={row.get('active_leases', 0)}/{row.get('max_slots', 0)} · "
            f"protocol={row.get('negotiated_protocol', '')} · heartbeat={row.get('heartbeat_at', '')}"
            + (f" · WARNING={row.get('concurrency_advisory', '')}" if row.get('concurrency_advisory') else "")
            for row in workers if isinstance(row, dict)
        ) or "No registered Workers")
        self.jobs_view.setPlainText("\n".join(
            f"{row.get('job_id', '')} · {row.get('state', '')} · {row.get('kind', '')} · "
            f"worker={row.get('lease_worker_id', '') or '-'} · attempt={row.get('attempt', 0)}/{row.get('max_attempts', 0)}"
            for row in jobs if isinstance(row, dict)
        ) or "No distributed Jobs")


    def export_snapshot(self) -> None:
        runtime = self.runtime
        if runtime is None:
            self.statusMessage.emit("Fleet Control runtime is unavailable")
            return
        try:
            snapshot = runtime.remote_ops_snapshot()
        except (ArenyxaError, OSError, RuntimeError, ValueError) as exc:
            self.statusMessage.emit(f"Fleet Control snapshot failed: {exc}")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Fleet Snapshot", "arenyxa-fleet-snapshot.json", "JSON (*.json)")
        if not path:
            return
        try:
            payload = json.dumps(snapshot, ensure_ascii=False, indent=2)
            if len(payload.encode("utf-8")) > 8 * 1024 * 1024:
                raise ValueError("Fleet snapshot exceeds 8 MiB export budget")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write(payload + "\n")
        except (OSError, ValueError) as exc:
            self.statusMessage.emit(f"Fleet Control export failed: {exc}")
            return
        self.statusMessage.emit("Fleet Control snapshot exported")

    def activated(self) -> None:
        self.refresh_runtime()
        self.timer.start()

    def deactivated(self) -> None:
        self.timer.stop()
