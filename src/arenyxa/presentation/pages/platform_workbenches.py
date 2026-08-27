from __future__ import annotations

import json
from typing import Any, Callable

from arenyxa.application.workbench_services import OperationalWorkbenchService
from arenyxa.presentation.background import run_background
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader
from arenyxa.qt_compat.QtCore import QTimer, Signal
from arenyxa.qt_compat.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QWidget,
)


class _SnapshotWorkbenchPage(WorkspacePage):
    TITLE = "Operational Workbench"
    DESCRIPTION = "Shared Application Control Plane status"
    SNAPSHOT = "diagnostics"
    REFRESH_MS = 4000

    def __init__(self, context: Any, theme: Any, motion: Any, parent: QWidget | None = None) -> None:
        super().__init__(context, theme, motion, parent)
        self.service = OperationalWorkbenchService(context)
        root = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(PageHeader(self.TITLE, self.DESCRIPTION), 1)
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.setProperty("primary", True)
        header.addWidget(self.refresh_button)
        root.addLayout(header)
        self.state_label = QLabel("Not loaded")
        self.state_label.setProperty("muted", True)
        self.state_label.setWordWrap(True)
        root.addWidget(self.state_label)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        root.addWidget(self.output, 1)
        self.refresh_button.clicked.connect(self.refresh_snapshot)
        self.timer = QTimer(self)
        self.timer.setInterval(self.REFRESH_MS)
        self.timer.timeout.connect(self.refresh_snapshot)
        self._refresh_inflight = False

    def snapshot(self) -> Any:
        operation = getattr(self.service, self.SNAPSHOT)
        return operation()

    def refresh_snapshot(self) -> None:
        if self._refresh_inflight:
            return
        self._refresh_inflight = True
        self.refresh_button.setEnabled(False)
        self.state_label.setText("Refreshing through shared Application Control Plane…")

        def completed(value: object) -> None:
            self._refresh_inflight = False
            self.refresh_button.setEnabled(True)
            self.state_label.setText("Live snapshot · background-dispatched · no business logic in QWidget")
            self.output.setPlainText(json.dumps(value, ensure_ascii=False, indent=2, default=str)[:500000])

        def failed(message: str) -> None:
            self._refresh_inflight = False
            self.refresh_button.setEnabled(True)
            self.state_label.setText("Degraded / unavailable")
            self.output.setPlainText(str(message))

        run_background(self.snapshot, completed, failed)

    def activated(self) -> None:
        super().activated()
        self.refresh_snapshot()
        self.timer.start()

    def deactivated(self) -> None:
        super().deactivated()
        self.timer.stop()


class ProtocolWorkbenchPage(_SnapshotWorkbenchPage):
    TITLE = "Protocol Intelligence"
    DESCRIPTION = "Protocol registry, field catalog, decoder availability and traffic-engine health"
    SNAPSHOT = "protocol"


class SecurityWorkbenchPage(_SnapshotWorkbenchPage):
    TITLE = "Security Center"
    DESCRIPTION = "Security Kernel, audit integrity, Root/Developer authority and Enterprise identity posture"
    SNAPSHOT = "security"


class StorageWorkbenchPage(_SnapshotWorkbenchPage):
    TITLE = "Storage & Database"
    DESCRIPTION = "SQLite local storage and Enterprise distributed runtime storage health"
    SNAPSHOT = "storage"


class AuditWorkbenchPage(_SnapshotWorkbenchPage):
    TITLE = "Audit"
    DESCRIPTION = "Tamper-evident Security Audit integrity and authorized Enterprise audit tail"
    SNAPSHOT = "audit"


class DiagnosticsWorkbenchPage(_SnapshotWorkbenchPage):
    TITLE = "Diagnostics"
    DESCRIPTION = "Deep platform health and Windows-native capability diagnostics"
    SNAPSHOT = "diagnostics"


class PerformanceWorkbenchPage(_SnapshotWorkbenchPage):
    TITLE = "Performance"
    DESCRIPTION = "Runtime policy, resource pressure, Job System and distributed capacity telemetry"
    SNAPSHOT = "performance"
    REFRESH_MS = 2500


class DeveloperWorkbenchPage(_SnapshotWorkbenchPage):
    surfaceRequested = Signal(str)
    TITLE = "Developer"
    DESCRIPTION = "Developer Authority, terminal workspace and plug-in sandbox state"
    SNAPSHOT = "developer"

    def __init__(self, context: Any, theme: Any, motion: Any, parent: QWidget | None = None) -> None:
        super().__init__(context, theme, motion, parent)
        actions = QHBoxLayout()
        for title, destination in (
            ("Terminal", "console"),
            ("Runtime", "diagnostics"),
            ("Plugin SDK", "plugins"),
            ("Diagnostics", "diagnostics"),
            ("Authority", "settings"),
            ("Test Lab", "advanced"),
        ):
            button = QPushButton(title)
            button.clicked.connect(
                lambda _checked=False, destination=destination: self.surfaceRequested.emit(destination)
            )
            actions.addWidget(button)
        actions.addStretch(1)
        self.layout().insertLayout(2, actions)


class ServerWorkbenchPage(_SnapshotWorkbenchPage):
    TITLE = "Server"
    DESCRIPTION = "Enterprise Server authority, distributed runtime and Windows service posture"
    SNAPSHOT = "server"
    REFRESH_MS = 2500


class WorkersWorkbenchPage(_SnapshotWorkbenchPage):
    TITLE = "Workers"
    DESCRIPTION = "Enterprise Worker identity, slots, heartbeat, drain and revocation control"
    SNAPSHOT = "workers"
    REFRESH_MS = 2000

    def __init__(self, context: Any, theme: Any, motion: Any, parent: QWidget | None = None) -> None:
        super().__init__(context, theme, motion, parent)
        controls = QHBoxLayout()
        self.worker_id = QLineEdit()
        self.worker_id.setPlaceholderText("worker id")
        self.drain_button = QPushButton("Drain")
        self.resume_button = QPushButton("Resume")
        self.revoke_button = QPushButton("Revoke")
        controls.addWidget(self.worker_id, 1)
        controls.addWidget(self.drain_button)
        controls.addWidget(self.resume_button)
        controls.addWidget(self.revoke_button)
        self.layout().insertLayout(2, controls)
        self.drain_button.clicked.connect(lambda: self._worker_action(lambda worker: self.service.worker_drain(worker, True)))
        self.resume_button.clicked.connect(lambda: self._worker_action(lambda worker: self.service.worker_drain(worker, False)))
        self.revoke_button.clicked.connect(lambda: self._worker_action(self.service.worker_revoke))

    def _worker_action(self, operation: Callable[[str], Any]) -> None:
        worker = self.worker_id.text().strip()
        if not worker:
            self.statusMessage.emit("Worker ID is required")
            return

        def work() -> Any:
            return operation(worker)

        def completed(value: object) -> None:
            self.statusMessage.emit(json.dumps(value, ensure_ascii=False, default=str))
            self.refresh_snapshot()

        run_background(work, completed, lambda message: self.statusMessage.emit(str(message)))


class PlatformJobsWorkbenchPage(_SnapshotWorkbenchPage):
    TITLE = "Jobs"
    DESCRIPTION = "Local persistent Job System and Enterprise distributed Job coordination"
    SNAPSHOT = "jobs"
    REFRESH_MS = 2000

    def __init__(self, context: Any, theme: Any, motion: Any, parent: QWidget | None = None) -> None:
        super().__init__(context, theme, motion, parent)
        controls = QHBoxLayout()
        self.job_id = QLineEdit()
        self.job_id.setPlaceholderText("distributed job id")
        self.retry_button = QPushButton("Retry Review-Required")
        self.recover_button = QPushButton("Recover Expired Leases")
        controls.addWidget(self.job_id, 1)
        controls.addWidget(self.retry_button)
        controls.addWidget(self.recover_button)
        self.layout().insertLayout(2, controls)
        self.retry_button.clicked.connect(self._retry)
        self.recover_button.clicked.connect(self._recover)

    def _retry(self) -> None:
        job = self.job_id.text().strip()
        if not job:
            self.statusMessage.emit("Distributed Job ID is required")
            return
        run_background(
            lambda: self.service.retry_distributed_job(job),
            lambda value: (self.statusMessage.emit(json.dumps(value, ensure_ascii=False, default=str)), self.refresh_snapshot()),
            lambda message: self.statusMessage.emit(str(message)),
        )

    def _recover(self) -> None:
        run_background(
            self.service.recover_leases,
            lambda value: (self.statusMessage.emit(json.dumps(value, ensure_ascii=False, default=str)), self.refresh_snapshot()),
            lambda message: self.statusMessage.emit(str(message)),
        )
