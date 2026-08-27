from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from arenyxa.qt_compat.QtCore import Qt, QTimer
from arenyxa.qt_compat.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QApplication,
    QWidget,
)

from arenyxa.application.runtime_health import RuntimeHealthService
from arenyxa.application.dependency_health import DependencyHealthService
from arenyxa.application.resilience_drills import ResilienceDrillService
from arenyxa.domain.errors import ArenyxaError
from arenyxa.application.runtime_recovery import RuntimeRecoveryService
from arenyxa.infrastructure.atomic_io import read_text_limited
from arenyxa.presentation.background import run_background
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.language import literal_for_locale
from arenyxa.presentation.widgets import PageHeader, hide_table_vertical_header, set_table_header_stretch_last, table_selection_model


class RecoveryCenterPage(WorkspacePage):
    






    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        layout = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(
            PageHeader(
                "Recovery & Health Center",
                "Resume interrupted workflows and inspect scheduler / worker health without deleting user data.",
            ),
            1,
        )
        self.refresh_button = QPushButton("Refresh")
        self.probe_button = QPushButton("Probe Workers")
        self.resume_button = QPushButton("Validate & Resume")
        self.resume_button.setProperty("primary", True)
        self.drill_button = QPushButton("Run Resilience Drills")
        self.auto_drill_button = QPushButton("Continuous Drills: Off")
        header.addWidget(self.refresh_button)
        header.addWidget(self.probe_button)
        header.addWidget(self.drill_button)
        header.addWidget(self.auto_drill_button)
        header.addWidget(self.resume_button)
        layout.addLayout(header)

        self.summary = QLabel("Runtime health has not been refreshed yet.")
        self.summary.setProperty("muted", True)
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)

        self.tabs = QTabWidget()
        self.recovery_table = self._table(
            ["Type", "ID", "State", "Action", "Details"]
        )
        self.scheduler_table = self._table(
            ["ID", "Kind", "Enabled", "Next run", "Running", "Pending"]
        )
        self.worker_table = self._table(
            ["ID", "Name", "Base URL", "Enabled", "Status", "Latency / Error"]
        )
        self.dependency_table = self._table(["Component", "State", "Latency", "Trend", "Details"])
        self.resilience_output = QPlainTextEdit()
        self.resilience_output.setReadOnly(True)
        self.history = QPlainTextEdit()
        self.history.setReadOnly(True)
        self.tabs.addTab(self.recovery_table, "Recovery")
        self.tabs.addTab(self.dependency_table, "Dependency Health")
        self.tabs.addTab(self.resilience_output, "Resilience Drills")
        self.tabs.addTab(self.scheduler_table, "Scheduler")
        self.tabs.addTab(self.worker_table, "Workers")
        self.tabs.addTab(self.history, "Recovery History")
        layout.addWidget(self.tabs, 1)

        self.refresh_button.clicked.connect(self.refresh)
        self.probe_button.clicked.connect(self.probe_workers)
        self.resume_button.clicked.connect(self.resume_selected)
        self.drill_button.clicked.connect(self.run_resilience_drills)
        self.auto_drill_button.clicked.connect(self.toggle_continuous_drills)
        self.recovery_table.itemSelectionChanged.connect(self._update_resume_enabled)
        self._health_refresh_sequence = 0
        self.health_timer = QTimer(self)
        self.health_timer.setInterval(60_000)
        self.health_timer.timeout.connect(self._scheduled_refresh)
        self._update_resume_enabled()


    def _tr(self, source: str) -> str:
        app = QApplication.instance()
        locale = str(app.property("arenyxa_locale") or "en_US") if app is not None else "en_US"
        return literal_for_locale(source, locale)

    @staticmethod
    def _table(headers: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        set_table_header_stretch_last(table, True)
        hide_table_vertical_header(table)
        return table

    def activated(self) -> None:
        if not self.health_timer.isActive():
            self.health_timer.start()
        self._update_auto_drill_button()
        self.refresh()

    def deactivated(self) -> None:
        self.health_timer.stop()

    def _scheduled_refresh(self) -> None:
        self._health_refresh_sequence += 1
        # Local dependency probes run every minute; bounded TLS probes run every 5 minutes.
        self._refresh(include_network=self._health_refresh_sequence % 5 == 0, background_status=False)

    def refresh(self) -> None:
        self._refresh(include_network=True, background_status=True)

    def _refresh(self, *, include_network: bool, background_status: bool) -> None:
        if not self.refresh_button.isEnabled():
            return
        self.refresh_button.setEnabled(False)
        if background_status:
            self.statusMessage.emit(self._tr("Refreshing runtime health…"))

        def worker() -> dict[str, Any]:
            return {
                "runtime": RuntimeHealthService(self.context).snapshot().to_dict(),
                "dependencies": DependencyHealthService(self.context).snapshot(include_network=include_network).to_dict(),
            }

        def completed(payload: object) -> None:
            self.refresh_button.setEnabled(True)
            data = dict(payload) if isinstance(payload, dict) else {}
            self._render_snapshot(dict(data.get("runtime") or {}))
            self._render_dependencies(dict(data.get("dependencies") or {}))
            self._load_history()
            if background_status:
                self.statusMessage.emit(self._tr("Runtime health refreshed"))

        def failed(message: str) -> None:
            self.refresh_button.setEnabled(True)
            if background_status:
                QMessageBox.warning(self, self._tr("Runtime Health"), message)

        run_background(worker, completed, failed)

    def _render_snapshot(self, snapshot: dict[str, Any]) -> None:
        recovery = dict(snapshot.get("recovery") or {})
        scheduler = dict(snapshot.get("scheduler") or {})
        runner = dict(snapshot.get("runner") or {})
        workers = dict(snapshot.get("workers") or {})
        resumable = len(recovery.get("resumable_workflows") or [])
        broken = len(recovery.get("broken_interrupted_workflows") or [])
        interrupted_revisions = len(recovery.get("resumable_revisions") or [])
        self.summary.setText(
            f"{self._tr('Resumable workflows')}: {resumable} · {self._tr('Blocked workflows')}: {broken} · "
            f"{self._tr('Interrupted revisions')}: {interrupted_revisions} · {self._tr('Active runs')}: {int(runner.get('active_runs', 0))} · "
            f"{self._tr('Scheduler')}: {int(scheduler.get('enabled', 0))}/{int(scheduler.get('configured', 0))} {self._tr('enabled')} · "
            f"{self._tr('Workers')}: {int(workers.get('enabled', 0))}/{int(workers.get('configured', 0))} {self._tr('enabled')}"
        )

        rows: list[tuple[str, str, str, str, str]] = []
        for execution_id in recovery.get("resumable_workflows") or []:
            execution = self.context.store.get_workflow_execution(str(execution_id))
            detail = "Durable checkpoint is valid"
            if execution:
                detail = (
                    f"processed={int(execution.get('processed_inputs', 0))} · "
                    f"outputs={int(execution.get('staged_outputs', 0))} · "
                    f"errors={int(execution.get('error_count', 0))}"
                )
            rows.append((self._tr("Workflow"), str(execution_id), self._tr("interrupted"), self._tr("Resume"), detail))
        for execution_id in recovery.get("broken_interrupted_workflows") or []:
            rows.append((self._tr("Workflow"), str(execution_id), self._tr("interrupted"), self._tr("Blocked"), self._tr("Resume chain is incomplete or inconsistent")))
        for revision_id in recovery.get("resumable_revisions") or []:
            rows.append((self._tr("Dataset Revision"), str(revision_id), self._tr("interrupted"), self._tr("Inspect"), self._tr("Source run metadata is preserved; automatic replay is intentionally not assumed")))
        for revision_id in recovery.get("broken_interrupted_revisions") or []:
            rows.append((self._tr("Dataset Revision"), str(revision_id), self._tr("interrupted"), self._tr("Blocked"), self._tr("Source metadata is incomplete")))
        for schedule_id in recovery.get("invalid_schedules") or []:
            rows.append((self._tr("Schedule"), str(schedule_id), self._tr("invalid"), self._tr("Repair Center"), self._tr("Invalid persisted schedule definition")))
        self.recovery_table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            for column, value in enumerate(row):
                item = QTableWidgetItem(value)
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, ("Workflow" if str(row[0]) == self._tr("Workflow") else str(row[0]), row[1], "Resume" if str(row[3]) == self._tr("Resume") else str(row[3])))
                self.recovery_table.setItem(row_index, column, item)
        self._update_resume_enabled()

        schedule_items = list(scheduler.get("items") or [])
        self.scheduler_table.setRowCount(len(schedule_items))
        for row_index, item in enumerate(schedule_items):
            values = [
                item.get("id", ""), item.get("kind", ""),
                self._tr("Yes") if item.get("enabled") else self._tr("No"), item.get("next_run_at", ""),
                self._tr("Yes") if item.get("running") else self._tr("No"),
                self._tr("Yes") if item.get("callback_pending") else self._tr("No"),
            ]
            for column, value in enumerate(values):
                self.scheduler_table.setItem(row_index, column, QTableWidgetItem(str(value)))

        worker_items = list(workers.get("items") or [])
        self.worker_table.setRowCount(len(worker_items))
        for row_index, item in enumerate(worker_items):
            values = [
                item.get("id", ""), item.get("name", ""), item.get("base_url", ""),
                self._tr("Yes") if item.get("enabled") else self._tr("No"), self._tr("Not probed"), "",
            ]
            for column, value in enumerate(values):
                self.worker_table.setItem(row_index, column, QTableWidgetItem(str(value)))

    def _render_dependencies(self, payload: dict[str, Any]) -> None:
        probes = list(payload.get("probes") or [])
        trends = dict(payload.get("trends") or {})
        self.dependency_table.setRowCount(len(probes))
        for row_index, probe in enumerate(probes):
            latency = probe.get("latency_ms")
            component = str(probe.get("component", ""))
            trend = dict(trends.get(component) or {})
            direction = str(trend.get("direction", "insufficient-data"))
            forecast = str(trend.get("forecast", "unknown"))
            trend_text = direction if forecast in {"unknown", str(probe.get("state", "unknown")).casefold()} else f"{direction} → {forecast}"
            values = [
                component,
                str(probe.get("state", "unknown")).upper(),
                "" if latency is None else f"{float(latency):.1f} ms",
                trend_text,
                str(probe.get("detail", "")),
            ]
            for column, value in enumerate(values):
                self.dependency_table.setItem(row_index, column, QTableWidgetItem(value))

    def _update_auto_drill_button(self) -> None:
        scheduler = getattr(self.context, "resilience_scheduler", None)
        if scheduler is None:
            self.auto_drill_button.setEnabled(False)
            self.auto_drill_button.setText("Continuous Drills: Unavailable")
            return
        state = dict(scheduler.snapshot())
        enabled = bool(state.get("enabled"))
        self.auto_drill_button.setEnabled(True)
        self.auto_drill_button.setText("Continuous Drills: On" if enabled else "Continuous Drills: Off")
        self.auto_drill_button.setToolTip(
            "Runs isolated resilience validation every 6 hours while an authorized Developer session is active."
        )

    def toggle_continuous_drills(self) -> None:
        scheduler = getattr(self.context, "resilience_scheduler", None)
        if scheduler is None:
            return
        access = getattr(self.context, "developer_access", None)
        status = access.status() if access is not None else None
        capabilities = set(() if status is None else status.capabilities)
        if "fault_injection" not in capabilities and "platform.root" not in capabilities:
            QMessageBox.warning(
                self,
                self._tr("Resilience Drills"),
                self._tr("Resilience drills require an authenticated Developer fault_injection capability."),
            )
            return
        state = dict(scheduler.snapshot())
        if bool(state.get("enabled")):
            scheduler.disable()
            self.statusMessage.emit("Continuous resilience validation disabled")
        else:
            scheduler.enable(interval_seconds=6 * 60 * 60)
            self.statusMessage.emit("Continuous resilience validation enabled · every 6 hours")
        self._update_auto_drill_button()

    def run_resilience_drills(self) -> None:
        access = getattr(self.context, "developer_access", None)
        status = access.status() if access is not None else None
        capabilities = set(() if status is None else status.capabilities)
        if "fault_injection" not in capabilities and "platform.root" not in capabilities:
            QMessageBox.warning(
                self,
                self._tr("Resilience Drills"),
                self._tr("Resilience drills require an authenticated Developer fault_injection capability."),
            )
            return
        self.drill_button.setEnabled(False)
        self.statusMessage.emit(self._tr("Running isolated resilience drills…"))

        def worker() -> list[dict[str, Any]]:
            return [item.to_dict() for item in ResilienceDrillService(self.context).run_all()]

        def completed(payload: object) -> None:
            self.drill_button.setEnabled(True)
            rows = list(payload) if isinstance(payload, list) else []
            self.resilience_output.setPlainText(json.dumps(rows, ensure_ascii=False, indent=2))
            passed = sum(1 for item in rows if isinstance(item, dict) and item.get("passed"))
            self.statusMessage.emit(f"Resilience drills completed · {passed}/{len(rows)} passed")
            self.inspectorChanged.emit("Resilience Drills", rows)

        def failed(message: str) -> None:
            self.drill_button.setEnabled(True)
            QMessageBox.warning(self, self._tr("Resilience Drills"), message)

        run_background(worker, completed, failed)

    def _selected_recovery(self) -> tuple[str, str, str] | None:
        selection = table_selection_model(self.recovery_table)
        selected_rows = getattr(selection, "selectedRows", None)
        rows = selected_rows() if callable(selected_rows) else []
        if len(rows) != 1:
            return None
        item = self.recovery_table.item(rows[0].row(), 0)
        value = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        if not isinstance(value, tuple) or len(value) != 3:
            return None
        return str(value[0]), str(value[1]), str(value[2])

    def _update_resume_enabled(self) -> None:
        selected = self._selected_recovery()
        self.resume_button.setEnabled(bool(selected and selected[0] == "Workflow" and selected[2] == "Resume"))

    def resume_selected(self) -> None:
        selected = self._selected_recovery()
        if not selected or selected[0] != "Workflow" or selected[2] != "Resume":
            return
        execution_id = selected[1]
        self.resume_button.setEnabled(False)
        self.refresh_button.setEnabled(False)
        self.operationProgress.emit("Workflow resume", 0, 0, "indeterminate")
        self.statusMessage.emit(self._tr("Resuming workflow from durable checkpoint…"))

        def worker():
            validation = self.context.workflow_runtime.validate_resume_checkpoint(execution_id)
            if not validation.valid:
                raise ArenyxaError(
                    "WORKFLOW_RESUME_PREFLIGHT_FAILED",
                    "Durable checkpoint failed isolated validation.",
                    domain="WORKFLOW",
                    context=validation.to_dict(),
                )
            if not validation.replayed:
                raise ArenyxaError(
                    "WORKFLOW_RESUME_REPLAY_REQUIRED",
                    "Checkpoint structure is valid, but this workflow contains handlers that cannot be safely replayed in the local sandbox.",
                    domain="WORKFLOW",
                    context=validation.to_dict(),
                )
            result = self.context.workflow_runtime.resume_execution(execution_id, validate_checkpoint=False)
            return {"validation": validation.to_dict(), "result": asdict(result)}

        def completed(result: object) -> None:
            self.operationProgress.emit("", 0, 0, "clear")
            self.refresh_button.setEnabled(True)
            payload = dict(result) if isinstance(result, dict) else result
            self.statusMessage.emit(self._tr("Workflow resume completed"))
            self.inspectorChanged.emit(self._tr("Workflow recovery"), payload)
            self.refresh()

        def failed(message: str) -> None:
            self.operationProgress.emit("", 0, 0, "clear")
            self.refresh_button.setEnabled(True)
            self._update_resume_enabled()
            QMessageBox.warning(self, self._tr("Workflow Resume"), message)
            self.refresh()

        run_background(worker, completed, failed)

    def probe_workers(self) -> None:
        self.probe_button.setEnabled(False)
        self.statusMessage.emit(self._tr("Probing configured workers…"))

        def worker():
            return RuntimeHealthService(self.context).probe_workers()

        def completed(payload: object) -> None:
            self.probe_button.setEnabled(True)
            rows = list(payload) if isinstance(payload, list) else []
            self.worker_table.setRowCount(len(rows))
            for row_index, item in enumerate(rows):
                worker_info = dict(item.get("worker") or {}) if isinstance(item, dict) else {}
                online = bool(item.get("online")) if isinstance(item, dict) else False
                error = item.get("error") if isinstance(item, dict) else "invalid result"
                latency = item.get("latency_ms") if isinstance(item, dict) else None
                values = [
                    worker_info.get("id", ""), worker_info.get("name", ""), worker_info.get("base_url", ""),
                    self._tr("Yes") if worker_info.get("enabled") else self._tr("No"),
                    self._tr("Online") if online else (self._tr("Disabled") if error == "disabled" else self._tr("Offline")),
                    f"{latency} ms" if latency is not None else str(error or ""),
                ]
                for column, value in enumerate(values):
                    self.worker_table.setItem(row_index, column, QTableWidgetItem(str(value)))
            self.statusMessage.emit(self._tr("Worker health probe completed"))

        def failed(message: str) -> None:
            self.probe_button.setEnabled(True)
            QMessageBox.warning(self, self._tr("Worker Health"), message)

        run_background(worker, completed, failed)

    def _load_history(self) -> None:
        path = self.context.paths.root / "repair" / "runtime_recovery_history.json"
        try:
            payload = json.loads(read_text_limited(path, 2 * 1024 * 1024, encoding="utf-8"))
            if not isinstance(payload, list):
                raise ValueError("history root must be an array")
            safe_rows = [item for item in payload if isinstance(item, dict)][-50:]
            self.history.setPlainText(json.dumps(safe_rows, ensure_ascii=False, indent=2, default=str))
        except FileNotFoundError:
            self.history.setPlainText(self._tr("No recovery history yet."))
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            self.history.setPlainText(f"{self._tr('Recovery history is unavailable')}: {type(exc).__name__}: {exc}")
