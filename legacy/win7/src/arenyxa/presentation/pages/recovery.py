from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from arenyxa.qt_compat.QtCore import Qt
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
        self.resume_button = QPushButton("Resume Selected")
        self.resume_button.setProperty("primary", True)
        header.addWidget(self.refresh_button)
        header.addWidget(self.probe_button)
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
        self.history = QPlainTextEdit()
        self.history.setReadOnly(True)
        self.tabs.addTab(self.recovery_table, "Recovery")
        self.tabs.addTab(self.scheduler_table, "Scheduler")
        self.tabs.addTab(self.worker_table, "Workers")
        self.tabs.addTab(self.history, "Recovery History")
        layout.addWidget(self.tabs, 1)

        self.refresh_button.clicked.connect(self.refresh)
        self.probe_button.clicked.connect(self.probe_workers)
        self.resume_button.clicked.connect(self.resume_selected)
        self.recovery_table.itemSelectionChanged.connect(self._update_resume_enabled)
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
        self.refresh()

    def refresh(self) -> None:
        if not self.refresh_button.isEnabled():
            return
        self.refresh_button.setEnabled(False)
        self.statusMessage.emit(self._tr("Refreshing runtime health…"))

        def worker() -> dict[str, Any]:
            return RuntimeHealthService(self.context).snapshot().to_dict()

        def completed(payload: object) -> None:
            self.refresh_button.setEnabled(True)
            data = dict(payload) if isinstance(payload, dict) else {}
            self._render_snapshot(data)
            self._load_history()
            self.statusMessage.emit(self._tr("Runtime health refreshed"))

        def failed(message: str) -> None:
            self.refresh_button.setEnabled(True)
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
            return self.context.workflow_runtime.resume_execution(execution_id)

        def completed(result: object) -> None:
            self.operationProgress.emit("", 0, 0, "clear")
            self.refresh_button.setEnabled(True)
            payload = asdict(result) if hasattr(result, "__dataclass_fields__") else result
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
