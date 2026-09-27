from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from arenyxa.qt_compat.QtCore import Qt, Signal
from arenyxa.qt_compat.QtWidgets import (
    QFileDialog,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from arenyxa.domain.errors import ArenyxaError
from arenyxa.enterprise.coordinator import CoordinatorClient
from arenyxa.enterprise.enrollment import parse_enrollment_token, verify_enrollment_token
from arenyxa.infrastructure.atomic_io import atomic_write_bytes, atomic_write_json, read_bytes_limited
from arenyxa.presentation.i18n_runtime import current_text
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader, ResponsiveActionBar, SectionCard


ENTERPRISE_UI_ERRORS = (ArenyxaError, sqlite3.Error, OSError, RuntimeError, ValueError, TypeError, KeyError)


class EnterpriseDistributedActionsMixin:
    def _export_enrollment_tokens(self, result: dict) -> None:
        tokens = list(result.get("tokens") or [])
        if not tokens:
            return
        directory = QFileDialog.getExistingDirectory(self, current_text("enterprise.enrollment.export_directory"), str(self.context.paths.exports))
        if not directory:
            return
        target = Path(directory)
        enrollment = getattr(self.context, "enrollment", None)
        for token in tokens:
            payload = token.get("payload", {})
            stem = f"Arenyxa_Enrollment_{payload.get('username','user')}_{payload.get('credential_id','credential')}"
            atomic_write_json(target / f"{stem}.aryxenroll.json", token, ensure_ascii=False, indent=2, mode=0o600)
            if enrollment is not None:


                qr_payload = enrollment.token_to_qr_payload(token)
                atomic_write_bytes(target / f"{stem}.qr.txt", qr_payload.encode("utf-8"), mode=0o600)
        QMessageBox.information(self, current_text("enterprise.enrollment.exported_title"), current_text("enterprise.enrollment.exported_message").format(count=len(tokens)))

    def _create_enrollment_campaign(self) -> None:
        enrollment = getattr(self.context, "enrollment", None)
        row = self._choose_account(current_text("enterprise.enrollment.create"))
        if enrollment is None or row is None or not self._prompt_step_up():
            return
        title, ok = QInputDialog.getText(self, current_text("enterprise.enrollment.campaign_title"), current_text("enterprise.enrollment.campaign_name"))
        if not ok:
            return
        try:
            result = enrollment.create_campaign(title or "Enrollment Campaign", [row["id"]])
            self._export_enrollment_tokens(result)
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.enrollment.create_failed"), exc)
        self.refresh()

    def _import_enrollment_csv(self) -> None:
        enrollment = getattr(self.context, "enrollment", None)
        if enrollment is None or not self._prompt_step_up():
            return
        path, _ = QFileDialog.getOpenFileName(self, current_text("enterprise.enrollment.import_csv_title"), str(self.context.paths.root), current_text("enterprise.enrollment.csv_filter"))
        if not path:
            return
        try:
            result = enrollment.import_members_csv(Path(path))
            self._export_enrollment_tokens(result)
            QMessageBox.information(self, current_text("enterprise.enrollment.batch_title"), current_text("enterprise.enrollment.batch_result").format(count=len(result.get("accounts", []))))
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.enrollment.csv_failed"), exc)
        self.refresh()

    def _show_devices(self) -> None:
        enrollment = getattr(self.context, "enrollment", None)
        if enrollment is None:
            return
        try:
            rows = enrollment.list_devices()
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.enrollment.devices_read_failed"), exc)
            return
        text = "\n".join(f"{row['id']} · {row.get('username','')} · {row.get('status','')} · {row.get('fingerprint','')[:16]}…" for row in rows) or current_text("enterprise.enrollment.no_devices")
        QMessageBox.information(self, current_text("enterprise.enrollment.registry_title"), text)

    def _revoke_device(self) -> None:
        enrollment = getattr(self.context, "enrollment", None)
        if enrollment is None or not self._prompt_step_up():
            return
        try:
            rows = enrollment.list_devices()
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error("读取设备失败", exc); return
        labels = [f"{row['id']} · {row.get('username','')} · {row.get('status','')}" for row in rows if row.get("status") == "active"]
        if not labels:
            return
        selected, ok = QInputDialog.getItem(self, current_text("enterprise.enrollment.revoke"), current_text("enterprise.enrollment.device_label"), labels, 0, False)
        if not ok:
            return
        try:
            enrollment.revoke_device(selected.split(" · ", 1)[0])
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.enrollment.revoke_failed"), exc)
        self.refresh()

    def _join_office_enterprise(self) -> None:
        enrollment = getattr(self.context, "enrollment", None)
        if enrollment is None:
            return
        path, _ = QFileDialog.getOpenFileName(self, current_text("enterprise.enrollment.select_credential"), str(self.context.paths.root), current_text("enterprise.enrollment.credential_filter"))
        if not path:
            return
        endpoint, ok = QInputDialog.getText(self, current_text("enterprise.enrollment.join"), current_text("enterprise.enrollment.coordinator_endpoint"))
        if not ok or ":" not in endpoint:
            return
        try:
            raw = read_bytes_limited(Path(path), 64 * 1024)
            token = parse_enrollment_token(raw)
            payload = verify_enrollment_token(token)
            public, rollback = enrollment.device_store.prepare_enrollment(
                str(payload["enterprise_id"]), str(payload["account_id"]),
            )
            try:
                host, port_text = endpoint.rsplit(":", 1)
                client = CoordinatorClient(host.strip(), int(port_text), str(token["root_fingerprint"]))


                client.verify_peer()
                enrolled = client.enroll(token, public)
                challenge = client.challenge(public["device_id"])
                challenge_raw = json.dumps(challenge, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
                signature = enrollment.device_store.sign(challenge_raw)
                session = client.authenticate(str(challenge["challenge_id"]), signature)
                verified_health = client.verify_peer()
                enrollment.device_store.set_office_binding(
                    host.strip(), int(port_text), str(token["root_fingerprint"]),
                    str(verified_health.get("coordinator_id", "")),
                )
            except ENTERPRISE_UI_ERRORS:
                enrollment.device_store.rollback_prepared_enrollment(rollback)
                raise
            QMessageBox.information(self, current_text("enterprise.enrollment.joined_title"), current_text("enterprise.enrollment.joined_message").format(device_id=enrolled["device_id"], ttl=session["expires_in"]))
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.enrollment.join_failed"), exc)
        self.refresh()

    def _reconnect_office_enterprise(self) -> None:
        enrollment = getattr(self.context, "enrollment", None)
        if enrollment is None or not enrollment.device_store.path.exists():
            return
        try:
            binding = enrollment.device_store.office_binding()
            public = enrollment.device_store.load_public()
            if not binding:
                raise RuntimeError(current_text("enterprise.enrollment.no_verified_binding"))
            client = CoordinatorClient(
                str(binding.get("host", "")), int(binding.get("port", 0)),
                str(binding.get("root_fingerprint", "")),
            )
            health = client.verify_peer()
            challenge = client.challenge(public["device_id"])
            challenge_raw = json.dumps(challenge, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
            signature = enrollment.device_store.sign(challenge_raw)
            session = client.authenticate(str(challenge["challenge_id"]), signature)
            QMessageBox.information(
                self, current_text("enterprise.enrollment.reconnected_title"),
                current_text("enterprise.enrollment.reconnected_message").format(coordinator=health.get("coordinator_id", ""), device=session.get("device_id", ""), ttl=session.get("expires_in", 0)),
            )
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.enrollment.reconnect_failed"), exc)

    def _start_coordinator(self) -> None:
        coordinator = getattr(self.context, "office_coordinator", None)
        if coordinator is None or not self._prompt_step_up():
            return
        bind, ok = QInputDialog.getText(self, current_text("enterprise.coordinator.start"), current_text("enterprise.coordinator.bind_address"), text="127.0.0.1")
        if not ok:
            return
        try:
            host, port = coordinator.start_tls(bind.strip() or "127.0.0.1", 0)
            QMessageBox.information(self, current_text("enterprise.coordinator.started_title"), current_text("enterprise.coordinator.started_message").format(host=host, port=port))
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.coordinator.start_failed"), exc)
        self.refresh()

    def _stop_coordinator(self) -> None:
        coordinator = getattr(self.context, "office_coordinator", None)
        if coordinator is None:
            return
        try:
            coordinator.stop()
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.coordinator.stop_failed"), exc)
        self.refresh()

    def _create_workspace(self) -> None:
        governance = getattr(self.context, "enterprise_governance", None)
        if governance is None:
            return
        title, ok = QInputDialog.getText(self, current_text("enterprise.governance.create_workspace"), current_text("enterprise.governance.workspace_name"))
        if not ok or not title.strip():
            return
        try:
            workspace_id = governance.create_workspace(title)
            QMessageBox.information(self, current_text("enterprise.governance.workspace_created"), workspace_id)
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.governance.workspace_create_failed"), exc)
        self.refresh()

    def _register_resource(self) -> None:
        governance = getattr(self.context, "enterprise_governance", None)
        if governance is None:
            return
        try:
            snapshot = governance.snapshot()
            workspaces = list(snapshot.get("workspaces", {}).values())
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.governance.read_failed"), exc); return
        if not workspaces:
            QMessageBox.information(self, current_text("enterprise.governance.register_resource"), current_text("enterprise.governance.create_workspace_first"))
            return
        labels = [f"{row['title']} · {row['id']}" for row in workspaces]
        selected, ok = QInputDialog.getItem(self, current_text("enterprise.governance.register_resource"), current_text("enterprise.governance.workspace_label"), labels, 0, False)
        if not ok:
            return
        workspace_id = selected.rsplit(" · ", 1)[-1]
        kind_options = (
            ("enterprise.resource_kind.workflow", "workflow"),
            ("enterprise.resource_kind.dataset", "dataset"),
            ("enterprise.resource_kind.capture", "capture"),
            ("enterprise.resource_kind.schedule", "schedule"),
            ("enterprise.resource_kind.worker", "worker"),
            ("enterprise.resource_kind.project", "project"),
        )
        kind_labels = [current_text(key) for key, _value in kind_options]
        selected_kind, ok = QInputDialog.getItem(
            self,
            current_text("enterprise.governance.register_resource"),
            current_text("enterprise.governance.resource_type"),
            kind_labels,
            0,
            False,
        )
        if not ok:
            return
        kind = kind_options[kind_labels.index(selected_kind)][1]
        candidates: list[tuple[str, str]] = []
        try:
            if kind == "workflow":
                candidates = [(str(row.get("id", "")), str(row.get("name", "Workflow"))) for row in self.context.store.list_workflows()]
            elif kind == "dataset":
                candidates = [(str(row.get("id", "")), str(row.get("name", "Dataset"))) for row in self.context.store.list_datasets(limit=5000)]
            elif kind == "capture":
                candidates = [(str(row.get("id", "")), str(row.get("name", "Capture"))) for row in self.context.store.list_captures(limit=1000)]
            elif kind == "schedule":
                candidates = [(str(row.get("id", "")), str(row.get("task_name", "Schedule"))) for row in self.context.store.list_schedules()]
            elif kind == "project":
                candidates = [(str(row.id), str(row.name)) for row in self.context.store.list_projects(limit=5000)]
            elif kind == "worker":
                server = getattr(self.context, "enterprise_server", None)
                if server is not None:
                    candidates = [(str(row.get("worker_id", "")), str(row.get("display_name") or row.get("worker_id", "Worker"))) for row in server.queue.list_workers(limit=2000)]
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.governance.local_resources_failed"), exc); return
        candidates = [(resource_id, title) for resource_id, title in candidates if resource_id]
        if not candidates:
            QMessageBox.information(self, current_text("enterprise.governance.register_resource"), current_text("enterprise.governance.no_local_resources"))
            return
        labels = [f"{title} · {resource_id}" for resource_id, title in candidates]
        selected_resource, ok = QInputDialog.getItem(self, current_text("enterprise.governance.register_resource"), current_text("enterprise.governance.local_resource_label"), labels, 0, False)
        if not ok:
            return
        selected_index = labels.index(selected_resource)
        external_id = candidates[selected_index][0]
        try:
            operations = getattr(self.context, "enterprise_operations", None)
            if operations is not None:
                rid = operations.register_and_bind_resource(kind, external_id, workspace_id)
            else:
                rid = governance.register_resource(kind, external_id, workspace_id)
            QMessageBox.information(self, current_text("enterprise.governance.resource_registered"), rid)
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.governance.register_failed"), exc)
        self.refresh()

    def _query_audit(self) -> None:
        governance = getattr(self.context, "enterprise_governance", None)
        if governance is None:
            return
        try:
            rows = governance.query_audit(limit=30)
            text = "\n".join(f"{row.get('time','')} · {row.get('actor','')} · {row.get('action','')} · {row.get('resource','')} · {row.get('decision','')}" for row in rows) or current_text("enterprise.audit.none")
            QMessageBox.information(self, current_text("enterprise.audit.query_title"), text)
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.audit.query_failed"), exc)

    def _show_operations_dashboard(self) -> None:
        governance = getattr(self.context, "enterprise_governance", None)
        if governance is None:
            return
        try:
            snapshot = governance.operations_snapshot()
            coordinator = getattr(self.context, "office_coordinator", None)
            coordinator_health = coordinator.health() if coordinator is not None else {}
            governor = getattr(self.context, "resource_governor", None)
            governor_state = governor.snapshot().to_dict() if governor is not None else {}
            text = current_text("enterprise.governance.dashboard_text").format(
                workspaces=snapshot["workspaces"],
                teams=snapshot["teams"],
                resources=snapshot["resources"],
                resources_by_kind=snapshot["resources_by_kind"],
                approvals=snapshot["pending_approvals"],
                quota=snapshot["quota_pressure"][:8],
                coordinator=coordinator_health,
                governor=governor_state,
            )
            QMessageBox.information(self, current_text("enterprise.governance.dashboard"), text)
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.governance.dashboard_failed"), exc)

    @property
    def enterprise_server(self):
        return getattr(self.context, "enterprise_server", None)

    @staticmethod
    def _bounded_lines(rows, formatter, *, limit: int = 120) -> str:
        materialized = list(rows or [])
        visible = materialized[:limit]
        text = "\n".join(formatter(row) for row in visible)
        if len(materialized) > limit:
            text += "\n" + current_text("enterprise.common.omitted").format(count=len(materialized) - limit)
        return text or current_text("enterprise.common.no_records")

    def _distributed_snapshot(self) -> dict:
        runtime = self.enterprise_server
        if runtime is None:
            raise RuntimeError(current_text("enterprise.server.backend_unavailable"))


        return runtime.remote_ops_snapshot()

    def _show_server_health(self) -> None:
        try:
            snapshot = self._distributed_snapshot()
            queue = dict(snapshot.get("queue") or {})
            capacity = dict(queue.get("capacity") or {})
            self.server_label.setText(
                f"Distributed Queue · integrity={queue.get('database_integrity', 'unknown')} · "
                f"capacity={str(capacity.get('severity', 'unknown')).upper()} · "
                f"jobs={queue.get('jobs', {})} · workers={queue.get('workers', {})}"
            )
            QMessageBox.information(
                self,
                current_text("enterprise.server.health_title"),
                json.dumps(queue, ensure_ascii=False, indent=2)[:12000],
            )
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.server.health_failed"), exc)

    def _show_server_workers(self) -> None:
        try:
            rows = self._distributed_snapshot().get("workers") or []
            text = self._bounded_lines(
                rows,
                lambda row: (
                    f"{row.get('worker_id', '')} · {row.get('state', '')} · slots={row.get('max_slots', '')} · "
                    f"protocol={row.get('negotiated_protocol', '')} · last_seen={row.get('heartbeat_at', '')}"
                ),
            )
            QMessageBox.information(self, current_text("enterprise.server.workers_title"), text)
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.server.workers_failed"), exc)

    def _show_server_jobs(self) -> None:
        try:
            rows = self._distributed_snapshot().get("jobs") or []
            text = self._bounded_lines(
                rows,
                lambda row: (
                    f"{row.get('job_id', '')} · {row.get('state', '')} · {row.get('kind', '')} · "
                    f"worker={row.get('lease_worker_id', '')} · attempt={row.get('attempt', '')}/{row.get('max_attempts', '')}"
                ),
            )
            QMessageBox.information(self, current_text("enterprise.server.jobs_title"), text)
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.server.jobs_failed"), exc)
