from __future__ import annotations
from arenyxa.presentation.pages.enterprise_identity_actions import EnterpriseIdentityActionsMixin
from arenyxa.presentation.pages.enterprise_distributed_actions import EnterpriseDistributedActionsMixin

import json
import sqlite3
from pathlib import Path
from typing import TypeVar

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
from arenyxa.presentation.i18n_runtime import current_text, source_text
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader, ResponsiveActionBar, SectionCard


ENTERPRISE_UI_ERRORS = (ArenyxaError, sqlite3.Error, OSError, RuntimeError, ValueError, TypeError, KeyError)
_TWidget = TypeVar("_TWidget", bound=QWidget)


def _i18n_widget(widget: _TWidget, key: str) -> _TWidget:
    widget.setProperty("i18n_key_text", key)
    return widget


class EnterprisePage(EnterpriseIdentityActionsMixin, EnterpriseDistributedActionsMixin, WorkspacePage):
    surfaceRequested = Signal(str)
    






    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        layout = page_layout(self)
        layout.addWidget(PageHeader(
            source_text("enterprise.page.title"),
            source_text("enterprise.page.subtitle"),
            title_key="enterprise.page.title",
            subtitle_key="enterprise.page.subtitle",
        ))

                                                                                              
                                                                                               
                                                                                                
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QScrollArea.Shape.NoFrame)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.scroll_container = QWidget()
        body = QVBoxLayout(self.scroll_container)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(12)
        self.scroll_area.setWidget(self.scroll_container)
        layout.addWidget(self.scroll_area, 1)

        console_card = SectionCard(theme, source_text("enterprise.console.title"), title_key="enterprise.console.title")
        console_hint = _i18n_widget(
            QLabel(source_text("enterprise.console.hint")),
            "enterprise.console.hint",
        )
        console_hint.setWordWrap(True)
        console_hint.setProperty("muted", True)
        console_card.body.addWidget(console_hint)
        self.console_identity_button = _i18n_widget(QPushButton(source_text("enterprise.console.identity")), "enterprise.console.identity")
        self.console_fleet_button = _i18n_widget(QPushButton(source_text("enterprise.console.fleet")), "enterprise.console.fleet")
        self.console_server_button = _i18n_widget(QPushButton(source_text("enterprise.console.server")), "enterprise.console.server")
        self.console_worker_button = _i18n_widget(QPushButton(source_text("enterprise.console.worker")), "enterprise.console.worker")
        self.console_jobs_button = _i18n_widget(QPushButton(source_text("enterprise.console.jobs")), "enterprise.console.jobs")
        self.console_audit_button = _i18n_widget(QPushButton(source_text("enterprise.console.audit")), "enterprise.console.audit")
        self.console_policy_button = _i18n_widget(QPushButton(source_text("enterprise.console.policy")), "enterprise.console.policy")
        console_card.body.addWidget(ResponsiveActionBar((
            self.console_identity_button, self.console_fleet_button, self.console_server_button,
            self.console_worker_button, self.console_jobs_button, self.console_audit_button,
            self.console_policy_button,
        )))
        body.addWidget(console_card)

        status_card = SectionCard(theme, source_text("enterprise.status.title"), title_key="enterprise.status.title")
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        status_card.body.addWidget(self.status_label)
        self.create_button = _i18n_widget(QPushButton(source_text("enterprise.status.create")), "enterprise.status.create")
        self.unlock_button = _i18n_widget(QPushButton(source_text("enterprise.status.unlock")), "enterprise.status.unlock")
        self.login_button = _i18n_widget(QPushButton(source_text("enterprise.status.login")), "enterprise.status.login")
        self.logout_button = _i18n_widget(QPushButton(source_text("enterprise.status.logout")), "enterprise.status.logout")
        self.lock_button = _i18n_widget(QPushButton(source_text("enterprise.status.lock")), "enterprise.status.lock")
        status_card.body.addWidget(ResponsiveActionBar((
            self.create_button, self.unlock_button, self.login_button, self.logout_button, self.lock_button,
        )))
        body.addWidget(status_card)

        account_card = SectionCard(theme, source_text("enterprise.accounts.title"), title_key="enterprise.accounts.title")
        account_hint = _i18n_widget(
            QLabel(source_text("enterprise.accounts.hint")),
            "enterprise.accounts.hint",
        )
        account_hint.setWordWrap(True)
        account_hint.setProperty("muted", True)
        account_card.body.addWidget(account_hint)
        self.accounts_view = QPlainTextEdit()
        self.accounts_view.setReadOnly(True)
        self.accounts_view.setMinimumHeight(170)
        account_card.body.addWidget(self.accounts_view)
        self.refresh_accounts_button = _i18n_widget(QPushButton(source_text("enterprise.accounts.refresh")), "enterprise.accounts.refresh")
        self.add_account_button = _i18n_widget(QPushButton(source_text("enterprise.accounts.add")), "enterprise.accounts.add")
        self.toggle_account_button = _i18n_widget(QPushButton(source_text("enterprise.accounts.toggle")), "enterprise.accounts.toggle")
        self.roles_button = _i18n_widget(QPushButton(source_text("enterprise.accounts.roles")), "enterprise.accounts.roles")
        self.rbac_matrix_button = _i18n_widget(QPushButton(source_text("enterprise.accounts.matrix")), "enterprise.accounts.matrix")
        self.password_button = _i18n_widget(QPushButton(source_text("enterprise.accounts.password")), "enterprise.accounts.password")
        self.delete_account_button = _i18n_widget(QPushButton(source_text("enterprise.accounts.delete")), "enterprise.accounts.delete")
        account_card.body.addWidget(ResponsiveActionBar((
            self.refresh_accounts_button, self.add_account_button, self.toggle_account_button,
            self.roles_button, self.rbac_matrix_button, self.password_button, self.delete_account_button,
        )))
        body.addWidget(account_card)

        vault_card = SectionCard(theme, source_text("enterprise.vault.title"), title_key="enterprise.vault.title")
        vault_hint = _i18n_widget(
            QLabel(source_text("enterprise.vault.hint")),
            "enterprise.vault.hint",
        )
        vault_hint.setWordWrap(True)
        vault_hint.setProperty("muted", True)
        vault_card.body.addWidget(vault_hint)
        self.step_up_button = _i18n_widget(QPushButton(source_text("enterprise.vault.step_up")), "enterprise.vault.step_up")
        self.vault_health_button = _i18n_widget(QPushButton(source_text("enterprise.vault.health")), "enterprise.vault.health")
        self.rotate_vault_button = _i18n_widget(QPushButton(source_text("enterprise.vault.rotate")), "enterprise.vault.rotate")
        self.backup_button = _i18n_widget(QPushButton(source_text("enterprise.vault.backup")), "enterprise.vault.backup")
        self.restore_button = _i18n_widget(QPushButton(source_text("enterprise.vault.restore")), "enterprise.vault.restore")
        vault_card.body.addWidget(ResponsiveActionBar((
            self.step_up_button, self.vault_health_button, self.rotate_vault_button, self.backup_button, self.restore_button,
        )))
        body.addWidget(vault_card)

        audit_card = SectionCard(theme, source_text("enterprise.audit.title"), title_key="enterprise.audit.title")
        self.audit_label = QLabel()
        self.audit_label.setWordWrap(True)
        audit_card.body.addWidget(self.audit_label)
        body.addWidget(audit_card)

        enrollment_card = SectionCard(theme, source_text("enterprise.enrollment.title"), title_key="enterprise.enrollment.title")
        self.enrollment_label = _i18n_widget(
            QLabel(source_text("enterprise.enrollment.hint")),
            "enterprise.enrollment.hint",
        )
        self.enrollment_label.setWordWrap(True)
        self.enrollment_label.setProperty("muted", True)
        enrollment_card.body.addWidget(self.enrollment_label)
        self.enroll_campaign_button = _i18n_widget(QPushButton(source_text("enterprise.enrollment.create")), "enterprise.enrollment.create")
        self.enroll_csv_button = _i18n_widget(QPushButton(source_text("enterprise.enrollment.csv")), "enterprise.enrollment.csv")
        self.devices_button = _i18n_widget(QPushButton(source_text("enterprise.enrollment.devices")), "enterprise.enrollment.devices")
        self.revoke_device_button = _i18n_widget(QPushButton(source_text("enterprise.enrollment.revoke")), "enterprise.enrollment.revoke")
        self.join_button = _i18n_widget(QPushButton(source_text("enterprise.enrollment.join")), "enterprise.enrollment.join")
        self.office_reconnect_button = _i18n_widget(QPushButton(source_text("enterprise.enrollment.reconnect")), "enterprise.enrollment.reconnect")
        enrollment_card.body.addWidget(ResponsiveActionBar((
            self.enroll_campaign_button, self.enroll_csv_button, self.devices_button,
            self.revoke_device_button, self.join_button, self.office_reconnect_button,
        )))
        body.addWidget(enrollment_card)

        coordinator_card = SectionCard(theme, source_text("enterprise.coordinator.title"), title_key="enterprise.coordinator.title")
        self.coordinator_label = _i18n_widget(
            QLabel(source_text("enterprise.coordinator.hint")),
            "enterprise.coordinator.hint",
        )
        self.coordinator_label.setWordWrap(True)
        coordinator_card.body.addWidget(self.coordinator_label)
        self.coordinator_start_button = _i18n_widget(QPushButton(source_text("enterprise.coordinator.start")), "enterprise.coordinator.start")
        self.coordinator_stop_button = _i18n_widget(QPushButton(source_text("enterprise.coordinator.stop")), "enterprise.coordinator.stop")
        coordinator_card.body.addWidget(ResponsiveActionBar((
            self.coordinator_start_button, self.coordinator_stop_button,
        )))
        body.addWidget(coordinator_card)

        governance_card = SectionCard(theme, source_text("enterprise.governance.title"), title_key="enterprise.governance.title")
        self.governance_label = _i18n_widget(
            QLabel(source_text("enterprise.governance.hint")),
            "enterprise.governance.hint",
        )
        self.governance_label.setWordWrap(True)
        governance_card.body.addWidget(self.governance_label)
        self.workspace_button = _i18n_widget(QPushButton(source_text("enterprise.governance.create_workspace")), "enterprise.governance.create_workspace")
        self.resource_button = _i18n_widget(QPushButton(source_text("enterprise.governance.register_resource")), "enterprise.governance.register_resource")
        self.audit_query_button = _i18n_widget(QPushButton(source_text("enterprise.governance.audit_query")), "enterprise.governance.audit_query")
        self.ops_dashboard_button = _i18n_widget(QPushButton(source_text("enterprise.governance.dashboard")), "enterprise.governance.dashboard")
        governance_card.body.addWidget(ResponsiveActionBar((
            self.workspace_button, self.resource_button, self.audit_query_button, self.ops_dashboard_button,
        )))
        body.addWidget(governance_card)

        server_card = SectionCard(theme, source_text("enterprise.server.title"), title_key="enterprise.server.title")
        self.server_label = _i18n_widget(
            QLabel(source_text("enterprise.server.hint")),
            "enterprise.server.hint",
        )
        self.server_label.setWordWrap(True)
        self.server_label.setProperty("muted", True)
        server_card.body.addWidget(self.server_label)
        self.server_health_button = _i18n_widget(QPushButton(source_text("enterprise.server.health")), "enterprise.server.health")
        self.server_workers_button = _i18n_widget(QPushButton(source_text("enterprise.server.workers")), "enterprise.server.workers")
        self.server_jobs_button = _i18n_widget(QPushButton(source_text("enterprise.server.jobs")), "enterprise.server.jobs")
        server_card.body.addWidget(ResponsiveActionBar((
            self.server_health_button, self.server_workers_button, self.server_jobs_button,
        )))
        body.addWidget(server_card)
        body.addStretch()

        self.create_button.clicked.connect(self._create_enterprise)
        self.unlock_button.clicked.connect(self._unlock)
        self.login_button.clicked.connect(self._login)
        self.logout_button.clicked.connect(self._logout)
        self.lock_button.clicked.connect(self._lock)
        self.refresh_accounts_button.clicked.connect(self._refresh_accounts)
        self.add_account_button.clicked.connect(self._add_account)
        self.toggle_account_button.clicked.connect(self._toggle_account)
        self.roles_button.clicked.connect(self._change_roles)
        self.rbac_matrix_button.clicked.connect(self._show_rbac_matrix)
        self.password_button.clicked.connect(self._change_password)
        self.delete_account_button.clicked.connect(self._delete_account)
        self.step_up_button.clicked.connect(self._step_up)
        self.vault_health_button.clicked.connect(self._vault_health)
        self.rotate_vault_button.clicked.connect(self._rotate_vault_passphrase)
        self.backup_button.clicked.connect(self._backup)
        self.restore_button.clicked.connect(self._restore)
        self.enroll_campaign_button.clicked.connect(self._create_enrollment_campaign)
        self.enroll_csv_button.clicked.connect(self._import_enrollment_csv)
        self.devices_button.clicked.connect(self._show_devices)
        self.revoke_device_button.clicked.connect(self._revoke_device)
        self.join_button.clicked.connect(self._join_office_enterprise)
        self.office_reconnect_button.clicked.connect(self._reconnect_office_enterprise)
        self.coordinator_start_button.clicked.connect(self._start_coordinator)
        self.coordinator_stop_button.clicked.connect(self._stop_coordinator)
        self.workspace_button.clicked.connect(self._create_workspace)
        self.resource_button.clicked.connect(self._register_resource)
        self.audit_query_button.clicked.connect(self._query_audit)
        self.ops_dashboard_button.clicked.connect(self._show_operations_dashboard)
        self.server_health_button.clicked.connect(self._show_server_health)
        self.server_workers_button.clicked.connect(self._show_server_workers)
        self.server_jobs_button.clicked.connect(self._show_server_jobs)
        self.console_identity_button.clicked.connect(
            lambda: self.scroll_area.verticalScrollBar().setValue(0)
        )
        self.console_policy_button.clicked.connect(
            lambda: self.scroll_area.verticalScrollBar().setValue(
                self.scroll_area.verticalScrollBar().maximum() * 2 // 3
            )
        )
        self.console_fleet_button.clicked.connect(self._open_fleet_surface)
        self.console_server_button.clicked.connect(
            lambda _checked=False: self.surfaceRequested.emit("server")
        )
        self.console_worker_button.clicked.connect(
            lambda _checked=False: self.surfaceRequested.emit("workers")
        )
        self.console_jobs_button.clicked.connect(
            lambda _checked=False: self.surfaceRequested.emit("platform_jobs")
        )
        self.console_audit_button.clicked.connect(
            lambda _checked=False: self.surfaceRequested.emit("audit")
        )
        self.refresh()

    def _open_fleet_surface(self, _checked: bool = False) -> None:
        runtime = str(getattr(self.context, "runtime_mode", "desktop") or "desktop").casefold()
        destination = "server_ops" if runtime in {"server", "worker"} else "server"
        self.surfaceRequested.emit(destination)

    @property
    def service(self):
        return getattr(self.context, "enterprise_identity", None)

    def activated(self) -> None:
        self.refresh()

    def refresh(self) -> None:
        service = self.service
        if service is None:
            self.status_label.setText(current_text("enterprise.status.backend_unavailable"))
            for button in (
                self.create_button, self.unlock_button, self.login_button, self.logout_button, self.lock_button,
                self.refresh_accounts_button, self.add_account_button, self.toggle_account_button, self.roles_button, self.rbac_matrix_button,
                self.password_button, self.delete_account_button, self.step_up_button, self.vault_health_button, self.rotate_vault_button, self.backup_button, self.restore_button,
                self.enroll_campaign_button, self.enroll_csv_button, self.devices_button, self.revoke_device_button, self.office_reconnect_button,
                self.coordinator_start_button, self.coordinator_stop_button, self.workspace_button, self.resource_button, self.audit_query_button, self.ops_dashboard_button,
                self.server_health_button, self.server_workers_button, self.server_jobs_button,
            ):
                button.setEnabled(False)
            return
        status = service.status()
        if not status.configured:
            self.status_label.setText(current_text("enterprise.status.not_configured"))
        elif not status.unlocked:
            self.status_label.setText(current_text("enterprise.status.locked"))
        elif not status.authenticated:
            self.status_label.setText(current_text("enterprise.status.unlocked").format(name=status.enterprise_name, enterprise_id=status.enterprise_id))
        else:
            self.status_label.setText(
                current_text("enterprise.status.authenticated").format(
                    name=status.enterprise_name,
                    enterprise_id=status.enterprise_id,
                    username=status.username,
                    roles=", ".join(status.roles),
                    permissions=", ".join(status.permissions),
                    expires=status.session_expires_at,
                )
            )
        self.create_button.setEnabled(not status.configured)
        self.unlock_button.setEnabled(status.configured and not status.unlocked)
        self.login_button.setEnabled(status.unlocked and not status.authenticated)
        self.logout_button.setEnabled(status.authenticated)
        self.lock_button.setEnabled(status.unlocked)
        for button in (self.refresh_accounts_button, self.add_account_button, self.toggle_account_button, self.roles_button, self.rbac_matrix_button, self.password_button, self.delete_account_button):
            button.setEnabled(status.authenticated and "enterprise.account.manage" in status.permissions)
        self.step_up_button.setEnabled(status.authenticated)
        vault_manage = status.authenticated and "enterprise.vault.manage" in status.permissions
        self.vault_health_button.setEnabled(vault_manage)
        self.rotate_vault_button.setEnabled(vault_manage)
        self.backup_button.setEnabled(vault_manage)
        self.restore_button.setEnabled(status.configured and not status.unlocked)
        enrollment_manage = status.authenticated and "enterprise.enrollment.manage" in status.permissions
        device_manage = status.authenticated and "enterprise.device.manage" in status.permissions
        coordinator_manage = status.authenticated and "enterprise.coordinator.manage" in status.permissions
        workspace_manage = status.authenticated and "enterprise.workspace.manage" in status.permissions
        self.enroll_campaign_button.setEnabled(enrollment_manage)
        self.enroll_csv_button.setEnabled(enrollment_manage)
        self.devices_button.setEnabled(device_manage)
        self.revoke_device_button.setEnabled(device_manage)
                                                                                                   
                                                                     
        self.join_button.setEnabled(True)
        enrollment_service = getattr(self.context, "enrollment", None)
        self.office_reconnect_button.setEnabled(bool(enrollment_service is not None and enrollment_service.device_store.path.exists()))
        coordinator = getattr(self.context, "office_coordinator", None)
        running = bool(coordinator is not None and coordinator.running)
        self.coordinator_start_button.setEnabled(coordinator_manage and not running)
        self.coordinator_stop_button.setEnabled(coordinator_manage and running)
        self.workspace_button.setEnabled(workspace_manage)
        self.resource_button.setEnabled(workspace_manage)
        self.audit_query_button.setEnabled(status.authenticated and "enterprise.audit.read" in status.permissions)
        self.ops_dashboard_button.setEnabled(workspace_manage)
        remote_ops = status.authenticated and "enterprise.remote_ops" in status.permissions
        self.server_health_button.setEnabled(remote_ops)
        self.server_workers_button.setEnabled(remote_ops)
        self.server_jobs_button.setEnabled(remote_ops)
        if coordinator is not None:
            health = coordinator.health()
            self.coordinator_label.setText(
                current_text("enterprise.coordinator.status").format(
                    state=current_text(
                        "enterprise.common.running" if health["running"] else "enterprise.common.stopped"
                    ),
                    coordinator_id=health["coordinator_id"],
                    sessions=health["active_sessions"],
                    challenges=health["pending_challenges"],
                )
            )
        self._refresh_accounts(silent=True)
        try:
            integrity = self.context.security.audit.verify() if self.context.security is not None else {"valid": False, "reason": "security unavailable"}
        except ENTERPRISE_UI_ERRORS as exc:
            integrity = {"valid": False, "reason": f"{type(exc).__name__}: {exc}"}
        self.audit_label.setText(current_text("enterprise.audit.integrity").format(integrity=integrity))
        self.inspectorChanged.emit(current_text("enterprise.page.title"), status.to_dict())








































