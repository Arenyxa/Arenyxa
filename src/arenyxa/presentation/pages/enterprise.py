from __future__ import annotations
from arenyxa.presentation.pages.enterprise_identity_actions import EnterpriseIdentityActionsMixin
from arenyxa.presentation.pages.enterprise_distributed_actions import EnterpriseDistributedActionsMixin

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
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader, ResponsiveActionBar, SectionCard


ENTERPRISE_UI_ERRORS = (ArenyxaError, sqlite3.Error, OSError, RuntimeError, ValueError, TypeError, KeyError)


class EnterprisePage(EnterpriseIdentityActionsMixin, EnterpriseDistributedActionsMixin, WorkspacePage):
    surfaceRequested = Signal(str)
    






    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        layout = page_layout(self)
        layout.addWidget(PageHeader(
            "企业管理",
            "Identity / Enrollment / Coordinator / Governance / Distributed Runtime",
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

        console_card = SectionCard(theme, "企业功能入口")
        console_hint = QLabel(
            "模式负责进入企业工作环境；Identity、Fleet、Server、Worker、Jobs、Audit 与 Policy 的具体操作继续由 capability policy 授权。"
        )
        console_hint.setWordWrap(True)
        console_hint.setProperty("muted", True)
        console_card.body.addWidget(console_hint)
        self.console_identity_button = QPushButton("Identity")
        self.console_fleet_button = QPushButton("Fleet")
        self.console_server_button = QPushButton("Server")
        self.console_worker_button = QPushButton("Worker")
        self.console_jobs_button = QPushButton("Jobs")
        self.console_audit_button = QPushButton("Audit")
        self.console_policy_button = QPushButton("Policy")
        console_card.body.addWidget(ResponsiveActionBar((
            self.console_identity_button, self.console_fleet_button, self.console_server_button,
            self.console_worker_button, self.console_jobs_button, self.console_audit_button,
            self.console_policy_button,
        )))
        body.addWidget(console_card)

        status_card = SectionCard(theme, "本地企业状态")
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        status_card.body.addWidget(self.status_label)
        self.create_button = QPushButton("创建本地企业")
        self.unlock_button = QPushButton("解锁 Identity Vault")
        self.login_button = QPushButton("企业登录")
        self.logout_button = QPushButton("退出企业会话")
        self.lock_button = QPushButton("锁定 Vault")
        status_card.body.addWidget(ResponsiveActionBar((
            self.create_button, self.unlock_button, self.login_button, self.logout_button, self.lock_button,
        )))
        body.addWidget(status_card)

        account_card = SectionCard(theme, "账户与 RBAC")
        account_hint = QLabel(
            "角色只是产品预设；真正授权由 SecurityKernel 的 capability / policy / resource / context 决策。"
            "禁用账户、修改角色或密码会递增 auth_generation，并立即撤销对应本机会话。"
        )
        account_hint.setWordWrap(True)
        account_hint.setProperty("muted", True)
        account_card.body.addWidget(account_hint)
        self.accounts_view = QPlainTextEdit()
        self.accounts_view.setReadOnly(True)
        self.accounts_view.setMinimumHeight(170)
        account_card.body.addWidget(self.accounts_view)
        self.refresh_accounts_button = QPushButton("刷新账户")
        self.add_account_button = QPushButton("新增账户")
        self.toggle_account_button = QPushButton("禁用 / 启用账户")
        self.roles_button = QPushButton("修改角色")
        self.rbac_matrix_button = QPushButton("RBAC Matrix")
        self.password_button = QPushButton("修改密码")
        self.delete_account_button = QPushButton("删除账户")
        account_card.body.addWidget(ResponsiveActionBar((
            self.refresh_accounts_button, self.add_account_button, self.toggle_account_button,
            self.roles_button, self.rbac_matrix_button, self.password_button, self.delete_account_button,
        )))
        body.addWidget(account_card)

        vault_card = SectionCard(theme, "Identity Vault 与恢复")
        vault_hint = QLabel(
            "Vault 使用认证加密、版本化格式和同目录原子替换。备份与高风险账户治理要求最近一次 step-up authentication。"
            "恢复只能在 Vault 锁定时执行，避免用新持久状态替换仍在运行的旧授权会话。"
        )
        vault_hint.setWordWrap(True)
        vault_hint.setProperty("muted", True)
        vault_card.body.addWidget(vault_hint)
        self.step_up_button = QPushButton("Step-up Authentication")
        self.vault_health_button = QPushButton("Vault Health")
        self.rotate_vault_button = QPushButton("Rotate Vault Passphrase")
        self.backup_button = QPushButton("备份 Vault")
        self.restore_button = QPushButton("恢复 Vault")
        vault_card.body.addWidget(ResponsiveActionBar((
            self.step_up_button, self.vault_health_button, self.rotate_vault_button, self.backup_button, self.restore_button,
        )))
        body.addWidget(vault_card)

        audit_card = SectionCard(theme, "Audit 基础")
        self.audit_label = QLabel()
        self.audit_label.setWordWrap(True)
        audit_card.body.addWidget(self.audit_label)
        body.addWidget(audit_card)

        enrollment_card = SectionCard(theme, "设备加入与信任")
        self.enrollment_label = QLabel("为新设备生成一次性加入凭据，登记设备公钥并限制设备只能加入受信任的企业环境。")
        self.enrollment_label.setWordWrap(True)
        self.enrollment_label.setProperty("muted", True)
        enrollment_card.body.addWidget(self.enrollment_label)
        self.enroll_campaign_button = QPushButton("为账户创建设备加入凭据")
        self.enroll_csv_button = QPushButton("批量导入并创建加入凭据")
        self.devices_button = QPushButton("查看设备")
        self.revoke_device_button = QPushButton("撤销设备")
        self.join_button = QPushButton("加入现有企业")
        self.office_reconnect_button = QPushButton("重新连接企业")
        enrollment_card.body.addWidget(ResponsiveActionBar((
            self.enroll_campaign_button, self.enroll_csv_button, self.devices_button,
            self.revoke_device_button, self.join_button, self.office_reconnect_button,
        )))
        body.addWidget(enrollment_card)

        coordinator_card = SectionCard(theme, "企业局域网协调器")
        self.coordinator_label = QLabel("协调器用于同一企业局域网内的设备注册和连接。局域网发现只负责找到服务地址，真正身份仍由企业签名与 TLS 证书验证。")
        self.coordinator_label.setWordWrap(True)
        coordinator_card.body.addWidget(self.coordinator_label)
        self.coordinator_start_button = QPushButton("启动企业协调器")
        self.coordinator_stop_button = QPushButton("停止企业协调器")
        coordinator_card.body.addWidget(ResponsiveActionBar((
            self.coordinator_start_button, self.coordinator_stop_button,
        )))
        body.addWidget(coordinator_card)

        governance_card = SectionCard(theme, "Enterprise Workspace Governance")
        self.governance_label = QLabel("Workspace / Team / Project 资源边界、资源级 RBAC、Quota、Approval 与 Audit Query 已接入治理层。")
        self.governance_label.setWordWrap(True)
        governance_card.body.addWidget(self.governance_label)
        self.workspace_button = QPushButton("创建 Workspace")
        self.resource_button = QPushButton("登记受治理资源")
        self.audit_query_button = QPushButton("查询最近 Audit")
        self.ops_dashboard_button = QPushButton("Operations Dashboard")
        governance_card.body.addWidget(ResponsiveActionBar((
            self.workspace_button, self.resource_button, self.audit_query_button, self.ops_dashboard_button,
        )))
        body.addWidget(governance_card)

        server_card = SectionCard(theme, "Enterprise Server / Distributed Worker")
        self.server_label = QLabel(
            "Enterprise Server 与 Worker 共享同一 Core Runtime / Task / Run 模型。Desktop 这里只提供受授权的"
            "远程运维视图；Server/Worker 本身仍通过独立 runtime/launcher 运行，不在 UI 内 fork 第二套执行引擎。"
        )
        self.server_label.setWordWrap(True)
        self.server_label.setProperty("muted", True)
        server_card.body.addWidget(self.server_label)
        self.server_health_button = QPushButton("分布式队列健康")
        self.server_workers_button = QPushButton("查看 Worker")
        self.server_jobs_button = QPushButton("查看分布式 Job")
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
            self.status_label.setText("Local Enterprise Identity 后端不可用。")
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
            self.status_label.setText(
                "尚未建立企业身份。你可以创建本地企业，或使用管理员提供的一次性设备加入凭据加入现有企业。"
            )
        elif not status.unlocked:
            self.status_label.setText("本机已配置 Enterprise Identity；Identity Vault 当前锁定。")
        elif not status.authenticated:
            self.status_label.setText(f"{status.enterprise_name} · {status.enterprise_id}\nVault 已解锁，尚未建立企业用户会话。")
        else:
            self.status_label.setText(
                f"{status.enterprise_name} · {status.enterprise_id}\n"
                f"当前账户：{status.username} · Roles: {', '.join(status.roles)}\n"
                f"Permissions: {', '.join(status.permissions)}\nSession expires: {status.session_expires_at}"
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
                f"Coordinator: {'RUNNING' if health['running'] else 'STOPPED'} · ID={health['coordinator_id']} · "
                f"sessions={health['active_sessions']} · challenges={health['pending_challenges']}"
            )
        self._refresh_accounts(silent=True)
        try:
            integrity = self.context.security.audit.verify() if self.context.security is not None else {"valid": False, "reason": "security unavailable"}
        except ENTERPRISE_UI_ERRORS as exc:
            integrity = {"valid": False, "reason": f"{type(exc).__name__}: {exc}"}
        self.audit_label.setText(f"Security Audit integrity: {integrity}")
        self.inspectorChanged.emit("Enterprise", status.to_dict())








































