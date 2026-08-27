from __future__ import annotations

import json
from pathlib import Path

from arenyxa.qt_compat.QtCore import Qt
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

from arenyxa.enterprise.coordinator import CoordinatorClient
from arenyxa.enterprise.enrollment import parse_enrollment_token, verify_enrollment_token
from arenyxa.infrastructure.atomic_io import atomic_write_bytes, atomic_write_json, read_bytes_limited
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader, ResponsiveActionBar, SectionCard


class EnterprisePage(WorkspacePage):
    






    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        layout = page_layout(self)
        layout.addWidget(PageHeader(
            "企业管理",
            "Phase 7–12 · Local Identity / Enrollment / Coordinator / Governance / Server",
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
        self.password_button = QPushButton("修改密码")
        self.delete_account_button = QPushButton("删除账户")
        account_card.body.addWidget(ResponsiveActionBar((
            self.refresh_accounts_button, self.add_account_button, self.toggle_account_button,
            self.roles_button, self.password_button, self.delete_account_button,
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
        self.backup_button = QPushButton("备份 Vault")
        self.restore_button = QPushButton("恢复 Vault")
        vault_card.body.addWidget(ResponsiveActionBar((
            self.step_up_button, self.backup_button, self.restore_button,
        )))
        body.addWidget(vault_card)

        audit_card = SectionCard(theme, "Audit 基础")
        self.audit_label = QLabel()
        self.audit_label.setWordWrap(True)
        audit_card.body.addWidget(self.audit_label)
        body.addWidget(audit_card)

        enrollment_card = SectionCard(theme, "Phase 8 · Enrollment / Device Trust / Domain Lock")
        self.enrollment_label = QLabel("一次性 Enrollment Credential、批量 Campaign、设备公钥登记与 Domain Lock 已接入。")
        self.enrollment_label.setWordWrap(True)
        self.enrollment_label.setProperty("muted", True)
        enrollment_card.body.addWidget(self.enrollment_label)
        self.enroll_campaign_button = QPushButton("为账户创建 Enrollment")
        self.enroll_csv_button = QPushButton("CSV 批量导入 + Campaign")
        self.devices_button = QPushButton("查看设备")
        self.revoke_device_button = QPushButton("撤销设备")
        self.join_button = QPushButton("加入 Office Enterprise")
        self.office_reconnect_button = QPushButton("重新连接 Office Enterprise")
        enrollment_card.body.addWidget(ResponsiveActionBar((
            self.enroll_campaign_button, self.enroll_csv_button, self.devices_button,
            self.revoke_device_button, self.join_button, self.office_reconnect_button,
        )))
        body.addWidget(enrollment_card)

        coordinator_card = SectionCard(theme, "Phase 9 · Office Enterprise Coordinator")
        self.coordinator_label = QLabel("Coordinator 当前未运行。LAN Discovery 仅用于发现，真正信任由 Enterprise Root 签名身份 + TLS 证书绑定建立。")
        self.coordinator_label.setWordWrap(True)
        coordinator_card.body.addWidget(self.coordinator_label)
        self.coordinator_start_button = QPushButton("启动 Coordinator")
        self.coordinator_stop_button = QPushButton("停止 Coordinator")
        coordinator_card.body.addWidget(ResponsiveActionBar((
            self.coordinator_start_button, self.coordinator_stop_button,
        )))
        body.addWidget(coordinator_card)

        governance_card = SectionCard(theme, "Phase 10 · Enterprise Workspace Governance")
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

        server_card = SectionCard(theme, "Phase 11 · Enterprise Server / Distributed Worker")
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
        self.password_button.clicked.connect(self._change_password)
        self.delete_account_button.clicked.connect(self._delete_account)
        self.step_up_button.clicked.connect(self._step_up)
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
        self.refresh()

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
                self.refresh_accounts_button, self.add_account_button, self.toggle_account_button, self.roles_button,
                self.password_button, self.delete_account_button, self.step_up_button, self.backup_button, self.restore_button,
                self.enroll_campaign_button, self.enroll_csv_button, self.devices_button, self.revoke_device_button, self.office_reconnect_button,
                self.coordinator_start_button, self.coordinator_stop_button, self.workspace_button, self.resource_button, self.audit_query_button, self.ops_dashboard_button,
                self.server_health_button, self.server_workers_button, self.server_jobs_button,
            ):
                button.setEnabled(False)
            return
        status = service.status()
        if not status.configured:
            self.status_label.setText("尚未创建本地企业。创建后会初始化 Enterprise ID、Enterprise Root Identity、加密 Vault 和 Local Super Administrator。")
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
        for button in (self.refresh_accounts_button, self.add_account_button, self.toggle_account_button, self.roles_button, self.password_button, self.delete_account_button):
            button.setEnabled(status.authenticated and "enterprise.account.manage" in status.permissions)
        self.step_up_button.setEnabled(status.authenticated)
        self.backup_button.setEnabled(status.authenticated and "enterprise.policy.modify" in status.permissions)
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
        except Exception as exc:
            integrity = {"valid": False, "reason": f"{type(exc).__name__}: {exc}"}
        self.audit_label.setText(f"Security Audit integrity: {integrity}")
        self.inspectorChanged.emit("Enterprise", status.to_dict())

    def _prompt_secret(self, title: str, label: str) -> str | None:
        value, ok = QInputDialog.getText(self, title, label, QLineEdit.EchoMode.Password)
        return str(value) if ok and value else None

    def _show_error(self, title: str, exc: Exception) -> None:
        code = getattr(exc, "code", type(exc).__name__)
        QMessageBox.warning(self, title, f"{code}\n\n{exc}")

    def _create_enterprise(self) -> None:
        service = self.service
        if service is None:
            return
        name, ok = QInputDialog.getText(self, "创建本地企业", "企业名称：")
        if not ok or not name.strip():
            return
        username, ok = QInputDialog.getText(self, "创建本地企业", "Local Super Administrator 用户名：")
        if not ok or not username.strip():
            return
        display_name, ok = QInputDialog.getText(self, "创建本地企业", "管理员显示名称：")
        if not ok:
            return
        password = self._prompt_secret("创建本地企业", "Super Administrator 密码（至少 12 个字符）：")
        if password is None:
            return
        passphrase = self._prompt_secret("创建本地企业", "Identity Vault 口令（至少 12 个字符，请与账户密码区分）：")
        if passphrase is None:
            return
        confirm = self._prompt_secret("创建本地企业", "再次输入 Identity Vault 口令：")
        if confirm != passphrase:
            QMessageBox.warning(self, "创建本地企业", "两次 Vault 口令不一致。")
            return
        try:
            service.create_enterprise(name, username, display_name, password, passphrase)
        except Exception as exc:
            self._show_error("创建本地企业失败", exc)
        else:
            QMessageBox.information(self, "本地企业已创建", "Enterprise Identity Vault 已初始化。请使用刚创建的 Super Administrator 登录。")
        finally:
            password = passphrase = confirm = ""
            self.refresh()

    def _unlock(self) -> None:
        service = self.service
        if service is None:
            return
        passphrase = self._prompt_secret("解锁 Identity Vault", "Vault 口令：")
        if passphrase is None:
            return
        try:
            service.unlock(passphrase)
        except Exception as exc:
            self._show_error("解锁失败", exc)
        finally:
            passphrase = ""
            self.refresh()

    def _login(self) -> None:
        service = self.service
        if service is None:
            return
        username, ok = QInputDialog.getText(self, "企业登录", "用户名：")
        if not ok or not username.strip():
            return
        password = self._prompt_secret("企业登录", "密码：")
        if password is None:
            return
        try:
            service.login(username, password)
        except Exception as exc:
            self._show_error("企业登录失败", exc)
        finally:
            password = ""
            self.refresh()

    def _logout(self) -> None:
        if self.service is not None:
            try:
                self.service.logout()
            except Exception as exc:
                self._show_error("退出企业会话时审计写入失败", exc)
        self.refresh()

    def _lock(self) -> None:
        if self.service is not None:
            try:
                self.service.lock()
            except Exception as exc:
                                                                                                
                                                                                          
                self._show_error("锁定 Vault 时发生错误", exc)
        self.refresh()

    def _refresh_accounts(self, *_args, silent: bool = False) -> None:
        service = self.service
        if service is None:
            return
        try:
            rows = service.accounts()
        except Exception as exc:
            self.accounts_view.clear()
            if not silent:
                self._show_error("读取账户失败", exc)
            return
        lines = []
        for row in rows:
            state = "enabled" if row["enabled"] else "disabled"
            lines.append(f"{row['username']} · {row['display_name']} · {state} · roles={','.join(row['roles'])} · gen={row['auth_generation']} · id={row['id']}")
        self.accounts_view.setPlainText("\n".join(lines) if lines else "暂无可显示账户。")

    def _choose_account(self, title: str):
        service = self.service
        if service is None:
            return None
        try:
            rows = service.accounts()
        except Exception as exc:
            self._show_error(title, exc)
            return None
        labels = [f"{row['username']} · {row['id']}" for row in rows]
        if not labels:
            return None
        selected, ok = QInputDialog.getItem(self, title, "账户：", labels, 0, False)
        if not ok:
            return None
        account_id = selected.rsplit(" · ", 1)[-1]
        return next((row for row in rows if row["id"] == account_id), None)

    def _prompt_step_up(self) -> bool:
        service = self.service
        if service is None:
            return False
        password = self._prompt_secret("Step-up Authentication", "重新输入当前企业账户密码：")
        if password is None:
            return False
        try:
            service.step_up(password)
        except Exception as exc:
            self._show_error("Step-up Authentication 失败", exc)
            return False
        finally:
            password = ""
        return True

    def _step_up(self) -> None:
        if self._prompt_step_up():
            QMessageBox.information(self, "Step-up Authentication", "高风险操作认证已刷新，有效时间为 5 分钟。")

    def _add_account(self) -> None:
        service = self.service
        if service is None:
            return
        username, ok = QInputDialog.getText(self, "新增企业账户", "用户名：")
        if not ok or not username.strip():
            return
        display, ok = QInputDialog.getText(self, "新增企业账户", "显示名称：")
        if not ok:
            return
        password = self._prompt_secret("新增企业账户", "初始密码（至少 12 个字符）：")
        if password is None:
            return
        try:
            roles = [row["id"] for row in service.roles()]
        except Exception as exc:
            self._show_error("读取角色失败", exc)
            return
        role, ok = QInputDialog.getItem(self, "新增企业账户", "初始角色：", roles, 0, False)
        if not ok:
            return
        try:
            service.create_account(username, display, password, [role])
        except Exception as exc:
            self._show_error("新增账户失败", exc)
        finally:
            password = ""
            self.refresh()

    def _toggle_account(self) -> None:
        service = self.service
        row = self._choose_account("禁用 / 启用账户")
        if service is None or row is None or not self._prompt_step_up():
            return
        try:
            service.set_account_enabled(row["id"], not bool(row["enabled"]))
        except Exception as exc:
            self._show_error("修改账户状态失败", exc)
        self.refresh()

    def _change_roles(self) -> None:
        service = self.service
        row = self._choose_account("修改角色")
        if service is None or row is None or not self._prompt_step_up():
            return
        try:
            roles = [item["id"] for item in service.roles()]
        except Exception as exc:
            self._show_error("读取角色失败", exc)
            return
        role, ok = QInputDialog.getItem(self, "修改角色", "选择角色（底层使用 capability / policy / resource 授权）：", roles, 0, False)
        if not ok:
            return
        try:
            service.set_account_roles(row["id"], [role])
        except Exception as exc:
            self._show_error("修改角色失败", exc)
        self.refresh()

    def _delete_account(self) -> None:
        service = self.service
        row = self._choose_account("删除账户")
        if service is None or row is None or not self._prompt_step_up():
            return
        answer = QMessageBox.question(
            self, "确认删除账户",
            f"删除 {row['username']} 后无法通过本地 Enterprise Identity 登录。\n\n最后一个启用的 Super Administrator 永远不能删除。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            service.delete_account(row["id"])
        except Exception as exc:
            self._show_error("删除账户失败", exc)
        self.refresh()

    def _change_password(self) -> None:
        service = self.service
        row = self._choose_account("修改密码")
        if service is None or row is None or not self._prompt_step_up():
            return
        new_password = self._prompt_secret("修改密码", "新密码（至少 12 个字符）：")
        if new_password is None:
            return
        try:
            service.change_password(row["id"], new_password)
        except Exception as exc:
            self._show_error("修改密码失败", exc)
        finally:
            new_password = ""
            self.refresh()

    def _backup(self) -> None:
        service = self.service
        if service is None or not self._prompt_step_up():
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "备份 Enterprise Identity Vault", str(self.context.paths.exports / "Arenyxa_Enterprise_Vault_Backup.aryxbak.json"),
            "Arenyxa Vault Backup (*.aryxbak.json *.json);;JSON (*.json);;All Files (*)",
        )
        if not path:
            return
        passphrase = self._prompt_secret("备份 Enterprise Identity Vault", "Vault 口令：")
        if passphrase is None:
            return
        try:
            service.backup(Path(path), passphrase)
        except Exception as exc:
            self._show_error("Vault 备份失败", exc)
        else:
            QMessageBox.information(self, "Vault 备份完成", f"已写入：{path}")
        finally:
            passphrase = ""
            self.refresh()

    def _restore(self) -> None:
        service = self.service
        if service is None:
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "恢复 Enterprise Identity Vault", str(self.context.paths.exports),
            "Arenyxa Vault Backup (*.aryxbak.json *.json);;JSON (*.json);;All Files (*)",
        )
        if not path:
            return
        passphrase = self._prompt_secret("恢复 Enterprise Identity Vault", "备份对应的 Vault 口令：")
        if passphrase is None:
            return
        confirm = QMessageBox.question(
            self, "恢复 Enterprise Identity Vault",
            "恢复会原子替换当前本地 Enterprise Vault。当前 Vault 必须保持锁定。继续？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        try:
            service.restore(Path(path), passphrase)
        except Exception as exc:
            self._show_error("Vault 恢复失败", exc)
        else:
            QMessageBox.information(self, "Vault 恢复完成", "备份已验证并恢复。请重新解锁和登录。")
        finally:
            passphrase = ""
            self.refresh()


    def _export_enrollment_tokens(self, result: dict) -> None:
        tokens = list(result.get("tokens") or [])
        if not tokens:
            return
        directory = QFileDialog.getExistingDirectory(self, "保存 Enrollment Credential", str(self.context.paths.exports))
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
        QMessageBox.information(self, "Enrollment Credential 已导出", f"已导出 {len(tokens)} 个一次性 Credential 与 QR-ready payload。\n请通过受信任渠道分发。")

    def _create_enrollment_campaign(self) -> None:
        enrollment = getattr(self.context, "enrollment", None)
        row = self._choose_account("创建 Enrollment Credential")
        if enrollment is None or row is None or not self._prompt_step_up():
            return
        title, ok = QInputDialog.getText(self, "Enrollment Campaign", "Campaign 名称：")
        if not ok:
            return
        try:
            result = enrollment.create_campaign(title or "Enrollment Campaign", [row["id"]])
            self._export_enrollment_tokens(result)
        except Exception as exc:
            self._show_error("创建 Enrollment 失败", exc)
        self.refresh()

    def _import_enrollment_csv(self) -> None:
        enrollment = getattr(self.context, "enrollment", None)
        if enrollment is None or not self._prompt_step_up():
            return
        path, _ = QFileDialog.getOpenFileName(self, "导入企业成员 CSV", str(self.context.paths.root), "CSV (*.csv);;All Files (*)")
        if not path:
            return
        try:
            result = enrollment.import_members_csv(Path(path))
            self._export_enrollment_tokens(result)
            QMessageBox.information(self, "批量 Enrollment", f"创建账户 {len(result.get('accounts', []))} 个。临时密码只在本次结果中生成，请安全保存。")
        except Exception as exc:
            self._show_error("CSV Enrollment 失败", exc)
        self.refresh()

    def _show_devices(self) -> None:
        enrollment = getattr(self.context, "enrollment", None)
        if enrollment is None:
            return
        try:
            rows = enrollment.list_devices()
        except Exception as exc:
            self._show_error("读取设备失败", exc)
            return
        text = "\n".join(f"{row['id']} · {row.get('username','')} · {row.get('status','')} · {row.get('fingerprint','')[:16]}…" for row in rows) or "暂无已注册设备。"
        QMessageBox.information(self, "Enterprise Device Registry", text)

    def _revoke_device(self) -> None:
        enrollment = getattr(self.context, "enrollment", None)
        if enrollment is None or not self._prompt_step_up():
            return
        try:
            rows = enrollment.list_devices()
        except Exception as exc:
            self._show_error("读取设备失败", exc); return
        labels = [f"{row['id']} · {row.get('username','')} · {row.get('status','')}" for row in rows if row.get("status") == "active"]
        if not labels:
            return
        selected, ok = QInputDialog.getItem(self, "撤销设备", "设备：", labels, 0, False)
        if not ok:
            return
        try:
            enrollment.revoke_device(selected.split(" · ", 1)[0])
        except Exception as exc:
            self._show_error("撤销设备失败", exc)
        self.refresh()

    def _join_office_enterprise(self) -> None:
        enrollment = getattr(self.context, "enrollment", None)
        if enrollment is None:
            return
        path, _ = QFileDialog.getOpenFileName(self, "选择 Enrollment Credential", str(self.context.paths.root), "Arenyxa Enrollment (*.aryxenroll.json *.json);;JSON (*.json)")
        if not path:
            return
        endpoint, ok = QInputDialog.getText(self, "加入 Office Enterprise", "Coordinator 地址（host:port）：")
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
            except Exception:
                enrollment.device_store.rollback_prepared_enrollment(rollback)
                raise
            QMessageBox.information(self, "已加入企业", f"设备已注册：{enrolled['device_id']}\nDevice-auth session 已建立，TTL={session['expires_in']} 秒。")
        except Exception as exc:
            self._show_error("加入企业失败", exc)
        self.refresh()

    def _reconnect_office_enterprise(self) -> None:
        enrollment = getattr(self.context, "enrollment", None)
        if enrollment is None or not enrollment.device_store.path.exists():
            return
        try:
            binding = enrollment.device_store.office_binding()
            public = enrollment.device_store.load_public()
            if not binding:
                raise RuntimeError("当前设备没有已验证的 Office Coordinator 绑定；请先完成一次 Enrollment。")
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
                self, "Office Enterprise 已重新认证",
                f"Coordinator={health.get('coordinator_id','')}\nDevice={session.get('device_id','')}\nTTL={session.get('expires_in',0)} 秒",
            )
        except Exception as exc:
            self._show_error("Office Enterprise 重连失败", exc)

    def _start_coordinator(self) -> None:
        coordinator = getattr(self.context, "office_coordinator", None)
        if coordinator is None or not self._prompt_step_up():
            return
        bind, ok = QInputDialog.getText(self, "启动 Office Coordinator", "监听地址（办公室 LAN 可使用 0.0.0.0）：", text="127.0.0.1")
        if not ok:
            return
        try:
            host, port = coordinator.start_tls(bind.strip() or "127.0.0.1", 0)
            QMessageBox.information(self, "Office Coordinator 已启动", f"TLS Coordinator 正在监听 {host}:{port}\nLAN Discovery 只应广播这个位置，不广播 Enrollment secret。")
        except Exception as exc:
            self._show_error("Coordinator 启动失败", exc)
        self.refresh()

    def _stop_coordinator(self) -> None:
        coordinator = getattr(self.context, "office_coordinator", None)
        if coordinator is None:
            return
        try:
            coordinator.stop()
        except Exception as exc:
            self._show_error("Coordinator 停止失败", exc)
        self.refresh()

    def _create_workspace(self) -> None:
        governance = getattr(self.context, "enterprise_governance", None)
        if governance is None:
            return
        title, ok = QInputDialog.getText(self, "创建 Enterprise Workspace", "Workspace 名称：")
        if not ok or not title.strip():
            return
        try:
            workspace_id = governance.create_workspace(title)
            QMessageBox.information(self, "Workspace 已创建", workspace_id)
        except Exception as exc:
            self._show_error("创建 Workspace 失败", exc)
        self.refresh()

    def _register_resource(self) -> None:
        governance = getattr(self.context, "enterprise_governance", None)
        if governance is None:
            return
        try:
            snapshot = governance.snapshot()
            workspaces = list(snapshot.get("workspaces", {}).values())
        except Exception as exc:
            self._show_error("读取治理状态失败", exc); return
        if not workspaces:
            QMessageBox.information(self, "登记资源", "请先创建 Workspace。")
            return
        labels = [f"{row['title']} · {row['id']}" for row in workspaces]
        selected, ok = QInputDialog.getItem(self, "登记受治理资源", "Workspace：", labels, 0, False)
        if not ok:
            return
        workspace_id = selected.rsplit(" · ", 1)[-1]
        kind, ok = QInputDialog.getItem(self, "登记受治理资源", "资源类型：", ["workflow", "dataset", "capture", "schedule", "worker", "project"], 0, False)
        if not ok:
            return
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
        except Exception as exc:
            self._show_error("读取本地资源失败", exc); return
        candidates = [(resource_id, title) for resource_id, title in candidates if resource_id]
        if not candidates:
            QMessageBox.information(self, "登记资源", "当前没有可登记的该类型本地资源。请先创建实际资源，再将其纳入 Enterprise Governance。")
            return
        labels = [f"{title} · {resource_id}" for resource_id, title in candidates]
        selected_resource, ok = QInputDialog.getItem(self, "登记受治理资源", "本地资源：", labels, 0, False)
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
            QMessageBox.information(self, "资源已纳入治理", rid)
        except Exception as exc:
            self._show_error("登记资源失败", exc)
        self.refresh()

    def _query_audit(self) -> None:
        governance = getattr(self.context, "enterprise_governance", None)
        if governance is None:
            return
        try:
            rows = governance.query_audit(limit=30)
            text = "\n".join(f"{row.get('time','')} · {row.get('actor','')} · {row.get('action','')} · {row.get('resource','')} · {row.get('decision','')}" for row in rows) or "暂无 Audit 记录。"
            QMessageBox.information(self, "Enterprise Audit Query", text)
        except Exception as exc:
            self._show_error("Audit Query 失败", exc)
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
            text = (
                f"Workspaces: {snapshot['workspaces']}\n"
                f"Teams: {snapshot['teams']}\n"
                f"Governed resources: {snapshot['resources']} · {snapshot['resources_by_kind']}\n"
                f"Pending approvals: {snapshot['pending_approvals']}\n"
                f"Top quota pressure: {snapshot['quota_pressure'][:8]}\n\n"
                f"Coordinator: {coordinator_health}\n\n"
                f"Resource Governor: {governor_state}"
            )
            QMessageBox.information(self, "Enterprise Operations Dashboard", text)
        except Exception as exc:
            self._show_error("Operations Dashboard 读取失败", exc)

    @property
    def enterprise_server(self):
        return getattr(self.context, "enterprise_server", None)

    @staticmethod
    def _bounded_lines(rows, formatter, *, limit: int = 120) -> str:
        materialized = list(rows or [])
        visible = materialized[:limit]
        text = "\n".join(formatter(row) for row in visible)
        if len(materialized) > limit:
            text += f"\n… 其余 {len(materialized) - limit} 条已省略"
        return text or "暂无记录。"

    def _distributed_snapshot(self) -> dict:
        runtime = self.enterprise_server
        if runtime is None:
            raise RuntimeError("Enterprise Server runtime 后端不可用。")
                                                                                               
                                                                                         
        return runtime.remote_ops_snapshot()

    def _show_server_health(self) -> None:
        try:
            snapshot = self._distributed_snapshot()
            queue = dict(snapshot.get("queue") or {})
            self.server_label.setText(
                f"Distributed Queue · integrity={queue.get('database_integrity', 'unknown')} · "
                f"jobs={queue.get('jobs', {})} · workers={queue.get('workers', {})}"
            )
            QMessageBox.information(
                self,
                "Enterprise Distributed Queue Health",
                json.dumps(queue, ensure_ascii=False, indent=2)[:12000],
            )
        except Exception as exc:
            self._show_error("读取分布式队列健康失败", exc)

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
            QMessageBox.information(self, "Enterprise Workers", text)
        except Exception as exc:
            self._show_error("读取 Worker 失败", exc)

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
            QMessageBox.information(self, "Enterprise Distributed Jobs", text)
        except Exception as exc:
            self._show_error("读取分布式 Job 失败", exc)

