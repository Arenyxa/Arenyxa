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
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader, ResponsiveActionBar, SectionCard


ENTERPRISE_UI_ERRORS = (ArenyxaError, sqlite3.Error, OSError, RuntimeError, ValueError, TypeError, KeyError)


class EnterpriseIdentityActionsMixin:
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
        except ENTERPRISE_UI_ERRORS as exc:
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
        except ENTERPRISE_UI_ERRORS as exc:
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
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error("企业登录失败", exc)
        finally:
            password = ""
            self.refresh()

    def _logout(self) -> None:
        if self.service is not None:
            try:
                self.service.logout()
            except ENTERPRISE_UI_ERRORS as exc:
                self._show_error("退出企业会话时审计写入失败", exc)
        self.refresh()

    def _lock(self) -> None:
        if self.service is not None:
            try:
                self.service.lock()
            except ENTERPRISE_UI_ERRORS as exc:


                self._show_error("锁定 Vault 时发生错误", exc)
        self.refresh()

    def _refresh_accounts(self, *_args, silent: bool = False) -> None:
        service = self.service
        if service is None:
            return
        try:
            rows = service.accounts()
        except ENTERPRISE_UI_ERRORS as exc:
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
        except ENTERPRISE_UI_ERRORS as exc:
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
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error("Step-up Authentication 失败", exc)
            return False
        finally:
            password = ""
        return True

    def _show_rbac_matrix(self) -> None:
        service = self.service
        if service is None:
            return
        try:
            matrix = service.rbac_matrix()
            self.accounts_view.setPlainText(json.dumps(matrix, ensure_ascii=False, indent=2, default=str))
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error("RBAC Matrix", exc)

    def _vault_health(self) -> None:
        service = self.service
        if service is None:
            return
        try:
            health = service.vault_health()
            QMessageBox.information(self, "Enterprise Vault Health", json.dumps(health, ensure_ascii=False, indent=2, default=str))
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error("Vault Health", exc)

    def _rotate_vault_passphrase(self) -> None:
        service = self.service
        if service is None:
            return
        current = self._prompt_secret("Rotate Vault Passphrase", "Current Vault passphrase:")
        if current is None:
            return
        new_value = self._prompt_secret("Rotate Vault Passphrase", "New Vault passphrase (12+ characters):")
        if new_value is None:
            current = ""
            return
        confirm = self._prompt_secret("Rotate Vault Passphrase", "Confirm new Vault passphrase:")
        if confirm != new_value:
            current = new_value = confirm = ""
            QMessageBox.warning(self, "Rotate Vault Passphrase", "The new Vault passphrases do not match.")
            return
        try:
            service.rotate_vault_passphrase(current, new_value)
            QMessageBox.information(self, "Rotate Vault Passphrase", "Vault key envelope was rotated atomically. The Enterprise data key and encrypted payload remain protected.")
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error("Rotate Vault Passphrase", exc)
        finally:
            current = new_value = confirm = ""
            self.refresh()

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
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error("读取角色失败", exc)
            return
        role, ok = QInputDialog.getItem(self, "新增企业账户", "初始角色：", roles, 0, False)
        if not ok:
            return
        try:
            service.create_account(username, display, password, [role])
        except ENTERPRISE_UI_ERRORS as exc:
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
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error("修改账户状态失败", exc)
        self.refresh()

    def _change_roles(self) -> None:
        service = self.service
        row = self._choose_account("修改角色")
        if service is None or row is None or not self._prompt_step_up():
            return
        try:
            roles = [item["id"] for item in service.roles()]
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error("读取角色失败", exc)
            return
        role, ok = QInputDialog.getItem(self, "修改角色", "选择角色（底层使用 capability / policy / resource 授权）：", roles, 0, False)
        if not ok:
            return
        try:
            service.set_account_roles(row["id"], [role])
        except ENTERPRISE_UI_ERRORS as exc:
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
        except ENTERPRISE_UI_ERRORS as exc:
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
        except ENTERPRISE_UI_ERRORS as exc:
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
        except ENTERPRISE_UI_ERRORS as exc:
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
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error("Vault 恢复失败", exc)
        else:
            QMessageBox.information(self, "Vault 恢复完成", "备份已验证并恢复。请重新解锁和登录。")
        finally:
            passphrase = ""
            self.refresh()
