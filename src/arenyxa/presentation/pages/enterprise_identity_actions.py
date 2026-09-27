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
        name, ok = QInputDialog.getText(self, current_text("enterprise.identity.create_title"), current_text("enterprise.identity.enterprise_name"))
        if not ok or not name.strip():
            return
        username, ok = QInputDialog.getText(self, current_text("enterprise.identity.create_title"), current_text("enterprise.identity.super_admin_username"))
        if not ok or not username.strip():
            return
        display_name, ok = QInputDialog.getText(self, current_text("enterprise.identity.create_title"), current_text("enterprise.identity.admin_display_name"))
        if not ok:
            return
        password = self._prompt_secret(current_text("enterprise.identity.create_title"), current_text("enterprise.identity.super_admin_password"))
        if password is None:
            return
        passphrase = self._prompt_secret(current_text("enterprise.identity.create_title"), current_text("enterprise.identity.vault_passphrase"))
        if passphrase is None:
            return
        confirm = self._prompt_secret(current_text("enterprise.identity.create_title"), current_text("enterprise.identity.vault_passphrase_confirm"))
        if confirm != passphrase:
            QMessageBox.warning(self, current_text("enterprise.identity.create_title"), current_text("enterprise.identity.vault_passphrase_mismatch"))
            return
        try:
            service.create_enterprise(name, username, display_name, password, passphrase)
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.identity.create_failed"), exc)
        else:
            QMessageBox.information(self, current_text("enterprise.identity.created_title"), current_text("enterprise.identity.created_message"))
        finally:
            password = passphrase = confirm = ""
            self.refresh()

    def _unlock(self) -> None:
        service = self.service
        if service is None:
            return
        passphrase = self._prompt_secret(current_text("enterprise.identity.unlock_title"), current_text("enterprise.identity.vault_passphrase_short"))
        if passphrase is None:
            return
        try:
            service.unlock(passphrase)
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.identity.unlock_failed"), exc)
        finally:
            passphrase = ""
            self.refresh()

    def _login(self) -> None:
        service = self.service
        if service is None:
            return
        username, ok = QInputDialog.getText(self, current_text("enterprise.identity.login_title"), current_text("enterprise.identity.username"))
        if not ok or not username.strip():
            return
        password = self._prompt_secret(current_text("enterprise.identity.login_title"), current_text("enterprise.identity.password"))
        if password is None:
            return
        try:
            service.login(username, password)
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.identity.login_failed"), exc)
        finally:
            password = ""
            self.refresh()

    def _logout(self) -> None:
        if self.service is not None:
            try:
                self.service.logout()
            except ENTERPRISE_UI_ERRORS as exc:
                self._show_error(current_text("enterprise.identity.logout_audit_failed"), exc)
        self.refresh()

    def _lock(self) -> None:
        if self.service is not None:
            try:
                self.service.lock()
            except ENTERPRISE_UI_ERRORS as exc:


                self._show_error(current_text("enterprise.identity.lock_failed"), exc)
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
                self._show_error(current_text("enterprise.accounts.read_failed"), exc)
            return
        lines = []
        for row in rows:
            state = "enabled" if row["enabled"] else "disabled"
            lines.append(f"{row['username']} · {row['display_name']} · {state} · roles={','.join(row['roles'])} · gen={row['auth_generation']} · id={row['id']}")
        self.accounts_view.setPlainText("\n".join(lines) if lines else current_text("enterprise.accounts.none"))

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
        selected, ok = QInputDialog.getItem(self, title, current_text("enterprise.accounts.account_label"), labels, 0, False)
        if not ok:
            return None
        account_id = selected.rsplit(" · ", 1)[-1]
        return next((row for row in rows if row["id"] == account_id), None)

    def _prompt_step_up(self) -> bool:
        service = self.service
        if service is None:
            return False
        password = self._prompt_secret(current_text("enterprise.step_up.title"), current_text("enterprise.step_up.password"))
        if password is None:
            return False
        try:
            service.step_up(password)
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.step_up.failed"), exc)
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
            self._show_error(current_text("enterprise.accounts.matrix"), exc)

    def _vault_health(self) -> None:
        service = self.service
        if service is None:
            return
        try:
            health = service.vault_health()
            QMessageBox.information(self, current_text("enterprise.vault.health"), json.dumps(health, ensure_ascii=False, indent=2, default=str))
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.vault.health_failed"), exc)

    def _rotate_vault_passphrase(self) -> None:
        service = self.service
        if service is None:
            return
        current = self._prompt_secret(current_text("enterprise.vault.rotate"), current_text("enterprise.vault.current_passphrase"))
        if current is None:
            return
        new_value = self._prompt_secret(current_text("enterprise.vault.rotate"), current_text("enterprise.vault.new_passphrase"))
        if new_value is None:
            current = ""
            return
        confirm = self._prompt_secret(current_text("enterprise.vault.rotate"), current_text("enterprise.vault.confirm_passphrase"))
        if confirm != new_value:
            current = new_value = confirm = ""
            QMessageBox.warning(self, current_text("enterprise.vault.rotate"), current_text("enterprise.vault.passphrase_mismatch"))
            return
        try:
            service.rotate_vault_passphrase(current, new_value)
            QMessageBox.information(self, current_text("enterprise.vault.rotate"), current_text("enterprise.vault.rotate_success"))
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.vault.rotate_failed"), exc)
        finally:
            current = new_value = confirm = ""
            self.refresh()

    def _step_up(self) -> None:
        if self._prompt_step_up():
            QMessageBox.information(self, current_text("enterprise.step_up.title"), current_text("enterprise.step_up.success"))

    def _add_account(self) -> None:
        service = self.service
        if service is None:
            return
        username, ok = QInputDialog.getText(self, current_text("enterprise.accounts.add"), current_text("enterprise.identity.username"))
        if not ok or not username.strip():
            return
        display, ok = QInputDialog.getText(self, current_text("enterprise.accounts.add"), current_text("enterprise.accounts.display_name"))
        if not ok:
            return
        password = self._prompt_secret(current_text("enterprise.accounts.add"), current_text("enterprise.accounts.initial_password"))
        if password is None:
            return
        try:
            roles = [row["id"] for row in service.roles()]
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.accounts.roles_read_failed"), exc)
            return
        role, ok = QInputDialog.getItem(self, current_text("enterprise.accounts.add"), current_text("enterprise.accounts.initial_role"), roles, 0, False)
        if not ok:
            return
        try:
            service.create_account(username, display, password, [role])
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.accounts.add_failed"), exc)
        finally:
            password = ""
            self.refresh()

    def _toggle_account(self) -> None:
        service = self.service
        row = self._choose_account(current_text("enterprise.accounts.toggle"))
        if service is None or row is None or not self._prompt_step_up():
            return
        try:
            service.set_account_enabled(row["id"], not bool(row["enabled"]))
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.accounts.toggle_failed"), exc)
        self.refresh()

    def _change_roles(self) -> None:
        service = self.service
        row = self._choose_account(current_text("enterprise.accounts.roles"))
        if service is None or row is None or not self._prompt_step_up():
            return
        try:
            roles = [item["id"] for item in service.roles()]
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error("读取角色失败", exc)
            return
        role, ok = QInputDialog.getItem(self, current_text("enterprise.accounts.roles"), current_text("enterprise.accounts.select_role"), roles, 0, False)
        if not ok:
            return
        try:
            service.set_account_roles(row["id"], [role])
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.accounts.roles_failed"), exc)
        self.refresh()

    def _delete_account(self) -> None:
        service = self.service
        row = self._choose_account(current_text("enterprise.accounts.delete"))
        if service is None or row is None or not self._prompt_step_up():
            return
        answer = QMessageBox.question(
            self, current_text("enterprise.accounts.delete_confirm_title"),
            current_text("enterprise.accounts.delete_confirm").format(username=row["username"]),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            service.delete_account(row["id"])
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.accounts.delete_failed"), exc)
        self.refresh()

    def _change_password(self) -> None:
        service = self.service
        row = self._choose_account(current_text("enterprise.accounts.password"))
        if service is None or row is None or not self._prompt_step_up():
            return
        new_password = self._prompt_secret(current_text("enterprise.accounts.password"), current_text("enterprise.accounts.new_password"))
        if new_password is None:
            return
        try:
            service.change_password(row["id"], new_password)
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.accounts.password_failed"), exc)
        finally:
            new_password = ""
            self.refresh()

    def _backup(self) -> None:
        service = self.service
        if service is None or not self._prompt_step_up():
            return
        path, _ = QFileDialog.getSaveFileName(
            self, current_text("enterprise.vault.backup_title"), str(self.context.paths.exports / "Arenyxa_Enterprise_Vault_Backup.aryxbak.json"),
            "Arenyxa Vault Backup (*.aryxbak.json *.json);;JSON (*.json);;All Files (*)",
        )
        if not path:
            return
        passphrase = self._prompt_secret(current_text("enterprise.vault.backup_title"), current_text("enterprise.identity.vault_passphrase_short"))
        if passphrase is None:
            return
        try:
            service.backup(Path(path), passphrase)
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.vault.backup_failed"), exc)
        else:
            QMessageBox.information(self, current_text("enterprise.vault.backup_done_title"), current_text("enterprise.vault.backup_done").format(path=path))
        finally:
            passphrase = ""
            self.refresh()

    def _restore(self) -> None:
        service = self.service
        if service is None:
            return
        path, _ = QFileDialog.getOpenFileName(
            self, current_text("enterprise.vault.restore_title"), str(self.context.paths.exports),
            "Arenyxa Vault Backup (*.aryxbak.json *.json);;JSON (*.json);;All Files (*)",
        )
        if not path:
            return
        passphrase = self._prompt_secret(current_text("enterprise.vault.restore_title"), current_text("enterprise.vault.restore_passphrase"))
        if passphrase is None:
            return
        confirm = QMessageBox.question(
            self, current_text("enterprise.vault.restore_title"),
            current_text("enterprise.vault.restore_confirm"),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        try:
            service.restore(Path(path), passphrase)
        except ENTERPRISE_UI_ERRORS as exc:
            self._show_error(current_text("enterprise.vault.restore_failed"), exc)
        else:
            QMessageBox.information(self, current_text("enterprise.vault.restore_done_title"), current_text("enterprise.vault.restore_done"))
        finally:
            passphrase = ""
            self.refresh()
