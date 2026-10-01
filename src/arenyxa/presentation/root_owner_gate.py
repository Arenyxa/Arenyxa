from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import logging
import time
from pathlib import Path
from typing import Any

from arenyxa.application.developer_access import (
    ROOT_OWNER_MAX_STARTUP_FAILURES,
    root_owner_startup_attempt_budget,
)
from arenyxa.domain.errors import ArenyxaError
from arenyxa.qt_compat.QtCore import QEventLoop, QTimer, Qt
from arenyxa.qt_compat.QtWidgets import QFileDialog, QInputDialog, QLineEdit, QMessageBox
from arenyxa.presentation.background import run_background
from arenyxa.presentation.i18n_runtime import current_text

LOGGER = logging.getLogger(__name__)
ROOT_AUTH_ERRORS = (ArenyxaError, OSError, RuntimeError, ValueError, TypeError, KeyError)


def _sync_root_capability_state(context: Any, manager: Any) -> None:
    """Refresh the read-only Root health projection without changing authority."""
    try:
        context.root_capability_state = manager.root_capability_state()
    except ROOT_AUTH_ERRORS:
        LOGGER.exception("Root capability state refresh failed closed")


def _security_message(status: Any) -> str:
    base = current_text("root_gate.owner.security_message")
    if bool(getattr(status, "locked", False)):
        base += current_text("root_gate.owner.security_locked_suffix")
    return base


def _ask_to_authenticate(status: Any) -> bool:
    box = QMessageBox()
    box.setWindowTitle(current_text("root_gate.owner.auth_window_title"))
    box.setIcon(QMessageBox.Icon.Warning if bool(getattr(status, "locked", False)) else QMessageBox.Icon.Information)
    box.setText(current_text("root_gate.owner.auth_prompt"))
    box.setInformativeText(_security_message(status))
    box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
    box.setDefaultButton(QMessageBox.StandardButton.Yes)
    box.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
    return box.exec() == QMessageBox.StandardButton.Yes


def _notify_locked(reason: str) -> None:
    QMessageBox.critical(
        None,
        current_text("root_gate.owner.locked_title"),
        current_text("root_gate.owner.locked_message").format(
            reason=reason or "ROOT_OWNER_AUTH_REQUIRED"
        ),
    )


def _cancel_startup(manager: Any) -> bool:
    try:
        status = manager.record_root_startup_cancel()
        reason = getattr(status, "reason", "ROOT_OWNER_STARTUP_AUTH_CANCELLED")
    except ROOT_AUTH_ERRORS:
        LOGGER.exception("Failed to persist Root Owner startup cancellation state")
        reason = "ROOT_OWNER_AUTH_STATE_PERSIST_FAILED"
    _notify_locked(reason)
    return False


def _authenticate_owner_device(context: Any, manager: Any, vault_path: str, passphrase: str) -> None:
    from arenyxa.application.root_owner_identity import (
        load_owner_device_vault,
        sign_owner_login_challenge,
    )

    # A registered Root workstation is bound to one verified Owner Login Bundle.
    # Never allow an arbitrary bundle to replace that binding during startup re-auth.
    bundle = manager.load_bound_root_owner_bundle()
    challenge = manager.begin_root_owner_login(bundle)
    vault = load_owner_device_vault(Path(vault_path))
    signature = sign_owner_login_challenge(vault, passphrase, challenge.to_dict(), bundle)
    manager.complete_root_owner_login(challenge.challenge_id, signature)
    authenticated = manager.status()
    if not (
        authenticated.authenticated
        and authenticated.kind == "root_owner"
        and "platform.root" in authenticated.capabilities
    ):
        raise RuntimeError("Root Owner session was not established after successful proof")
    refreshed = manager.root_startup_security_status()
    if refreshed.locked:
        raise RuntimeError("Root workstation startup lock did not clear after valid Root Owner proof")
    context.root_developer_workstation = True
    context.root_workstation_registered = True
    _sync_root_capability_state(context, manager)


def _prompt_owner_secret(context: Any) -> tuple[str, str] | None:
    vault_path, _ = QFileDialog.getOpenFileName(
        None,
        current_text("root_gate.owner.select_vault"),
        str(context.paths.root),
        current_text("root_gate.owner.vault_filter"),
    )
    if not vault_path:
        return None
    passphrase, ok = QInputDialog.getText(
        None,
        current_text("root_gate.owner.passphrase_title"),
        current_text("root_gate.owner.passphrase_prompt"),
        QLineEdit.EchoMode.Password,
    )
    if not ok or not passphrase:
        return None
    return str(vault_path), str(passphrase)


def enforce_root_owner_startup_gate(context: Any) -> bool:
    """Require a fresh Root Owner device-key proof before a registered Root workstation can open."""
    manager = getattr(context, "developer_access", None)
    registered = bool(getattr(context, "root_workstation_registered", False))
    if manager is not None:
        try:
            registered = bool(registered or manager.root_workstation_registered())
        except ROOT_AUTH_ERRORS:
            LOGGER.exception("Root workstation registration probe failed closed")
            registered = True
    if not registered:
        context.root_developer_workstation = False
        return True
    if manager is None or not manager.ready:
        _notify_locked("ROOT_OWNER_TRUST_BACKEND_UNAVAILABLE")
        return False

    status = manager.root_startup_security_status()
    if not _ask_to_authenticate(status):
        return _cancel_startup(manager)

    attempt_budget = root_owner_startup_attempt_budget(status)
    if attempt_budget <= 0:
        _notify_locked(status.reason or "ROOT_OWNER_AUTH_ATTEMPTS_EXHAUSTED")
        return False

    for _attempt in range(attempt_budget):
        secret = _prompt_owner_secret(context)
        if secret is None:
            return _cancel_startup(manager)
        vault_path, passphrase = secret
        try:
            _authenticate_owner_device(context, manager, vault_path, passphrase)
            return True
        except ROOT_AUTH_ERRORS as exc:
            LOGGER.warning("Root Owner startup authentication failed: %s", exc)
            try:
                status = manager.record_root_startup_failure(getattr(exc, "code", type(exc).__name__))
            except ROOT_AUTH_ERRORS:
                LOGGER.exception("Failed to persist Root Owner authentication failure; failing closed")
                _notify_locked("ROOT_OWNER_AUTH_STATE_PERSIST_FAILED")
                return False
            if status.locked:
                _notify_locked(status.reason or "ROOT_OWNER_AUTH_ATTEMPTS_EXHAUSTED")
                return False
            remaining = max(0, int(status.max_attempts) - int(status.failed_attempts))
            if remaining <= 0:
                _notify_locked(status.reason or "ROOT_OWNER_AUTH_ATTEMPTS_EXHAUSTED")
                return False
            QMessageBox.warning(
                None,
                current_text("root_gate.owner.failed_title"),
                current_text("root_gate.owner.failed_message").format(
                    remaining=remaining,
                    code=getattr(exc, "code", type(exc).__name__),
                ),
            )
        finally:
            passphrase = ""
    _notify_locked(status.reason or "ROOT_OWNER_AUTH_ATTEMPTS_EXHAUSTED")
    return False


def authenticate_root_owner_in_shell(context: Any, shell: Any) -> bool:
    """Run mandatory Root authentication inside ArenyxaShellWindow.

    A registered Root workstation is fail-closed: the Main UI is not constructed
    until the fresh Owner-device challenge succeeds for this process.
    """
    manager = getattr(context, "developer_access", None)
    registered = bool(getattr(context, "root_workstation_registered", False))
    if manager is not None:
        try:
            registered = bool(registered or manager.root_workstation_registered())
        except ROOT_AUTH_ERRORS:
            LOGGER.exception("Root workstation registration probe failed closed")
            registered = True
    if not registered:
        context.root_developer_workstation = False
        return True

    binding = None
    if manager is not None:
        try:
            binding = manager.root_workstation_status()
        except ROOT_AUTH_ERRORS:
            LOGGER.exception("Root workstation identity probe failed")
    protector = getattr(getattr(manager, "root_workstation", None), "protector", None)
    tpm_status = (
        current_text("root_gate.owner.protector_available").format(
            provider=getattr(protector, "name", "protected-key")
        )
        if bool(getattr(getattr(manager, "root_workstation", None), "supported", False))
        else current_text("root_gate.owner.protector_unavailable")
    )
    shell.show_authentication(
        device_identity=str(
            getattr(binding, "owner_id", "")
            or current_text("root_gate.owner.registered_workstation")
        ),
        tpm_status=tpm_status,
        fingerprint=str(
            getattr(binding, "fingerprint", "")
            or current_text("root_gate.owner.pending_challenge")
        ),
    )
    if manager is None or not manager.ready:
        shell.authentication_page.set_failed(current_text("root_gate.owner.backend_unavailable"))

    loop = QEventLoop(shell)
    result = {"mode": "denied"}
    authentication = shell.authentication_page

    def verify(vault_path: str, passphrase: str) -> None:
        if manager is None or not manager.ready:
            authentication.set_failed(current_text("root_gate.owner.backend_unavailable"))
            return

        started = time.perf_counter()

        def worker() -> bool:
            _authenticate_owner_device(context, manager, vault_path, passphrase)
            return True

        def completed(_value: object) -> None:
            context.navigation_metrics["root_unlock_latency_ms"] = (
                time.perf_counter() - started
            ) * 1000.0
            authentication.set_authenticated()
            result["mode"] = "root"
            QTimer.singleShot(80, loop.quit)

        def failed(message: str) -> None:
            context.navigation_metrics["root_unlock_latency_ms"] = (
                time.perf_counter() - started
            ) * 1000.0
            LOGGER.warning("Root Owner shell authentication failed: %s", message)
            try:
                manager.record_root_startup_failure("ROOT_OWNER_SHELL_AUTH_FAILED")
            except ROOT_AUTH_ERRORS:
                LOGGER.exception("Failed to persist Root shell authentication failure")
            context.root_developer_workstation = False
            authentication.set_failed(message)

        run_background(worker, completed, failed)

    authentication.verifyRequested.connect(verify)
    shell.destroyed.connect(loop.quit)
    loop.exec()
    try:
        authentication.verifyRequested.disconnect(verify)
    except (RuntimeError, TypeError):
        record_current_exception(__name__, 'authenticate_root_owner_in_shell:269')
    return result["mode"] == "root"
