from __future__ import annotations

import importlib.util

import pytest

if importlib.util.find_spec("PySide6") is None and importlib.util.find_spec("PySide2") is None:
    pytest.skip("No supported Qt binding is installed", allow_module_level=True)

import dataclasses

from arenyxa.config import AppSettings
from arenyxa.presentation.shell_window import ArenyxaShellWindow
from arenyxa.qt_compat.QtWidgets import QApplication, QMainWindow


def test_shell_owns_splash_authentication_and_main_pages(qapp) -> None:
    shell = ArenyxaShellWindow()
    embedded = QMainWindow()
    shell.show()
    shell.show_authentication(
        device_identity="device-fixture",
        tpm_status="Available",
        fingerprint="abc123",
    )
    shell.attach_main_window(embedded)
    shell.show_main()
    qapp.processEvents()

    assert shell.stack.currentWidget() is shell.main_page
    assert embedded.parent() is shell.main_page
    assert not embedded.isWindow()
    assert shell in QApplication.topLevelWidgets()
    assert embedded not in QApplication.topLevelWidgets()
    shell.close()


def test_root_failure_stays_in_window_and_remains_fail_closed(qapp) -> None:
    shell = ArenyxaShellWindow()
    shell.show_authentication(
        device_identity="device-fixture",
        tpm_status="Unavailable",
        fingerprint="fixture",
    )
    shell.authentication_page.set_failed("signature mismatch")
    assert shell.stack.currentWidget() is shell.authentication_page
    assert not shell.authentication_page.continue_button.isVisibleTo(shell.authentication_page)
    assert not shell.authentication_page.continue_button.isEnabled()
    assert "Root authentication failed" in shell.authentication_page.verification_state.text()
    shell.close()


def test_root_session_is_not_persisted_in_application_settings() -> None:
    names = {field.name for field in dataclasses.fields(AppSettings)}
    assert "root_session" not in names
    assert "active_root_session" not in names
