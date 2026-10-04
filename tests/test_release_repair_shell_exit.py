from __future__ import annotations

import os
import subprocess
import sys
import textwrap

from arenyxa.presentation.main_window_operations import MainWindowOperationsMixin
from arenyxa.presentation.shell_window import ArenyxaShellWindow
from arenyxa.qt_compat.QtCore import Signal
from arenyxa.qt_compat.QtWidgets import QMainWindow


class RepairMainWindow(QMainWindow):
    shellCloseRequested = Signal()
    request_repair_exit = MainWindowOperationsMixin.request_repair_exit


def test_repair_exit_emits_shell_close_contract_after_embedded_window_closes(qapp):
    shell = ArenyxaShellWindow()
    main = RepairMainWindow()
    shell.attach_main_window(main)
    shell.show_main()
    shell.show()
    qapp.processEvents()
    closed = []
    shell.closeRequested.connect(lambda: closed.append(True))
    try:
        main.request_repair_exit()
        qapp.processEvents()
        assert not main.isVisible()
        assert not shell.isVisible()
        assert closed == [True]
    finally:
        shell.close()


def test_repair_exit_terminates_explicit_quit_application_event_loop():
    code = textwrap.dedent('''
        from arenyxa.qt_compat.QtCore import QTimer, Signal
        from arenyxa.qt_compat.QtWidgets import QApplication, QMainWindow
        from arenyxa.presentation.shell_window import ArenyxaShellWindow
        from arenyxa.presentation.main_window_operations import MainWindowOperationsMixin
        class RepairMain(QMainWindow):
            shellCloseRequested = Signal()
            request_repair_exit = MainWindowOperationsMixin.request_repair_exit
        app = QApplication([])
        app.setQuitOnLastWindowClosed(False)
        shell = ArenyxaShellWindow()
        main = RepairMain()
        shell.attach_main_window(main)
        shell.show_main()
        shell.show()
        shell.closeRequested.connect(app.quit)
        QTimer.singleShot(25, main.request_repair_exit)
        QTimer.singleShot(1500, lambda: app.exit(77))
        raise SystemExit(app.exec())
    ''')
    environment = os.environ.copy()
    environment['QT_QPA_PLATFORM'] = 'offscreen'
    result = subprocess.run(
        [sys.executable, '-B', '-c', code], env=environment,
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
