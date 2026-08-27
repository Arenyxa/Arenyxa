from __future__ import annotations

import os

import pytest

from arenyxa.infrastructure.database import SQLiteStore

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture()
def store(tmp_path):
    database = SQLiteStore(tmp_path / "arenyxa.db")
    database.initialize()
    return database


@pytest.fixture(scope="session")
def qapp():
    from arenyxa.qt_compat import binding_available
    if not binding_available():
        pytest.skip("No supported Qt binding is installed")
    from arenyxa.qt_compat.QtWidgets import QApplication

    application = QApplication.instance() or QApplication([])
    yield application


_ENVIRONMENT_SKIP_MARKERS = (
    "No supported Qt binding is installed",
    "Qt binding unavailable in this validation environment",
)


def pytest_sessionfinish(session, exitstatus):
    if os.environ.get("ARENYXA_CI_FORBID_ENVIRONMENT_SKIPS") != "1":
        return
    rows = list(getattr(session.config, "_arenyxa_forbidden_environment_skips", []))
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        for report in reporter.stats.get("skipped", []):
            detail = str(getattr(report, "longrepr", ""))
            if any(marker in detail for marker in _ENVIRONMENT_SKIP_MARKERS):
                rows.append(f"{getattr(report, 'nodeid', '<test>')}: {detail[-500:]}")
    if rows:
        session.exitstatus = 1
        if reporter is not None:
            reporter.write_sep("=", "forbidden Arenyxa CI environment skips")
            for row in rows[:32]:
                reporter.write_line(row)
