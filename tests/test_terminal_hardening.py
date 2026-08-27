from __future__ import annotations

import os
import shlex
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

from arenyxa.application.terminal import TerminalMode, TerminalResult, TerminalSession


def _python_direct(code: str) -> str:
    if os.name == "nt":
                                                                                        
                                                                                      
                                                                                         
        return subprocess.list2cmdline([sys.executable, "-c", code])
    executable = shlex.quote(sys.executable)
    return f"{executable} -c {shlex.quote(code)}"


def test_terminal_cwd_is_confined_to_projects_root(tmp_path: Path) -> None:
    root = tmp_path / "projects"
    nested = root / "alpha" / "beta"
    nested.mkdir(parents=True)
    (nested / "sample.txt").write_text("ok", encoding="utf-8")
    session = TerminalSession(root)

    assert session.set_cwd("alpha") == (root / "alpha").resolve()
    assert session.set_cwd("beta") == nested.resolve()
    rows = session.list_directory()
    assert rows == [{"name": "sample.txt", "type": "file", "size": 2}]

    with pytest.raises(PermissionError):
        session.set_cwd("../../..")
    with pytest.raises(PermissionError):
        session.list_directory(tmp_path)

    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "escape-link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pass
    else:
        with pytest.raises(PermissionError):
            session.set_cwd(link)


def test_terminal_environment_is_session_scoped_and_redacted(tmp_path: Path) -> None:
    session = TerminalSession(tmp_path / "projects")
    session.set_environment("ARENYXA_TEST_VALUE", "visible")
    session.set_environment("ARENYXA_API_KEY", "super-secret")
    session.set_environment("ARENYXA_ENDPOINT", "https://user:password@example.com/api")

    values = dict(session.environment_items("ARENYXA_"))
    assert values["ARENYXA_TEST_VALUE"] == "visible"
    assert values["ARENYXA_API_KEY"] == "<redacted>"
    assert values["ARENYXA_ENDPOINT"] == "<redacted>"
    assert session.unset_environment("ARENYXA_TEST_VALUE") is True
    assert session.unset_environment("ARENYXA_TEST_VALUE") is False

    with pytest.raises(ValueError):
        session.set_environment("NOT VALID", "x")


def test_terminal_redacts_secrets_before_history_or_display(tmp_path: Path) -> None:
    session = TerminalSession(tmp_path / "projects")
    command = "curl -H 'Authorization: Bearer abc.def' --api-key topsecret https://example.com"
    redacted = session.redact_command(command)
    assert "abc.def" not in redacted
    assert "topsecret" not in redacted
    assert redacted.count("<redacted>") >= 2

    session.remember("setenv ARENYXA_API_KEY=super-secret")
    assert "super-secret" not in session.history()[-1]


def test_terminal_history_is_bounded_and_deduplicates_adjacent_entries(tmp_path: Path) -> None:
    session = TerminalSession(tmp_path / "projects", history_limit=20)
    session.remember("help")
    session.remember("help")
    for index in range(30):
        session.remember(f"command-{index}")

    history = session.history()
    assert len(history) == 20
    assert history[-1] == "command-29"
    assert history[0] == "command-10"
    assert session.history(2) == ("command-28", "command-29")


def test_terminal_readonly_sql_allows_queries_and_rejects_writes(tmp_path: Path) -> None:
    database = tmp_path / "arenyxa.db"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, value TEXT)")
    connection.executemany("INSERT INTO sample(value) VALUES (?)", [("one",), ("two",)])
    connection.commit()
    connection.close()

    result = TerminalSession.readonly_sql(database, "SELECT id, value FROM sample ORDER BY id")
    assert result["row_count"] == 2
    assert result["rows"] == [{"id": 1, "value": "one"}, {"id": 2, "value": "two"}]
    tables = TerminalSession.readonly_sql(database, "tables")
    assert any(row["name"] == "sample" for row in tables["rows"])

    with pytest.raises(PermissionError):
        TerminalSession.readonly_sql(database, "DELETE FROM sample")
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("SELECT COUNT(*) FROM sample").fetchone()[0] == 2
    finally:
        connection.close()


def test_terminal_risk_detection_distinguishes_shell_and_destructive_commands(tmp_path: Path) -> None:
    session = TerminalSession(tmp_path / "projects")
    assert session.detect_risk("git status", TerminalMode.DIRECT) is None
    assert "高风险" in str(session.detect_risk("Remove-Item -Recurse .", TerminalMode.POWERSHELL))
    assert "Shell" in str(session.detect_risk("Get-ChildItem | Select-Object Name", TerminalMode.POWERSHELL))


def test_direct_process_streams_output_and_reports_exit(tmp_path: Path) -> None:
    session = TerminalSession(tmp_path / "projects", default_timeout_seconds=10)
    launch = session.build_launch(_python_direct("print('alpha'); print('beta')"), TerminalMode.DIRECT)
    chunks: list[str] = []
    results: list[TerminalResult] = []

    session.start(launch, chunks.append, results.append)
    assert session.wait(5)
    assert "alpha" in "".join(chunks)
    assert "beta" in "".join(chunks)
    assert len(results) == 1
    assert results[0].exit_code == 0
    assert results[0].timed_out is False
    assert results[0].cancelled is False
    assert results[0].output_truncated is False


def test_terminal_timeout_terminates_long_running_process(tmp_path: Path) -> None:
    session = TerminalSession(tmp_path / "projects", default_timeout_seconds=1)
    launch = session.build_launch(_python_direct("import time; time.sleep(10)"), TerminalMode.DIRECT)
    results: list[TerminalResult] = []

    started = time.monotonic()
    session.start(launch, lambda _text: None, results.append)
    assert session.wait(5)
    assert time.monotonic() - started < 5
    assert len(results) == 1
    assert results[0].timed_out is True


def test_terminal_stop_marks_process_cancelled(tmp_path: Path) -> None:
    session = TerminalSession(tmp_path / "projects", default_timeout_seconds=30)
    launch = session.build_launch(_python_direct("import time; time.sleep(10)"), TerminalMode.DIRECT)
    results: list[TerminalResult] = []

    session.start(launch, lambda _text: None, results.append)
    time.sleep(0.15)
    assert session.stop() is True
    assert session.wait(5)
    assert len(results) == 1
    assert results[0].cancelled is True


def test_terminal_output_budget_stops_runaway_output(tmp_path: Path) -> None:
    session = TerminalSession(
        tmp_path / "projects",
        default_timeout_seconds=10,
        max_output_chars=32_768,
    )
    launch = session.build_launch(_python_direct("print('x' * 200000)"), TerminalMode.DIRECT)
    chunks: list[str] = []
    results: list[TerminalResult] = []

    session.start(launch, chunks.append, results.append)
    assert session.wait(5)
    assert len("".join(chunks)) <= 32_768
    assert len(results) == 1
    assert results[0].output_truncated is True


def test_terminal_can_send_stdin_to_running_process(tmp_path: Path) -> None:
    session = TerminalSession(tmp_path / "projects", default_timeout_seconds=10)
    code = "value=input(); print('echo:' + value)"
    launch = session.build_launch(_python_direct(code), TerminalMode.DIRECT)
    chunks: list[str] = []
    results: list[TerminalResult] = []

    session.start(launch, chunks.append, results.append)
    time.sleep(0.1)
    assert session.send_input("hello") is True
    assert session.wait(5)
    assert "echo:hello" in "".join(chunks)
    assert results[0].exit_code == 0


def test_terminal_callback_failure_does_not_strand_process_state(tmp_path: Path) -> None:
    session = TerminalSession(tmp_path / "projects", default_timeout_seconds=10)
    launch = session.build_launch(_python_direct("print('hello')"), TerminalMode.DIRECT)
    results: list[TerminalResult] = []

    def broken_output(_text: str) -> None:
        raise RuntimeError("observer failed")

    session.start(launch, broken_output, results.append)
    assert session.wait(5)
    assert session.is_running is False
    assert len(results) == 1
    assert results[0].exit_code == 0


def test_terminal_request_stop_is_nonblocking_and_eventually_cancels(tmp_path: Path) -> None:
    session = TerminalSession(tmp_path / "projects", default_timeout_seconds=30)
    launch = session.build_launch(_python_direct("import time; time.sleep(10)"), TerminalMode.DIRECT)
    results: list[TerminalResult] = []
    session.start(launch, lambda _text: None, results.append)
    time.sleep(0.1)

    started = time.monotonic()
    assert session.request_stop() is True
    assert time.monotonic() - started < 0.5
    assert session.wait(5)
    assert results[0].cancelled is True
