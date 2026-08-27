from __future__ import annotations

from pathlib import Path

from arenyxa.application.developer_safety import DEVELOPER_TERMS_VERSION
from arenyxa.cli import main
from arenyxa.config import AppPaths, AppSettings


def _enable_developer(root: Path) -> None:
    paths = AppPaths.discover(root)
    paths.initialize()
    settings = AppSettings()
    settings.developer_mode = True
    settings.developer_terms_version = DEVELOPER_TERMS_VERSION
    settings.developer_terms_accepted_at = "2026-08-18T12:00:00+00:00"
    settings.save(paths.root / "settings.json")


def test_cli_version_does_not_require_developer_mode(tmp_path: Path, capsys) -> None:
    code = main(["--data-dir", str(tmp_path / "runtime"), "version"])
    assert code == 0
    assert "Arenyxa" in capsys.readouterr().out


def test_cli_status_uses_machine_readable_control_plane(tmp_path: Path, capsys) -> None:
    root = tmp_path / "runtime"
    _enable_developer(root)
    code = main(["--data-dir", str(root), "--json", "status"])
    assert code == 0
    output = capsys.readouterr().out
    assert '"ok": true' in output.lower()
    assert '"developer_authorized": true' in output.lower()
