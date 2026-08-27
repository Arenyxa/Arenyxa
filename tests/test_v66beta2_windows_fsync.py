from __future__ import annotations

import os
from pathlib import Path

from arenyxa.infrastructure import atomic_io


def test_fsync_existing_file_uses_write_capable_descriptor(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "artifact.bin"
    target.write_bytes(b"arenyxa")
    real_open = atomic_io.os.open
    observed: dict[str, int] = {}

    def tracking_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        observed["flags"] = flags
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(atomic_io.os, "open", tracking_open)
    atomic_io.fsync_existing_file(target)

    assert observed["flags"] & os.O_RDWR == os.O_RDWR


def test_windows_sensitive_runtime_flushes_use_portable_helper() -> None:
    root = Path(__file__).resolve().parents[1]
    expected = {
        "src/arenyxa/infrastructure/database.py": "fsync_existing_file(temporary)",
        "src/arenyxa/application/export.py": "fsync_existing_file(temp_path)",
        "src/arenyxa/application/project_format.py": "fsync_existing_file(temporary)",
        "src/arenyxa/presentation/pages/settings.py": "fsync_existing_file(temporary)",
    }
    for relative, needle in expected.items():
        text = (root / relative).read_text(encoding="utf-8")
        assert needle in text


def test_repair_seed_builder_fsync_uses_write_capable_descriptor() -> None:
    root = Path(__file__).resolve().parents[1]
    text = (root / "scripts/build_source_repair_seed.py").read_text(encoding="utf-8")
    assert "os.O_RDWR" in text
    body = text.split('def _fsync_file(path: Path) -> None:', 1)[1].split('def _write_json_temp', 1)[0]
    assert 'os.O_RDWR' in body
    assert 'path.open("rb")' not in body
