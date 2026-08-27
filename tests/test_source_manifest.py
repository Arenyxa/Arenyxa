from __future__ import annotations

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "SOURCE_MANIFEST.sha256"


def test_source_manifest_hashes_are_current() -> None:
    assert MANIFEST.is_file()
    rows = [line.strip() for line in MANIFEST.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert rows
    seen: set[str] = set()
    for row in rows:
        expected, relative = row.split("  ", 1)
        assert relative not in seen
        seen.add(relative)
        path = ROOT / relative
        assert path.is_file(), relative
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert digest == expected, relative
    assert "src/arenyxa/application/competitive.py" in seen
    assert "scripts/build_source_manifest.py" in seen
