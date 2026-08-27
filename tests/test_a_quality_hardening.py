from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_win7_build_uses_its_own_source_repair_lane() -> None:
    source = (ROOT / "scripts" / "build-win7.ps1").read_text(encoding="utf-8")
    assert "build_source_repair_seed.py') --win7" in source
    builder = (ROOT / "scripts" / "build_source_repair_seed.py").read_text(encoding="utf-8")
    assert 'runtime = "win7-frozen"' in builder
    assert 'project / "legacy" / "win7" / "src" / "arenyxa"' in builder


def test_source_manifest_excludes_coverage_artifacts() -> None:
    builder = (ROOT / "scripts" / "build_source_manifest.py").read_text(encoding="utf-8")
    assert '"coverage.json"' in builder
    assert 'relative.name.startswith(".coverage.")' in builder


def test_final_quality_full_lane_enforces_branch_coverage_and_20d() -> None:
    source = (ROOT / "scripts" / "final_quality_gate.py").read_text(encoding="utf-8")
    assert "scripts/quality_20d_gate.py" in source
    assert "--include-legacy" in source
    assert "if include_legacy" in source
    assert "scripts/win7_legacy_quality_gate.py" in source
    assert "--cov-branch" in source
    assert "scripts/coverage_gate.py" in source
