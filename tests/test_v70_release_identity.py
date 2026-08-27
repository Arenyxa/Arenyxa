from __future__ import annotations

from pathlib import Path

import arenyxa
from arenyxa.architecture_contracts import COMPATIBILITY_CONTRACTS
from arenyxa.release_hardening import ReleaseChannel, ReleaseGateReport, compatibility_matrix

ROOT = Path(__file__).resolve().parents[1]


def test_v70_product_packaging_and_compatibility_identity_are_explicit() -> None:
    assert arenyxa.__version__ == "8.1"
    assert arenyxa.__package_version__ == "8.1.0"
                                                                                               
    assert arenyxa.__compat_version__ == "6.8.0"

    assert 'version = "8.1.0"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version_info = (ROOT / "packaging/version_info.txt").read_text(encoding="utf-8")
    assert "filevers=(8,1,0,0)" in version_info
    assert "prodvers=(8,1,0,0)" in version_info
    assert "FileDescription', 'Arenyxa V8.1'" in version_info
    assert "ProductVersion', '8.1'" in version_info

    installer = (ROOT / "packaging/installer.iss").read_text(encoding="utf-8")
    legacy = (ROOT / "packaging/installer_win7.iss").read_text(encoding="utf-8")
    assert '#define MyAppVersion "8.1"' in installer
    assert "OutputBaseFilename=Arenyxa_V8.1_Setup_x64" in installer
    assert '#define MyAppVersion "8.1"' in legacy
    assert "OutputBaseFilename=Arenyxa_V8.1_Legacy_Win7_x64_Setup" in legacy


def test_v70_release_matrix_distinguishes_product_version_from_compatibility_identity() -> None:
    matrix = compatibility_matrix()
    assert matrix["product_release_version"] == "8.1.0"
    assert matrix["runtime_compatibility_identity"] == "6.8.0"
    names = {(item.name, item.kind, item.compatibility_level) for item in COMPATIBILITY_CONTRACTS}
    assert ("arenyxa", "python-package", "8.1") in names
    assert ("arenyxa", "legacy-python-package", "8.1") in names
    assert ("plugin-api", "plugin", "6.8.0") in names


def test_v70_stable_gate_still_requires_real_release_evidence() -> None:
    automated_only = ReleaseGateReport(
        regression=True,
        integrity=True,
        migration_rollback=True,
        security_review=True,
        native_windows=False,
        distributed_failure_drill=False,
    )
    assert automated_only.can_promote(ReleaseChannel.STABLE) is False
    assert set(automated_only.missing(ReleaseChannel.STABLE)) == {"native_windows", "distributed_failure_drill"}


def test_v70_build_attestation_and_launcher_no_longer_emit_v68_release_identity() -> None:
    build = (ROOT / "scripts/build.ps1").read_text(encoding="utf-8")
    attestation = (ROOT / "scripts/build_release_attestation.py").read_text(encoding="utf-8")
    launcher = (ROOT / "RUN_ARENYXA.cmd").read_text(encoding="utf-8")
    assert '--version $ProjectVersion' in build
    assert '$ProjectVersion = $Matches[1]' in build
    assert 'default="8.1"' in attestation
    assert "title Arenyxa v8.1 Source Launcher" in launcher

def test_v70_inno_code_sections_use_pascal_comment_syntax() -> None:
    for relative in ("packaging/installer.iss", "packaging/installer_win7.iss"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "[Code]" in text
        code = text.split("[Code]", 1)[1]
        assert not any(line.lstrip().startswith(";") for line in code.splitlines())
