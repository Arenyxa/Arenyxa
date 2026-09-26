from __future__ import annotations

import json
from pathlib import Path

import arenyxa
from arenyxa.architecture_contracts import COMPATIBILITY_CONTRACTS
from arenyxa.release_hardening import compatibility_matrix

ROOT = Path(__file__).resolve().parents[1]


def test_public_release_identity_is_v01_while_engineering_history_is_preserved() -> None:
    assert arenyxa.__version__ == "0.1"
    assert arenyxa.__display_version__ == "0.1"
    assert arenyxa.__package_version__ == "0.1.0"
    assert arenyxa.__distribution_version__ == "0.1.0"
    assert arenyxa.__public_version__ == "0.1"
    assert arenyxa.__public_package_version__ == "0.1.0"
    assert arenyxa.__engineering_build__ == "v8.2.0"
    assert arenyxa.__internal_version__ == "8.2.0"
    assert arenyxa.__compat_version__ == "6.8.0"


def test_public_packaging_identity_is_v01() -> None:
    assert 'version = "0.1.0"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    version_info = (ROOT / "packaging/version_info.txt").read_text(encoding="utf-8")
    assert "filevers=(0,1,0,0)" in version_info
    assert "prodvers=(0,1,0,0)" in version_info
    assert "FileDescription', 'Arenyxa v0.1'" in version_info
    assert "FileVersion', '0.1.0.0'" in version_info
    assert "ProductVersion', '0.1.0'" in version_info

    installer = (ROOT / "packaging/installer.iss").read_text(encoding="utf-8")
    legacy = (ROOT / "packaging/installer_win7.iss").read_text(encoding="utf-8")
    assert '#define MyAppVersion "0.1.0"' in installer
    assert "OutputBaseFilename=Arenyxa_v0.1_Setup_x64" in installer
    assert '#define MyAppVersion "0.1.0"' in legacy
    assert "OutputBaseFilename=Arenyxa_v0.1_Legacy_Win7_x64_Setup" in legacy


def test_release_identity_documents_distinguish_public_and_internal_versions() -> None:
    release = json.loads((ROOT / "RELEASE_IDENTITY.json").read_text(encoding="utf-8"))
    assert release["display_version"] == "0.1"
    assert release["package_version"] == "0.1.0"
    assert release["engineering_baseline"] == "v8.2.0"
    assert release["compatibility_identity"] == "6.8.0"
    assert release["github_public_release"] is True

    engineering = json.loads((ROOT / "V8_2_RELEASE_IDENTITY.json").read_text(encoding="utf-8"))
    assert engineering["display_version"] == "8.2"
    assert engineering["version_scope"] == "internal_engineering_milestone"
    assert engineering["github_public_release"] is False
    assert engineering["public_release_mapping"] == "v0.1"


def test_compatibility_contracts_follow_public_identity_without_resetting_protocols() -> None:
    matrix = compatibility_matrix()
    assert matrix["product_release_version"] == "0.1.0"
    assert matrix["runtime_compatibility_identity"] == "6.8.0"
    assert matrix["enterprise_protocol"] == {
        "current": 2,
        "minimum": 1,
        "strategy": "server accepts N and N-1; worker negotiates the highest common version",
    }

    names = {(item.name, item.kind, item.compatibility_level) for item in COMPATIBILITY_CONTRACTS}
    assert ("arenyxa", "python-package", "0.1") in names
    assert ("arenyxa", "legacy-python-package", "0.1") in names
    assert ("plugin-api", "plugin", "6.8.0") in names


def test_versioning_document_declares_public_reset() -> None:
    text = (ROOT / "VERSIONING.md").read_text(encoding="utf-8")
    assert "GitHub release line starts at **v0.1**" in text
    assert "current internal engineering baseline is **v8.2.0**" in text
    assert "must not be reset to `0.1`" in text
