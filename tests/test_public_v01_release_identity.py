from __future__ import annotations

import json
import importlib.util
import shutil
from pathlib import Path

import arenyxa
import pytest
from arenyxa.release_hardening import compatibility_matrix

ROOT = Path(__file__).resolve().parents[1]


def test_public_identity_is_independent_from_engineering_and_compatibility() -> None:
    assert arenyxa.__version__ == arenyxa.__display_version__ == "0.1"
    assert arenyxa.__package_version__ == arenyxa.__distribution_version__ == "0.1.0"
    assert arenyxa.__engineering_build__ == "v8.2.0"
    assert arenyxa.__compat_version__ == "6.8.0"
    matrix = compatibility_matrix()
    assert matrix["product_release_version"] == "0.1.0"
    assert matrix["runtime_compatibility_identity"] == "6.8.0"
    assert matrix["enterprise_protocol"]["current"] == 2
    assert matrix["enterprise_protocol"]["minimum"] == 1


def test_public_source_identity_records_publication_without_signing() -> None:
    identity = json.loads((ROOT / "RELEASE_IDENTITY.json").read_text(encoding="utf-8"))
    assert identity["release_status"] == "public"
    assert identity["release_readiness"] == "READY FOR SOURCE PUBLICATION"
    assert identity["github_public_release"] is True
    assert identity["distribution_channel"] == "community"
    assert identity["signing_status"] == "unsigned"
    assert identity["windows_file_version"] == "0.1.0.0"
    assert identity["compatibility_identity"] == "6.8.0"


def test_har_creator_uses_product_package_version(tmp_path: Path) -> None:
    from arenyxa.infrastructure.capture.proxy_export import export_proxy_har

    path = export_proxy_har(tmp_path / "empty.har", [])
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["log"]["version"] == "1.2"
    assert payload["log"]["creator"] == {"name": "Arenyxa Proxy", "version": "0.1.0"}


@pytest.fixture
def identity_gate():
    spec = importlib.util.spec_from_file_location("public_identity_gate", ROOT / "scripts/verify_release_identity.py")
    assert spec is not None and spec.loader is not None
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    return gate


@pytest.fixture
def identity_source_tree(tmp_path: Path) -> Path:
    for relative in (
        "src/arenyxa/__init__.py", "legacy/win7/src/arenyxa/__init__.py", "pyproject.toml",
        "packaging/version_info.txt", "packaging/installer.iss", "packaging/installer_win7.iss",
        "scripts/build.ps1", "scripts/build-win7.ps1", "scripts/build_release_attestation.py",
        "RUN_ARENYXA.cmd", "RELEASE_IDENTITY.json", "docs/release/COMPATIBILITY_MATRIX.json",
        "V8_2_RELEASE_IDENTITY.json",
    ):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    return tmp_path


def test_source_identity_gate_rejects_compatibility_drift_and_false_depromotion(identity_gate, identity_source_tree: Path) -> None:
    assert identity_gate.verify_identity()["package_version"] == "0.1.0"
    metadata = identity_source_tree / "src/arenyxa/__init__.py"
    original = metadata.read_text(encoding="utf-8")
    metadata.write_text(original.replace('__compat_version__ = "6.8.0"', '__compat_version__ = "0.1.0"'), encoding="utf-8")
    with pytest.raises(RuntimeError, match="compatibility identity mismatch"):
        identity_gate.verify_identity(identity_source_tree)
    metadata.write_text(original, encoding="utf-8")
    identity = identity_source_tree / "RELEASE_IDENTITY.json"
    value = json.loads(identity.read_text(encoding="utf-8"))
    value["github_public_release"] = False
    identity.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(RuntimeError, match="github_public_release"):
        identity_gate.verify_identity(identity_source_tree)


@pytest.mark.parametrize("installer", ["installer.iss", "installer_win7.iss"])
@pytest.mark.parametrize("directive", [
    "VersionInfoVersion", "VersionInfoTextVersion",
    "VersionInfoProductVersion", "VersionInfoProductTextVersion",
])
@pytest.mark.parametrize("mutation", ["missing", "wrong", "commented", "wrong_section", "duplicate"])
def test_source_identity_gate_rejects_installer_pe_identity_drift(
    identity_gate, identity_source_tree: Path, installer: str, directive: str, mutation: str,
) -> None:
    versions = {
        "VersionInfoVersion": "{#MyAppVersion}.0",
        "VersionInfoTextVersion": "{#MyAppVersion}.0",
        "VersionInfoProductVersion": "{#MyAppVersion}.0",
        "VersionInfoProductTextVersion": "{#MyAppVersion}",
    }
    # Both source fixtures start with a complete, valid PE identity.
    for filename in ("installer.iss", "installer_win7.iss"):
        path = identity_source_tree / "packaging" / filename
        text = path.read_text(encoding="utf-8")
        for key, value in versions.items():
            line = key + "=" + value + "\n"
            if line not in text:
                text = text.replace("AppVersion={#MyAppVersion}\n", "AppVersion={#MyAppVersion}\n" + line)
        path.write_text(text, encoding="utf-8")
    assert identity_gate.verify_identity(identity_source_tree)["windows_file_version"] == "0.1.0.0"

    path = identity_source_tree / "packaging" / installer
    original = path.read_text(encoding="utf-8")
    line = directive + "=" + versions[directive] + "\n"
    replacements = {
        "missing": "",
        "wrong": directive + "=0.0.0.0\n",
        "commented": ";" + line,
        "wrong_section": "",
        "duplicate": line + directive + "=9.9.9.9\n",
    }
    changed = original.replace(line, replacements[mutation], 1)
    if mutation == "wrong_section":
        changed += "\n[CustomMessages]\n" + line
    path.write_text(changed, encoding="utf-8")
    with pytest.raises(RuntimeError, match=directive):
        identity_gate.verify_identity(identity_source_tree)
