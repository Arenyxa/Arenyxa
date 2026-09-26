from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PUBLIC_DISPLAY_VERSION = "0.1"
PUBLIC_PACKAGE_VERSION = "0.1.0"
WINDOWS_FILE_VERSION = "0.1.0.0"
ENGINEERING_BASELINE = "v8.2.0"
INTERNAL_VERSION = "8.2.0"
COMPAT_VERSION = "6.8.0"
MODERN_INSTALLER = "Arenyxa_v0.1_Setup_x64"
LEGACY_INSTALLER = "Arenyxa_v0.1_Legacy_Win7_x64_Setup"


def _require(path: str, needle: str) -> None:
    text = (ROOT / path).read_text(encoding="utf-8")
    if needle not in text:
        raise RuntimeError(f"{path}: missing release identity token {needle!r}")


def _constant(path: str, name: str) -> str:
    text = (ROOT / path).read_text(encoding="utf-8")
    match = re.search(
        rf'(?m)^\s*{re.escape(name)}\s*=\s*["\']([^"\']+)["\']\s*$',
        text,
    )
    if match is None:
        raise RuntimeError(f"{path}: unable to read {name}")
    return match.group(1)


def _project_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(
        r'(?ms)^\[project\]\s*$.*?^version\s*=\s*["\']([^"\']+)["\']',
        text,
    )
    if match is None:
        raise RuntimeError("pyproject.toml: unable to read [project] version")
    return match.group(1)


def _require_pascal_code_comments(path: str) -> None:
    text = (ROOT / path).read_text(encoding="utf-8")
    marker = "[Code]"
    if marker not in text:
        raise RuntimeError(f"{path}: missing [Code] section")
    code = text.split(marker, 1)[1]
    invalid = [line for line in code.splitlines() if line.lstrip().startswith(";")]
    if invalid:
        raise RuntimeError(
            f"{path}: semicolon comments are invalid in Pascal [Code]; use // comments instead"
        )


def _verify_namespace(path: str) -> None:
    expected = {
        "__version__": PUBLIC_DISPLAY_VERSION,
        "__display_version__": PUBLIC_DISPLAY_VERSION,
        "__distribution_version__": PUBLIC_PACKAGE_VERSION,
        "__package_version__": PUBLIC_PACKAGE_VERSION,
        "__public_version__": PUBLIC_DISPLAY_VERSION,
        "__public_package_version__": PUBLIC_PACKAGE_VERSION,
        "__engineering_build__": ENGINEERING_BASELINE,
        "__internal_version__": INTERNAL_VERSION,
        "__compat_version__": COMPAT_VERSION,
    }
    observed = {name: _constant(path, name) for name in expected}
    if observed != expected:
        raise RuntimeError(f"{path}: release identity mismatch: {observed!r}")


def main() -> int:
    _verify_namespace("src/arenyxa/__init__.py")
    _verify_namespace("legacy/win7/src/arenyxa/__init__.py")

    if _project_version() != PUBLIC_PACKAGE_VERSION:
        raise RuntimeError("pyproject.toml does not carry the public 0.1.0 distribution identity")

    _require("packaging/version_info.txt", "filevers=(0,1,0,0)")
    _require("packaging/version_info.txt", "prodvers=(0,1,0,0)")
    _require("packaging/version_info.txt", "FileDescription', 'Arenyxa v0.1'")
    _require("packaging/version_info.txt", f"FileVersion', '{WINDOWS_FILE_VERSION}'")
    _require("packaging/version_info.txt", "ProductVersion', '0.1.0'")
    _require("packaging/installer.iss", '#define MyAppVersion "0.1.0"')
    _require("packaging/installer.iss", f"OutputBaseFilename={MODERN_INSTALLER}")
    _require("packaging/installer_win7.iss", '#define MyAppVersion "0.1.0"')
    _require("packaging/installer_win7.iss", f"OutputBaseFilename={LEGACY_INSTALLER}")
    _require_pascal_code_comments("packaging/installer.iss")
    _require_pascal_code_comments("packaging/installer_win7.iss")

    _require("scripts/build.ps1", "verify_release_identity.py")
    _require("scripts/build-win7.ps1", "verify_release_identity.py")
    _require(
        "scripts/build_release_attestation.py",
        'parser.add_argument("--version", default="0.1.0")',
    )
    _require("RUN_ARENYXA.cmd", "title Arenyxa v0.1 Source Launcher")

    _require("README.md", "# Arenyxa v0.1")
    _require("README.md", "Internal engineering baseline:")
    _require("VERSIONING.md", "The GitHub release line starts at **v0.1**.")

    _require("RELEASE_IDENTITY.json", '"display_version": "0.1"')
    _require("RELEASE_IDENTITY.json", '"package_version": "0.1.0"')
    _require("RELEASE_IDENTITY.json", '"engineering_baseline": "v8.2.0"')
    _require("V8_2_RELEASE_IDENTITY.json", '"version_scope": "internal_engineering_milestone"')

    docs_matrix = json.loads(
        (ROOT / "docs/release/COMPATIBILITY_MATRIX.json").read_text(encoding="utf-8")
    )
    if docs_matrix.get("product_release_version") != PUBLIC_PACKAGE_VERSION:
        raise RuntimeError("documented compatibility matrix public product version is stale")
    if docs_matrix.get("runtime_compatibility_identity") != COMPAT_VERSION:
        raise RuntimeError("documented compatibility identity is stale")
    if docs_matrix.get("engineering_baseline") != ENGINEERING_BASELINE:
        raise RuntimeError("documented engineering baseline is stale")

    _require(
        "src/arenyxa/architecture_contracts.py",
        'CompatibilityContract("arenyxa", "python-package", '
        '"Public facade remains importable and re-exports public v0.1 version metadata.", "0.1")',
    )
    _require(
        "src/arenyxa/architecture_contracts.py",
        'CompatibilityContract("plugin-api", "plugin", '
        '"Existing manifest/API compatibility comparator remains at 6.8.0 unless explicitly migrated.", '
        '"6.8.0")',
    )

    print("Arenyxa v0.1 public release identity gate: PASS")
    print(f"- public display version: {PUBLIC_DISPLAY_VERSION}")
    print(f"- public package version: {PUBLIC_PACKAGE_VERSION}")
    print(f"- internal engineering baseline: {ENGINEERING_BASELINE}")
    print(f"- runtime/plugin compatibility: {COMPAT_VERSION}")
    print(f"- modern installer: {MODERN_INSTALLER}.exe")
    print(f"- legacy installer: {LEGACY_INSTALLER}.exe")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
