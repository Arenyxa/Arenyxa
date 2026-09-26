from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arenyxa import (
    __compat_version__,
    __display_version__,
    __distribution_version__,
    __engineering_build__,
    __internal_version__,
    __package_version__,
    __public_package_version__,
    __public_version__,
    __version__,
)
from arenyxa.release_hardening import compatibility_matrix

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


def main() -> int:
    public = (
        __version__,
        __display_version__,
        __distribution_version__,
        __package_version__,
        __public_version__,
        __public_package_version__,
    )
    expected_public = (
        PUBLIC_DISPLAY_VERSION,
        PUBLIC_DISPLAY_VERSION,
        PUBLIC_PACKAGE_VERSION,
        PUBLIC_PACKAGE_VERSION,
        PUBLIC_DISPLAY_VERSION,
        PUBLIC_PACKAGE_VERSION,
    )
    if public != expected_public:
        raise RuntimeError(f"Public release identity mismatch: {public!r}")

    if __engineering_build__ != ENGINEERING_BASELINE or __internal_version__ != INTERNAL_VERSION:
        raise RuntimeError(
            "Internal engineering baseline changed unexpectedly: "
            f"{__engineering_build__!r}, {__internal_version__!r}"
        )
    if __compat_version__ != COMPAT_VERSION:
        raise RuntimeError(f"Runtime compatibility identity changed unexpectedly: {__compat_version__!r}")

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'(?ms)^\[project\]\s*$.*?^version\s*=\s*["\']([^"\']+)["\']', pyproject)
    if match is None or match.group(1) != PUBLIC_PACKAGE_VERSION:
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
    _require("scripts/build_release_attestation.py", 'parser.add_argument("--version", default="0.1.0")')
    _require("RUN_ARENYXA.cmd", "title Arenyxa v0.1 Source Launcher")
    _require("README.md", "# Arenyxa v0.1")
    _require("README.md", "Internal engineering baseline:")
    _require("RELEASE_IDENTITY.json", '"display_version": "0.1"')
    _require("RELEASE_IDENTITY.json", '"engineering_baseline": "v8.2.0"')
    _require("V8_2_RELEASE_IDENTITY.json", '"version_scope": "internal_engineering_milestone"')

    legacy_namespace = (ROOT / "legacy/win7/src/arenyxa/__init__.py").read_text(encoding="utf-8")
    for token in (
        '__version__ = "0.1"',
        '__package_version__ = "0.1.0"',
        '__engineering_build__ = "v8.2.0"',
        '__compat_version__ = "6.8.0"',
    ):
        if token not in legacy_namespace:
            raise RuntimeError(f"Legacy runtime identity is stale: {token}")

    matrix = compatibility_matrix()
    if matrix.get("product_release_version") != PUBLIC_PACKAGE_VERSION:
        raise RuntimeError("compatibility matrix public product version is stale")
    if matrix.get("runtime_compatibility_identity") != COMPAT_VERSION:
        raise RuntimeError("runtime compatibility identity changed without an explicit migration")

    docs_matrix = json.loads((ROOT / "docs/release/COMPATIBILITY_MATRIX.json").read_text(encoding="utf-8"))
    if docs_matrix.get("product_release_version") != PUBLIC_PACKAGE_VERSION:
        raise RuntimeError("documented compatibility matrix public product version is stale")
    if docs_matrix.get("runtime_compatibility_identity") != COMPAT_VERSION:
        raise RuntimeError("documented compatibility identity is stale")

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
