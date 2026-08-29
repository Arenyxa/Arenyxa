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
    __package_version__,
    __version__,
)
from arenyxa.release_hardening import compatibility_matrix

RUNTIME_COMPATIBILITY_VERSION = "8.1"
DISPLAY_VERSION = "8.1.1"
DISTRIBUTION_VERSION = "8.1.1"
PACKAGE_VERSION = "8.1.0"
COMPAT_VERSION = "6.8.0"
FILE_VERSION = "8.1.1.0"
MODERN_INSTALLER = "Arenyxa_V8.1.1_Setup_x64"
LEGACY_INSTALLER = "Arenyxa_V8.1_Legacy_Win7_x64_Setup"


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
    if (
        __version__,
        __display_version__,
        __distribution_version__,
        __engineering_build__,
        __package_version__,
        __compat_version__,
    ) != (
        RUNTIME_COMPATIBILITY_VERSION,
        DISPLAY_VERSION,
        DISTRIBUTION_VERSION,
        "v8.1.1",
        PACKAGE_VERSION,
        COMPAT_VERSION,
    ):
        raise RuntimeError(
            "Runtime/engineering/package/compat identity mismatch: "
            f"{__version__!r}, {__display_version__!r}, {__distribution_version__!r}, "
            f"{__engineering_build__!r}, {__package_version__!r}, {__compat_version__!r}"
        )

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'(?ms)^\[project\]\s*$.*?^version\s*=\s*["\']([^"\']+)["\']', pyproject)
    if match is None or match.group(1) != DISTRIBUTION_VERSION:
        raise RuntimeError("pyproject.toml does not carry the v8.1.1 stable distribution identity")

    _require("packaging/version_info.txt", "filevers=(8,1,1,0)")
    _require("packaging/version_info.txt", "prodvers=(8,1,1,0)")
    _require("packaging/version_info.txt", "FileDescription', 'Arenyxa V8.1.1'")
    _require("packaging/version_info.txt", f"FileVersion', '{FILE_VERSION}'")
    _require("packaging/version_info.txt", "ProductVersion', '8.1.1'")
    _require("packaging/installer.iss", '#define MyAppVersion "8.1.1"')
    _require("packaging/installer.iss", f"OutputBaseFilename={MODERN_INSTALLER}")
    _require("packaging/installer_win7.iss", '#define MyAppVersion "8.1"')
    _require("packaging/installer_win7.iss", f"OutputBaseFilename={LEGACY_INSTALLER}")
    _require_pascal_code_comments("packaging/installer.iss")
    _require_pascal_code_comments("packaging/installer_win7.iss")
    _require("scripts/build.ps1", "verify_v81_release_identity.py")
    _require("scripts/build.ps1", "$ProjectVersion = $Matches[1]")
    _require("scripts/build_release_attestation.py", 'parser.add_argument("--version", default="8.1.1")')
    _require("RUN_ARENYXA.cmd", "title Arenyxa v8.1.1 Source Launcher")
    _require("README.md", "# Arenyxa V8.1.1")

    legacy_namespace = (ROOT / "legacy/win7/src/arenyxa/__init__.py").read_text(encoding="utf-8")
    for token in ('__version__ = "8.1"', '__package_version__ = "8.1.0"'):
        if token not in legacy_namespace:
            raise RuntimeError(f"Legacy Enterprise runtime identity is stale: {token}")

    matrix = compatibility_matrix()
    if matrix.get("product_release_version") != DISTRIBUTION_VERSION:
        raise RuntimeError("compatibility matrix product release version is stale")
    if matrix.get("runtime_compatibility_identity") != COMPAT_VERSION:
        raise RuntimeError("runtime compatibility identity changed without an explicit migration")

    docs_matrix_path = ROOT / "docs/release/COMPATIBILITY_MATRIX.json"
    docs_matrix = json.loads(docs_matrix_path.read_text(encoding="utf-8"))
    if docs_matrix.get("product_release_version") != DISTRIBUTION_VERSION:
        raise RuntimeError("documented compatibility matrix product version is stale")
    if docs_matrix.get("runtime_compatibility_identity") != COMPAT_VERSION:
        raise RuntimeError("documented compatibility identity is stale")

    print("Arenyxa v8.1.1 release identity gate: PASS")
    print(f"- display: {DISPLAY_VERSION}")
    print(f"- engineering distribution: {DISTRIBUTION_VERSION}")
    print(f"- package compatibility: {PACKAGE_VERSION}")
    print(f"- plugin/runtime compatibility: {COMPAT_VERSION}")
    print(f"- modern installer: {MODERN_INSTALLER}.exe")
    print(f"- legacy installer: {LEGACY_INSTALLER}.exe")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
