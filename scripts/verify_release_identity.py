"""Validate the current product identity without changing engineering or wire versions.

This source/metadata gate is Python 3.8 compatible. Passing it does not qualify
Windows runtime, clean-machine install, or a signed binary release.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify_identity(root: Path = ROOT) -> dict:
    def read(relative: str) -> str:
        return (root / relative).read_text(encoding="utf-8-sig")

    def require(relative: str, token: str) -> None:
        if token not in read(relative):
            raise RuntimeError("{}: missing identity token {!r}".format(relative, token))

    expected = {
        "__version__": "0.1",
        "__display_version__": "0.1",
        "__public_version__": "0.1",
        "__package_version__": "0.1.0",
        "__public_package_version__": "0.1.0",
        "__distribution_version__": "0.1.0",
        "__engineering_build__": "v8.2.0",
        "__internal_version__": "8.2.0",
        "__compat_version__": "6.8.0",
        "__release_channel__": "stable",
        "__release_phase__": 8,
    }
    for relative in ("src/arenyxa/__init__.py", "legacy/win7/src/arenyxa/__init__.py"):
        values = {}
        for node in ast.parse(read(relative), filename=relative).body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in expected:
                        values[target.id] = ast.literal_eval(node.value)
        if values != expected:
            raise RuntimeError("{}: public/engineering/compatibility identity mismatch".format(relative))

    match = re.search(r'(?ms)^\[project\]\s*$.*?^version\s*=\s*["\']([^"\']+)["\']', read("pyproject.toml"))
    if match is None or match.group(1) != "0.1.0":
        raise RuntimeError("pyproject.toml: distribution version must be 0.1.0")
    for token in ("filevers=(0,1,0,0)", "prodvers=(0,1,0,0)", "FileDescription', 'Arenyxa v0.1'", "FileVersion', '0.1.0.0'", "ProductVersion', '0.1.0'"):
        require("packaging/version_info.txt", token)
    for relative, artifact in (
        ("packaging/installer.iss", "Arenyxa_v0.1_Setup_x64"),
        ("packaging/installer_win7.iss", "Arenyxa_v0.1_Legacy_Win7_x64_Setup"),
    ):
        require(relative, '#define MyAppVersion "0.1.0"')
        require(relative, "OutputBaseFilename=" + artifact)
        require(relative, "AppId={{62ED5A19-19D3-402F-8819-D06C9D4A768B}")
        text = read(relative)
        setup = re.search(r"(?ims)^\[Setup\][ \t]*\n(.*?)(?=^\[|\Z)", text)
        if setup is None:
            raise RuntimeError(relative + ": missing [Setup] identity section")
        for directive, expected_version in (
            ("VersionInfoVersion", "0.1.0.0"),
            ("VersionInfoTextVersion", "0.1.0.0"),
            ("VersionInfoProductVersion", "0.1.0.0"),
            ("VersionInfoProductTextVersion", "0.1.0"),
        ):
            values = re.findall(r"(?im)^[ \t]*" + directive + r"[ \t]*=([^\n]*)$", setup.group(1))
            if len(values) != 1 or values[0].strip().replace("{#MyAppVersion}", "0.1.0") != expected_version:
                raise RuntimeError("{}: [Setup] {} must resolve to {} exactly once".format(relative, directive, expected_version))
        if "[Code]" not in text or any(line.lstrip().startswith(";") for line in text.split("[Code]", 1)[1].splitlines()):
            raise RuntimeError(relative + ": invalid Pascal [Code] comments")
        for key in re.findall(r"\{cm:([A-Za-z]+)\}", text):
            for language in ("english", "chinesesimplified"):
                if not re.search(r"(?m)^" + language + r"\." + key + r"=.+$", text):
                    raise RuntimeError(relative + ": missing localized message " + language + "." + key)
    for relative in ("scripts/build.ps1", "scripts/build-win7.ps1"):
        require(relative, "verify_release_identity.py")
    require("scripts/build.ps1", "$ProjectVersion = $Matches[1]")
    require("scripts/build_release_attestation.py", 'parser.add_argument("--version", default="0.1.0")')
    require("RUN_ARENYXA.cmd", "title Arenyxa v0.1 Source Launcher")

    identity = json.loads(read("RELEASE_IDENTITY.json"))
    identity_fields = {
        "schema": "arenyxa.release-identity/v1", "display_version": "0.1",
        "package_version": "0.1.0", "windows_file_version": "0.1.0.0",
        "artifact_name": "Arenyxa_v0.1", "release_channel": "stable",
        "engineering_baseline": "v8.2.0", "internal_version": "8.2.0",
        "compatibility_identity": "6.8.0", "release_status": "public",
        "release_readiness": "READY FOR SOURCE PUBLICATION", "github_public_release": True,
        "distribution_channel": "community", "signing_status": "unsigned",
        "legacy_validation": "NOT TESTED", "engineering_phase": 8,
    }
    for key, value in identity_fields.items():
        if identity.get(key) != value:
            raise RuntimeError("RELEASE_IDENTITY.json: inconsistent " + key)
    matrix = json.loads(read("docs/release/COMPATIBILITY_MATRIX.json"))
    if matrix.get("product_release_version") != "0.1.0" or matrix.get("runtime_compatibility_identity") != "6.8.0":
        raise RuntimeError("documented public/compatibility identity mismatch")
    require("V8_2_RELEASE_IDENTITY.json", '"artifact_name": "Arenyxa_v8.2"')
    return identity


def main() -> int:
    verify_identity()
    print("Arenyxa v0.1 source identity gate: PASS")
    print("Product 0.1 / package 0.1.0 / PE 0.1.0.0; engineering v8.2.0; compatibility 6.8.0")
    print("Public source release; community unsigned; READY FOR SOURCE PUBLICATION; legacy runtime NOT TESTED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
