from __future__ import annotations

import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODERN = ROOT / "src" / "arenyxa"
WIN7 = ROOT / "legacy" / "win7" / "src" / "arenyxa"
REMOVED = "n" + "exora"
BINARY_SUFFIXES = {".png", ".ico", ".jpg", ".jpeg", ".webp", ".exe", ".dll", ".pyd", ".pyc"}


def main() -> int:
    failures: list[str] = []
    if not MODERN.is_dir():
        failures.append("modern Arenyxa package is missing")
    if not WIN7.is_dir():
        failures.append("Win7 Arenyxa package is missing")
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT).as_posix()
        if REMOVED in rel.casefold():
            failures.append("removed namespace path residue: " + rel)
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        if path.suffix.casefold() == ".zip":
            try:
                with zipfile.ZipFile(path) as archive:
                    for member in archive.namelist():
                        if REMOVED in member.casefold():
                            failures.append(f"removed namespace archive residue: {rel}::{member}")
                            break
            except zipfile.BadZipFile:
                failures.append("unreadable zip archive: " + rel)
            continue
        if path.suffix.casefold() in BINARY_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if REMOVED in text.casefold():
            failures.append("removed namespace text residue: " + rel)
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    for expected in (
        'name = "arenyxa"',
        'arenyxa = "arenyxa.cli:main"',
        'arenyxa-gui = "arenyxa.app:main"',
        'arenyxa-cli = "arenyxa.cli:main"',
        'arenyxa-server = "arenyxa.infrastructure.server:main"',
    ):
        if expected not in pyproject:
            failures.append("canonical packaging entry missing: " + expected)
    if failures:
        print("ARENYXA_NAMESPACE_GATE=FAIL")
        for item in failures[:40]:
            print(item)
        return 1
    print("ARENYXA_NAMESPACE_GATE=PASS")
    print("canonical_packages=modern+win7")
    print("removed_namespace_residue=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
