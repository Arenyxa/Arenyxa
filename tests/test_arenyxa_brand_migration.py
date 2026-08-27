from __future__ import annotations

import struct
import zipfile
from pathlib import Path

from arenyxa import __version__
from arenyxa.branding import APP_NAME, PROJECT_FORMAT
from arenyxa.config import AppPaths

ROOT = Path(__file__).resolve().parents[1]
REMOVED_NAMESPACE = "n" + "exora"


def test_removed_namespace_is_absent_from_source_paths_text_and_repair_archives() -> None:
    offenders: list[str] = []
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT).as_posix()
        if REMOVED_NAMESPACE in relative.casefold():
            offenders.append(relative)
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        if path.suffix.casefold() == ".zip":
            try:
                with zipfile.ZipFile(path) as archive:
                    if any(REMOVED_NAMESPACE in member.casefold() for member in archive.namelist()):
                        offenders.append(relative + "::<archive>")
            except zipfile.BadZipFile:
                pass
            continue
        if path.suffix.casefold() in {".png", ".ico", ".jpg", ".jpeg", ".webp", ".pyc", ".exe", ".dll"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if REMOVED_NAMESPACE in text.casefold():
            offenders.append(relative)
    assert offenders == []


def test_arenyxa_is_the_only_public_python_and_cli_identity() -> None:
    assert APP_NAME == "Arenyxa"
    assert PROJECT_FORMAT == "arenyxa.project/1"
    assert (ROOT / "src" / "arenyxa" / "__main__.py").is_file()
    assert (ROOT / "legacy" / "win7" / "src" / "arenyxa" / "__main__.py").is_file()
    assert (ROOT / "packaging" / "arenyxa.spec").is_file()
    assert (ROOT / "packaging" / "arenyxa_win7.spec").is_file()
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'name = "arenyxa"' in pyproject
    assert pyproject.count('arenyxa = "arenyxa.cli:main"') == 1
    assert pyproject.count('arenyxa-gui = "arenyxa.app:main"') == 1
    assert pyproject.count('arenyxa-cli = "arenyxa.cli:main"') == 1
    assert pyproject.count('arenyxa-server = "arenyxa.infrastructure.server:main"') == 1


def test_installer_never_deletes_current_arenyxa_executable() -> None:
    for relative in ("packaging/installer.iss", "packaging/installer_win7.iss"):
        source = (ROOT / relative).read_text(encoding="utf-8-sig")
        assert '#define MyAppName "Arenyxa"' in source
        assert '#define MyAppExeName "Arenyxa.exe"' in source
        assert "DeleteFile(" not in source
        assert source.count('Subkey: "Software\\Classes\\.arenyxa"') == 1


def test_data_root_is_canonical_arenyxa(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("ARENYXA_DATA_DIR", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    fresh = AppPaths.discover()
    assert fresh.root == (tmp_path / "Arenyxa").resolve()
    assert fresh.database.name == "arenyxa.db"
    explicit = tmp_path / "explicit-root"
    monkeypatch.setenv("ARENYXA_DATA_DIR", str(explicit))
    assert AppPaths.discover().root == explicit.resolve()


def test_bootstrap_probes_all_supported_64_bit_python_versions() -> None:
    bootstrap = (ROOT / "scripts" / "bootstrap.ps1").read_text(encoding="utf-8")
    for version in ("-3.13", "-3.12", "-3.11"):
        assert version in bootstrap
    assert "sys.maxsize > 2**32" in bootstrap


def test_application_png_has_alpha_and_ico_has_expected_windows_sizes() -> None:
    png = ROOT / "src" / "arenyxa" / "resources" / "icons" / "arenyxa.png"
    raw = png.read_bytes()
    assert raw[:8] == b"\x89PNG\r\n\x1a\n"
    ihdr_length = struct.unpack(">I", raw[8:12])[0]
    assert raw[12:16] == b"IHDR" and ihdr_length == 13
    width, height, bit_depth, color_type = struct.unpack(">IIBB", raw[16:26])
    assert (width, height, bit_depth, color_type) == (1024, 1024, 8, 6)
    ico = ROOT / "src" / "arenyxa" / "resources" / "icons" / "arenyxa.ico"
    data = ico.read_bytes()
    reserved, kind, count = struct.unpack("<HHH", data[:6])
    assert (reserved, kind, count) == (0, 1, 7)


def test_source_repair_manifest_covers_canonical_facade() -> None:
    import json
    manifest_path = ROOT / "src" / "arenyxa" / "resources" / "repair_manifest.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = set(payload.get("files", {}))
    for expected in ("src/arenyxa/__init__.py", "src/arenyxa/__main__.py", "src/arenyxa/app.py", "src/arenyxa/server.py"):
        assert expected in files


def test_public_server_module_is_executable() -> None:
    server = (ROOT / "src" / "arenyxa" / "server.py").read_text(encoding="utf-8")
    assert 'if __name__ == "__main__":' in server
    assert "raise SystemExit(main())" in server
