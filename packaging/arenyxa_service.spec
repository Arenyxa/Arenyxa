from pathlib import Path

project = Path(SPECPATH).parent
icon = project / "src" / "arenyxa" / "resources" / "icons" / "arenyxa.ico"

a = Analysis(
    [str(project / "src" / "arenyxa" / "windows_service_entry.py")],
    pathex=[str(project / "src")],
    binaries=[],
    datas=[],
    hiddenimports=[
        "cryptography.hazmat.primitives.asymmetric.ed25519",
        "psycopg",
        "psycopg_pool",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=["PySide6", "PySide2", "tkinter", "matplotlib", "numpy", "pytest", "mypy", "ruff"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ArenyxaService",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon=str(icon),
    version=str(project / "packaging" / "version_info.txt"),
)
