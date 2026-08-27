from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files

project = Path(SPECPATH).parent
legacy = project / "legacy" / "win7"
icon = legacy / "src" / "arenyxa" / "resources" / "icons" / "arenyxa.ico"
resources = legacy / "src" / "arenyxa" / "resources"
data_files = [
    (str(resources), "arenyxa/resources"),
    (str(project / "LICENSE"), "."),
    (str(project / "NOTICE.md"), "."),
    (str(project / "TRADEMARKS.md"), "."),
] + collect_data_files("tzdata") + collect_data_files("backports.zoneinfo")

a = Analysis(
    [str(legacy / "src" / "arenyxa" / "app.py")],
    pathex=[str(legacy / "src")],
    binaries=[],
    datas=data_files,
    hiddenimports=[
        "lxml.cssselect",
        "openpyxl",
        "dns.resolver",
        "PySide2.QtCore",
        "PySide2.QtGui",
        "PySide2.QtWidgets",
        "PySide2.QtNetwork",
        "backports.zoneinfo",
        "cryptography.hazmat.primitives.asymmetric.ed25519",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        "tkinter", "matplotlib", "numpy", "PySide6", "playwright",
        "PySide2.QtWebEngine", "PySide2.QtWebEngineCore", "PySide2.QtWebEngineWidgets",
    ],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Arenyxa",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon=str(icon),
    version=str(project / "packaging" / "version_info.txt"),
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="Arenyxa",
)
