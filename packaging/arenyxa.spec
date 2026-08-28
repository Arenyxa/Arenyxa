from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files
from PyInstaller.utils.hooks import collect_dynamic_libs

project = Path(SPECPATH).parent
icon = project / "src" / "arenyxa" / "resources" / "icons" / "arenyxa.ico"
resources = project / "src" / "arenyxa" / "resources"
data_files = [
    (str(resources), "arenyxa/resources"),
    (str(project / "LICENSE"), "."),
    (str(project / "NOTICE.md"), "."),
    (str(project / "TRADEMARKS.md"), "."),
] + collect_data_files("tzdata")
# Qt6Core loads ICU at runtime.  Keep PySide6's native dependency set in the
# same directory as the Qt extension modules so the installed one-folder app
# does not depend on the developer machine's DLL search path.
qt_binaries = collect_dynamic_libs("PySide6")

a = Analysis(
    [str(project / "src" / "arenyxa" / "app.py")],
    pathex=[str(project / "src")],
    binaries=qt_binaries,
    datas=data_files,
    hiddenimports=[
        "lxml.cssselect",
        "openpyxl",
        "dns.resolver",
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
        "PySide6.QtNetwork",
        "cryptography.hazmat.primitives.asymmetric.ed25519",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        "tkinter", "matplotlib", "numpy", "PySide2",
        # Build/test tooling is installed in the development venv but is never
        # part of the desktop runtime. Pydantic's optional mypy plugin otherwise
        # pulls much of this toolchain into the frozen distribution.
        "mypy", "pytest", "_pytest", "pytest_cov", "coverage", "ruff",
        "PyInstaller", "setuptools", "pkg_resources", "wheel", "pip",
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
