# Arenyxa V6.6.1 — Windows 7 Legacy Enterprise Compatibility & 6× Deep Review

Date: 2026-08-09

## Release intent

V6.6.1 continues the V6.6.0 stability-first line and adds a maintained **Legacy Enterprise** runtime lane whose minimum target is **Windows 7 SP1 x64**. The implementation deliberately keeps one Domain/Application/Infrastructure codebase. Operating-system, Python and Qt differences are isolated behind `platform_compat.py`, `compat.py`, and `qt_compat/` instead of creating a separate legacy fork.

The modern lane remains Windows 10 1809+/Windows 11 with CPython 3.11-3.13 and PySide6. The Legacy lane uses CPython 3.8.x and PySide2 5.15.2.1, reduced visual effects and software OpenGL defaults. Browser Recorder/Playwright execution and QtWebEngine are excluded from the Legacy package; HTTP collection, Dataset, Workflow, SQLite/FTS5, plugin runtime, Developer Terminal, scheduler, recovery and Headless core remain shared.

## Review 1 — Baseline and release-contract freeze

Starting point: `Arenyxa_V6.6.0_Stability_Compatibility_Crash_Resistance_Hardened_Reviewed.zip`.

Checks:

- froze the existing V6.6.0 regression baseline before compatibility changes;
- preserved the V6.5.6 security/crash-consistency fixes already incorporated by V6.6.0;
- bumped internal product/file version to 6.6.1;
- retained the stable modern installer series output name `Arenyxa_V6.6_Setup_x64` so existing deployment automation is not silently broken;
- added a separate `Arenyxa_V6.6.1_Legacy_Win7_x64_Setup` installer identity for the Legacy lane.

Finding fixed: an early version of the patch renamed the modern installer output to V6.6.1 and broke an existing release-contract test. The modern series name was restored while the internal file/product version remains 6.6.1.

## Review 2 — Python 3.8 import/runtime compatibility

The source tree was parsed with Python 3.8 grammar and scanned for APIs that would import successfully on 3.11+ but fail on 3.8.

Compatibility shims now cover:

- `dataclass(slots=True)`;
- `enum.StrEnum`;
- `datetime.UTC`;
- `zoneinfo` via `backports.zoneinfo`;
- `Path.is_relative_to()`;
- `str.removeprefix()` / `str.removesuffix()`;
- `Executor.shutdown(cancel_futures=...)`;
- module-level type aliases that would otherwise evaluate PEP 585/604 expressions on Python 3.8.

Additional static gates reject direct use of known post-3.8 APIs outside the compatibility module and reject direct PySide2/PySide6 imports outside the Qt facade.

Current static result:

- Python source files scanned: 84
- Python 3.8 grammar failures: 0
- direct Qt binding imports outside facade: 0
- known post-3.8 runtime API violations: 0
- unsafe module-level type-alias evaluations: 0

## Review 3 — Qt 5 / Qt 6 compatibility facade

All presentation-layer binding imports now target `arenyxa.qt_compat`.

The facade:

- prefers PySide6 on the modern runtime and PySide2 on the Legacy runtime;
- maps Qt6 scoped-enum forms such as `Qt.AlignmentFlag.AlignCenter` to Qt5 constants;
- maps class-scoped enums for `QMessageBox`, `QDialog`, `QAbstractItemView`, `QHeaderView`, `QPalette`, `QIcon`, `QPainter`, `QTextCursor`, and related types;
- aliases legacy `exec_()` to the Qt6-style `exec()` surface;
- relocates `QAction` and `QShortcut` between Qt5/Qt6 modules;
- adapts Qt5 mouse-position access (`localPos()`) where Qt6 uses `position()`.

The Win7 PyInstaller profile explicitly excludes PySide6, Playwright and QtWebEngine so an unsupported Chromium path cannot be accidentally pulled into the Legacy executable.

## Review 4 — Windows 7 packaging/dependency determinism

Legacy runtime files:

- `requirements-win7.txt`
- `requirements-dev-win7.txt`
- `packaging/arenyxa_win7.spec`
- `packaging/installer_win7.iss`
- `scripts/bootstrap-win7.ps1`
- `scripts/test-win7.ps1`
- `scripts/run-win7.ps1`
- `scripts/build-win7.ps1`

The bootstrap script is intentionally compatible with Windows PowerShell 2.0 syntax and checks:

- x64 Windows;
- Windows 7 SP1 minimum;
- KB2533623 on Windows 7;
- CPython 3.8.x x64;
- deterministic packaging toolchain versions.

Legacy dependency pins include:

- PySide2 5.15.2.1
- cryptography 42.0.7
- backports.zoneinfo 0.2.1
- PyInstaller 4.10
- pyinstaller-hooks-contrib 2024.4
- pip 24.3.1 / setuptools 75.3.2 / wheel 0.45.1 for bootstrap tooling

The PyInstaller hooks package is pinned independently because later hook releases can require PyInstaller 5+ APIs even when an older PyInstaller itself remains installable.

## Review 5 — Concurrency, lifecycle and crash-resistance deep review

A real race/liveness defect was found while investigating a pytest process that printed 100% completion but did not terminate.

Previous behavior:

1. `RunHandle.pause()` / `resume()` acquired the run state lock;
2. while still holding that lock they performed a full SQLite `save_run()`;
3. high-frequency pause/resume could repeatedly retain/reacquire the lock around disk I/O;
4. the run completion thread could be starved from acquiring the same state lock;
5. a delayed PAUSED/RUNNING full-row save also had a window where it could overwrite terminal-state data.

Fix:

- lock scope now covers only in-memory state/token transitions;
- persistence happens after releasing the state lock;
- pause/resume uses a guarded status-only `UPDATE`, not a whole-run rewrite;
- terminal states cannot be overwritten by PAUSED/RUNNING control writes;
- a pause requested after `submit()` but before worker startup remains PAUSED instead of being forced back to RUNNING;
- request futures and scheduler callback futures are explicitly tracked/cancelled before the Python 3.8 shutdown fallback;
- executor shutdown no longer depends on the Python 3.9+ `cancel_futures` keyword.

Result: the previously observed post-test process hang is no longer reproducible; the full pytest process exits normally with code 0.

## Review 6 — Full regression, integrity and artifact verification

Final release gates include:

- `compileall` for source and tests;
- Python 3.8 grammar/static compatibility scan;
- 18 dedicated Win7/Legacy compatibility contract tests;
- V6.5.6/V6.6 stability, concurrent scraping, scheduler, recovery and lifecycle regressions;
- full pytest suite;
- Repair Seed rebuild + ZIP CRC validation;
- source SHA-256 manifest rebuild;
- wheel build and wheel CRC validation;
- final source/overlay archive CRC + SHA-256 verification.

At the first full V6.6.1 release gate after the fixes, the suite completed with **299 passed, 6 skipped, 0 failed** and the Python process exited normally. The six skips are Qt GUI smoke tests in the Linux review container because no PySide binding is installed there; they are not assertion failures.

## Native Windows 7 certification status

This review environment is Linux. It can validate source grammar, runtime contracts, concurrency behavior, database consistency, packaging metadata and deterministic artifact construction, but it **cannot honestly certify a Windows 7 executable launch or real PySide2 GUI rendering**.

Before labeling a specific binary as Windows-7-certified, run these gates on a clean Windows 7 SP1 x64 VM or physical machine with KB2533623 installed:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\bootstrap-win7.ps1
.\scripts\test-win7.ps1
.\scripts\run-win7.ps1
.\scripts\build-win7.ps1
```

Then smoke-test the built `dist\Arenyxa\Arenyxa.exe`, shutdown/restart, Dataset/Workflow/HTTP capture/Terminal/Headless paths, DPI scaling, old Intel/AMD graphics with software rendering, and installer install/uninstall/file-association behavior.

## Support policy note

Windows 7 and CPython 3.8 are legacy/EOL platforms. V6.6.1 therefore treats Windows 7 as a compatibility lane rather than the preferred security baseline. Security-sensitive or directly internet-exposed enterprise deployments should use the modern Windows 10/11 runtime whenever operationally possible.
