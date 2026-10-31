# Arenyxa v6.6 — Stable Release (2026-08-10)

## Release identity

- Public application version: **6.6**
- Python package version (PEP 440): **6.6.0**
- Plugin/API compatibility comparator: **6.6.2**
- Windows version-resource numeric revision: **6.6.0.3**
- Modern installer output: `Arenyxa_V6.6_Setup_x64.exe`
- Legacy installer output: `Arenyxa_V6.6_Legacy_Win7_x64_Setup.exe`

## Stable promotion basis

This release promotes the independently reviewed v6.6beta2 stabilization line without reopening the architecture. It retains the native Qt ownership hardening, lazy page construction/navigation contract, ApplicationContext shutdown serialization, DataRootLease recovery, workflow/dataset lineage consistency, capture and terminal lifecycle fixes, Scheduler generation protection, Runner pause/resume and shutdown-race fixes, Repair Center wrapper compatibility, Windows terminal command quoting fix, and the Modern/Legacy runtime split.

## Final Windows packaging closure

The final packaging blocker was not a PyInstaller or MainWindow failure. The release test script assigned `QT_QPA_PLATFORM=offscreen` at process scope and did not restore it. Running the newly built GUI from the same PowerShell session therefore inherited Qt's offscreen platform: the process remained alive and Qt reported the window as visible, but Windows received no normal desktop top-level window.

`test.ps1` now scopes `QT_QPA_PLATFORM=offscreen` only around pytest and restores the exact previous process-level value in `finally`. `MYPYPATH` receives the same cleanup discipline. The temporary packaged-startup trace used to isolate the defect is intentionally excluded from the stable runtime.

## Release gates

The stable source preserves the beta2 release gates: Python compile, critical Ruff (`E9,F63,F7,F82`), Python 3.8 grammar compatibility, release-blocking pytest, advisory full Ruff, and advisory mypy. The final source also adds regression coverage for stable version identity, Qt offscreen environment restoration, and absence of diagnostic startup-trace instrumentation.

A native Windows rebuild is required to produce the final EXE/installer artifacts from this source. A Linux/static review cannot substitute for that native packaging step or for the separate Windows 7 Legacy binary certification requirement.
