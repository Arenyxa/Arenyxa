# Arenyxa v8.1 Release Notes

Arenyxa v8.1 is a stable source refresh based on the v8.0 feature set. It does not remove product features or relax Root Developer authentication/integrity controls.

## v8.1 changes

- Replaced the legacy green network/crawler application artwork with the new Arenyxa geometric `A` + Core identity.
- Regenerated the canonical 1024 px RGBA application PNG and the Windows multi-size ICO (16/24/32/48/64/128/256 px).
- The new icon is used by the Qt runtime, title bar, main window, About page, startup splash, PyInstaller executable, Windows service packaging, and Inno Setup installer through the existing canonical branding paths.
- Promoted the product/display version to `8.1`, Python distribution/package version to `8.1.0`, and Windows file version to `8.1.0.0`.
- Updated installer output names to `Arenyxa_V8.1_Setup_x64.exe` and `Arenyxa_V8.1_Legacy_Win7_x64_Setup.exe`.
- Hardened the source launcher so a stale editable virtual environment cannot silently import an older Arenyxa source tree. The launch probe now verifies that `arenyxa.__file__` resolves under the current project's `src` directory before startup.
- The clean v8.1 source delivery intentionally omits the machine-bound `.venv`; `RUN_ARENYXA.cmd` / `scripts\bootstrap.ps1` recreates it against the extracted v8.1 source tree. This prevents an old editable environment from silently pointing back to a previous project directory.

## Compatibility

- Runtime/plugin compatibility identity remains `6.8.0` by design.
- Existing v8.0 feature architecture is preserved; this release is a brand/version/launcher-integrity refresh, not a database schema migration.
