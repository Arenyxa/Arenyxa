# Arenyxa Competitive Edge Release Audit — 2026-08-09

## Scope

Baseline: `Arenyxa_V6.0_Intelligence_Studio_All_Features_Reviewed.zip`.

This iteration adds the Explainable Web Intelligence Blueprint, Context Bridge, `arenyxa.workflow/v1` portability, Compatibility Lab, Reliability Advisor, toolbar/command-palette/system-tray access, and auxiliary progress propagation into the Windows taskbar UI.

## Verification completed in the review container

- Python `compileall`: passed for source/tests before packaging.
- Internal `arenyxa.*` import reference scan: no unresolved internal module references.
- Competitive-edge + existing non-GUI regression set: **158 passed**; one expected `zipfile` warning from the duplicate-entry rejection security test.
- Repair seed/manifest targeted regression: passed.
- Source-manifest verification: passed.
- Legacy pre-Arenyxa brand-string scan: no matches in shippable text.
- `pyproject.toml` parsed with Python `tomllib`.
- Shippable JSON resources parsed successfully.
- Wheel build using `pip wheel --no-deps --no-build-isolation`: passed; `arenyxa-6.0.0-py3-none-any.whl` contained `arenyxa/application/competitive.py` and the updated Intelligence Studio.
- Repair seed ZIP CRC: passed during targeted tests.

## Deliberate truthfulness boundary

The current review container does not include PySide6, therefore the full Qt/offscreen UI suite cannot be executed here. Windows-specific taskbar COM, system tray, PyInstaller executable behavior, and Inno Setup installer behavior still require the existing Windows release gate (`scripts/test.ps1` / `scripts/build.ps1`).

The Compatibility Lab bundled report is explicitly an **offline deterministic fixture regression**. It is not presented as a measured compatibility percentage against live third-party websites. Live compatibility claims should only be published after permissioned fixture/live benchmark coverage is established.

Blueprint latency/RAM/request figures are heuristic planning estimates, not benchmark measurements. They are labelled accordingly in the API/UI.

## Release-integrity automation improvement

A new `scripts/build_source_manifest.py` regenerates `SOURCE_MANIFEST.sha256`. `scripts/build.ps1` now runs it immediately after rebuilding the source repair seed and before test gates, preventing the source manifest from becoming stale after normal release preparation.
