# CI Quality Matrix

The repository defines `.github/workflows/quality.yml` as the cross-platform release validation matrix.

## Linux lane

Python 3.11 and 3.13 execute the full pytest suite. Both lanes execute the release-blocking critical Ruff rules (`E9,F63,F7,F82`) through `scripts/static_quality_gate.py`. Full Ruff and strict Mypy audits also run and are retained under `dist/audit` so the pre-existing backlog stays visible without making an unrelated tool-rule expansion silently stop packaging.

## Windows lane

The Windows job installs the full development/runtime extras, PySide6 and Playwright Chromium, sets `QT_QPA_PLATFORM=offscreen`, and explicitly executes:

- Windows process-probe contracts;
- Qt UI smoke tests;
- lazy page runtime construction;
- Windows Qt crash/header/DPI contracts;
- the complete `scripts/final_quality_gate.py --full` release gate.

This lane exists specifically so Linux validation skips for Windows/Qt contracts cannot be mistaken for completed release validation.

## Policy

Critical Ruff/Pyflakes runtime-safety findings are release-blocking in CI. Full Ruff and Mypy are mandatory retained audits but remain advisory until their existing backlogs are reduced to zero or an explicit, versioned ratchet is adopted. A local/offline validation environment that does not contain those tools may still run targeted runtime tests, but it must not claim that the final static-analysis release gate has passed.
