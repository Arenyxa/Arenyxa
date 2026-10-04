# Arenyxa v6.8 Stable Release Audit

Date: 2026-08-11

## Release identity

- Public runtime: **6.8**
- Python distribution: **6.8.0**
- Plugin/API compatibility comparator: **6.8.0**
- Modern Windows installer target: `Arenyxa_V6.8_Setup_x64.exe`
- Windows 7 Legacy installer target: `Arenyxa_V6.8_Legacy_Win7_x64_Setup.exe`

## Stable-release goals

v6.8 promotes the adaptive-concurrency beta line to a stable release while concentrating on startup presentation and failure-boundary reliability. No feature was intentionally removed. The release retains the v6.7 multi-monitor launch-geometry contract, Repair single-console hotfix, UI scaling, Capture lifecycle cleanup, and the v6.8 adaptive request-admission controller.

## Startup motion refinement

The startup handoff was redesigned to remove several sources of visible micro-stutter on Windows compositors:

- the in-window handoff overlay is now paint-only instead of combining two `QGraphicsOpacityEffect` objects;
- the icon is no longer rescaled into a new `QPixmap` on every animation frame;
- `QPainter` draws the original icon with `SmoothPixmapTransform` and a scalar transform;
- a quintic smootherstep curve gives zero start and end velocity instead of the abrupt initial acceleration of the prior OutCubic handoff;
- icon opacity reaches zero before the opaque launch surface begins revealing the real workspace;
- Quality/Balanced/Efficiency modes keep distinct durations without artificial sleeps or nested event loops;
- Reduce Motion remains a static continuous handoff;
- the existing single launch-geometry plan continues to bind splash, MainWindow, handoff overlay, Recovery Mode, and refresh-rate policy to the same target display.

The temporary top-level fallback path preserves the same two-stage visual order, so a compositor or overlay-preparation failure does not expose the dashboard behind a still-visible logo.

## Reliability hardening

### Run pause/resume transaction boundary

`CancellationToken.pause()` / `resume()` failures are now handled before volatile or durable Run state is changed. Token-transition failures are logged and leave both the in-memory Run and database status unchanged. Existing persistence rollback remains in place for database-write failures after a successful token transition.

### Diagnostic visibility

Several non-fatal recovery paths that previously swallowed secondary exceptions now retain the safe fallback behavior but emit diagnostic logging, including Dataset terminal-state writeback, Activity Center subscriber failures, distributed-worker vault rollback, and native Repair dialog fallback.

### Packaging audit output

Full Ruff and mypy audits remain available, but advisory findings are written to `dist/audit` instead of flooding the packaging console. Release-blocking compile, critical-lint, Python 3.8 grammar, and pytest gates remain separate hard gates in the Windows build script.

## Regression matrix for previously observed issues

- Multi-monitor startup surface and MainWindow placement: shared `LaunchGeometryPlan` retained and re-tested.
- Startup icon visible while workspace appears: two-stage icon-then-surface reveal retained and strengthened.
- Startup motion feels abrupt: paint-only smootherstep handoff introduced.
- Repair progress terminal followed by a blank terminal: source relaunch continues to prefer `pythonw.exe` with no-console/detached fallbacks and DEVNULL standard handles.
- Repair progress terminal not closing: Repair worker/relaunch process boundaries remain independently testable and the visible progress host is not inherited by the relaunched GUI.
- Large-display text too small: automatic/manual 85%-160% UI scaling contract retained.
- Capture completed but top activity strip keeps moving: terminal Capture states continue to clear the indeterminate global-progress state.
- Pause/resume persistence mismatch: durable rollback retained; token-transition failures are now covered before state mutation.
- Adaptive concurrency overload: configured worker count remains the ceiling, while automatic admission starts from the local four-slot floor and can grow/back off based on local-processing pressure.
- Silent secondary failures: reviewed and reduced; intentional destructor/Windows-API fallback catches remain non-fatal by design.

## Validation record

Before the final Source Manifest freeze, the complete historical regression collection (excluding only the manifest self-check while files were still changing) completed with **434 passed / 6 skipped / 0 failed**. The six skips are native Qt visual/UI tests because the current audit container has no installable PySide2/PySide6 binding.

Additional focused gates completed successfully for stable identity/packaging, startup geometry and motion mathematics, Repair/Capture/UI-scale contracts, Runner concurrency and shutdown, Dataset/Workflow/lineage/recovery, security/provenance/terminal, Python compilation, and Python 3.8 grammar compatibility.

After the release tree was frozen, the Repair Seed and Source Manifest were regenerated. The final Source Manifest covers **259 files**. Repair/Manifest/stable-release focused integrity checks completed with **31 passed / 0 failed**. Including the Source Manifest self-check, the complete historical regression result is **435 passed / 6 skipped / 0 failed**.

## Windows-native release verification

The current audit environment cannot honestly certify exact Windows compositor smoothness or native Qt rendering. On the target Windows machine, verify the final source/build with:

1. normal startup on each connected display, repeated close/relaunch, maximize/restore, display disconnect/reconnect, and Reduce Motion;
2. `test-all`;
3. `stress-test standard` and `stress-test extreme`;
4. repeated Repair Center runs, confirming only one visible progress terminal and no blank terminal after relaunch;
5. Browser/tshark Capture start/stop/completed/failed/cancelled paths, confirming the top activity strip always clears;
6. `scripts\build.ps1`, followed by install/upgrade/uninstall smoke testing of `Arenyxa_V6.8_Setup_x64.exe`.

The stable designation reflects the verified source/runtime contracts and regression record; native Windows visual playback remains the authoritative final check for subjective animation smoothness.
