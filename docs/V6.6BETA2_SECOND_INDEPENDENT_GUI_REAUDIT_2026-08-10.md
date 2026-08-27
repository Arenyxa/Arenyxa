# Arenyxa v6.6beta2 — Second Independent GUI Re-audit

Date: 2026-08-10
Scope: cumulative Windows GUI interaction hardened source, independently re-extracted and reviewed.

## Findings fixed in this pass

1. **Qt wrapper identity was still part of navigation verification.**
   `QStackedWidget.currentWidget() is page` can be false when a binding exposes another Python wrapper for the same C++ widget. Route correctness is now verified by the integer stack index; canonical page objects come from Arenyxa's own `pages` registry.

2. **One skipped Windows/Qt RTL test still encoded the obsolete layout contract.**
   It expected Arabic widgets to become structurally RTL, contradicting the new stable-shell design. The test now checks LTR widget geometry plus right-aligned Arabic human text and LTR technical fields.

3. **Motion-setting slider drags performed synchronous durable disk writes on every tick.**
   `settings.json` uses atomic replace + fsync. Repeated `valueChanged` signals therefore caused avoidable GUI-thread I/O. Motion/concurrency persistence is now debounced and flushed on page deactivation/application quit.

4. **Motion profile changes traversed every QApplication widget on every slider tick.**
   Glass repaint scheduling is now coalesced to ~30 Hz and limited to visible glass widgets.

5. **Additional side-effecting combo boxes could still react to accidental wheel input.**
   Data Run selection, Visualization Run selection, and Developer Console mode now use `ScrollSafeComboBox`.

6. **Arabic technical-field detection ignored the current text of QLineEdit.**
   URL/IP/path fields whose technical nature exists only in their current value are now kept LTR.

7. **Old status-clear timers could clear newer status messages.**
   Status messages now use a generation guard.

8. **Windows taskbar COM lifetime was not fully balanced.**
   Successful `CoInitialize` calls are paired with `CoUninitialize`; partial initialization failures release the taskbar COM interface through the same close path.

## Verification

- Full pytest suite: **360 passed, 6 skipped, 0 failed**.
- ResourceWarning-as-error suite: **360 passed, 6 skipped, 0 failed**.
- Focused GUI-interaction contract loop: **23 tests × 10 runs = 230/230 passed**.
- Python 3.8 grammar gate: **89 runtime/build Python files, 0 failures**.
- `compileall`: passed.
- Static scans:
  - direct chained `horizontalHeader()/verticalHeader()/selectionModel()` calls: 0
  - unsafe locale/performance combo change signals: 0
  - `currentWidget() is page` route identity checks: 0
  - dangerous QDialogButtonBox text-overload result assignments: 0
- Wheel build: `arenyxa-6.6b2-py3-none-any.whl` built successfully.
- Isolated wheel import: runtime `6.6beta2`, package `6.6b2`, plugin compatibility `6.6.2`.

## Remaining environment limitation

Six GUI tests are skipped in the Linux review environment because PySide2/PySide6 is not installed there. They must be executed on the Windows PySide6 6.11.1 machine before calling the GUI release fully certified. The stale RTL assertion that would have failed there has been corrected in this pass.
