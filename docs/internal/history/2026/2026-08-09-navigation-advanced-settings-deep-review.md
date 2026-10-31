# Arenyxa V6.0 — Navigation / Advanced Settings Deep Review

Date: 2026-08-09

## Scope

This review started from `Arenyxa_V6.0_DeepReview_About_Refined` and deliberately kept the existing Dashboard, six visual presets, capture/data/runtime architecture, provenance chain, Repair Center and backend contracts intact. The change concentrates on navigation information architecture, Developer Mode discoverability, maintenance entry points, localization/RTL behavior and state safety.

## Navigation information architecture

The primary rail is now separated into four semantic layers:

- Core: Dashboard, Search, Capture, Network, Data, Visualization.
- Advanced: Workflow, Automation, Advanced Platform, Data Versions, Plugins. The group is collapsed by default and remembers its state.
- Developer: Terminal/Debug Console, API Explorer, Plugin Sandbox, Performance Monitor, and Logs/Trace Viewer. The API/Performance/Sandbox entries are shortcuts into existing real analysis/plugin surfaces rather than duplicate pages. The entire group is invisible unless Developer Mode is enabled.
- System: Settings and About remain pinned at the bottom.

The rail keeps the existing animated 72 px compact mode and 220–250 px expanded mode. Expanded/collapsed state and Advanced/Developer group state are persisted independently. RTL uses mirrored group arrows and right-aligned navigation text while technical content remains LTR.

## Advanced Settings

Maintenance and development switches are centralized in Settings → Advanced Settings:

- Developer Mode.
- Run Diagnostics.
- Repair Center.
- Export redacted diagnostic package.
- Optional local-path inclusion for diagnostic packages (off by default).
- Reset application settings without deleting Projects, Captures, Exports, the database, or formal result data.

Ctrl+K exposes diagnostics and Repair Center directly. Developer-only destinations are omitted from the palette while Developer Mode is disabled.

## Defects found and fixed during the post-change review

1. Runtime diagnostics could interpret the current `crash.marker` as a previous crash. `StartupHealthScanner` now supports `ignore_current_session=True` and validates current PID/phase.
2. Source/development builds could be unintentionally restored from the source repair seed when the user selected only language/encoding repair. Language repair no longer restores program files implicitly; source restoration occurs only when Program Files is explicitly selected.
3. Opening Repair Center could cancel active jobs before the user actually committed to repair. Health scanning is now background/read-mostly; active jobs are stopped only after a repair selection is accepted and a second confirmation is given.
4. Repair Center integrity scanning could block the Qt GUI while hashing installation contents. The in-app scan now runs through the existing Qt thread-pool boundary and only opens the selection dialog after completion.
5. Custom-painted theme previews and several QPainter-only labels bypassed the normal event-driven translation walker. They now resolve the active locale explicitly, including Arabic alignment. Painted Dashboard/Network/Visualization empty-state labels follow the same localization fallback.
6. Developer navigation could remain persisted as expanded while Developer Mode was disabled. Settings loading and Repair Center normalization now force the hidden developer group closed.
7. Startup health diagnostics did not report invalid Boolean navigation/developer settings or invalid performance mode. Those conditions now produce structured findings and are safely normalized during repair.
8. Inspector toggle text used a hard-coded English label and did not mirror direction consistently. It now uses the active localized Context Inspector label and RTL-aware arrows.
9. Advanced/Developer group opening was visually abrupt. Child destinations use a short staggered reveal through the existing MotionOrchestrator, respecting Reduce Motion/performance policy.
10. Rail expansion could finish at full width while buttons remained icon-only because retranslation inferred state from the in-flight maximum width. The persisted `left_sidebar_collapsed` flag is now the single semantic source of truth.

## Verification

- Python AST parsing: all source/test/script Python files parsed successfully.
- `compileall`: passed for `src`, `tests`, and `scripts`.
- Focused navigation/repair/provenance/security/http/capture/scheduler/project suite: 53 passed.
- Broader non-GUI suite excluding the environment-missing `cssselect` parser case and Qt-only suites: 62 passed.
- `cssselect>=1.2,<2` remains explicitly declared in both `requirements.txt` and `pyproject.toml`; the current audit container does not provide it.
- PySide6 is not installed in the audit container, so real Qt rendering, Windows DPI/multi-monitor behavior, and GUI animation smoke testing remain Windows release-gate items rather than being falsely reported as executed here.

## Design invariants retained

- Developer Mode hides/discloses developer surfaces but does not gate normal Capture/Search/Data/Network capabilities.
- Terminal system commands still require the Console's own explicit confirmation boundary.
- Repair/diagnostic tooling does not become a normal left-navigation destination.
- Source builds remain freely modifiable.
- Reduce Motion remains authoritative over navigation micro-motion.
- Theme changes do not duplicate page implementations or alter business-state ownership.
