# Arenyxa V6.5.2 Sidebar & Selection-State Review

Date: 2026-08-09

## Scope

V6.5.2 is a presentation/state-safety hotfix on top of V6.5.1. Dataset, lineage, workflow execution, network capture and storage contracts are unchanged. The release targets two classes of defects: navigation/selection state that can represent more states than the product semantics allow, and the visual density/hierarchy of the primary left rail.

## Selection-state audit

- All page destinations remain in one explicit exclusive `QButtonGroup`; a committed route is the sole source of truth for the checked page.
- Command Palette, local search results, plugin list, network session list, network event table, task list, task-field table and data record table now explicitly declare single-selection semantics instead of relying on Qt defaults.
- Automation schedule table is display-only and therefore declares `NoSelection`.
- Dataset Revision comparison intentionally supports multi-selection, but the UI now enforces a hard budget of two selected revisions. Selecting additional revisions evicts older selections instead of allowing an invalid 3+ state and rejecting it only after the user presses Compare.
- Repair Center category checkboxes remain intentionally independent/multi-select, and its Auto/Manual radio modes remain an explicit exclusive button group.

## Sidebar redesign

The left rail is rebuilt around a quieter Modern Dark hierarchy:

- Expanded rail: 236 px fixed design width.
- Compact rail: 68 px.
- Primary/system destinations: 40 px rows.
- Advanced/developer child destinations: 36 px rows.
- Advanced and Developer group headers: 30 px rows.
- Brand header is split into logo, product name, compact subtitle and a low-emphasis collapse control.
- The primary navigation body is the only scrollable region.
- Settings and About are pinned in a non-scrolling footer, so they remain reachable on short windows.
- Local service state is rendered as a small status pill instead of a loose two-line label.
- Normal navigation labels use neutral text. Accent green is reserved for the committed selection indicator/background and semantic status, preventing multiple actionable items from visually resembling selected pages.
- Selected child routes also subtly emphasize their owning section header when the child itself is hidden by a collapsed Advanced/Developer group.
- RTL alignment and compact-mode semantics continue to use the persisted sidebar state rather than in-flight animation geometry.

## Stability constraints

- No new dependency was added.
- No source-of-truth route state was moved into visual widgets.
- Sidebar collapse/expand continues to respect Reduce Motion through `MotionOrchestrator.animate_width`.
- Developer Mode remains the authority boundary for developer-only pages/actions.
- Settings/About remain part of the same exclusive page group even though they are physically pinned outside the scroll area.

## Verification

Release verification includes AST/internal-import contracts, explicit selection-state contracts, compileall, focused navigation tests, the broader non-GUI suite, repair-seed regeneration, source-manifest regeneration and archive CRC/SHA-256 verification. Qt rendering tests remain an additional Windows gate when PySide6 is available.
