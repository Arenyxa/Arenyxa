# Arenyxa V6.0 — Personalization & Dashboard Redesign

## Scope
This revision changes presentation/theme configuration only. Core crawling, capture, storage, task, workflow, plugin and server logic is intentionally left intact.

## Personalization
- Keeps all six presets.
- Official visual baseline: Modern Dark, Aurora Glass, Clean Light, Terminal Green.
- Codex extension presets retained: Professional Graphite, Blue Productivity.
- Modern Dark is the default for new settings profiles.
- Replaces text-only preset buttons with 2×3 visual preview cards.
- Every card draws a miniature Arenyxa workspace using that preset's own theme tokens: background gradient, sidebar, top bar, metric cards, chart and health ring.
- Selected preset receives an accent outline and check indicator.
- Theme switching still persists to `settings.json` and does not rebuild business pages.

## Liquid Glass settings persistence
The following visual settings are now persisted:
- glass strength
- blur strength
- motion strength
- reduce motion
- edge flow
- live data motion
- performance mode

## Dashboard
- Introduces a command-center hero surface with local-service state and four headline values.
- Reflows the six core KPI cards into a wide responsive 12-column layout.
- Keeps recent tasks and recent run activity.
- Adds a stronger run-health module with ring gauge + compact progress line.
- Adds a live-looking activity pulse graph driven by workspace metrics.
- Keeps automation schedule visibility in the primary dashboard.

## Verification performed in this revision
- `python -m compileall -q src tests` — pass.
- Direct AST parse of all edited Python files — pass.
- Runtime Qt smoke test was not executed in the editing environment because PySide6 is not installed there.
