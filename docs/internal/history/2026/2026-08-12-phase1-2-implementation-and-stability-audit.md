# Arenyxa Phase 1–2 Implementation & Stability Audit

Date: 2026-08-12
Source identity: Arenyxa 6.8 development candidate
Scope: Roadmap Phase 1 Architecture/Contract Freeze + Phase 2 Web Intelligence 2.x

## Executive status

- Phase 1 automated gate: PASS.
- Phase 2 automated gate: PASS.
- Historical regression: 471 passed / 12 skipped / 0 failed, executed as three isolated groups to avoid one long host timeout.
- Python compileall: PASS.
- Python 3.8 grammar gate: PASS (94 runtime source files).
- Configuration parse gate: PASS.
- Targeted static security scan for the new architecture/Web Intelligence modules: PASS.
- Repair Seed / Repair Manifest consistency: PASS after regeneration.
- Source Manifest exact inventory: PASS after regeneration.
- Approved startup visual baseline: unchanged; the two startup visual implementation files match the Phase 0 SHA-256 values byte-for-byte.
- Native Windows Phase 1/2 UI/Capture verification: PENDING. This package is therefore a development candidate, not a newly frozen Windows release baseline.

## Phase 1 delivered

### Executable architecture contract

Added `src/arenyxa/architecture_contracts.py` with explicit contracts for:

1. Run
2. Workflow
3. Dataset
4. Capture
5. Recovery
6. Plugin
7. Storage
8. UI Shell

Each contract names the owner, module boundary, inputs/outputs, lifecycle, failure boundary and allowed dependency direction.

### Lifecycle contract

The canonical lifecycle is frozen as:

`create -> start -> pause -> resume -> terminal -> persist -> recover -> dispose`

Pause/resume repetition is permitted only before terminal state. Tests reject backwards lifecycle evidence after terminal state.

### Failure model

The frozen taxonomy is:

- transient: bounded idempotency-aware retry;
- recoverable: restore/reconcile last durable invariant;
- configuration: reject before side effects;
- permission: backend reject, never UI-only enforcement;
- corruption: stop mutation and preserve evidence;
- fatal: finalize owned resources and terminate with diagnostics.

### Dependency rules

AST-based dependency validation now rejects:

- domain -> application/infrastructure/presentation;
- application -> presentation;
- infrastructure -> presentation;
- direct presentation import of the application persistence implementation.

The developer database adapter surface remains explicit tooling and is not treated as the application store.

### Compatibility freeze

No public namespace/CLI migration was performed. `arenyxa` and historical `arenyxa` compatibility surfaces remain intact and the package/plugin compatibility identity remains 6.8/6.8.0.

Eight ADRs under `docs/adr/` document the frozen ownership decisions.

## Phase 2 delivered

### Web Intelligence Center

Added `src/arenyxa/application/web_intelligence.py` and integrated it into `NextGenFeatureHub` as a single facade over:

- explainable SmartPath;
- Data Source Discovery;
- Capture / Network events;
- GraphQL/WebSocket/SSE inspection;
- Context Bridge;
- Selector Studio;
- Browser Recorder;
- Web Time Machine.

The existing SmartPath desktop surface now runs through the center, preserving the established UI layout while returning a richer cross-feature report.

### SmartPath 2.x path explainability

Every SmartPath result now includes an explicit ordered execution path:

1. static/direct HTML inspection;
2. structured endpoint discovery/preference;
3. browser discovery/execution fallback.

This trace explains the path without silently overriding the established engine scoring model.

### Capture -> Workflow safety gate

Endpoint candidates are classified by structured-data evidence, HTTP method, status and sensitivity.

Automatic conversion requires:

- structured API/XHR/Fetch/GraphQL evidence;
- an idempotent method (`GET`, `HEAD`, `OPTIONS`);
- no sensitive query/header/cookie/sensitivity flags.

Non-idempotent or sensitive requests are review-only. Even explicitly reviewed conversion uses the redacted candidate URL and never restores sensitive query values into the Workflow definition.

The Studio now exposes `Top API -> Workflow` through this gate. The existing `Top API -> HTTP Builder` path also replaces sensitive query values and strips sensitive headers/cookies.

### Selector Recovery 2.x

Selector fingerprints now carry bounded ancestor structure evidence plus a deterministic structure hash. Healing candidates include:

- historical-success evidence;
- match count;
- uniqueness risk;
- auto-apply eligibility.

`heal_with_policy()` separates `review-only` from `auto-apply`. Auto-apply is conservative and requires a unique high-confidence candidate. Legacy `heal()` remains supported.

### Browser Recorder semantic compiler

Added semantic compilation for:

- login;
- search;
- pagination;
- extraction;
- download;
- generic interaction fallback.

`to_semantic_workflow()` annotates existing browser-action Workflow nodes with semantic evidence without changing the old `to_workflow()` contract.

### Web Time Machine linkage

Added a bounded local linkage journal that records:

- redacted target URL;
- exact DOM SHA-256;
- exact response SHA-256/status/content type;
- selector;
- Workflow definition SHA-256;
- Dataset revision ID;
- bounded sanitized metadata.

Raw DOM/response bodies are deliberately not duplicated into the linkage index. Sensitive URL query values and sensitive metadata keys/text are redacted.

## Stability / regression evidence

Historical tests were split into three isolated groups:

- Group 1: 161 passed / 1 skipped.
- Group 2: 182 passed / 4 skipped.
- Group 3: 128 passed / 7 skipped.
- Total: 471 passed / 12 skipped / 0 failed.

The skips are environment-explicit: missing Qt binding in the Linux/headless validation host and Windows-only process/DPI probes. They are not hidden failures.

Phase-specific tests:

- Phase 1 architecture contracts: 5 passed.
- Phase 2 Web Intelligence + compatibility regression: 45 passed in the phase gate.
- Repair/Source Manifest focused validation: 21 passed.

## Startup animation freeze

The owner-approved startup animation was not modified.

Frozen visual implementation hashes:

- `src/arenyxa/presentation/startup_splash.py` — `a95bf948c3ddb2a165100711c59843e1eef013e7f9fb7e392ffbc38c9ddd5267`
- `src/arenyxa/presentation/startup_motion_math.py` — `81ce778eed5682ca042cdd1c7875ac46b20ea622d75c50d144d3b8043963231e`

`scripts/verify_startup_visual_baseline.py` makes accidental future modification a hard automated failure unless this scope is explicitly reopened.

## Known remaining native gate

This environment cannot truthfully validate native Windows Qt/compositor behavior, real Capture adapters, multi-monitor/DPI behavior, or the new Studio interaction flow with an installed Qt runtime. The user has already confirmed the Phase 0 startup animation visually on Windows, but Phase 1/2 remains pending for the separate Windows verification checklist.

## No out-of-scope expansion

This work did not implement Enterprise Identity, Developer Authority, Official Developer Access, Coordinator, distributed Server/Worker redesign, or a cloud dependency. Git operations and Inno Setup packaging were not performed.
