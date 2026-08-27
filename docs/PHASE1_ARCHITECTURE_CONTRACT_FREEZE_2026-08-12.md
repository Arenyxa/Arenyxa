# Arenyxa Phase 1 — Architecture & Contract Freeze

Version milestone: 6.8.x architecture freeze. The package version remains 6.8 during this development gate so historical compatibility tests remain meaningful; release naming is deferred.

## Purpose

Phase 1 does not rewrite the Runtime. It converts implicit ownership into an auditable contract so later Web, Reliability, Security, Enterprise and Server work cannot create hidden dependency cycles or incompatible state semantics.

## Core Runtime ownership map

| Area | Owner | Durable truth | Primary boundary |
|---|---|---|---|
| Run | `RunOrchestrator` | Run state/results | bounded retry + durable state transition |
| Workflow | `WorkflowEngine` / `WorkflowDatasetService` | execution/checkpoint/output revision | no duplicate non-idempotent side effects |
| Dataset | `DatasetVersionService` / `DataLineageService` | revision + lineage | complete attributable revision or absent |
| Capture | `CaptureController` | capture session/events/drop counters | bounded queues; dropped data disclosed |
| Recovery | `RuntimeRecoveryService` | reconciled lifecycle state | repair only defined invariants |
| Plugin | `PluginManager` / `PluginSandbox` | manifest/health/result | fault and capability isolation |
| Storage | `SQLiteStore` / `atomic_io` | committed rows/files | atomicity/durability owner |
| UI Shell | presentation layer | presentation state only | user intent; never authorization truth |

The executable copy of this table lives in `arenyxa.architecture_contracts.CORE_COMPONENTS`.

## Lifecycle matrix

Canonical lifecycle: `create → start → pause → resume → terminal → persist → recover → dispose`.

Pause/resume may repeat while the object remains active. A terminal object may persist/recover/dispose but must not silently return to an active state. Storage/recovery components use the applicable subset rather than pretending they are interactive jobs.

## Dependency direction

Hard rules enforced by `validate_dependency_rules()`:

- `domain` must not import `application`, `infrastructure`, or `presentation`.
- `application` must not import `presentation`.
- `infrastructure` must not import `presentation`.
- presentation code must not directly import the application persistence implementation (`arenyxa.infrastructure.database`).
- developer database adapters remain an explicit tooling surface; they are not the application store.

## Failure model

The frozen taxonomy is: `transient`, `recoverable`, `configuration`, `permission`, `corruption`, `fatal`.

- transient: bounded, cancellable, idempotency-aware retry;
- recoverable: rollback/reconcile to the last durable invariant;
- configuration: reject before side effects;
- permission: backend deny; UI visibility is irrelevant;
- corruption: stop mutation and preserve evidence;
- fatal: finalize owned resources and terminate with diagnostics.

## Compatibility contract

This Phase 1/2 development candidate does **not** silently advance product or plugin/API compatibility. `arenyxa` and historical `arenyxa` Python/CLI surfaces remain present, while `__compat_version__` stays at `6.8.0` until an explicit compatibility migration is designed and tested.

## Gate

Phase 1 passes only when the architecture contract tests, dependency-direction scan, legacy package/CLI checks, lifecycle/failure model tests, Python grammar/compile gates and historical regression pass. Phase 1 introduces no Enterprise Identity, Developer Login or Server Runtime redesign.
