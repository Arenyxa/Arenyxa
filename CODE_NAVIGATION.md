# Arenyxa v8.0 Code Navigation

This document is the operational map for changing Arenyxa without creating architecture drift.
The rule of thumb is: **enter through the application/service boundary, keep domain contracts
stable, and push platform-specific effects into infrastructure adapters.**

## 1. Startup flow

### Source / desktop

1. `scripts/launch.ps1` resolves `.venv\Scripts\python.exe` and runs the environment probe through
   `scripts/launch_probe.ps1` using `System.Diagnostics.Process`.
2. The probe records executable, version, working directory, exit code, stdout and stderr without
   PowerShell 5.1's merged native-stream/`RemoteException` ambiguity.
3. Source startup is `python.exe -m arenyxa`.
4. `src/arenyxa/__main__.py` dispatches into the application entry point.
5. `src/arenyxa/app.py` owns GUI process startup, repair gating and top-level failure handling.
6. `src/arenyxa/bootstrap.py` builds `ApplicationContext` and wires persistence, browser, workflow,
   capture, security, scheduling, enterprise services and runtime supervision.

### Windows Service

- Entry point: `src/arenyxa/infrastructure/windows_service.py`.
- Runtime classification and startup evidence: `src/arenyxa/infrastructure/windows_diagnostics.py`.
- Service mode sets machine-oriented runtime policy; desktop/console mode remains user-oriented.
- DPAPI selection is centralized in `src/arenyxa/security/key_protection.py`.
- Unhandled service failures attempt native MiniDump capture and Windows Application Event Log
  reporting before returning failure to the Service Control Manager.

## 2. GUI lifecycle

- Main entry/lifecycle: `src/arenyxa/app.py`.
- Dependency graph: `ApplicationContext` in `src/arenyxa/bootstrap.py`.
- Main-window operational callbacks: `src/arenyxa/presentation/main_window_operations.py`.
- Pages: `src/arenyxa/presentation/pages/`.
- UI-thread liveness is periodically heartbeated into `ArenyxaRuntimeSupervisor`; the signal is also
  forwarded to an **independent supervisor process**, so a wedged Python event loop can be observed
  externally.
- Future completion callbacks that reference UI/application owners should use
  `src/arenyxa/application/future_callbacks.py` rather than anonymous closures that retain owners.

### Shutdown order

`ApplicationContext.shutdown()` in `bootstrap.py` uses an explicit dependency-aware coordinator.
When adding a long-lived service, register its shutdown action there and define ordering against
runtime supervisor, scheduler, workflow runtime, capture/proxy/MITM, runner and database teardown.
Do not rely on interpreter finalizers for correctness.

## 3. Worker lifecycle

### Durable queue

- Queue core/fencing/lease execution: `src/arenyxa/enterprise/distributed_queue.py`.
- Worker registry, heartbeat, revocation and expired-lease recovery: `src/arenyxa/enterprise/distributed_queue_workers.py`.
- Backend abstraction + PostgreSQL pool: `src/arenyxa/enterprise/runtime_storage.py`.
- Worker runtime/orchestration: `src/arenyxa/enterprise/distributed_runtime.py`.
- Remote agent: `src/arenyxa/enterprise/worker_agent.py`.
- HTTP control plane: `src/arenyxa/enterprise/server_api.py`.

### Lease safety invariants

- Lease durations are derived from a monotonic-backed clock projection in
  `src/arenyxa/infrastructure/timebase.py`; user-visible timestamps remain wall-clock timestamps.
- Every lease is fenced by a secret token digest persisted in the queue.
- A stale worker cannot complete after recovery/handover.
- Network partition handover requeues safe/idempotent work, but a non-idempotent job whose side
  effect has started transitions to `review_required`.
- `lease_grace_seconds` absorbs bounded heartbeat/transport jitter before recovery.

### PostgreSQL

Never create ad-hoc `psycopg.connect()` calls in product code. Acquire connections through the
pool-backed storage implementation. Pool health, acquisition failures and reconnect failures are
observable via `pool_metrics()` / queue `storage_metrics()`.

The release concurrency gate is `scripts/postgresql_64_worker_128_concurrency_gate.py` and is run
against a real PostgreSQL service in `.github/workflows/industrialization.yml`.

## 4. Workflow lifecycle

### Contract authority

`src/arenyxa/application/workflow_contract.py` is the single authority for persisted workflow node
kinds. `SUPPORTED_WORKFLOW_NODE_KINDS` is shared by producer validation, canonical serialization,
migration expectations, runtime validation and the CI contract gate.

When adding a **persistable** node kind, update all of the following in the same change:

1. central contract + schema/config validator;
2. serializer version;
3. migration version/path;
4. runtime handler;
5. producer(s);
6. regression tests.

`scripts/workflow_contract_gate.py` fails CI if one side is missing. Runtime-only extension handlers
registered programmatically remain executable for backward compatibility, but cannot be serialized
or saved as a supported persisted workflow until they have a central contract.

### Browser workflow

- Producer/recorder: `src/arenyxa/application/nextgen_browser.py`.
- Stateful runtime: `src/arenyxa/application/browser_workflow.py`.
- Generic engine: `src/arenyxa/application/workflows.py`.
- Durable dataset workflow runtime: `src/arenyxa/application/workflow_runtime.py`.
- Main workflow UI save path: `src/arenyxa/presentation/pages/tools.py`.

`browser_action` execution shares one browser/context/page lifecycle for the workflow execution;
goto/fill/click/assert/download actions are not independent dummy handlers. Save-time validation
rejects workflows whose required runtime is unavailable.

## 5. Enterprise lifecycle

- Identity/auth: `src/arenyxa/enterprise/identity_auth.py` and related enterprise identity modules.
- Governance/control plane: `src/arenyxa/application/enterprise_control_plane.py`.
- Distributed queue/runtime: `src/arenyxa/enterprise/distributed_queue.py`,
  `distributed_queue_workers.py`, `distributed_runtime.py`, `worker_agent.py`.
- Server APIs: `src/arenyxa/enterprise/server_api.py`.
- Storage backend: `src/arenyxa/enterprise/runtime_storage.py`.
- Transport security: `src/arenyxa/enterprise/transport_security.py`.

Keep Desktop, Server and Worker policy distinct. A feature that exists in the GUI but is absent
from CLI/server/runtime is an integration defect, not a completed feature.

## 6. Audit and logging

### Security audit

`src/arenyxa/security/audit.py` is tamper-evident security evidence, not ordinary logging.

- `fail_closed`: a primary-chain integrity/persistence failure blocks new audited operations.
- `fail_operational`: preserves the damaged primary chain and writes a separate recovery chain with
  an explicit `audit.degraded` marker.
- If both durable audit sinks fail, emergency memory retains security semantics; once its bounded
  capacity is reached the system fails closed rather than silently dropping audit events.

### Business logging

`src/arenyxa/infrastructure/observability.py` uses a bounded asynchronous queue. Disk/permission/
handler failures switch to a structured stderr fallback on the listener thread. Overflow is
explicitly counted. Never route the security audit chain through this best-effort business logger.

## 7. Repair Center lifecycle

Repair is split by one-way responsibility:

- `src/arenyxa/repair_models.py` — domain contracts/models only;
- `src/arenyxa/repair_diagnostics.py` — diagnostic enrichment;
- `src/arenyxa/repair_scanner.py` — health scanning;
- `src/arenyxa/repair_planner.py` — plan construction/origin validation;
- `src/arenyxa/repair_executor.py` — worker process lifecycle/execution;
- `src/arenyxa/repair_recovery.py` — relaunch/recovery policy;
- `src/arenyxa/repair_engine.py` — repair action implementations;
- `src/arenyxa/repair_common.py` — legacy shared low-level helpers/resources;
- `src/arenyxa/repair.py` — compatibility facade only.

Do not add new repair behavior to the facade. Keep scanner/planner/executor/recovery dependencies
one-way and preserve `repair.py` exports for backward compatibility.

## 8. CLI and debugging

- CLI entry point: `src/arenyxa/cli.py` (`arenyxa`, `arenyxa-cli`).
- Server entry point: `src/arenyxa/infrastructure/server.py` (`arenyxa-server`).
- Windows service: `src/arenyxa/infrastructure/windows_service.py`.
- Runtime incident supervision: `src/arenyxa/application/runtime_supervisor.py` plus
  `src/arenyxa/infrastructure/external_supervisor.py`.
- Startup diagnostics: launch probe + Windows startup diagnostic JSON/event log.

For a startup failure, collect in this order: launch-probe stdout/stderr/exit code → startup
 diagnostic → structured application log → security audit status → external supervisor incidents →
MiniDump/crash dump where available.

## 9. Database and compatibility changes

- SQLite store facade: `src/arenyxa/infrastructure/database.py`.
- SQLite schema migrations: `src/arenyxa/infrastructure/database_migrations.py`.
- SQLite maintenance/recovery/settings/enterprise bindings: `src/arenyxa/infrastructure/database_maintenance.py`.
- Historical binary fixtures: `tests/fixtures/compatibility/`.
- Shadow upgrade/restart/rollback gate: `tests/test_shadow_compatibility.py`.
- SQL identifiers: `src/arenyxa/security/sql_safety.py`; never interpolate an unvalidated identifier.

Every persistent schema change must preserve historical fixtures or include a migration that makes
the shadow gate pass. Do not rewrite fixtures to hide a migration defect.

## 10. Performance and large-object changes

- Streaming primitives: `src/arenyxa/infrastructure/streaming_io.py`.
- HTTP clients: `src/arenyxa/infrastructure/http_client.py`, `async_http_client.py`.
- Large evidence hashing: capture/passive-evidence and control-plane callers use streamed hashing.
- 100/500/1024 MiB memory gate: `scripts/hot_path_memory_gate.py`.

Prefer streaming, bounded `bytearray`, `mmap`, or temporary files according to API semantics. Avoid
building a list of full-size chunks followed by `b''.join(...)` on large paths.

## 11. Quality, security and release gates

- Parallel local orchestrator: `scripts/parallel_quality_gate.py`.
- Unified CI: `.github/workflows/industrialization.yml`.
- Windows reproducible build: `.github/workflows/windows-reproducible-build.yml` and
  `scripts/reproducible_windows_build.ps1`.
- Dependency CVE/hash/SBOM: `scripts/dependency_security_gate.py`.
- Workflow contract: `scripts/workflow_contract_gate.py`.
- Existing static/architecture/release gates remain authoritative and are not weakened.

A failing gate must be recorded in `FINAL_GATE_REPORT`; sibling gates continue so one defect does
not hide additional failures.

## 12. Common modification entry points

| Change | Start here | Then verify |
|---|---|---|
| Startup/venv detection | `scripts/launch.ps1`, `launch_probe.ps1` | PowerShell 5.1 probe test |
| New persisted workflow node | `workflow_contract.py` | contract gate + runtime + migration tests |
| Browser automation action | `browser_workflow.py` | recorder + validator + save + runtime tests |
| Worker lease semantics | `distributed_queue.py` | fault matrix + network partition + PostgreSQL gates |
| PostgreSQL behavior | `runtime_storage.py` | 64W/128C stress gate + pool metrics |
| Audit policy | `security/audit.py` | tamper/fail-closed/fail-operational tests |
| Ordinary logging | `infrastructure/observability.py` | sink-failure/overflow tests |
| Service secret scope | `security/key_protection.py` | Windows service + DPAPI policy tests |
| Crash diagnostics | `windows_diagnostics.py` | Windows service CI |
| Repair behavior | specific `repair_*` responsibility module | repair-center regression suite |
| Schema/migration | database migration layer | compatibility shadow gate |
| Large file/body path | `streaming_io.py` + caller | 100/500/1024 MiB memory gate |
