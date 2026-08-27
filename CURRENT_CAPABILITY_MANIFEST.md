# Arenyxa v8.1 — Current Capability Manifest

## Release identity

- Display version: `8.1`
- Package version: `8.1.0`
- Windows file/product version: `8.1.0.0`
- Completed engineering phase: **Phase 6**
- Compatibility identity: `6.8.0` (intentionally preserved)
- Primary runtime lane: Windows-first Python 3.11–3.13 / PySide6
- Frozen compatibility lane: Windows 7 SP1 x64 / Python 3.8 / PySide2

## Preserved platform capabilities

The phase6 candidate tree retains the existing Desktop GUI, complete developer CLI, Application Control Plane, Traffic Control Plane, Enterprise Control Plane, Capture Engine, Protocol Intelligence, Proxy Suite, MITM, API analysis, Traffic Forensics, automation/workflows, local search/data lineage, Security Kernel, Zero Trust, TPM/Root authority, Enterprise identity/enrollment/governance, Server/Worker execution, SQLite/PostgreSQL boundaries, Job System, Audit, Recovery Center, Windows runtime/service integration, signed plugin trust, source repair, packaging and legacy runtime lane.

No valid user-facing capability was intentionally deleted or bypassed in Phase 6.

## Phase 6 capabilities added

### Survivability state machine

`src/arenyxa/application/survivability.py` adds a bounded process-local survivability coordinator with explicit states:

- `normal`
- `degraded`
- `resource_pressure`
- `read_only`
- `recovering`
- `safe_mode`

The manager samples the existing resource probe/governor, persists a bounded transition history, exposes admission decisions, keeps diagnostics/audit/read paths available during pressure, enters read-only mode for critical free-disk pressure, and recovers gradually with the existing governor hysteresis.

### Bounded performance telemetry

`src/arenyxa/application/performance_telemetry.py` adds bounded latency/counter/gauge telemetry with fixed metric and sample budgets and p50/p95/p99 summaries. It is explicitly designed so telemetry labels and histories cannot grow without bound.

### Failure isolation and drills

The preserved four-drill periodic scheduler contract remains unchanged. An extended Phase 6 campaign adds SQLite lock-backpressure, corrupt-configuration fallback, and resource-pressure degradation/recovery to the existing worker-lease, synthetic network-loss, delayed-disk, and runtime-recovery drills.

### Runtime supervision and logging survivability

Runtime-supervisor incidents can now notify bounded listeners and feed component degradation into the survivability state. Structured logging now falls back to a structured stderr sink if the primary log path cannot be created/opened, preventing a log-storage fault from turning into a global boot failure.

### Unified control surfaces

The shared `PlatformControlPlane` now exposes survivability status, bounded performance telemetry, and extended resilience drills as persistent Job System work. Diagnostic bundles include survivability and performance telemetry snapshots. CLI and GUI workbench adapters call those same services; no duplicate GUI-only business logic was introduced.

## Phase 6 CLI surface

- `arenyxa resilience status`
- `arenyxa resilience refresh`
- `arenyxa resilience performance`
- `arenyxa resilience drills [--timeout SECONDS] [--no-wait]`

The existing developer-mode and Security Kernel authorization requirements remain in force.

## Current acceptance boundary

Phase 1–6 source implementation is complete for this staged artifact. Phase 7 final-system certification, native Windows hardware/service/installer execution, physical TPM/CNG ceremonies, TShark parity where unavailable, and real multi-host PostgreSQL soak/chaos remain outside this artifact's completion claim and are explicitly `NOT EXECUTED` where the current host cannot perform them.

## Phase 6 completion addendum

The final phase6 candidate tree additionally contains bounded ordered proxy persistence (`proxy_persistence.py`) and its separated resilience/telemetry integration (`proxy_resilience.py`), survivability-aware Job System admission, bounded crawler robots-cache pressure handling, repair-seed regeneration, and a Phase 6 current-host performance gate. `proxy.py` remains below the 1,000-line module ceiling after the resilience split.

Executed cumulative regression: **1,251 passed / 19 skipped / 0 failed**. Windows-native and external-backend certification remains explicitly `NOT EXECUTED` where the current host cannot exercise it.
