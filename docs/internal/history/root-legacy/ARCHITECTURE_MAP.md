# Arenyxa v8.0 — Architecture Map

## Runtime surfaces

`Desktop GUI / CLI / Server / Worker / Automation`

↓

## Shared application control

- `PlatformControlPlane` — health, diagnostics, jobs, Enterprise, Windows runtime, survivability, performance telemetry, resilience drills
- `TrafficControlPlane` — Network, Capture, Protocol, Proxy, MITM
- `EnterpriseControlPlane` — enterprise identity/governance/enrollment/server/worker/storage/audit

↓

## Core execution and protection services

- Security Kernel / capability authorization / audit
- Persistent bounded Job System
- Storage repositories and migrations
- Scheduler / workflow runtime / automation
- Runtime Recovery Service / Recovery Center / Safe Mode
- **SurvivabilityManager (Phase 6)**
- **PerformanceTelemetry (Phase 6)**
- Runtime Supervisor / dependency health

↓

## Engines

- Capture / packet / flow / session / protocol engines
- Proxy Suite / MITM / replay / API analysis / Traffic Forensics
- Run orchestrator / async HTTP connection pools
- Enterprise Server / Worker / lease queue
- Search / indexing / data lineage
- Plugin manager / sandbox / signed trust

↓

## Platform and persistence

- SQLite default local store / PostgreSQL enterprise boundary
- Atomic I/O / source repair / crash diagnostics
- Windows Service / SCM / Event Log / DPAPI / TPM-CNG / ETW / Npcap / WFP-capability paths
- Windows 7 frozen legacy lane

## Phase 6 failure-domain contract

A local resource or component failure changes an explicit component/global survivability state; it does not silently imply whole-platform failure. Critical disk pressure can stop noncritical writes while retaining read/diagnostic/audit access. CPU/memory pressure reduces admission/concurrency. Supervisor incidents mark the affected component degraded. Security/integrity boundaries remain fail-closed.

## Long-work contract

Long-running Phase 6 drills use the existing Job System with timeout/cancellation/progress/result/error persistence. No new long operation is executed as QWidget business logic or as a fake print-success CLI path.

## Phase 6 hot-path / pressure additions

`Proxy request completion → bounded ProxyPersistencePipeline → ordered SQLite history + legacy archive`, with synchronous evidence-preserving fallback only when the bounded queue is saturated or unavailable. This makes normal persistence off the request handler while keeping explicit backpressure and no silent evidence loss.

`Resource probe/governor → SurvivabilityManager → admission policy + pressure handlers → Job System / Proxy volatile history / crawler cache`, while read/diagnostics/audit paths remain available according to state. `PerformanceTelemetry` is bounded and shared by control-plane diagnostics rather than adding per-workbench unbounded metrics state.
