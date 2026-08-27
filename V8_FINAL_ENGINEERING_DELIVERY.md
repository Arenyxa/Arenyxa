# Arenyxa v8.0 Industrialization Delivery

Status: **engineering implementation completed in the current source tree; release certification is environment-gated, not falsely asserted.**

Artifact label: **Arenyxa_v8.0**

## Source Changes

This delivery applies the v8.0 industrialization work across startup, workflow runtime, storage, lease safety, observability, audit/logging fail-safe behavior, worker partition handling, Windows runtime diagnostics, hot-path memory handling, future callback lifecycle, SQL identifier hardening, repair modularization, reproducible build wiring, quality gate parallelization, dependency security wiring, and release documentation.

Change summary against the supplied source package:

- Added files: 49
- Removed files: 1
- Changed files: 119
- Python production AST `pass`: 0
- Production `TODO`, `FIXME`, `NotImplementedError`, `Dummy Handler`, `Mock Logic`, `Fake Implementation`: 0 findings

## Root Cause Analysis Summary

| Area | Root cause | Fix |
|---|---|---|
| launch.ps1 probe | PowerShell 5.1 merges stderr into structured error records; arrays and RemoteException can turn benign warnings into false probe failure. | Use `System.Diagnostics.Process` in `scripts/launch_probe.ps1`; capture stdout/stderr/ExitCode independently; source startup uses `python.exe -m arenyxa`, not `pythonw.exe`. |
| Browser workflow | Browser Recorder emitted `browser_action`, but runtime contract did not guarantee executable node support. | Added `src/arenyxa/application/browser_workflow.py`, runtime execution, validator contract, and `scripts/workflow_contract_gate.py`. |
| Workflow drift | Producers, serializers, migrations, validators and runtime had no single supported-kind authority. | Added `SUPPORTED_WORKFLOW_NODE_KINDS` and contract snapshot enforcement. |
| Historical migration risk | Upgrade path lacked shadow fixture coverage. | Added historical SQLite compatibility fixtures under `tests/fixtures/compatibility/` and restart/read/write/rollback checks. |
| Liveness supervision | In-process health endpoints cannot detect event-loop/GIL stalls. | Added out-of-process supervisor with IPC, heartbeat, DB responsiveness and incident persistence. |
| PostgreSQL connection storms | Distributed storage needed explicit pool health/timeout/reconnect/metrics invariants. | Hardened pool usage and added high-concurrency gate script. |
| Lease clock risk | Lease/heartbeat logic used wall-clock time in paths that must survive NTP rollback/suspend/resume. | Added monotonic timebase and lease handover/fencing semantics. |
| Audit/logging failure semantics | Ordinary logging and security audit failure were not cleanly separated. | Added fail-safe async logging semantics and audit degraded/recovery policy boundaries. |
| Network partition | Lease re-acquisition could not distinguish safe handover from review-required work. | Added grace/handover/self-protection/review-required semantics. |
| Windows service hardening | Service/Desktop/User/Machine DPAPI and crash diagnostics were not unified. | Added Windows runtime diagnostics, DPAPI scope handling, service/event/minidump support wiring. |
| Hot path memory | Large object paths risked `chunks -> join` double allocation. | Added streaming IO paths and 100 MiB/500 MiB/1 GiB memory gate. |
| Future callbacks | Anonymous closures risked lifecycle retention in long-running workers. | Added explicit callback lifecycle helpers and 24h soak harness. |
| SQL identifiers | Identifier safety needed cross-database validation. | Added strict identifier validator and deterministic fuzz coverage. |
| Repair module size | `repair.py` mixed scanner/planner/executor/recovery/diagnostics concerns. | Split into responsibility modules while preserving public facade. |

## Verification Completed in This Environment

- `python -m compileall -q src scripts tests`: PASS
- Production AST `pass` scan: PASS, 0 findings
- Forbidden placeholder scan: PASS, 0 findings
- `scripts/quality_20d_gate.py`: PASS
- `scripts/workflow_contract_gate.py`: PASS
- `scripts/architecture_debt_gate.py`: PASS
- `scripts/exception_quality_gate.py`: PASS
- `scripts/strict_quality_gate.py`: PASS
- `scripts/api_contract_gate.py`: PASS
- `scripts/arenyxa_namespace_gate.py`: PASS
- `scripts/test_skip_policy_gate.py`: PASS
- `scripts/report_assertion_gate.py`: PASS after stale failed local report removal
- `scripts/production_config_gate.py`: PASS
- `scripts/performance_regression_gate.py`: PASS
- `scripts/hot_path_memory_gate.py`: PASS
- `scripts/enterprise_release_gate.py`: PASS
- `scripts/v8_acceptance_gate.py`: local engineering PASS / production certification PARTIAL
- Phase gates executed directly: Phase 1 PASS, Phase 2 PASS, Phase 3 PASS, Phase 4 PASS, Phase 6 PASS, Phase 7 PASS
- Targeted regression after final code changes: 60 passed
- Repair/source manifest regression after regeneration: 22 passed

## Performance and Memory Evidence

Hot-path memory gate:

| Input | Peak Python allocation | Result |
|---:|---:|---|
| 100 MiB | ~2.001 MiB | PASS |
| 500 MiB | ~2.001 MiB | PASS |
| 1024 MiB | ~2.001 MiB | PASS |

Performance regression gate remained healthy across 3 checked server reports.

## Environment-Gated Items Not Falsely Marked PASS

These were not executed in the Linux container and must be executed on the matching target infrastructure before a formal production release:

1. Windows PowerShell 5.1 native launch probe execution.
2. Windows Service Control Manager / DPAPI User-vs-Machine / Event Log / MiniDump runtime certification.
3. Real PostgreSQL 64-worker / 128-concurrency connection-storm test using `ARENYXA_POSTGRES_TEST_DSN`.
4. Full 24-hour future callback soak using `ARENYXA_24H_LEAK_TEST=1`.
5. `ruff`, `mypy`, `pip-audit`, and CycloneDX SBOM execution; the current container lacks these tools and cannot install them because external package resolution is unavailable.
6. Native Qt UI tests; the current container has no supported Qt binding, so Qt-only tests skip by design.

## Release Position

This source tree is a substantially industrialized v8.0 engineering candidate with the requested code, tests, gates, and documentation added. It is **not** labeled as externally production-certified because the required Windows, PostgreSQL, CVE/SBOM toolchain, and 24-hour soak gates were not available in this execution environment.

## v8.0 stable identity and maintainability finalization

The beta7 engineering candidate has been promoted to the official v8.0 stable source identity. The package keeps the public product version `8.0`, package version `8.0.0`, Windows file version `8.0.0.0`, and release channel `stable`. Current-package `beta5`/`beta6`/`beta7` residue was removed from release metadata and artifact identity; historical v6.x beta documentation remains only as compatibility history.

Startup probe hardening is retained in the stable source: `scripts/launch.ps1` calls `scripts/launch_probe.ps1`, which uses `System.Diagnostics.ProcessStartInfo` with independent stdout/stderr/ExitCode capture and a bounded timeout. Source-mode startup remains `python.exe -m arenyxa` rather than `pythonw.exe`.

Maintainability optimization completed in this pass:

- `database.py`: 1000 lines -> 210 lines by extracting schema migrations and maintenance helpers.
- `database_migrations.py`: owns the migration tuple and `PLATFORM_JOB_MIGRATION` inclusion.
- `database_maintenance.py`: owns integrity, backup, recovery, settings and enterprise binding helpers.
- `distributed_queue.py`: 1000 lines -> 722 lines by extracting worker lifecycle/recovery logic.
- `distributed_queue_workers.py`: owns worker row conversion, registration, heartbeat, drain/revoke and expired-lease recovery.

The split preserves external imports: callers still use `arenyxa.infrastructure.database.SQLiteStore` and `arenyxa.enterprise.distributed_queue.DurableDistributedQueue`.
