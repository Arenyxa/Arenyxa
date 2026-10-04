# Arenyxa v6.8 Beta — Adaptive Concurrency

Date: 2026-08-11

## Release identity

- Public runtime: `6.8beta`
- Python distribution: `6.8.0b1`
- Plugin/API compatibility comparator: `6.8.0`
- Modern installer target: `Arenyxa_V6.8beta_Setup_x64.exe`
- Windows 7 Legacy installer target: `Arenyxa_V6.8beta_Legacy_Win7_x64_Setup.exe`

## Why this beta exists

The v6.7 Windows stability run reached 64 local stress workers with zero errors, but the
controlled mixed local workload reached peak throughput at four workers and showed increasing
P95 latency above that point. That measurement is useful for local CPU/SQLite/atomic-write
pressure, but it is not valid to treat four workers as a universal HTTP concurrency limit:
real crawling is frequently I/O-bound and may benefit from a larger request pool.

v6.8 Beta therefore separates the two concerns instead of hard-capping all concurrency at four.

## Adaptive process-wide request admission

`RunOrchestrator` still owns a bounded request executor whose configured size is the hard
ceiling. When adaptive request concurrency is enabled:

1. the live process-wide admission budget begins at `min(4, request_workers)`;
2. only local parse/extract processing time is sampled;
3. network latency is explicitly excluded from the global pressure signal;
4. after a full healthy sample window with pending demand, the live budget grows by one;
5. if local-processing P95 grows materially above the low-contention baseline, the live budget
   backs off toward the four-slot floor;
6. already-running requests are never cancelled merely because the budget is reduced;
7. executor objects are never rebuilt during a live adjustment.

Remote-host throttling remains a separate concern. Existing per-host adaptive rate limiting
continues to react to HTTP 429/503 and large remote latency increases.

## Manual control

Settings now exposes `自动调节全局请求并发（推荐）`.

- Enabled: the configured global request concurrency is a ceiling and v6.8 controls the live
  admission budget.
- Disabled: the configured budget is fixed/manual.
- The Developer Live Run & Activity Center exposes both `Apply Request Budget` and `Auto Budget`.
- Applying a manual live budget suspends automatic changes for that session until `Auto Budget`
  is selected again.

The concurrency diagnostic snapshot now includes the live mode, floor, ceiling, local P95 and
last adaptive decision.

## Stress-test reporting

`stress-test` remains a bounded local stability test. v6.8 adds:

- `recommended_local_workers`
- `max_p95_ms`

`recommended_local_workers` intentionally describes only the local mixed stress workload; it
must not be interpreted as a per-host HTTP concurrency recommendation.

## Compatibility and safety

- Existing `request_concurrency` and `per_host_concurrency` settings remain valid.
- Settings schema advances to 7; old settings load with adaptive request concurrency enabled by
  default unless the user explicitly disables it.
- The historical `arenyxa` implementation namespace remains for compatibility.
- Windows 7 Legacy remains on the same shared core and can disable adaptive request concurrency
  if a deployment requires a fixed budget.
- The v6.7 Repair single-console fix is retained unchanged.

## Validation boundary

The v6.8 Beta source is regression-tested in the build environment. Final Windows release
acceptance still requires rerunning `test-all`, `stress-test standard`, and `stress-test extreme`
on the target Windows machine and checking GUI/Repair/Capture behavior. The earlier v6.7 Windows
measurements motivated this controller but are not represented as post-change v6.8 Windows
certification.
