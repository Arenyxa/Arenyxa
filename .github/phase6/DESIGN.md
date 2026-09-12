# Phase 6 diagnostic observation contract

No new production changes. Frozen ABG patch applied by existing preflight; four required hashes checked before and after every run. No additional timed PostgreSQL SQL. No SQL polling, no PostgreSQL setting changes inside capture.

## Outcomes considered
1. Execute-wall regime dominates.
2. Non-execute client intervals dominate.
3. Both, or insufficient/observer-intrusive evidence.
No root cause is selected before capture.

## Calibration and stopping
One original fresh gate is saved separately. Next use OFF -> ON -> OFF -> ON. OFF retains only timed recovery-child invocation counters and original clock/business methods. ON adds exact gate-clock observation, existing raw execute/fetch/checkout/health/materialization timing and 250ms read-only OS sampling.
Stop before long capture when any median P50/P95/P99 ON/OFF ratio exceeds 1.10, throughput ratio falls below .95, or absolute median recovery invocation delta exceeds 6 calls/run. These are practical gates, not statistical proof of zero observer effect. Save all calibration runs including failures.
On acceptance: exactly 40 continuous warm runs in one job, one source, one PostgreSQL cluster, one Python environment. No replacement of failures. Any correctness regression, source mismatch, tracer overflow, or mismatch against original cycle samples stops capture.

## Correlation and arithmetic
Gate-clock proxy forwards every original perf_counter result unchanged. It observes the original operation_start and elapsed sites and must reproduce the original cycle-sample multiset. Raw driver execute is not server CPU. Health is nested inside checkout; raw execute is nested inside facade execute. Use an exclusive interval ledger with conservation checks. Remaining wall is unattributed, never automatically scheduler/GIL.
Ordinary means no actual stale/expired recovery child execution. Keep recovery as a control only. Existing backend PID is metadata, obtained without SQL. No credentials or lease tokens are emitted.

## Historical comparison
Phase5 Runs 11-23 versus 24-40 are historical windows. They lack execute/fetch decomposition and cannot be retrospectively populated. New-host warm runs must be analyzed independently; identical ordinal numbers do not imply identical host state.

## Local validation before remote execution
7 arithmetic, gate-boundary/source, and inherited-hook restoration tests passed. Ledger tests first failed on a deliberately empty implementation; inherited method restoration failed on the initial diagnostic code and was corrected before publication. These are tracer tests, not performance runs.
