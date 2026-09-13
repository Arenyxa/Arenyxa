# ARENYXA v8.2 — P99 Phase 7B Boundary-Lite Diagnostic Design

## Scope
Diagnostic-only `.github/phase7b` branch. Production `src/`, business SQL, pool geometry, schema, recovery, health policy, gate workload/timing/percentile, and PostgreSQL configuration remain frozen.

Frozen candidate identity:
- archive SHA-256 `72360b9e1598fa1c2f3166f9637ab012342c404d6ff38d3269c5f659eb05be0f`
- `runtime_storage.py` `5702ee19406e72525c96d848eeb7b909141872e0d8c0ebdb29c149b4d596594a`
- `distributed_queue.py` `8d34fef8df28b3ef7521dd2c465aa2bdf8a6217244635f151c6f752d704c2ccd`
- `postgresql_32_worker_gate.py` `1dcb09ea7490abebb8e73546178415530adc852422a0346b8d72de56e5322657`
- `postgresql_64_worker_128_concurrency_gate.py` `ba766b7e02b0f511c1e721628e8e0d615adada27b24918762a73bc1ef7762588`

## Release contract
64 workers / 128 concurrency / 1024 jobs / 16 independent clients. PostgreSQL server 16.15, `max_connections=256`, `fsync=on`, `synchronous_commit=on`, cycle P99 budget 500 ms.

## Single Phase 7B question
For ordinary successful non-recovery calls with exactly one high-level `lease_fast` execute and no fallback, is the execute wall predominantly before or after a stable full-PGresult boundary?

## Boundary semantics
- T0: existing Phase6-minimal `Connection.execute()` lease_fast span begin.
- T1: target BaseCursor send-method entry. This is not PQflush completion.
- T2/T3/T4: NOT DIRECTLY OBSERVABLE in Boundary-Lite.
- T5: `BaseCursor._check_results(results)` entry.
- T6: existing Phase6-minimal `Connection.execute()` lease_fast span end.

Psycopg 3.3.5 source establishes that the main query `results = yield from execute(self._pgconn)` completes before optional prepared-cache `validate()`, then `_check_results(results)`, then `_set_results(results)`. Therefore T5 is a conservative, slightly late boundary at which the main query PGresult list is already fully returned from the libpq execution generator. T0→T5 is **not** pure server/wire time: it may also contain implicit BEGIN, driver/libpq work, client descheduling, PREPARE transition work, and prepared-cache validation. T5→T6 includes `_check_results`, `_set_results`, prepared maintenance and high-level return work.

`PrepareManager.prepare_threshold=5`; segment classes are preserved separately as `UNPREPARED_QUERY`, `PREPARE_PLUS_PREPARED_QUERY`, `PREPARED_QUERY`, or OTHER.

## Observer surface
Boundary-Lite adds only monotonic timestamps around the three existing cursor send methods and one timestamp at `_check_results` entry. It does not add SQL, poll PostgreSQL, read/recv sockets, call `PQconsumeInput`, wrap psycopg wait generators, read schedstat, or add per-execute rusage calls. Phase6-minimal remains the OFF baseline.

Diagnostic bookkeeping is fail-open: instrumentation exceptions must not replace business results or exceptions.

## TDD evidence contract
Tests must prove: psycopg 3.3.5 T5 ordering, T0/T1/T5/T6 ordering, single segment, PREPARE+query preservation, conservation, target/recovery/fallback classification, query/result transparency, diagnostic fault containment, and the calibration gates. RED and GREEN workflow runs are retained as evidence.

## Calibration
Exactly `OFF → ON → OFF → ON`; no bad-run deletion or retry-to-pass.

Primary gate:
- median ON/OFF ratios for P50, P95, P99 <= 1.10
- median throughput ON/OFF >= 0.95
- absolute mean recovery-call delta <= 6
- full target trace coverage
- max absolute PRE+POST conservation error <= 1e-5 ms

Tail-safety gate, each two-sided ratio within `[0.80, 1.20]`:
- cycle P99.9
- pooled ordinary lease P99 and P99.9
- pooled execute P99 and P99.9

Calibration failure terminates attribution with `D — INCONCLUSIVE`. No third/heavier observer is permitted.

## Natural warm capture
Only after accepted calibration: retain one first-use run separately, then execute exactly 80 predeclared natural warm ON runs. No adaptive stop, no retry-to-pass, no worst-run deletion.

Every run must satisfy completed=1024, non_completed=0, errors=[], fencing PASS, invariants clean, active_leases_after=0, acquisition_failures=0 and connection_storm_free=true. Any correctness failure stops the experiment.

Tail reproduction is predeclared as sufficient only if at least **2** of the 80 natural warm runs have official cycle P99 >500 ms. Otherwise final attribution is `D — INCONCLUSIVE (INSUFFICIENT TAIL REPRODUCTION)`.

## Grouping
Primary ordinary dataset: successful, non-recovery, exactly one high-level lease_fast execute, no fallback. Groups by execute wall: FAST <= Q50, MID Q50–Q99, TOP1 >Q99, TOP0.1 >Q99.9. Controls: PASS-vs-FAIL runs, health-probe vs no-probe, recovery-only control, and each prepared segment class separately. Top100 slow and fastest100 controls are retained.

## Predeclared mechanical candidate rule
This creates only an **INITIAL CANDIDATE**, never the final verdict:
- A candidate: both TOP1 and TOP0.1 have aggregate PRE_RESULT share >=90% and POST_RESULT <=10%, with the same direction in steady-state `PREPARED_QUERY` controls and no conservation/coverage failure.
- B candidate: both TOP1 and TOP0.1 have aggregate POST_RESULT share >=90%, with the same direction in steady-state prepared controls.
- otherwise C candidate if both boundaries materially contribute.
- D if calibration fails, tail reproduction is insufficient, T5/coverage/conservation is invalid, or evidence is contradictory.

All A/B/C candidates must undergo self-falsification and red-team review and may be downgraded. A never means PostgreSQL server root cause: PRE_RESULT still contains backend, wire, libpq and client descheduling.

## Historical limitation
Any Phase 7B mechanism is `CURRENT HOST` only. It must not be backfilled into historical Phase5 Runs 11–23 without equivalent-regime or independent-environment evidence.
