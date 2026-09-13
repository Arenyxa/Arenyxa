# Phase 7B Boundary-Lite Execute Attribution — Reviewed Diagnostic Design

Scope: diagnostic-only `.github/phase7`; production `src/`, business SQL, pool geometry, schema, recovery, health policy, PostgreSQL config, gate workload, cycle timing and percentile boundaries remain frozen.

## Authoritative observer

The Phase 7 v1 protocol/schedstat and protocol-only observers were rejected by their predeclared calibration gates and are not admissible for root-cause attribution.

Phase 7B uses `BOUNDARY_LITE` only:

1. OFF is the already accepted Phase6 minimal observer.
2. ON adds only cursor send-method entry/exit timestamps and `BaseCursor._check_results()` entry.
3. Existing Phase6-minimal `Connection.execute()` begin/end spans provide T0/T6.
4. No wait-generator proxy, schedstat, socket poll/read/recv, `PQconsumeInput`, extra SQL, or extra per-execute rusage call is added.
5. Diagnostic bookkeeping is fail-open: instrumentation exceptions cannot replace the original business return value or exception.

## Boundary semantics

- T0: existing Phase6-minimal lease_fast `Connection.execute()` span begin.
- T1: matching BaseCursor send-method entry (`_execute_send`, `_send_prepare`, or `_send_query_prepared`). This is not PQflush completion.
- T2: NOT DIRECTLY OBSERVABLE.
- T3: NOT DIRECTLY OBSERVABLE.
- T4: NOT DIRECTLY OBSERVABLE.
- T5: `BaseCursor._check_results(results)` entry. In psycopg 3.3.5 non-pipeline execute, the main-query `results = yield from execute(self._pgconn)` has returned before this boundary. Prepared-cache `validate()` may run before T5 when a key is present. T5 is therefore a full-main-query-PGresult-available driver boundary, not server-completion or wire-completion time.
- T6: existing Phase6-minimal lease_fast `Connection.execute()` span end.

Primary decomposition:

- PRE_RESULT = T5 - T0
- POST_RESULT = T6 - T5

The observer records prepared-query segment kinds and does not silently collapse `prepare + prepared_query` into a single send semantic. Possible implicit BEGIN from psycopg transaction start is inside T0→T5 and is a retained confound, not silently assigned to the lease SQL server execution.

## TDD gates

Phase 7B requires RED→GREEN evidence for:

- boundary/conservation arithmetic and event ordering,
- prepared multi-segment retention,
- missing/multiple T5 rejection,
- gate-style percentile arithmetic,
- ordinary/recovery classification independence,
- query/result argument identity preservation,
- original business exception preservation under observer failure,
- cycle P99.9 inclusion in tail-safety calibration.

## Calibration

Exactly OFF → ON → OFF → ON before any warm capture.

Primary acceptance keeps the existing predefined limits: P50/P95/P99 median ratios <= 1.10, throughput ratio >= 0.95, recovery-incidence delta <= 6. Tail safety is two-sided 0.80–1.20 for cycle P99.9, pooled ordinary lease P99/P99.9, and pooled execute P99/P99.9. Exact trace coverage and conservation are mandatory. Temporal order evidence is reported but never used to relax a failed gate.

Calibration failure stops Phase 7B attribution with D — INCONCLUSIVE. No heavier fallback observer is permitted.

## Natural warm capture

Only after calibration PASS: one retained first-use run followed by exactly 80 predeclared natural warm runs at workers=64, concurrency=128, jobs=1024, 16 independent clients, PostgreSQL 16.15, max_connections=256, fsync=on and synchronous_commit=on. No adaptive stop, retry-to-pass, worst-run discard, or production patch.
