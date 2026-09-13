# ARENYXA v8.2 P99 Phase 7 — Execute-wall internal attribution design

Diagnostic-only. Production source, SQL text, release workload, percentile code,
retry behavior, pool sizing, recovery, schema and PostgreSQL settings are frozen.

## Source identity

Required SHA-256:

- `src/arenyxa/enterprise/runtime_storage.py` `5702ee19406e72525c96d848eeb7b909141872e0d8c0ebdb29c149b4d596594a`
- `src/arenyxa/enterprise/distributed_queue.py` `8d34fef8df28b3ef7521dd2c465aa2bdf8a6217244635f151c6f752d704c2ccd`
- `scripts/postgresql_32_worker_gate.py` `1dcb09ea7490abebb8e73546178415530adc852422a0346b8d72de56e5322657`
- `scripts/postgresql_64_worker_128_concurrency_gate.py` `ba766b7e02b0f511c1e721628e8e0d615adada27b24918762a73bc1ef7762588`

Phase 7 runs from the successful Phase 6 diagnostic HEAD whose production
source is the frozen RECONSTRUCTED A+B+G candidate.

## Psycopg 3.3.5 execution path reconstructed from source

`Connection.execute()` -> `Cursor.execute()` -> `Connection.wait(_execute_gen)`
-> `BaseCursor._maybe_prepare_gen()` -> send/query-prepared operation ->
`_cursor_base.execute` (`generators._execute`) -> `_send()` -> `_fetch_many()`
-> `_fetch()` -> libpq `is_busy/consume_input/get_result` -> result validation /
materialization -> `Connection.execute()` return.

On Linux with the C extension, `psycopg.waiting.wait` resolves to `wait_c`.
`wait_c_impl()` calls poll/select with the GIL released. Phase 7 therefore does
not interpret wall-minus-thread-CPU or context-switch counts as scheduler wait.

## Timeline and semantics

- T0: high-level `psycopg.Connection.execute()` begin for the existing lease_fast.
- T1: begin of the business-query send-enqueue method (`_execute_send` or
  `_send_query_prepared`). If automatic PREPARE occurs first, that round trip is
  explicitly retained in T0->T1 and in the exchange list.
- T2: end of `_send()` for the business exchange, after libpq `flush()` reports
  no pending outbound data. This is **not** server completion.
- T3: kernel earliest socket readability is **NOT DIRECTLY OBSERVABLE** by the
  accepted core hook. `T3_driver` records when psycopg's own wait implementation
  returns a read-ready value to the original generator. The observer never reads
  the socket. Kernel wake-to-user scheduling delay can precede this timestamp.
- T4: direct `PQconsumeInput` completion is **NOT DIRECTLY OBSERVABLE** without
  replacing/competing with driver protocol consumption. We reject such a hook.
- T5: business `generators.execute()` returns after `_fetch_many()` completes;
  the driver's full result list has been collected for that exchange.
- T6: high-level `Connection.execute()` returns.

Mutually exclusive conservation ledger:

`T6-T0 = (T1-T0) + (T2-T1) + (T5-T2) + (T6-T5)`.

`T5-T2` can be sub-split when `T3_driver` exists, but T3_driver is not promoted
to a kernel-first-readable timestamp.

## Observer hooks — five-question contract

### Connection.execute context
1. Measures T0/T6, thread rusage and optional per-thread schedstat.
2. Does not directly measure server CPU, kernel socket arrival, or libpq input-copy time.
3. Does not change query/result semantics; wrapper delegates once.
4. Does not consume protocol/socket data.
5. Adds Python calls and clocks; OFF/ON calibration is mandatory.

### BaseCursor send methods
1. Identifies unprepared query, PREPARE, and prepared-query enqueue boundaries.
2. Does not mean bytes are fully sent to the server.
3. Delegates the original method once with identical args/result/exception.
4. No socket read.
5. Adds two clocks and list append per send operation.

### generators._send wrapper
1. Measures the original libpq flush generator begin/end.
2. Does not measure server execution or response completion.
3. Delegates original generator; no protocol reimplementation.
4. No observer socket read; any consume_input remains original psycopg behavior.
5. Adds generator hop and clocks.

### waiting.wait generator proxy
1. Observes readiness values already returned by psycopg's original wait_c.
2. Does not measure the instant the kernel first marked the fd readable.
3. Original wait_c still owns poll/select and feeds the original generator.
4. Never calls recv/read/PQconsumeInput/select/poll independently.
5. Adds a Python proxy generator hop per driver readiness event; tail calibration
   is therefore the central acceptance test.

### generators._fetch wrapper
1. Records when the original fetch generator returns a PGresult or final None.
2. Does not directly timestamp PQconsumeInput nor PQisBusy transitions.
3. Delegates original fetch generator with no reimplementation.
4. Does not read socket itself.
5. Adds a generator hop and metadata append.

### `/proc/thread-self/schedstat` optional mode
1. Delta field 2 measures Linux runqueue-wait time for the executing thread.
2. Does not say *why* it was runnable or localize wait inside one protocol substep.
3. Does not change SQL/protocol semantics.
4. Does not touch socket/protocol.
5. Two procfs reads per lease_fast can disturb tail; it is calibrated separately
   and automatically rejected in favor of core mode if limits fail.

## Rejected observers

- `recv/read/PQconsumeInput` from an observer: rejected; would compete with driver.
- Reimplementing `_fetch()` solely to timestamp consume_input/is_busy: rejected;
  changes protocol machinery being measured.
- Extra SQL (`pg_stat_activity`, `pg_locks`, pg_stat_*): rejected.
- Per-call independent select/poll watcher: rejected as the primary observer;
  it can change fd wake behavior and still does not expose kernel event time.
- Phase 6 FULL OS polling data: already rejected as intrusive and is not reused.

## Calibration

New additions are compared against the already accepted Phase 6 MINIMAL tracer,
not against an uninstrumented run, so both OFF and ON retain execute/lease P99.
Sequence is always OFF -> ON -> OFF -> ON.

Predeclared rejection limits:
- cycle P50/P95/P99 ON/OFF <= 1.10
- ordinary lease P99 <= 1.10
- ordinary execute P99 <= 1.10
- ordinary Top1 median <= 1.12
- ordinary Top0.1 median <= 1.20
- throughput ratio >= 0.95
- median context-switch ratio <= 1.30
- recovery-call mean absolute delta <= 6

`schedstat` is attempted first. If rejected, all its attribution data is rejected
and the full OFF/ON/OFF/ON sequence is repeated for core mode.

## Capture rule

Retain every run. Start with 40 natural warm runs. If fewer than two genuine
P99>500ms failures occur, extend in blocks of 10 up to 80 runs. No failed run is
dropped and no retry is used to obtain a lucky pass. If fewer than two failures
remain at 80, emit `INSUFFICIENT_TAIL_REPRODUCTION`.
