# Phase 7 Execute-Wall Internal Attribution — Diagnostic Design

Scope: diagnostic-only `.github/phase7`; production `src/`, business SQL, pool geometry, schema, recovery, health policy, PostgreSQL config, gate workload and percentile boundaries remain frozen.

Observer chain:
1. Phase6 minimal observer is the OFF baseline for incremental Phase7 calibration.
2. Phase7 ON wraps only the existing lease_fast `Connection.execute()` call.
3. `_execute_send`, `_send_prepare`, `_send_query_prepared` timestamp enqueue boundaries without changing query payloads.
4. `_cursor_base.execute` is replaced by the semantically equivalent native `send()` then native `fetch_many()` composition to expose PQflush-complete (T2) and full-result-return (T5). Native psycopg/libpq send/fetch implementations are preserved.
5. `waiting.wait` still performs the actual wait. A transparent generator proxy timestamps yielded Wait states and returned Ready states. It performs no `select`, `recv`, `read`, or `PQconsumeInput` itself.
6. Optional `/proc/thread-self/schedstat` is read twice per target execute to measure per-thread CPU/runqueue deltas. If calibration rejects this observer, a predeclared protocol-only observer is calibrated once as a distinct fallback.

Semantic limits:
- T2 means libpq output queue flush complete, not backend receipt.
- T3 means the original psycopg wait function returned Ready.R to the driver; it is not an independent kernel packet-arrival timestamp.
- T4 (`PQconsumeInput` exact boundary) is intentionally NOT DIRECTLY OBSERVABLE because hooking/duplicating consumption would risk altering protocol semantics.
- T5 means native `fetch_many` has completed result collection for the protocol segment. Cursor result validation/materialization after this point remains inside T5→T6.
- Prepared-statement transitions may create multiple protocol segments inside one `Connection.execute`; segment count and kind are retained and multi-segment calls are not silently collapsed into the single-segment primary decomposition.

Calibration: OFF→ON→OFF→ON. In addition to prior Phase6 P50/P95/P99/throughput/recovery gates, Phase7 applies a two-sided 0.80–1.20 tail-stability gate to pooled ordinary lease and execute P99/P99.9 and requires exact trace coverage plus timing conservation.

Warm capture: 80 predeclared natural warm runs after an explicit retained first-use run. No adaptive stop, no retry-to-pass, no worst-run discard.
