# Arenyxa v8.2 P99 Phase 8R — Admissible Longitudinal Rerun

## Scope
Diagnostic-only. Production candidate, SQL/business semantics, release gate, `MAX_WORKERS`, pool geometry, PostgreSQL durability settings, fencing and timing boundaries are frozen.

## Why 60 warm runs
Each gate invocation registers 64 unique worker identities. One retained first run plus 60 warm runs yields `61*64=3904`, below frozen `MAX_WORKERS=4096`, leaving 192 identities of margin. No worker deletion, identity reuse, registry purge, or safety-limit modification is permitted.

## Measurement
Timed workload uses the already-accepted Phase6 minimal OFF recorder only. No new execute hot-path observer. Run-boundary OS/PG snapshots must independently pass the frozen direction-balanced calibration before attribution use. Exact worker registry count is captured from the existing post-timed production `health()` return; the diagnostic wrapper adds no SQL and returns the result unchanged.

## Formal datasets
Same runner: three independent fresh PostgreSQL 16.15 instances, each retained first run + exactly 60 warm runs. Fourth fresh instance: retained first + 60 warm, fixed 30s pauses after warm 10/20/30/40/50. Independent runner: retained first + exactly 60 warm.

## Frozen release contract
64 workers, 128 concurrency, 1024 jobs, 16 independent clients, pool 8/8, PostgreSQL 16.15, max_connections=256, fsync=on, synchronous_commit=on, hard cycle P99=500ms.

## Change point
Unchanged Phase8 algorithm: official cycle P99, one L1/median split, min segment 8, cost reduction >=25%, post/pre <=0.80 or >=1.25, 1000 permutations, seed 20260913, p<=0.05. Rolling median/MAD are visualization only.

## Stop/advance rule
At least 2/3 same-host fresh instances must show valid same-direction frozen change points before any regime classification. Partial lanes are non-authoritative. If no reproducible regime, Phase7C stable-window boundary-lite is selected automatically; no production patch is authorized.
