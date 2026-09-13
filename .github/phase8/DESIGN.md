# Arenyxa v8.2 Phase 8 — OFF-Baseline Temporal Regime Attribution

Scope is diagnostic-only `.github/phase8`. Production `src/`, business SQL, pool geometry, recovery, health policy, gate workload, PostgreSQL durability settings, percentile algorithm and 500 ms release budget remain frozen.

## Question

Why can the already accepted Phase6-minimal **OFF baseline** move from a very slow run to a much faster run with the same production candidate and workload? Phase 8 does not instrument deeper inside `execute()` and does not attempt PRE/POST-PGresult attribution.

## Existing timed observer

Every benchmark run reuses the already accepted Phase6 `MinimalRecorder` only. Phase 8 adds **no timed-window or per-execute observation**. New observations happen only between runs.

## Boundary snapshot tiers

A run-boundary snapshot is an intervention and must earn admissibility before the natural series.

1. **OS-only**: `/proc/stat`, loadavg, memory/vm counters, PSI, Python process counters, and PostgreSQL-container cgroup counters. No SQL.
2. **OS+PG combined**: OS-only plus dedicated autocommit `prepare_threshold=None` queries of `pg_stat_database`, `pg_stat_wal`, `pg_stat_bgwriter`, `pg_stat_user_tables`, `pg_stat_user_indexes`, `pg_stat_activity`, and `pg_stat_io` when available. These queries execute only between timed runs.
3. If OS-only fails calibration, PG-only is calibrated as the remaining candidate.
4. If no profile passes, the natural series proceeds timing-only; rejected snapshots are not used to attribute the regime.

Calibration runs use a dedicated fresh PostgreSQL instance and a direction-balanced adjacent-pair pattern:

`OFF, ON, ON, OFF, OFF, ON, ON, OFF`

Each ON action occurs **before** its probe run; OFF performs no snapshot. Pair orientation is balanced to reduce a monotonic temporal-trend alias. Acceptance is predeclared:

- median paired ON/OFF ratio for P50/P95/P99/throughput: 0.90–1.10;
- median paired ON/OFF ratio for P99.9 and Lease/Start/Complete P99: 0.80–1.20;
- median absolute paired recovery-count delta <= 6;
- snapshot errors = 0;
- every probe must satisfy correctness.

Calibration never occurs on a database later used for the natural 80-run characterization.

## Natural characterization

The primary job uses one hosted runner and sequentially creates three fresh `postgres:16.15` containers. Each instance verifies `max_connections=256`, `fsync=on`, and `synchronous_commit=on`, retains one first-use run separately, then executes exactly 80 warm OFF-baseline runs. No adaptive stop, retry-to-pass, or worst-run deletion is permitted.

A fourth fresh instance performs the idle counterfactual: exactly 80 warm runs with a fixed 30-second pause after runs 10,20,30,40,50,60,70. This tests elapsed-time versus cumulative-workload alignment.

A second independent Actions job performs one additional fresh-instance 80-run sequence on a separate runner for cross-host comparison. It is analyzed separately and is never pooled into same-host medians.

## Important static control

`run_gate()` creates a new coordinator plus 16 client queue/pool objects for every run and closes all of them in `finally`. Therefore psycopg connection-local prepared caches and the associated PostgreSQL client backends do not persist across runs. Prepared-state evolution still exists **within every run**, but persistent prepared-population accumulation across OFF#1→OFF#2 is not a viable cross-run mechanism without new contrary evidence.

## Change-point algorithm

The primary series is official cycle P99. A single robust split is chosen algorithmically:

- minimum segment length: 8 runs;
- cost: total absolute deviation from each segment median (L1);
- choose the split with minimum two-segment L1 cost;
- require >=25% cost reduction relative to no split;
- require post/pre median <=0.80 or >=1.25;
- require permutation p<=0.05 using 1000 deterministic permutations (seed 20260913).

Rolling 5-run median and MAD are reported for visualization only and never select the split. P99.9, throughput, Lease P99, Start P99, and Complete P99 are independently evaluated and compared at the P99-selected boundary.

## Evidence semantics

Run-boundary `/proc` and PostgreSQL snapshots may support temporal alignment but cannot by themselves establish cause. A regime verdict requires repeated transition plus counterfactual/replication evidence. Current-host evidence cannot be backfilled into historical Phase5 Runs 11–23.
