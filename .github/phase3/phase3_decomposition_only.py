from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path

from phase3_db_decomp import run_condition


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--replicates", type=int, default=3)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    variants = [
        ("S0_FRESH", "none"),
        ("S1_CATALOG", "catalog"),
        ("S2_RELATION", "relation"),
        ("S3_PLANNER", "planner"),
        ("S4_FULL", "full"),
    ]
    rows = []
    for rep in range(1, max(1, args.replicates) + 1):
        ordered = variants[rep - 1:] + variants[: rep - 1]
        for name, precondition in ordered:
            rows.append(run_condition(f"D{rep}-{name}", precondition, args.out))

    grouped = {}
    for name, _precondition in variants:
        subset = [r for r in rows if name in r["label"]]
        metrics = {}
        for key in (
            "p50", "p95", "p99", "p999", "max", "lease_p99", "start_p99",
            "complete_p99", "throughput", "runq_avg", "pg_cpu_avg",
            "python_cpu_avg", "active_backend_avg", "db_blks_read", "db_blks_hit",
            "wal_records", "lock_samples", "wal_wait_samples",
        ):
            vals = [float(r[key]) for r in subset if r.get(key) is not None]
            metrics[key] = {
                "median": statistics.median(vals) if vals else None,
                "min": min(vals) if vals else None,
                "max": max(vals) if vals else None,
            }
        grouped[name] = {"runs": subset, "metrics": metrics}

    fresh_p99 = grouped["S0_FRESH"]["metrics"]["p99"]["median"]
    for name in grouped:
        p99 = grouped[name]["metrics"]["p99"]["median"]
        grouped[name]["median_p99_effect_vs_fresh_ms"] = None if p99 is None or fresh_p99 is None else p99 - fresh_p99

    summary = {
        "schema": "arenyxa.phase3-database-decomposition/v1",
        "replicate_count": max(1, args.replicates),
        "conditions": grouped,
        "interpretation_constraints": [
            "All condition measurements use independent fresh PostgreSQL 16.15 clusters on one runner.",
            "S1 initializes schema/catalog and inspects relation/index metadata only.",
            "S2 performs safe read-only relation/index touch on newly initialized empty distributed relations; it does not seed representative business rows.",
            "S3 uses EXPLAIN without ANALYZE and does not execute lease/start/complete mutations.",
            "S4 executes one full diagnostic workload before measurement and is an upper-bound warm database state, not a release result.",
            "Effects overlap and must not be mechanically added.",
        ],
    }
    (args.out / "phase3a-decomposition-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(json.dumps({
        k: {
            "p99_median": v["metrics"]["p99"]["median"],
            "lease_p99_median": v["metrics"]["lease_p99"]["median"],
            "effect_vs_fresh_ms": v["median_p99_effect_vs_fresh_ms"],
        }
        for k, v in grouped.items()
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
