from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

import psycopg
from psycopg.conninfo import conninfo_to_dict, make_conninfo

PAIR_ORDERS = [("A0", "A1"), ("A1", "A0"), ("A0", "A1"), ("A1", "A0"), ("A0", "A1")]


def database_uri(base_dsn: str, dbname: str) -> str:
    parsed = urlsplit(base_dsn)
    if parsed.scheme not in {"postgresql", "postgres"}:
        raise ValueError(f"expected PostgreSQL URI, got {parsed.scheme!r}")
    return urlunsplit((parsed.scheme, parsed.netloc, "/" + quote(dbname, safe=""), parsed.query, parsed.fragment))


def create_database(base_dsn: str, label: str) -> str:
    info = conninfo_to_dict(base_dsn)
    admin = dict(info)
    admin["dbname"] = "postgres"
    suffix = f"{int(time.time()*1_000_000)%1_000_000_000}_{os.getpid()}"
    dbname = f"p3_{label}_{suffix}".lower()
    with psycopg.connect(make_conninfo(**admin), autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{dbname}" TEMPLATE template0')
    return database_uri(base_dsn, dbname)


def run_json(cmd: list[str], output: Path) -> dict[str, Any]:
    env = {**os.environ, "PYTHONPATH": os.environ.get("GITHUB_WORKSPACE", os.getcwd())}
    subprocess.run(cmd, check=True, env=env)
    payload = json.loads(output.read_text(encoding="utf-8"))
    return payload


def validate_measurement(payload: dict[str, Any]) -> None:
    result = payload.get("result") or {}
    backend = str((result.get("storage") or {}).get("backend", ""))
    if backend != "postgresql":
        raise RuntimeError(f"measurement backend mismatch: {backend!r}")
    if not payload.get("correctness_pass"):
        raise RuntimeError("measurement correctness failure")


def measure(script: Path, dsn: str, output: Path) -> dict[str, Any]:
    row = run_json([sys.executable, str(script), "--dsn", dsn, "--mode", "measure-fresh", "--output", str(output)], output)
    validate_measurement(row)
    return row


def full_warm(script: Path, dsn: str, output: Path) -> dict[str, Any]:
    row = run_json([sys.executable, str(script), "--dsn", dsn, "--mode", "warmup-db", "--output", str(output)], output)
    result = row.get("result") or {}
    if str((result.get("storage") or {}).get("backend", "")) != "postgresql":
        raise RuntimeError("full warmup backend mismatch")
    if not row.get("correctness_pass"):
        raise RuntimeError("full warmup correctness failure")
    return row


def prep(prep_script: Path, dsn: str, mode: str, output: Path) -> dict[str, Any]:
    return run_json([sys.executable, str(prep_script), "--dsn", dsn, "--mode", mode, "--output", str(output)], output)


def m(row: dict[str, Any], name: str) -> float:
    r = row["result"]
    d = row["full_distributions"]
    mp = {
        "p50": r["latency_ms"]["p50"], "p95": r["latency_ms"]["p95"], "p99": r["latency_ms"]["p99"],
        "p999": d["cycle"]["p999"], "max": r["latency_ms"]["max"],
        "lease_p99": r["latency_ms"]["phases"]["lease_next"]["p99"],
        "start_p99": r["latency_ms"]["phases"]["start_job"]["p99"],
        "complete_p99": r["latency_ms"]["phases"]["complete"]["p99"],
        "throughput": r["throughput_jobs_per_second"],
    }
    return float(mp[name])


def compact(row: dict[str, Any]) -> dict[str, Any]:
    sched = row["scheduler"]
    pgd = row["timed_pg_delta"]
    return {
        **{k: m(row, k) for k in ("p50", "p95", "p99", "p999", "max", "lease_p99", "start_p99", "complete_p99", "throughput")},
        "pool_wait_ms": float(row["pool_summary"]["wait_ms_total"]),
        "acquisition_failures": int(row["pool_summary"]["acquisition_failures_total"]),
        "runq_avg": sched["runnable"]["mean"], "runq_peak": sched["runnable"]["max"],
        "postgres_cpu_avg": sched["postgres_cpu_percent"]["mean"], "python_cpu_avg": sched["python_cpu_percent"]["mean"],
        "active_backends_avg": sched["active_backend_count"]["mean"],
        "lock_wait_samples": sum(sched["lock_wait_weighted_samples"].values()),
        "wal_wait_samples": sum(sched["wal_wait_weighted_samples"].values()),
        "blks_read": pgd["database"].get("blks_read"), "blks_hit": pgd["database"].get("blks_hit"),
        "wal_records": pgd["wal"].get("wal_records"), "wal_bytes": pgd["wal"].get("wal_bytes"),
        "wal_write": pgd["wal"].get("wal_write"), "wal_sync": pgd["wal"].get("wal_sync"),
        "snapshot_start_request_offset_ms": row["boundary_pg"]["start"]["request_offset_ms"],
        "snapshot_start_complete_offset_ms": row["boundary_pg"]["start"]["complete_offset_ms"],
        "correctness": bool(row["correctness_pass"]),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    here = Path(__file__).resolve().parent
    measure_script = here / "timed_state_isolation.py"
    prep_script = here / "phase3_db_prep.py"

    pair_rows: list[dict[str, Any]] = []
    for idx, order in enumerate(PAIR_ORDERS, 1):
        dbs = {kind: create_database(args.dsn, f"pair{idx}_{kind.lower()}") for kind in ("A0", "A1")}
        measured: dict[str, dict[str, Any]] = {}
        for kind in order:
            if kind == "A1":
                full_warm(measure_script, dbs[kind], args.out / f"pair-{idx:02d}-A1-warmup.json")
            measured[kind] = measure(measure_script, dbs[kind], args.out / f"pair-{idx:02d}-{kind}.json")
        a0c, a1c = compact(measured["A0"]), compact(measured["A1"])
        pair_rows.append({
            "pair": idx, "order": list(order), "A0": a0c, "A1": a1c,
            "p99_delta_ms_A0_minus_A1": a0c["p99"] - a1c["p99"],
            "p50_delta_ms_A0_minus_A1": a0c["p50"] - a1c["p50"],
            "throughput_gain_A1_minus_A0": a1c["throughput"] - a0c["throughput"],
            "a1_faster": a1c["p99"] < a0c["p99"],
        })
        print(json.dumps(pair_rows[-1], sort_keys=True), flush=True)

    deltas = [float(x["p99_delta_ms_A0_minus_A1"]) for x in pair_rows]
    wins = sum(1 for x in pair_rows if x["a1_faster"])
    replicated = wins >= 4 and statistics.median(deltas) >= 250.0
    summary: dict[str, Any] = {
        "schema": "arenyxa.phase3-track3a/v1",
        "pair_orders": [list(x) for x in PAIR_ORDERS],
        "pairs": pair_rows,
        "replication": {
            "a1_faster_pairs": wins, "pair_count": len(pair_rows),
            "median_p99_delta_ms_A0_minus_A1": statistics.median(deltas),
            "range_p99_delta_ms_A0_minus_A1": [min(deltas), max(deltas)],
            "replicated": replicated,
            "criterion": ">=4/5 A1 faster and median P99 improvement >=250ms",
        },
        "decomposition": None,
    }
    (args.out / "track3a-pairs-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True, default=str), encoding="utf-8")
    if not replicated:
        print(json.dumps(summary["replication"], sort_keys=True), flush=True)
        return 7

    decomp: list[dict[str, Any]] = []
    modes = [
        ("DB-S1", "catalog"),
        ("DB-S2", "relation"),
        ("DB-S3", "planner"),
        ("DB-S4", "full"),
    ]
    for label, mode in modes:
        dsn = create_database(args.dsn, label.lower().replace("-", ""))
        if mode == "full":
            pre = full_warm(measure_script, dsn, args.out / f"{label}-precondition.json")
            pre_summary: Any = {"full_workload_p99": (pre.get("result") or {}).get("latency_ms", {}).get("p99")}
        else:
            pre_summary = prep(prep_script, dsn, mode, args.out / f"{label}-precondition.json")
        measured = measure(measure_script, dsn, args.out / f"{label}.json")
        decomp.append({"condition": label, "precondition": mode, "measurement": compact(measured), "precondition_summary": pre_summary})
        print(json.dumps(decomp[-1], sort_keys=True, default=str), flush=True)

    summary["decomposition"] = decomp
    (args.out / "track3a-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
