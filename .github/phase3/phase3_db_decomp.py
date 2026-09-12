from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import psycopg

ROOT = Path(os.environ.get("GITHUB_WORKSPACE", os.getcwd()))
TIMED_SCRIPT = ROOT / ".github/phase2/timed_state_isolation.py"
OUT: Path


def run(cmd: list[str], *, check: bool = True, capture: bool = False, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=check, text=True, capture_output=capture, env=env)


class FreshPostgres:
    def __init__(self, label: str) -> None:
        self.label = label
        self.name = f"arenyxa-p3-{label.lower().replace('_','-')}-{uuid.uuid4().hex[:8]}"
        self.dsn = ""
        self.image_id = ""
        self.container_id = ""
        self.started_wall = 0.0

    def __enter__(self) -> "FreshPostgres":
        self.image_id = run(["docker", "image", "inspect", "postgres:16.15", "--format", "{{.Id}}"], capture=True).stdout.strip()
        cp = run([
            "docker", "run", "-d", "--name", self.name,
            "-e", "POSTGRES_USER=arenyxa",
            "-e", "POSTGRES_PASSWORD=arenyxa_ci",
            "-e", "POSTGRES_DB=arenyxa_ci",
            "-p", "127.0.0.1::5432",
            "postgres:16.15", "-c", "max_connections=256",
        ], capture=True)
        self.container_id = cp.stdout.strip()
        port_line = run(["docker", "port", self.name, "5432/tcp"], capture=True).stdout.strip().splitlines()[0]
        port = int(port_line.rsplit(":", 1)[1])
        self.dsn = f"postgresql://arenyxa:arenyxa_ci@127.0.0.1:{port}/arenyxa_ci"
        deadline = time.monotonic() + 45.0
        last = ""
        while time.monotonic() < deadline:
            try:
                with psycopg.connect(self.dsn, connect_timeout=2, autocommit=True) as conn:
                    vals = conn.execute(
                        "SELECT current_setting('server_version_num'),current_setting('max_connections'),"
                        "current_setting('fsync'),current_setting('synchronous_commit'),"
                        "extract(epoch from pg_postmaster_start_time())"
                    ).fetchone()
                    if vals and str(vals[0]) == "160015" and str(vals[1]) == "256" and str(vals[2]) == "on" and str(vals[3]) == "on":
                        self.started_wall = float(vals[4])
                        return self
                    last = repr(vals)
            except Exception as exc:
                last = f"{type(exc).__name__}: {exc}"
            time.sleep(0.2)
        raise RuntimeError(f"PostgreSQL {self.name} did not become ready: {last}")

    def __exit__(self, exc_type, exc, tb) -> None:
        run(["docker", "rm", "-f", self.name], check=False, capture=True)


def child_env() -> dict[str, str]:
    return {**os.environ, "PYTHONPATH": str(ROOT)}


def measure(dsn: str, output: Path, label: str) -> dict[str, Any]:
    output.parent.mkdir(parents=True, exist_ok=True)
    run([sys.executable, str(TIMED_SCRIPT), "--dsn", dsn, "--mode", "measure-fresh", "--output", str(output)], env=child_env())
    payload = json.loads(output.read_text(encoding="utf-8"))
    result = payload.get("result") or {}
    backend = str((result.get("storage") or {}).get("backend", ""))
    if backend != "postgresql":
        raise RuntimeError(f"{label}: backend mismatch {backend!r}")
    if not payload.get("correctness_pass"):
        raise RuntimeError(f"{label}: correctness failure")
    payload["phase3_label"] = label
    output.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return payload


def full_workload_precondition(dsn: str, output: Path) -> None:
    code = r'''
import json, os
from scripts import postgresql_32_worker_gate as g
r = g.run_gate(os.environ["P3_DSN"], workers=64, concurrency=128, jobs=1024, p99_budget_ms=500.0)
assert (r.get("storage") or {}).get("backend") == "postgresql"
assert r.get("completed") == 1024 and not r.get("errors") and r.get("non_completed") == 0
open(os.environ["P3_OUT"], "w", encoding="utf-8").write(json.dumps(r, indent=2, sort_keys=True))
'''
    run([sys.executable, "-c", code], env={**child_env(), "P3_DSN": dsn, "P3_OUT": str(output)})


def schema_catalog_precondition(dsn: str, output: Path) -> None:
    code = r'''
import json, os
from arenyxa.enterprise.runtime_storage import storage_backend_for
from arenyxa.enterprise.distributed_protocol import DISTRIBUTED_SCHEMA, CURRENT_PROTOCOL, MIN_COMPATIBLE_PROTOCOL
s = storage_backend_for(os.environ["P3_DSN"])
assert s.capabilities.backend == "postgresql"
s.initialize_schema(DISTRIBUTED_SCHEMA, CURRENT_PROTOCOL, MIN_COMPATIBLE_PROTOCOL)
with s.connection() as c:
    rows = c.execute("""SELECT c.relname,c.relkind,pg_relation_size(c.oid) AS bytes
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname=current_schema() AND c.relname LIKE 'distributed_%' ORDER BY c.relname""").fetchall()
    c.execute("SELECT indexname,indexdef FROM pg_indexes WHERE schemaname=current_schema() AND tablename LIKE 'distributed_%'").fetchall()
s.close()
open(os.environ["P3_OUT"], "w", encoding="utf-8").write(json.dumps({"relations":[[str(x[0]),str(x[1]),int(x[2])] for x in rows]}, indent=2))
'''
    run([sys.executable, "-c", code], env={**child_env(), "P3_DSN": dsn, "P3_OUT": str(output)})


def relation_touch_precondition(dsn: str, output: Path) -> None:
    schema_catalog_precondition(dsn, output.with_name(output.stem + "-schema.json"))
    with psycopg.connect(dsn, autocommit=True) as c:
        touched: list[dict[str, Any]] = []
        queries = [
            "SELECT count(*) FROM distributed_meta",
            "SELECT count(*) FROM distributed_workers",
            "SELECT count(*) FROM distributed_jobs",
            "SELECT count(*) FROM distributed_job_events",
            "SELECT job_id FROM distributed_jobs WHERE state='queued' ORDER BY priority DESC,created_at ASC LIMIT 1",
            "SELECT worker_id FROM distributed_workers WHERE worker_id='__phase3_read_probe__'",
            "SELECT event_id FROM distributed_job_events WHERE job_id='__phase3_read_probe__' ORDER BY event_id DESC LIMIT 1",
        ]
        for q in queries:
            st = time.perf_counter()
            rows = c.execute(q).fetchall()
            touched.append({"query_class":"safe_read", "elapsed_ms":(time.perf_counter()-st)*1000.0, "rows":len(rows)})
        io = c.execute("""SELECT relname,heap_blks_read,heap_blks_hit,idx_blks_read,idx_blks_hit
             FROM pg_statio_user_tables WHERE relname LIKE 'distributed_%' ORDER BY relname""").fetchall()
    output.write_text(json.dumps({"safe_reads": touched, "table_io": [list(x) for x in io]}, indent=2, default=str), encoding="utf-8")


def planner_precondition(dsn: str, output: Path) -> None:
    schema_catalog_precondition(dsn, output.with_name(output.stem + "-schema.json"))
    with psycopg.connect(dsn, autocommit=True) as c:
        plans: list[dict[str, Any]] = []
        statements = [
            "EXPLAIN (COSTS OFF) SELECT worker_id,protocol_min,protocol_max FROM distributed_workers WHERE worker_id='__phase3_plan__' AND state='active' AND active_leases<max_slots",
            "EXPLAIN (COSTS OFF) SELECT * FROM distributed_jobs WHERE state='queued' ORDER BY priority DESC,created_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED",
            "EXPLAIN (COSTS OFF) SELECT job_id,state FROM distributed_jobs WHERE job_id='__phase3_plan__' AND state='leased' FOR UPDATE",
            "EXPLAIN (COSTS OFF) SELECT job_id,state,side_effect_state FROM distributed_jobs WHERE job_id='__phase3_plan__' AND state IN ('leased','running') FOR UPDATE",
            "EXPLAIN (COSTS OFF) SELECT event_id FROM distributed_job_events WHERE job_id='__phase3_plan__' ORDER BY event_id DESC LIMIT 1",
        ]
        for q in statements:
            st = time.perf_counter(); rows = c.execute(q).fetchall()
            plans.append({"elapsed_ms":(time.perf_counter()-st)*1000.0, "plan":[str(r[0]) for r in rows]})
    output.write_text(json.dumps({"plans":plans}, indent=2), encoding="utf-8")


def compact(payload: dict[str, Any]) -> dict[str, Any]:
    r = payload["result"]; lat = r["latency_ms"]; ph = lat["phases"]; s = payload.get("scheduler") or {}; pg = payload.get("timed_pg_delta") or {}
    def dm(name: str, key: str) -> Any:
        return (s.get(name) or {}).get(key)
    return {
        "p50":lat["p50"], "p95":lat["p95"], "p99":lat["p99"], "p999":(payload.get("full_distributions") or {}).get("cycle",{}).get("p999"), "max":lat["max"],
        "lease_p99":ph["lease_next"]["p99"], "start_p99":ph["start_job"]["p99"], "complete_p99":ph["complete"]["p99"],
        "throughput":r["throughput_jobs_per_second"], "passed":r["passed"], "correctness":payload.get("correctness_pass"),
        "pool_wait_ms":(payload.get("pool_summary") or {}).get("wait_ms_total"),
        "runq_avg":dm("runnable","mean"), "runq_peak":dm("runnable","max"), "pg_cpu_avg":dm("postgres_cpu_percent","mean"), "python_cpu_avg":dm("python_cpu_percent","mean"), "active_backend_avg":dm("active_backend_count","mean"),
        "lock_samples":sum((s.get("lock_wait_weighted_samples") or {}).values()), "wal_wait_samples":sum((s.get("wal_wait_weighted_samples") or {}).values()),
        "db_blks_read":(pg.get("database") or {}).get("blks_read"), "db_blks_hit":(pg.get("database") or {}).get("blks_hit"),
        "wal_records":(pg.get("wal") or {}).get("wal_records"), "wal_sync":(pg.get("wal") or {}).get("wal_sync"), "wal_write":(pg.get("wal") or {}).get("wal_write"),
        "snapshot_start_finish_ms":(((payload.get("boundary_pg") or {}).get("start") or {}).get("finish_offset_ms")),
    }


def run_condition(label: str, precondition: str, root: Path) -> dict[str, Any]:
    with FreshPostgres(label) as pg:
        meta = {"label":label, "precondition":precondition, "dsn_redacted":pg.dsn.rsplit('@',1)[-1], "image_id":pg.image_id, "container_id":pg.container_id, "postmaster_start_epoch":pg.started_wall}
        (root / f"{label}-cluster.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        if precondition == "full": full_workload_precondition(pg.dsn, root / f"{label}-precondition-full.json")
        elif precondition == "catalog": schema_catalog_precondition(pg.dsn, root / f"{label}-precondition-catalog.json")
        elif precondition == "relation": relation_touch_precondition(pg.dsn, root / f"{label}-precondition-relation.json")
        elif precondition == "planner": planner_precondition(pg.dsn, root / f"{label}-precondition-planner.json")
        elif precondition != "none": raise ValueError(precondition)
        payload = measure(pg.dsn, root / f"{label}.json", label)
        out = {"label":label, "precondition":precondition, **compact(payload)}
        print(json.dumps(out, sort_keys=True), flush=True)
        return out


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--out", type=Path, required=True); args = ap.parse_args()
    global OUT; OUT = args.out; OUT.mkdir(parents=True, exist_ok=True)
    pairs: list[dict[str, Any]] = []
    orders = [("A0","A1"),("A1","A0"),("A0","A1"),("A1","A0"),("A0","A1"),("A1","A0")]
    for i, order in enumerate(orders, 1):
        results: dict[str, Any] = {}
        for cond in order:
            pre = "none" if cond == "A0" else "full"
            results[cond] = run_condition(f"P{i}-{cond}", pre, OUT)
        delta = float(results["A1"]["p99"]) - float(results["A0"]["p99"])
        pairs.append({"pair":i, "order":"->".join(order), "A0":results["A0"], "A1":results["A1"], "p99_delta_a1_minus_a0":delta, "a1_win":delta < 0})
    wins = sum(1 for p in pairs if p["a1_win"])
    deltas = [float(p["p99_delta_a1_minus_a0"]) for p in pairs]
    replication = {"pairs":pairs, "wins":wins, "median_p99_delta_a1_minus_a0":statistics.median(deltas), "replicated": wins >= 5 and statistics.median(deltas) <= -200.0}
    (OUT/"paired-replication.json").write_text(json.dumps(replication, indent=2, sort_keys=True), encoding="utf-8")
    if not replication["replicated"]:
        (OUT/"decomposition-skipped.json").write_text(json.dumps({"reason":"A0/A1 replication gate not met", **replication}, indent=2), encoding="utf-8")
        return 0

    decomposition: list[dict[str, Any]] = []
    variants = [("S0_FRESH","none"),("S1_CATALOG","catalog"),("S2_RELATION","relation"),("S3_PLANNER","planner"),("S4_FULL","full")]
    for rep in (1,2):
        for name, pre in variants:
            decomposition.append(run_condition(f"D{rep}-{name}", pre, OUT))
    grouped: dict[str, Any] = {}
    for name, _pre in variants:
        rows = [r for r in decomposition if name in r["label"]]
        grouped[name] = {k: statistics.median([float(r[k]) for r in rows if r.get(k) is not None]) for k in ("p50","p95","p99","lease_p99","start_p99","complete_p99","throughput")}
        grouped[name]["runs"] = rows
    summary = {"replication":replication, "decomposition":grouped, "note":"S2 touches only safe read paths on newly initialized empty relations; it does not seed representative business rows."}
    (OUT/"phase3a-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
