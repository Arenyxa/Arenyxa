from __future__ import annotations

import argparse
import json
import os
import statistics
import threading
import time
import uuid
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import psutil
import psycopg
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from arenyxa.enterprise import runtime_storage
from scripts import postgresql_32_worker_gate as gate


def _percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


def _dist(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "p50": None, "p95": None, "p99": None, "p999": None, "max": None, "mean": None, "total": 0.0}
    return {
        "count": len(values),
        "p50": round(float(_percentile(values, 0.50)), 3),
        "p95": round(float(_percentile(values, 0.95)), 3),
        "p99": round(float(_percentile(values, 0.99)), 3),
        "p999": round(float(_percentile(values, 0.999)), 3),
        "max": round(max(values), 3),
        "mean": round(statistics.fmean(values), 3),
        "total": round(sum(values), 3),
    }


def _uri_database(base_dsn: str, dbname: str) -> str:
    parts = urlsplit(base_dsn)
    if parts.scheme.casefold() not in {"postgresql", "postgres"}:
        raise ValueError("P99 probe requires a PostgreSQL URI DSN")
    return urlunsplit((parts.scheme, parts.netloc, f"/{dbname}", parts.query, parts.fragment))


def _admin_dsn(base_dsn: str) -> str:
    info = conninfo_to_dict(base_dsn)
    info["dbname"] = "postgres"
    return make_conninfo(**info)


def _scratch_database(base_dsn: str) -> tuple[str, str]:
    dbname = f"arenyxa_p99_{uuid.uuid4().hex[:10]}"
    with psycopg.connect(_admin_dsn(base_dsn), autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{dbname}"')
    dsn = _uri_database(base_dsn, dbname)
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("CREATE EXTENSION IF NOT EXISTS pg_stat_statements")
    return dsn, dbname


def _drop_database(base_dsn: str, dbname: str) -> None:
    with psycopg.connect(_admin_dsn(base_dsn), autocommit=True) as conn:
        conn.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=%s", (dbname,))
        conn.execute(f'DROP DATABASE IF EXISTS "{dbname}"')


class Probe:
    def __init__(self, dsn: str, *, observe: bool, sample_ms: int) -> None:
        self.dsn = dsn
        self.observe = observe
        self.sample_s = max(0.05, sample_ms / 1000.0)
        self.active = threading.Event()
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.checkout_ms: list[float] = []
        self.health_ms: list[float] = []
        self.activity: Counter[str] = Counter()
        self.waits: Counter[str] = Counter()
        self.lock_waits: Counter[str] = Counter()
        self.host: list[dict[str, float | int]] = []
        self.server: list[dict[str, Any]] = []
        self.thread: threading.Thread | None = None
        cls = runtime_storage.PostgreSQLDistributedRuntimeStorage
        self.cls = cls
        self.orig_check = cls._check_pool_connection
        self.orig_connection = cls.connection
        self.orig_pool_locked = cls._connection_pool_locked
        self.orig_executor = gate.ThreadPoolExecutor
        self.prewarmed: set[int] = set()
        self.full_prewarm = False

    def install(self, *, full_prewarm: bool) -> None:
        self.full_prewarm = full_prewarm
        probe = self

        def traced_check(connection: Any) -> None:
            t0 = time.perf_counter()
            try:
                probe.orig_check(connection)
            finally:
                if probe.active.is_set():
                    with probe.lock:
                        probe.health_ms.append((time.perf_counter() - t0) * 1000.0)

        @contextmanager
        def traced_connection(storage_self: Any):
            t0 = time.perf_counter()
            with probe.orig_connection(storage_self) as facade:
                if probe.active.is_set():
                    with probe.lock:
                        probe.checkout_ms.append((time.perf_counter() - t0) * 1000.0)
                yield facade

        def traced_pool_locked(storage_self: Any) -> Any:
            pool = probe.orig_pool_locked(storage_self)
            marker = id(storage_self)
            if probe.full_prewarm and marker not in probe.prewarmed:
                pool.resize(min_size=8, max_size=8)
                pool.wait(timeout=15.0)
                pool.resize(min_size=4, max_size=8)
                probe.prewarmed.add(marker)
            return pool

        self.cls._check_pool_connection = staticmethod(traced_check)
        self.cls.connection = traced_connection
        self.cls._connection_pool_locked = traced_pool_locked
        orig_executor = self.orig_executor

        class TimedExecutor(orig_executor):
            def __enter__(executor_self):
                probe.begin()
                try:
                    return super(TimedExecutor, executor_self).__enter__()
                except BaseException:
                    probe.end()
                    raise

            def __exit__(executor_self, exc_type, exc, tb):
                try:
                    return super(TimedExecutor, executor_self).__exit__(exc_type, exc, tb)
                finally:
                    probe.end()

        gate.ThreadPoolExecutor = TimedExecutor

    def uninstall(self) -> None:
        self.cls._check_pool_connection = staticmethod(self.orig_check)
        self.cls.connection = self.orig_connection
        self.cls._connection_pool_locked = self.orig_pool_locked
        gate.ThreadPoolExecutor = self.orig_executor

    def begin(self) -> None:
        with psycopg.connect(self.dsn, autocommit=True) as conn:
            conn.execute("SELECT pg_stat_statements_reset()")
        self.stop.clear()
        self.active.set()
        if self.observe:
            psutil.cpu_percent(interval=None)
            self.thread = threading.Thread(target=self._sample, daemon=True, name="p99-observer")
            self.thread.start()

    def end(self) -> None:
        if not self.active.is_set():
            return
        self.active.clear()
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=5.0)
        with psycopg.connect(self.dsn, autocommit=True) as conn:
            rows = conn.execute(
                """
                SELECT calls,total_exec_time,mean_exec_time,max_exec_time,rows,
                       shared_blks_hit,shared_blks_read,shared_blks_dirtied,shared_blks_written,
                       temp_blks_read,temp_blks_written,wal_records,wal_fpi,wal_bytes,query
                FROM pg_stat_statements
                WHERE dbid=(SELECT oid FROM pg_database WHERE datname=current_database())
                ORDER BY total_exec_time DESC
                LIMIT 50
                """
            ).fetchall()
        self.server = [
            {
                "calls": int(r[0]), "total_exec_ms": round(float(r[1]), 3),
                "mean_exec_ms": round(float(r[2]), 3), "max_exec_ms": round(float(r[3]), 3),
                "rows": int(r[4]), "shared_hit": int(r[5]), "shared_read": int(r[6]),
                "shared_dirtied": int(r[7]), "shared_written": int(r[8]),
                "temp_read": int(r[9]), "temp_written": int(r[10]),
                "wal_records": int(r[11]), "wal_fpi": int(r[12]), "wal_bytes": int(r[13]),
                "query": str(r[14])[:1200],
            }
            for r in rows if "pg_stat_statements" not in str(r[14])
        ]

    def _sample(self) -> None:
        process = psutil.Process(os.getpid())
        try:
            with psycopg.connect(self.dsn, autocommit=True) as conn:
                observer_pid = conn.info.backend_pid
                while not self.stop.wait(self.sample_s):
                    activity = conn.execute(
                        """
                        SELECT state,COALESCE(wait_event_type,''),COALESCE(wait_event,''),count(*)
                        FROM pg_stat_activity
                        WHERE datname=current_database() AND pid<>%s
                        GROUP BY 1,2,3
                        """, (observer_pid,),
                    ).fetchall()
                    locks = conn.execute(
                        """
                        SELECT l.locktype,l.mode,l.granted,count(*)
                        FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid
                        WHERE a.datname=current_database() AND a.pid<>%s
                        GROUP BY 1,2,3
                        """, (observer_pid,),
                    ).fetchall()
                    with self.lock:
                        for state, wet, we, count in activity:
                            self.activity[str(state)] += int(count)
                            if wet or we:
                                self.waits[f"{state}|{wet}|{we}"] += int(count)
                        for locktype, mode, granted, count in locks:
                            if not bool(granted):
                                self.lock_waits[f"{locktype}|{mode}"] += int(count)
                        self.host.append({
                            "cpu": float(psutil.cpu_percent(interval=None)),
                            "load1": float(os.getloadavg()[0]),
                            "ctx": int(psutil.cpu_stats().ctx_switches),
                            "threads": int(process.num_threads()),
                        })
        except BaseException:
            return

    def report(self) -> dict[str, Any]:
        valid = list(self.host)
        ctx_delta = int(valid[-1]["ctx"] - valid[0]["ctx"]) if len(valid) > 1 else None
        return {
            "checkout_ms": _dist(self.checkout_ms),
            "health_check_ms": _dist(self.health_ms),
            "activity_weighted_samples": dict(self.activity),
            "wait_event_weighted_samples": dict(self.waits.most_common()),
            "lock_wait_weighted_samples": dict(self.lock_waits.most_common()),
            "host": {
                "samples": len(valid),
                "cpu_percent": _dist([float(x["cpu"]) for x in valid]),
                "load1": _dist([float(x["load1"]) for x in valid]),
                "context_switches_delta": ctx_delta,
                "max_process_threads": max((int(x["threads"]) for x in valid), default=None),
            },
            "pg_stat_statements": self.server,
        }


def _settings(dsn: str) -> dict[str, str]:
    names = ["server_version", "max_connections", "shared_preload_libraries", "track_io_timing", "track_wal_io_timing"]
    with psycopg.connect(dsn, autocommit=True) as conn:
        return {name: str(conn.execute(f"SHOW {name}").fetchone()[0]) for name in names}


def run_one(base_dsn: str, *, variant: str, mode: str, sample_ms: int) -> dict[str, Any]:
    dsn, dbname = _scratch_database(base_dsn)
    probe = Probe(dsn, observe=(mode == "full"), sample_ms=sample_ms)
    installed = False
    try:
        if mode != "bare":
            probe.install(full_prewarm=(variant == "full_prewarm"))
            installed = True
        result = gate.run_gate(dsn, workers=64, concurrency=128, jobs=1024, p99_budget_ms=500.0)
        return {"variant": variant, "mode": mode, "gate": result, "probe": probe.report()}
    finally:
        if installed:
            probe.uninstall()
        _drop_database(base_dsn, dbname)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", default=os.environ.get("ARENYXA_POSTGRES_TEST_DSN", ""))
    ap.add_argument("--variant", choices=["baseline", "full_prewarm"], default="baseline")
    ap.add_argument("--mode", choices=["bare", "trace", "full"], default="trace")
    ap.add_argument("--sample-ms", type=int, default=100)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    if not args.dsn:
        raise SystemExit("DSN required")
    payload = {
        "schema": "arenyxa.p99-ci-probe/v2",
        "settings": _settings(args.dsn),
        "result": run_one(args.dsn, variant=args.variant, mode=args.mode, sample_ms=args.sample_ms),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    g = payload["result"]["gate"]
    p = payload["result"]["probe"]
    print(json.dumps({
        "mode": args.mode, "variant": args.variant,
        "cycle_p99": g["latency_ms"]["p99"],
        "lease_p99": g["latency_ms"]["phases"]["lease_next"]["p99"],
        "start_p99": g["latency_ms"]["phases"]["start_job"]["p99"],
        "complete_p99": g["latency_ms"]["phases"]["complete"]["p99"],
        "throughput": g["throughput_jobs_per_second"],
        "completed": g["completed"], "errors": g["errors"], "fencing": g["fencing_probe"]["passed"],
        "checkout_p99": p["checkout_ms"]["p99"], "health_p99": p["health_check_ms"]["p99"],
        "health_calls": p["health_check_ms"]["count"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
