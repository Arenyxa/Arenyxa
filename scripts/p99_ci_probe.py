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

import psutil
import psycopg
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from arenyxa.enterprise import runtime_storage
from scripts import postgresql_32_worker_gate as gate


def pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    idx = (len(ordered) - 1) * q
    lo = int(idx)
    hi = min(lo + 1, len(ordered) - 1)
    frac = idx - lo
    return ordered[lo] + (ordered[hi] - ordered[lo]) * frac


def dist(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "p50": None, "p95": None, "p99": None, "p999": None, "max": None, "mean": None, "total": 0.0}
    return {
        "count": len(values),
        "p50": round(float(pct(values, 0.50)), 3),
        "p95": round(float(pct(values, 0.95)), 3),
        "p99": round(float(pct(values, 0.99)), 3),
        "p999": round(float(pct(values, 0.999)), 3),
        "max": round(max(values), 3),
        "mean": round(statistics.fmean(values), 3),
        "total": round(sum(values), 3),
    }


class Probe:
    def __init__(self, dsn: str, sample_ms: int = 25) -> None:
        self.dsn = dsn
        self.sample_s = max(0.01, sample_ms / 1000.0)
        self.active = threading.Event()
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.checkout_ms: list[float] = []
        self.health_ms: list[float] = []
        self.activity: Counter[str] = Counter()
        self.waits: Counter[str] = Counter()
        self.lock_waits: Counter[str] = Counter()
        self.host_samples: list[dict[str, Any]] = []
        self.server: dict[str, Any] = {}
        self.db_stats_before: dict[str, Any] = {}
        self.db_stats_after: dict[str, Any] = {}
        self.thread: threading.Thread | None = None
        self.start_wall = 0.0
        self.stop_wall = 0.0
        self.orig_check = runtime_storage.PostgreSQLRuntimeStorageBackend._check_pool_connection
        self.orig_connection = runtime_storage.PostgreSQLRuntimeStorageBackend.connection
        self.orig_pool_locked = runtime_storage.PostgreSQLRuntimeStorageBackend._connection_pool_locked
        self.orig_executor = gate.ThreadPoolExecutor
        self.full_prewarm = False

    def install(self, *, full_prewarm: bool) -> None:
        self.full_prewarm = full_prewarm
        probe = self
        orig_check = self.orig_check
        orig_connection = self.orig_connection
        orig_pool_locked = self.orig_pool_locked

        def traced_check(connection: Any) -> None:
            t0 = time.perf_counter()
            try:
                orig_check(connection)
            finally:
                if probe.active.is_set():
                    with probe.lock:
                        probe.health_ms.append((time.perf_counter() - t0) * 1000.0)

        @contextmanager
        def traced_connection(storage_self: Any):
            t0 = time.perf_counter()
            with orig_connection(storage_self) as facade:
                acquired = time.perf_counter()
                if probe.active.is_set():
                    with probe.lock:
                        probe.checkout_ms.append((acquired - t0) * 1000.0)
                yield facade

        def traced_pool_locked(storage_self: Any) -> Any:
            pool = orig_pool_locked(storage_self)
            if probe.full_prewarm and not getattr(storage_self, "_p99_full_prewarmed", False):
                pool.resize(min_size=8, max_size=8)
                pool.wait(timeout=15.0)
                pool.resize(min_size=4, max_size=8)
                setattr(storage_self, "_p99_full_prewarmed", True)
            return pool

        runtime_storage.PostgreSQLRuntimeStorageBackend._check_pool_connection = staticmethod(traced_check)
        runtime_storage.PostgreSQLRuntimeStorageBackend.connection = traced_connection
        runtime_storage.PostgreSQLRuntimeStorageBackend._connection_pool_locked = traced_pool_locked

        orig_executor = self.orig_executor

        class WindowExecutor(orig_executor):
            def __enter__(executor_self):
                probe.begin_window()
                try:
                    return super(WindowExecutor, executor_self).__enter__()
                except BaseException:
                    probe.end_window()
                    raise

            def __exit__(executor_self, exc_type, exc, tb):
                try:
                    return super(WindowExecutor, executor_self).__exit__(exc_type, exc, tb)
                finally:
                    probe.end_window()

        gate.ThreadPoolExecutor = WindowExecutor

    def uninstall(self) -> None:
        runtime_storage.PostgreSQLRuntimeStorageBackend._check_pool_connection = staticmethod(self.orig_check)
        runtime_storage.PostgreSQLRuntimeStorageBackend.connection = self.orig_connection
        runtime_storage.PostgreSQLRuntimeStorageBackend._connection_pool_locked = self.orig_pool_locked
        gate.ThreadPoolExecutor = self.orig_executor

    def _db_stats(self, conn: psycopg.Connection[Any]) -> dict[str, Any]:
        row = conn.execute(
            """
            SELECT xact_commit, xact_rollback, blks_read, blks_hit,
                   tup_returned, tup_fetched, tup_inserted, tup_updated, tup_deleted,
                   conflicts, temp_files, temp_bytes, deadlocks,
                   blk_read_time, blk_write_time
            FROM pg_stat_database WHERE datname = current_database()
            """
        ).fetchone()
        keys = [
            "xact_commit", "xact_rollback", "blks_read", "blks_hit", "tup_returned",
            "tup_fetched", "tup_inserted", "tup_updated", "tup_deleted", "conflicts",
            "temp_files", "temp_bytes", "deadlocks", "blk_read_time", "blk_write_time",
        ]
        return dict(zip(keys, row, strict=True)) if row else {}

    def begin_window(self) -> None:
        if self.active.is_set():
            return
        self.stop.clear()
        with psycopg.connect(self.dsn, autocommit=True) as conn:
            conn.execute("SELECT pg_stat_statements_reset()")
            self.db_stats_before = self._db_stats(conn)
        psutil.cpu_percent(interval=None)
        self.start_wall = time.time()
        self.active.set()
        self.thread = threading.Thread(target=self._sample, name="p99-probe", daemon=True)
        self.thread.start()

    def end_window(self) -> None:
        if not self.active.is_set():
            return
        self.stop_wall = time.time()
        self.active.clear()
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=5.0)
        with psycopg.connect(self.dsn, autocommit=True) as conn:
            self.db_stats_after = self._db_stats(conn)
            rows = conn.execute(
                """
                SELECT calls, total_exec_time, mean_exec_time, max_exec_time,
                       rows, shared_blks_hit, shared_blks_read, shared_blks_dirtied,
                       shared_blks_written, temp_blks_read, temp_blks_written,
                       wal_records, wal_fpi, wal_bytes, query
                FROM pg_stat_statements
                WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
                ORDER BY total_exec_time DESC
                LIMIT 40
                """
            ).fetchall()
            self.server = {
                "statements": [
                    {
                        "calls": int(r[0]), "total_exec_ms": round(float(r[1]), 3),
                        "mean_exec_ms": round(float(r[2]), 3), "max_exec_ms": round(float(r[3]), 3),
                        "rows": int(r[4]), "shared_hit": int(r[5]), "shared_read": int(r[6]),
                        "shared_dirtied": int(r[7]), "shared_written": int(r[8]),
                        "temp_read": int(r[9]), "temp_written": int(r[10]),
                        "wal_records": int(r[11]), "wal_fpi": int(r[12]),
                        "wal_bytes": int(r[13]), "query": str(r[14])[:800],
                    }
                    for r in rows
                    if "pg_stat_statements" not in str(r[14])
                ]
            }

    def _sample(self) -> None:
        process = psutil.Process(os.getpid())
        try:
            with psycopg.connect(self.dsn, autocommit=True) as conn:
                observer_pid = conn.info.backend_pid
                while not self.stop.wait(self.sample_s):
                    rows = conn.execute(
                        """
                        SELECT state, COALESCE(wait_event_type,''), COALESCE(wait_event,''), count(*)
                        FROM pg_stat_activity
                        WHERE datname = current_database() AND pid <> %s
                        GROUP BY 1,2,3
                        """,
                        (observer_pid,),
                    ).fetchall()
                    locks = conn.execute(
                        """
                        SELECT l.locktype, l.mode, l.granted, count(*)
                        FROM pg_locks l
                        JOIN pg_stat_activity a ON a.pid=l.pid
                        WHERE a.datname=current_database() AND a.pid <> %s
                        GROUP BY 1,2,3
                        """,
                        (observer_pid,),
                    ).fetchall()
                    with self.lock:
                        for state, wet, we, count in rows:
                            self.activity[str(state)] += int(count)
                            if wet or we:
                                self.waits[f"{state}|{wet}|{we}"] += int(count)
                        for locktype, mode, granted, count in locks:
                            if not bool(granted):
                                self.lock_waits[f"{locktype}|{mode}"] += int(count)
                        self.host_samples.append({
                            "cpu_percent": psutil.cpu_percent(interval=None),
                            "load1": os.getloadavg()[0],
                            "ctx_switches": psutil.cpu_stats().ctx_switches,
                            "proc_threads": process.num_threads(),
                            "proc_cpu_user": process.cpu_times().user,
                            "proc_cpu_system": process.cpu_times().system,
                        })
        except BaseException as exc:
            with self.lock:
                self.host_samples.append({"observer_error": f"{type(exc).__name__}: {exc}"})

    def report(self) -> dict[str, Any]:
        db_delta: dict[str, Any] = {}
        for key, after in self.db_stats_after.items():
            before = self.db_stats_before.get(key)
            if isinstance(after, (int, float)) and isinstance(before, (int, float)):
                db_delta[key] = round(float(after) - float(before), 3)
        host_valid = [r for r in self.host_samples if "cpu_percent" in r]
        ctx_delta = None
        if len(host_valid) >= 2:
            ctx_delta = int(host_valid[-1]["ctx_switches"] - host_valid[0]["ctx_switches"])
        return {
            "window_seconds": round(max(0.0, self.stop_wall - self.start_wall), 3),
            "checkout_ms": dist(self.checkout_ms),
            "health_check_ms": dist(self.health_ms),
            "activity_weighted_samples": dict(self.activity),
            "wait_event_weighted_samples": dict(self.waits.most_common()),
            "lock_wait_weighted_samples": dict(self.lock_waits.most_common()),
            "host": {
                "samples": len(host_valid),
                "cpu_percent": dist([float(r["cpu_percent"]) for r in host_valid]),
                "load1": dist([float(r["load1"]) for r in host_valid]),
                "context_switches_delta": ctx_delta,
                "max_process_threads": max((int(r["proc_threads"]) for r in host_valid), default=None),
            },
            "pg_stat_database_delta": db_delta,
            "pg_stat_statements": self.server.get("statements", []),
        }


def scratch_dsn(base_dsn: str) -> tuple[str, str]:
    info = conninfo_to_dict(base_dsn)
    dbname = f"arenyxa_p99_{uuid.uuid4().hex[:10]}"
    admin_info = dict(info)
    admin_info["dbname"] = "postgres"
    admin_dsn = make_conninfo(**admin_info)
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{dbname}"')
    run_info = dict(info)
    run_info["dbname"] = dbname
    dsn = make_conninfo(**run_info)
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("CREATE EXTENSION IF NOT EXISTS pg_stat_statements")
    return dsn, dbname


def drop_scratch(base_dsn: str, dbname: str) -> None:
    info = conninfo_to_dict(base_dsn)
    info["dbname"] = "postgres"
    admin_dsn = make_conninfo(**info)
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        conn.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=%s", (dbname,))
        conn.execute(f'DROP DATABASE IF EXISTS "{dbname}"')


def settings(base_dsn: str) -> dict[str, Any]:
    with psycopg.connect(base_dsn, autocommit=True) as conn:
        version = conn.execute("SHOW server_version").fetchone()[0]
        names = ["max_connections", "shared_preload_libraries", "track_io_timing", "track_wal_io_timing", "log_lock_waits", "deadlock_timeout"]
        out = {"server_version": version}
        for name in names:
            out[name] = conn.execute(f"SHOW {name}").fetchone()[0]
        return out


def run_one(base_dsn: str, variant: str, sample_ms: int) -> dict[str, Any]:
    dsn, dbname = scratch_dsn(base_dsn)
    probe = Probe(dsn, sample_ms=sample_ms)
    try:
        probe.install(full_prewarm=(variant == "full_prewarm"))
        result = gate.run_gate(dsn, workers=64, concurrency=128, jobs=1024, p99_budget_ms=500.0)
        return {"variant": variant, "gate": result, "probe": probe.report()}
    finally:
        probe.uninstall()
        drop_scratch(base_dsn, dbname)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", default=os.environ.get("ARENYXA_POSTGRES_TEST_DSN", ""))
    ap.add_argument("--variant", choices=["baseline", "full_prewarm"], required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--sample-ms", type=int, default=25)
    args = ap.parse_args()
    if not args.dsn:
        raise SystemExit("DSN required")
    payload = {
        "schema": "arenyxa.p99-ci-probe/v1",
        "settings": settings(args.dsn),
        "variant": args.variant,
        "result": run_one(args.dsn, args.variant, args.sample_ms),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    gate_result = payload["result"]["gate"]
    print(json.dumps({
        "variant": args.variant,
        "cycle_p99": gate_result["latency_ms"]["p99"],
        "lease_p99": gate_result["latency_ms"]["phases"]["lease_next"]["p99"],
        "passed": gate_result["passed"],
        "checkout": payload["result"]["probe"]["checkout_ms"],
        "health": payload["result"]["probe"]["health_check_ms"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
