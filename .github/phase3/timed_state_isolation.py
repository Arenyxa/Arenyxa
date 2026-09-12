from __future__ import annotations

import argparse
import gc
import importlib
import json
import os
import queue
import resource
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import psutil
import psycopg

# This script is diagnostic-only. It does not modify production source or release gate code.
from scripts import postgresql_32_worker_gate as gate


import variance_observer as vo

def _runtime_boundary() -> dict[str, Any]:
    p = psutil.Process(os.getpid())
    ru = resource.getrusage(resource.RUSAGE_SELF)
    cpu = p.cpu_times()
    return {
        "mono": time.monotonic(),
        "wall": time.time(),
        "threads": p.num_threads(),
        "rss": p.memory_info().rss,
        "modules": sorted(sys.modules),
        "module_count": len(sys.modules),
        "minor_faults": ru.ru_minflt,
        "major_faults": ru.ru_majflt,
        "voluntary_ctx": ru.ru_nvcsw,
        "involuntary_ctx": ru.ru_nivcsw,
        "cpu_user_s": cpu.user,
        "cpu_system_s": cpu.system,
    }


def _runtime_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    numeric = (
        "threads", "rss", "module_count", "minor_faults", "major_faults",
        "voluntary_ctx", "involuntary_ctx", "cpu_user_s", "cpu_system_s",
    )
    out = {k: after[k] - before[k] for k in numeric}
    out["modules_loaded"] = sorted(set(after["modules"]) - set(before["modules"]))
    out["elapsed_s"] = after["mono"] - before["mono"]
    return out


def _dict_row(cur: psycopg.Cursor[Any]) -> dict[str, Any]:
    row = cur.fetchone()
    if row is None:
        return {}
    return {d.name: v for d, v in zip(cur.description, row)}


def timed_pg_snapshot(conn: psycopg.Connection[Any]) -> dict[str, Any]:
    conn.execute("SELECT pg_stat_clear_snapshot()")
    database = _dict_row(conn.execute(
        """
        SELECT numbackends,xact_commit,xact_rollback,blks_read,blks_hit,
               tup_returned,tup_fetched,tup_inserted,tup_updated,tup_deleted,
               temp_files,temp_bytes,deadlocks,blk_read_time,blk_write_time
        FROM pg_stat_database WHERE datname=current_database()
        """
    ))
    wal = _dict_row(conn.execute(
        """
        SELECT wal_records,wal_fpi,wal_bytes,wal_buffers_full,wal_write,wal_sync,
               wal_write_time,wal_sync_time
        FROM pg_stat_wal
        """
    ))
    table_io: dict[str, Any] = {}
    for row in conn.execute(
        """
        SELECT relname,heap_blks_read,heap_blks_hit,idx_blks_read,idx_blks_hit,
               toast_blks_read,toast_blks_hit,tidx_blks_read,tidx_blks_hit
        FROM pg_statio_user_tables
        WHERE relname LIKE 'distributed_%'
        ORDER BY relname
        """
    ).fetchall():
        table_io[str(row[0])] = {
            "heap_blks_read": int(row[1] or 0), "heap_blks_hit": int(row[2] or 0),
            "idx_blks_read": int(row[3] or 0), "idx_blks_hit": int(row[4] or 0),
            "toast_blks_read": int(row[5] or 0), "toast_blks_hit": int(row[6] or 0),
            "tidx_blks_read": int(row[7] or 0), "tidx_blks_hit": int(row[8] or 0),
        }
    index_io: dict[str, Any] = {}
    for row in conn.execute(
        """
        SELECT indexrelname,idx_blks_read,idx_blks_hit
        FROM pg_statio_user_indexes
        WHERE relname LIKE 'distributed_%'
        ORDER BY indexrelname
        """
    ).fetchall():
        index_io[str(row[0])] = {"idx_blks_read": int(row[1] or 0), "idx_blks_hit": int(row[2] or 0)}
    user_tables: dict[str, Any] = {}
    for row in conn.execute(
        """
        SELECT relname,n_live_tup,n_dead_tup,n_tup_ins,n_tup_upd,n_tup_del,
               autovacuum_count,autoanalyze_count,last_autovacuum,last_autoanalyze
        FROM pg_stat_user_tables
        WHERE relname LIKE 'distributed_%'
        ORDER BY relname
        """
    ).fetchall():
        user_tables[str(row[0])] = {
            "n_live_tup": int(row[1] or 0), "n_dead_tup": int(row[2] or 0),
            "n_tup_ins": int(row[3] or 0), "n_tup_upd": int(row[4] or 0), "n_tup_del": int(row[5] or 0),
            "autovacuum_count": int(row[6] or 0), "autoanalyze_count": int(row[7] or 0),
            "last_autovacuum": None if row[8] is None else str(row[8]),
            "last_autoanalyze": None if row[9] is None else str(row[9]),
        }
    activity: dict[str, int] = {}
    for state, wet, we, count in conn.execute(
        """
        SELECT COALESCE(state,''),COALESCE(wait_event_type,''),COALESCE(wait_event,''),count(*)
        FROM pg_stat_activity
        WHERE datname=current_database() AND pid<>pg_backend_pid()
        GROUP BY 1,2,3
        """
    ).fetchall():
        activity[f"{state}|{wet}|{we}"] = int(count)
    server_state = _dict_row(conn.execute(
        """
        SELECT EXTRACT(EPOCH FROM pg_postmaster_start_time()) AS postmaster_start_epoch,
               count(*) FILTER (WHERE pid<>pg_backend_pid()) AS backend_count,
               count(*) FILTER (WHERE pid<>pg_backend_pid() AND state='active') AS active_backends
        FROM pg_stat_activity
        """
    ))
    return {
        "captured_wall": time.time(),
        "database": database,
        "wal": wal,
        "table_io": table_io,
        "index_io": index_io,
        "user_tables": user_tables,
        "activity": activity,
        "server_state": server_state,
    }


def _numeric_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in after.items():
        old = before.get(key)
        if isinstance(value, (int, float)) and isinstance(old, (int, float)):
            out[key] = value - old
    return out


def _nested_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in after.items():
        old = before.get(key)
        if isinstance(value, dict) and isinstance(old, dict):
            out[key] = _numeric_delta(old, value)
    return out


class BoundarySampler:
    """Take PostgreSQL snapshots near executor boundaries without blocking the gate thread."""

    def __init__(self, dsn: str) -> None:
        self.dsn = dsn
        self.requests: queue.Queue[tuple[str, float] | None] = queue.Queue()
        self.results: dict[str, Any] = {}
        self.errors: list[str] = []
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run, name="phase2-boundary-sampler", daemon=True)
        self.thread.start()
        if not self.ready.wait(timeout=10.0):
            raise RuntimeError("Boundary sampler failed to establish its PostgreSQL session")

    def request(self, label: str, event_mono: float) -> None:
        self.requests.put((label, event_mono))

    def wait(self) -> None:
        self.requests.join()

    def close(self) -> None:
        self.requests.put(None)
        self.thread.join(timeout=10.0)

    def _run(self) -> None:
        try:
            with psycopg.connect(self.dsn, autocommit=True, application_name="arenyxa-phase2-boundary") as conn:
                self.ready.set()
                while True:
                    item = self.requests.get()
                    if item is None:
                        self.requests.task_done()
                        return
                    label, event_mono = item
                    started = time.monotonic()
                    try:
                        snap = timed_pg_snapshot(conn)
                        finished = time.monotonic()
                        self.results[label] = {
                            "event_mono": event_mono,
                            "snapshot_started_mono": started,
                            "snapshot_finished_mono": finished,
                            "start_offset_ms": (started - event_mono) * 1000.0,
                            "finish_offset_ms": (finished - event_mono) * 1000.0,
                            "snapshot": snap,
                        }
                    except BaseException as exc:
                        self.errors.append(f"{label}:{type(exc).__name__}:{exc}")
                    finally:
                        self.requests.task_done()
        except BaseException as exc:
            self.ready.set()
            self.errors.append(f"sampler:{type(exc).__name__}:{exc}")
            while True:
                try:
                    item = self.requests.get_nowait()
                except queue.Empty:
                    break
                self.requests.task_done()


class BoundaryWindow:
    def __init__(self, original: type[Any], sampler: BoundarySampler) -> None:
        self.original = original
        self.sampler = sampler
        self.start_mono: float | None = None
        self.end_mono: float | None = None
        self.runtime_start: dict[str, Any] | None = None
        self.runtime_end: dict[str, Any] | None = None

    def make(self) -> type[Any]:
        owner = self
        original = self.original

        class DiagnosticExecutor(original):
            def __enter__(self):
                owner.start_mono = time.monotonic()
                owner.runtime_start = _runtime_boundary()
                owner.sampler.request("start", owner.start_mono)
                return super().__enter__()

            def __exit__(self, exc_type, exc, tb):
                try:
                    return super().__exit__(exc_type, exc, tb)
                finally:
                    owner.end_mono = time.monotonic()
                    owner.runtime_end = _runtime_boundary()
                    owner.sampler.request("end", owner.end_mono)

        return DiagnosticExecutor


class ThreadStartupRecorder:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self._original = threading.Thread.start

    def __enter__(self) -> "ThreadStartupRecorder":
        owner = self
        original = self._original

        def patched(thread: threading.Thread, *args: Any, **kwargs: Any):
            if thread.name.startswith("arenyxa-pg-pool"):
                owner.records.append({"name": thread.name, "mono": time.monotonic(), "wall": time.time()})
            return original(thread, *args, **kwargs)

        threading.Thread.start = patched  # type: ignore[assignment]
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        threading.Thread.start = self._original  # type: ignore[assignment]


def runtime_precondition(module_names: list[str]) -> dict[str, Any]:
    before = _runtime_boundary()
    imported: list[str] = []
    failed: list[str] = []
    for name in module_names:
        if not name or name == "__main__":
            continue
        try:
            importlib.import_module(name)
            imported.append(name)
        except Exception as exc:
            failed.append(f"{name}:{type(exc).__name__}")

    # Exercise crypto/key generation path already used by the release gate.
    for _ in range(32):
        gate._public_key()

    # Force first-use construction of the same executor width without touching PostgreSQL.
    barrier = threading.Barrier(129)

    def parked() -> None:
        barrier.wait(timeout=15.0)

    with ThreadPoolExecutor(max_workers=128, thread_name_prefix="phase2-runtime-precondition") as ex:
        futures = [ex.submit(parked) for _ in range(128)]
        barrier.wait(timeout=15.0)
        for future in futures:
            future.result(timeout=15.0)

    # Exercise allocator/page commitment without retaining memory into the measured gate.
    blocks = [bytearray(1024 * 1024) for _ in range(8)]
    for block in blocks:
        block[0] = 1
        block[-1] = 1
    del blocks
    gc.collect()
    after = _runtime_boundary()
    return {
        "imported": sorted(set(imported)),
        "failed_imports": sorted(set(failed)),
        "runtime_delta": _runtime_delta(before, after),
    }


def run_measured(dsn: str, *, runtime_warm: bool, module_names: list[str]) -> dict[str, Any]:
    preconditioning = runtime_precondition(module_names) if runtime_warm else None
    observer = vo.LightObserver(dsn, 0.25)
    sampler = BoundarySampler(dsn)
    original_percentile = gate._percentile
    p99_lists: list[list[float]] = []

    def capturing_percentile(values: list[float], q: float) -> float:
        if q == 0.99 and len(p99_lists) < 4:
            p99_lists.append(list(values))
        return original_percentile(values, q)

    original_executor = gate.ThreadPoolExecutor
    boundary = BoundaryWindow(original_executor, sampler)
    gate._percentile = capturing_percentile
    gate.ThreadPoolExecutor = boundary.make()
    observer.start()
    try:
        with ThreadStartupRecorder() as thread_recorder:
            result = gate.run_gate(dsn, workers=64, concurrency=128, jobs=1024, p99_budget_ms=500.0)
            thread_records = list(thread_recorder.records)
    finally:
        gate._percentile = original_percentile
        gate.ThreadPoolExecutor = original_executor
        observer.close()
        sampler.wait()
        sampler.close()

    if boundary.start_mono is None or boundary.end_mono is None:
        raise RuntimeError("ThreadPool timed boundary was not observed")
    if boundary.runtime_start is None or boundary.runtime_end is None:
        raise RuntimeError("Runtime boundary snapshots are missing")
    if sampler.errors:
        raise RuntimeError(f"Boundary sampler errors: {sampler.errors}")
    if "start" not in sampler.results or "end" not in sampler.results:
        raise RuntimeError("PostgreSQL boundary snapshots are incomplete")

    start_pg = sampler.results["start"]["snapshot"]
    end_pg = sampler.results["end"]["snapshot"]
    phase_names = ["cycle", "lease_next", "start_job", "complete"]
    distributions = {
        phase_names[i]: vo.dist(p99_lists[i]) if i < len(p99_lists) else None
        for i in range(len(phase_names))
    }
    timed_duration = boundary.end_mono - boundary.start_mono
    pg_delta = {
        "database": _numeric_delta(start_pg["database"], end_pg["database"]),
        "wal": _numeric_delta(start_pg["wal"], end_pg["wal"]),
        "table_io": _nested_delta(start_pg["table_io"], end_pg["table_io"]),
        "index_io": _nested_delta(start_pg["index_io"], end_pg["index_io"]),
        "user_tables": _nested_delta(start_pg["user_tables"], end_pg["user_tables"]),
    }
    pool_metrics = list((result.get("pool") or {}).get("metrics") or [])
    payload = {
        "mode": "runtime_warm" if runtime_warm else "runtime_fresh",
        "result": result,
        "correctness_pass": vo.correctness(result),
        "full_distributions": distributions,
        "threadpool_window": {
            "start_mono": boundary.start_mono,
            "end_mono": boundary.end_mono,
            "duration_s": timed_duration,
            "diagnostic_throughput_jobs_per_second": result.get("completed", 0) / max(timed_duration, 1e-9),
        },
        "boundary_pg": sampler.results,
        "timed_pg_delta": pg_delta,
        "runtime_start": boundary.runtime_start,
        "runtime_end": boundary.runtime_end,
        "timed_runtime_delta": _runtime_delta(boundary.runtime_start, boundary.runtime_end),
        "runtime_preconditioning": preconditioning,
        "thread_startups": thread_records,
        "thread_startup_summary": {
            "count": len(thread_records),
            "first_offset_ms": None if not thread_records else (min(x["mono"] for x in thread_records) - boundary.start_mono) * 1000.0,
            "last_offset_ms": None if not thread_records else (max(x["mono"] for x in thread_records) - boundary.start_mono) * 1000.0,
        },
        "scheduler": observer.summary(boundary.start_mono, boundary.end_mono),
        "pool_summary": {
            "wait_ms_total": sum(float(x.get("requests_wait_ms", 0.0) or 0.0) for x in pool_metrics),
            "acquisition_failures_total": sum(int(x.get("acquisition_failures", 0) or 0) for x in pool_metrics),
            "pool_size_total_final": sum(int(x.get("pool_size", 0) or 0) for x in pool_metrics),
            "pool_available_total_final": sum(int(x.get("pool_available", 0) or 0) for x in pool_metrics),
        },
    }
    return payload


def run_warmup(dsn: str) -> dict[str, Any]:
    result = gate.run_gate(dsn, workers=64, concurrency=128, jobs=1024, p99_budget_ms=500.0)
    return {"result": result, "correctness_pass": vo.correctness(result)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dsn", required=True)
    parser.add_argument("--mode", choices=("measure-fresh", "measure-runtime-warm", "warmup-db"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--module-list", type=Path, default=None)
    args = parser.parse_args()
    module_names: list[str] = []
    if args.module_list is not None and args.module_list.exists():
        module_names = json.loads(args.module_list.read_text(encoding="utf-8"))
    if args.mode == "warmup-db":
        payload = run_warmup(args.dsn)
    else:
        payload = run_measured(args.dsn, runtime_warm=args.mode == "measure-runtime-warm", module_names=module_names)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
    if not payload.get("correctness_pass"):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
