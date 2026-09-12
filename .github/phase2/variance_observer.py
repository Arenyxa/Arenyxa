from __future__ import annotations

import json
import os
import resource
import statistics
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

import psutil
import psycopg

from scripts import postgresql_32_worker_gate as gate

DSN = os.environ["ARENYXA_POSTGRES_TEST_DSN"]
OUT = Path("phase2_variance_artifacts")
OUT.mkdir(exist_ok=True)
ROUNDS = int(os.environ.get("ARENYXA_PHASE2_VARIANCE_ROUNDS", "12"))
SAMPLE_INTERVAL_S = float(os.environ.get("ARENYXA_PHASE2_SAMPLE_INTERVAL_S", "0.25"))


def pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    return round(float(gate._percentile(list(values), q)), 3)


def dist(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "mean": None, "min": None, "p50": None, "p95": None, "p99": None, "p999": None, "max": None}
    return {
        "count": len(values),
        "mean": round(statistics.fmean(values), 3),
        "min": round(min(values), 3),
        "p50": pct(values, 0.50),
        "p95": pct(values, 0.95),
        "p99": pct(values, 0.99),
        "p999": pct(values, 0.999),
        "max": round(max(values), 3),
    }


def correctness(result: dict[str, Any]) -> bool:
    inv = result.get("state_invariants") or {}
    return bool(
        not result.get("errors")
        and result.get("completed") == result.get("jobs") == 1024
        and result.get("non_completed") == 0
        and (result.get("fencing_probe") or {}).get("passed")
        and all(int(inv.get(k, 1)) == 0 for k in (
            "inconsistent_lease_rows",
            "unreceipted_completed_jobs",
            "implausible_future_leases",
        ))
        and result.get("active_leases_after") == 0
        and (result.get("pool") or {}).get("connection_storm_free")
    )


def fetch_one_dict(conn: psycopg.Connection[Any], query: str, params: tuple[Any, ...] = ()) -> dict[str, Any]:
    cur = conn.execute(query, params)
    row = cur.fetchone()
    if row is None:
        return {}
    cols = [d.name for d in cur.description]
    return {k: v for k, v in zip(cols, row)}


def pg_stat_statements_capability(conn: psycopg.Connection[Any]) -> dict[str, Any]:
    preload = str(conn.execute("SHOW shared_preload_libraries").fetchone()[0])
    ext = conn.execute("SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname='pg_stat_statements')").fetchone()[0]
    available = False
    error = None
    if ext:
        try:
            conn.execute("SELECT 1 FROM pg_stat_statements LIMIT 1").fetchone()
            available = True
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            conn.rollback()
    return {"shared_preload_libraries": preload, "extension_installed": bool(ext), "available": available, "error": error}


def statement_class(query: str) -> str:
    q = " ".join(str(query).lower().split())
    if "arenyxa_pool_health" in q:
        return "health_check"
    if "with eligible_worker" in q and "distributed_jobs" in q and "'leased'" in q:
        return "lease"
    if "distributed_job_idempotency" in q and "'completed'" in q:
        return "complete"
    if "'started'" in q and "state='leased'" in q:
        return "start"
    if "update distributed_workers" in q and "active_leases=active_leases+" in q:
        return "worker_active_leases_inc"
    if "update distributed_workers" in q and "active_leases=greatest" in q:
        return "worker_active_leases_dec"
    if "insert into distributed_job_events" in q:
        return "event_insert"
    if "recover" in q or "lease_expires_at" in q and "state in ('leased','running')" in q:
        return "recovery"
    return "other"


def pgss_snapshot(conn: psycopg.Connection[Any], capability: dict[str, Any]) -> dict[str, Any]:
    if not capability.get("available"):
        return {"available": False, "reason": capability}
    rows = conn.execute(
        """
        SELECT queryid,calls,total_exec_time,mean_exec_time,max_exec_time,rows,
               shared_blks_hit,shared_blks_read,shared_blks_dirtied,shared_blks_written,
               temp_blks_read,temp_blks_written,wal_records,wal_fpi,wal_bytes,query
        FROM pg_stat_statements
        WHERE dbid=(SELECT oid FROM pg_database WHERE datname=current_database())
        """
    ).fetchall()
    payload: dict[str, Any] = {"available": True, "by_queryid": {}}
    for r in rows:
        q = str(r[15])
        payload["by_queryid"][str(r[0])] = {
            "class": statement_class(q),
            "calls": int(r[1]),
            "total_exec_time": float(r[2]),
            "mean_exec_time": float(r[3]),
            "max_exec_time": float(r[4]),
            "rows": int(r[5]),
            "shared_blks_hit": int(r[6]),
            "shared_blks_read": int(r[7]),
            "shared_blks_dirtied": int(r[8]),
            "shared_blks_written": int(r[9]),
            "temp_blks_read": int(r[10]),
            "temp_blks_written": int(r[11]),
            "wal_records": int(r[12]),
            "wal_fpi": int(r[13]),
            "wal_bytes": int(r[14]),
            "query": q[:1400],
        }
    return payload


def pg_snapshot(conn: psycopg.Connection[Any], pgss_cap: dict[str, Any]) -> dict[str, Any]:
    conn.execute("SELECT pg_stat_clear_snapshot()")
    database = fetch_one_dict(
        conn,
        """
        SELECT numbackends,xact_commit,xact_rollback,blks_read,blks_hit,
               tup_returned,tup_fetched,tup_inserted,tup_updated,tup_deleted,
               temp_files,temp_bytes,deadlocks,blk_read_time,blk_write_time,
               session_time,active_time,idle_in_transaction_time,sessions,
               sessions_abandoned,sessions_fatal,sessions_killed,stats_reset
        FROM pg_stat_database WHERE datname=current_database()
        """,
    )
    wal = fetch_one_dict(
        conn,
        """
        SELECT wal_records,wal_fpi,wal_bytes,wal_buffers_full,wal_write,wal_sync,
               wal_write_time,wal_sync_time,stats_reset
        FROM pg_stat_wal
        """,
    )
    bgwriter = fetch_one_dict(
        conn,
        """
        SELECT checkpoints_timed,checkpoints_req,checkpoint_write_time,checkpoint_sync_time,
               buffers_checkpoint,buffers_clean,maxwritten_clean,buffers_backend,
               buffers_backend_fsync,buffers_alloc,stats_reset
        FROM pg_stat_bgwriter
        """,
    )
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
    table_stats: dict[str, Any] = {}
    for row in conn.execute(
        """
        SELECT relname,n_live_tup,n_dead_tup,n_tup_ins,n_tup_upd,n_tup_del,
               seq_scan,idx_scan,vacuum_count,autovacuum_count,analyze_count,autoanalyze_count
        FROM pg_stat_user_tables
        WHERE relname LIKE 'distributed_%'
        ORDER BY relname
        """
    ).fetchall():
        table_stats[str(row[0])] = {
            "n_live_tup": int(row[1] or 0), "n_dead_tup": int(row[2] or 0),
            "n_tup_ins": int(row[3] or 0), "n_tup_upd": int(row[4] or 0), "n_tup_del": int(row[5] or 0),
            "seq_scan": int(row[6] or 0), "idx_scan": int(row[7] or 0),
            "vacuum_count": int(row[8] or 0), "autovacuum_count": int(row[9] or 0),
            "analyze_count": int(row[10] or 0), "autoanalyze_count": int(row[11] or 0),
        }
    server_state = fetch_one_dict(
        conn,
        """
        SELECT EXTRACT(EPOCH FROM pg_postmaster_start_time()) AS postmaster_start_epoch,
               count(*) FILTER (WHERE pid<>pg_backend_pid()) AS backend_count,
               count(*) FILTER (WHERE pid<>pg_backend_pid() AND state='active') AS active_backends
        FROM pg_stat_activity
        """,
    )
    settings = {
        name: str(conn.execute(f"SHOW {name}").fetchone()[0])
        for name in (
            "server_version", "max_connections", "fsync", "synchronous_commit",
            "track_io_timing", "track_wal_io_timing", "shared_preload_libraries",
        )
    }
    return {
        "captured_wall": time.time(),
        "database": database,
        "wal": wal,
        "bgwriter": bgwriter,
        "table_io": table_io,
        "table_stats": table_stats,
        "server_state": server_state,
        "settings": settings,
        "pg_stat_statements": pgss_snapshot(conn, pgss_cap),
    }


def numeric_delta(before: dict[str, Any], after: dict[str, Any], *, exclude: set[str] | None = None) -> dict[str, Any]:
    exclude = exclude or set()
    out: dict[str, Any] = {}
    for k, av in after.items():
        if k in exclude:
            continue
        bv = before.get(k)
        if isinstance(av, (int, float)) and isinstance(bv, (int, float)):
            out[k] = av - bv
    return out


def nested_numeric_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, aval in after.items():
        bval = before.get(key)
        if isinstance(aval, dict) and isinstance(bval, dict):
            out[key] = numeric_delta(bval, aval)
    return out


def pgss_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    if not before.get("available") or not after.get("available"):
        return {"available": False, "reason": after.get("reason") or before.get("reason")}
    bq = before.get("by_queryid") or {}
    aq = after.get("by_queryid") or {}
    classes: dict[str, Counter[str]] = {}
    for qid, a in aq.items():
        b = bq.get(qid) or {}
        cls = str(a.get("class", "other"))
        dst = classes.setdefault(cls, Counter())
        for key in (
            "calls", "total_exec_time", "rows", "shared_blks_hit", "shared_blks_read",
            "shared_blks_dirtied", "shared_blks_written", "temp_blks_read", "temp_blks_written",
            "wal_records", "wal_fpi", "wal_bytes",
        ):
            dst[key] += float(a.get(key, 0) or 0) - float(b.get(key, 0) or 0)
        dst["server_max_exec_time_observed"] = max(
            float(dst.get("server_max_exec_time_observed", 0.0)), float(a.get("max_exec_time", 0.0) or 0.0)
        )
    return {"available": True, "classes": {k: dict(v) for k, v in classes.items()}}


def read_proc_scheduler() -> tuple[int, int]:
    ctxt = 0
    running = 0
    with open("/proc/stat", "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("ctxt "):
                ctxt = int(line.split()[1])
            elif line.startswith("procs_running "):
                running = int(line.split()[1])
    return ctxt, running


def postgres_processes() -> list[psutil.Process]:
    rows: list[psutil.Process] = []
    for p in psutil.process_iter(["name"]):
        try:
            name = str(p.info.get("name") or "").lower()
            if name.startswith("postgres"):
                rows.append(p)
        except (psutil.Error, OSError):
            continue
    return rows


class LightObserver:
    def __init__(self, dsn: str, interval_s: float) -> None:
        self.dsn = dsn
        self.interval_s = max(0.1, min(0.25, interval_s))
        self.stop = threading.Event()
        self.samples: list[dict[str, Any]] = []
        self.thread: threading.Thread | None = None
        self.python = psutil.Process(os.getpid())

    def start(self) -> None:
        psutil.cpu_percent(interval=None)
        self.python.cpu_percent(interval=None)
        for p in postgres_processes():
            try:
                p.cpu_percent(interval=None)
            except psutil.Error:
                pass
        self.thread = threading.Thread(target=self._run, name="phase2-light-observer", daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=5.0)

    def _run(self) -> None:
        last_t = time.monotonic()
        last_ctxt, _ = read_proc_scheduler()
        try:
            with psycopg.connect(self.dsn, autocommit=True, application_name="arenyxa-phase2-light-observer") as conn:
                observer_pid = conn.info.backend_pid
                sample_idx = 0
                while not self.stop.wait(self.interval_s):
                    now = time.monotonic()
                    ctxt, runnable = read_proc_scheduler()
                    dt = max(now - last_t, 1e-9)
                    ctxt_rate = (ctxt - last_ctxt) / dt
                    last_ctxt, last_t = ctxt, now
                    rows = conn.execute(
                        """
                        SELECT state,COALESCE(wait_event_type,''),COALESCE(wait_event,''),count(*)
                        FROM pg_stat_activity
                        WHERE datname=current_database() AND pid<>%s
                        GROUP BY 1,2,3
                        """,
                        (observer_pid,),
                    ).fetchall()
                    waits: dict[str, int] = {}
                    backends = 0
                    active = 0
                    for state, wet, we, count in rows:
                        n = int(count)
                        backends += n
                        if str(state) == "active":
                            active += n
                        if wet or we:
                            waits[f"{state}|{wet}|{we}"] = n
                    pg_cpu = None
                    pg_proc_count = None
                    if sample_idx % 4 == 0:
                        pg_rows = postgres_processes()
                        pg_proc_count = len(pg_rows)
                        vals = []
                        for p in pg_rows:
                            try:
                                vals.append(float(p.cpu_percent(interval=None)))
                            except psutil.Error:
                                pass
                        pg_cpu = sum(vals) if vals else 0.0
                    sample_idx += 1
                    ru = resource.getrusage(resource.RUSAGE_SELF)
                    self.samples.append({
                        "mono": now,
                        "wall": time.time(),
                        "cpu_total_percent": float(psutil.cpu_percent(interval=None)),
                        "load1": float(os.getloadavg()[0]),
                        "runnable": int(runnable),
                        "ctx_switches_per_s": float(ctxt_rate),
                        "process_count": len(psutil.pids()),
                        "python_cpu_percent": float(self.python.cpu_percent(interval=None)),
                        "python_threads": int(self.python.num_threads()),
                        "python_rss": int(self.python.memory_info().rss),
                        "python_voluntary_ctx": int(ru.ru_nvcsw),
                        "python_involuntary_ctx": int(ru.ru_nivcsw),
                        "python_minor_faults": int(ru.ru_minflt),
                        "python_major_faults": int(ru.ru_majflt),
                        "postgres_cpu_percent": pg_cpu,
                        "postgres_process_count": pg_proc_count,
                        "backend_count": backends,
                        "active_backend_count": active,
                        "waits": waits,
                    })
        except BaseException as exc:
            self.samples.append({"mono": time.monotonic(), "wall": time.time(), "observer_error": f"{type(exc).__name__}: {exc}"})

    def summary(self, start_mono: float, end_mono: float) -> dict[str, Any]:
        rows = [x for x in self.samples if start_mono <= float(x.get("mono", -1)) <= end_mono and "observer_error" not in x]
        waits: Counter[str] = Counter()
        for row in rows:
            waits.update(row.get("waits") or {})
        def vals(key: str) -> list[float]:
            return [float(x[key]) for x in rows if x.get(key) is not None]
        return {
            "samples": len(rows),
            "cpu_total_percent": dist(vals("cpu_total_percent")),
            "load1": dist(vals("load1")),
            "runnable": dist(vals("runnable")),
            "ctx_switches_per_s": dist(vals("ctx_switches_per_s")),
            "python_cpu_percent": dist(vals("python_cpu_percent")),
            "python_threads": dist(vals("python_threads")),
            "postgres_cpu_percent": dist(vals("postgres_cpu_percent")),
            "postgres_process_count": dist(vals("postgres_process_count")),
            "backend_count": dist(vals("backend_count")),
            "active_backend_count": dist(vals("active_backend_count")),
            "wait_event_weighted_samples": dict(waits.most_common()),
            "lock_wait_weighted_samples": {k: v for k, v in waits.items() if "|Lock|" in k},
            "wal_wait_weighted_samples": {k: v for k, v in waits.items() if "WAL" in k},
            "observer_errors": [x.get("observer_error") for x in self.samples if x.get("observer_error")],
        }


def runtime_state() -> dict[str, Any]:
    p = psutil.Process(os.getpid())
    ru = resource.getrusage(resource.RUSAGE_SELF)
    return {
        "wall": time.time(),
        "monotonic": time.monotonic(),
        "python_uptime_s": time.time() - p.create_time(),
        "python_threads": p.num_threads(),
        "python_rss": p.memory_info().rss,
        "loaded_modules": len(sys.modules),
        "voluntary_ctx": ru.ru_nvcsw,
        "involuntary_ctx": ru.ru_nivcsw,
        "minor_faults": ru.ru_minflt,
        "major_faults": ru.ru_majflt,
    }


class GateWindow:
    def __init__(self, original: type[Any]) -> None:
        self.original = original
        self.timed_start: float | None = None
        self.timed_end: float | None = None

    def make(self) -> type[Any]:
        owner = self
        original = self.original
        class WindowedExecutor(original):
            def __enter__(self):
                owner.timed_start = time.monotonic()
                return super().__enter__()
            def __exit__(self, exc_type, exc, tb):
                try:
                    return super().__exit__(exc_type, exc, tb)
                finally:
                    owner.timed_end = time.monotonic()
        return WindowedExecutor


def run_one(round_no: int, stats_conn: psycopg.Connection[Any], observer: LightObserver, pgss_cap: dict[str, Any]) -> dict[str, Any]:
    pre_runtime = runtime_state()
    pre_pg = pg_snapshot(stats_conn, pgss_cap)

    original_percentile = gate._percentile
    p99_lists: list[list[float]] = []
    def capturing_percentile(values: list[float], q: float) -> float:
        if q == 0.99 and len(p99_lists) < 4:
            p99_lists.append(list(values))
        return original_percentile(values, q)
    gate._percentile = capturing_percentile

    original_executor = gate.ThreadPoolExecutor
    window = GateWindow(original_executor)
    gate.ThreadPoolExecutor = window.make()

    external_start = time.monotonic()
    try:
        result = gate.run_gate(DSN, workers=64, concurrency=128, jobs=1024, p99_budget_ms=500.0)
    finally:
        external_end = time.monotonic()
        gate._percentile = original_percentile
        gate.ThreadPoolExecutor = original_executor

    post_pg = pg_snapshot(stats_conn, pgss_cap)
    post_runtime = runtime_state()
    timed_start = window.timed_start or external_start
    timed_end = window.timed_end or external_end

    phase_names = ["cycle", "lease_next", "start_job", "complete"]
    full_distributions = {
        phase_names[i]: dist(p99_lists[i]) if i < len(p99_lists) else None
        for i in range(len(phase_names))
    }
    pool_metrics = list((result.get("pool") or {}).get("metrics") or [])
    pg_delta = {
        "database": numeric_delta(pre_pg["database"], post_pg["database"], exclude={"numbackends"}),
        "wal": numeric_delta(pre_pg["wal"], post_pg["wal"]),
        "bgwriter": numeric_delta(pre_pg["bgwriter"], post_pg["bgwriter"]),
        "table_io": nested_numeric_delta(pre_pg["table_io"], post_pg["table_io"]),
        "table_stats": nested_numeric_delta(pre_pg["table_stats"], post_pg["table_stats"]),
        "pg_stat_statements": pgss_delta(pre_pg["pg_stat_statements"], post_pg["pg_stat_statements"]),
    }
    payload = {
        "round": round_no,
        "result": result,
        "full_distributions": full_distributions,
        "external_wall_seconds": external_end - external_start,
        "timed_window": {"start_monotonic": timed_start, "end_monotonic": timed_end, "duration_seconds": timed_end - timed_start},
        "runtime_pre": pre_runtime,
        "runtime_post": post_runtime,
        "pg_pre": pre_pg,
        "pg_post": post_pg,
        "pg_delta": pg_delta,
        "scheduler": observer.summary(timed_start, timed_end),
        "pool_summary": {
            "requests_wait_ms_total": sum(float(x.get("requests_wait_ms", 0.0) or 0.0) for x in pool_metrics),
            "requests_waiting_final": sum(int(x.get("requests_waiting", 0) or 0) for x in pool_metrics),
            "acquisitions_total": sum(int(x.get("acquisitions", 0) or 0) for x in pool_metrics),
            "acquisition_failures_total": sum(int(x.get("acquisition_failures", 0) or 0) for x in pool_metrics),
            "pool_size_total_final": sum(int(x.get("pool_size", 0) or 0) for x in pool_metrics),
            "pool_available_total_final": sum(int(x.get("pool_available", 0) or 0) for x in pool_metrics),
        },
        "correctness_pass": correctness(result),
    }
    (OUT / f"run-{round_no:02d}.json").write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return payload


def compact(row: dict[str, Any]) -> dict[str, Any]:
    result = row["result"]
    lat = result["latency_ms"]
    sched = row["scheduler"]
    dbd = row["pg_delta"]["database"]
    wald = row["pg_delta"]["wal"]
    bgd = row["pg_delta"]["bgwriter"]
    return {
        "run": row["round"],
        "p50": lat["p50"], "p95": lat["p95"], "p99": lat["p99"],
        "p999": row["full_distributions"]["cycle"]["p999"], "max": lat["max"],
        "lease_p50": row["full_distributions"]["lease_next"]["p50"],
        "lease_p95": row["full_distributions"]["lease_next"]["p95"],
        "lease_p99": lat["phases"]["lease_next"]["p99"],
        "lease_p999": row["full_distributions"]["lease_next"]["p999"],
        "lease_max": lat["phases"]["lease_next"]["max"],
        "start_p50": row["full_distributions"]["start_job"]["p50"],
        "start_p95": row["full_distributions"]["start_job"]["p95"],
        "start_p99": lat["phases"]["start_job"]["p99"],
        "start_p999": row["full_distributions"]["start_job"]["p999"],
        "start_max": lat["phases"]["start_job"]["max"],
        "complete_p50": row["full_distributions"]["complete"]["p50"],
        "complete_p95": row["full_distributions"]["complete"]["p95"],
        "complete_p99": lat["phases"]["complete"]["p99"],
        "complete_p999": row["full_distributions"]["complete"]["p999"],
        "complete_max": lat["phases"]["complete"]["max"],
        "duration_seconds": result["duration_seconds"],
        "throughput": result["throughput_jobs_per_second"],
        "correctness": row["correctness_pass"],
        "pool_wait_ms": round(row["pool_summary"]["requests_wait_ms_total"], 3),
        "acquisition_failures": row["pool_summary"]["acquisition_failures_total"],
        "cpu_avg": sched["cpu_total_percent"]["mean"], "cpu_peak": sched["cpu_total_percent"]["max"],
        "runnable_avg": sched["runnable"]["mean"], "runnable_peak": sched["runnable"]["max"],
        "ctx_s_avg": sched["ctx_switches_per_s"]["mean"], "ctx_s_peak": sched["ctx_switches_per_s"]["max"],
        "backend_min": sched["backend_count"]["min"] if sched["backend_count"]["count"] else None,
        "backend_max": sched["backend_count"]["max"],
        "lock_wait_samples": sum(sched["lock_wait_weighted_samples"].values()),
        "wal_wait_samples": sum(sched["wal_wait_weighted_samples"].values()),
        "blks_read_delta": dbd.get("blks_read"), "blks_hit_delta": dbd.get("blks_hit"),
        "wal_bytes_delta": wald.get("wal_bytes"), "wal_records_delta": wald.get("wal_records"),
        "wal_write_delta": wald.get("wal_write"), "wal_sync_delta": wald.get("wal_sync"),
        "wal_write_time_delta": wald.get("wal_write_time"), "wal_sync_time_delta": wald.get("wal_sync_time"),
        "checkpoints_timed_delta": bgd.get("checkpoints_timed"), "checkpoints_req_delta": bgd.get("checkpoints_req"),
        "buffers_checkpoint_delta": bgd.get("buffers_checkpoint"), "buffers_backend_delta": bgd.get("buffers_backend"),
        "python_modules_pre": row["runtime_pre"]["loaded_modules"], "python_modules_post": row["runtime_post"]["loaded_modules"],
        "python_threads_pre": row["runtime_pre"]["python_threads"], "python_threads_post": row["runtime_post"]["python_threads"],
        "pg_numbackends_pre": row["pg_pre"]["database"].get("numbackends"), "pg_numbackends_post": row["pg_post"]["database"].get("numbackends"),
    }


def main() -> int:
    with psycopg.connect(DSN, autocommit=True, application_name="arenyxa-phase2-snapshot") as stats_conn:
        pgss_cap = pg_stat_statements_capability(stats_conn)
        initial = pg_snapshot(stats_conn, pgss_cap)
        observer = LightObserver(DSN, SAMPLE_INTERVAL_S)
        observer.start()
        rows: list[dict[str, Any]] = []
        try:
            for run in range(1, ROUNDS + 1):
                row = run_one(run, stats_conn, observer, pgss_cap)
                rows.append(row)
                print(json.dumps(compact(row), sort_keys=True), flush=True)
        finally:
            observer.close()
        final = pg_snapshot(stats_conn, pgss_cap)

    compact_rows = [compact(x) for x in rows]
    summary = {
        "schema": "arenyxa.phase2-cold-warm-variance/v1",
        "round_count": len(rows),
        "sample_interval_seconds": SAMPLE_INTERVAL_S,
        "pg_stat_statements_capability": pgss_cap,
        "initial_pg": initial,
        "final_pg": final,
        "runs": compact_rows,
        "all_correctness_pass": all(x["correctness_pass"] for x in rows),
        "observer_errors": [e for e in (s for x in rows for s in x["scheduler"].get("observer_errors", [])) if e],
    }
    (OUT / "variance-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True, default=str), encoding="utf-8")
    (OUT / "scheduler-samples.json").write_text(json.dumps(observer.samples, separators=(",", ":"), default=str), encoding="utf-8")
    if not summary["all_correctness_pass"]:
        raise SystemExit("correctness failure during variance characterization")
    if summary["observer_errors"]:
        raise SystemExit("observer error during variance characterization")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
