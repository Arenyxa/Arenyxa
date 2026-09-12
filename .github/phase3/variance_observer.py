from __future__ import annotations

import os
import statistics
import threading
import time
from collections import Counter
from typing import Any

import psutil
import psycopg

from scripts import postgresql_32_worker_gate as gate


def pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    return round(float(gate._percentile(list(values), q)), 3)


def dist(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "mean": None, "min": None, "p50": None, "p95": None, "p99": None, "p999": None, "max": None}
    return {
        "count": len(values), "mean": round(statistics.fmean(values), 3), "min": round(min(values), 3),
        "p50": pct(values, 0.50), "p95": pct(values, 0.95), "p99": pct(values, 0.99),
        "p999": pct(values, 0.999), "max": round(max(values), 3),
    }


def correctness(result: dict[str, Any]) -> bool:
    inv = result.get("state_invariants") or {}
    return bool(
        not result.get("errors")
        and result.get("completed") == result.get("jobs") == 1024
        and result.get("non_completed") == 0
        and (result.get("fencing_probe") or {}).get("passed")
        and all(int(inv.get(k, 1)) == 0 for k in (
            "inconsistent_lease_rows", "unreceipted_completed_jobs", "implausible_future_leases",
        ))
        and result.get("active_leases_after") == 0
        and (result.get("pool") or {}).get("connection_storm_free")
    )


def read_proc_scheduler() -> tuple[int, int]:
    ctxt = running = 0
    with open("/proc/stat", "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("ctxt "):
                ctxt = int(line.split()[1])
            elif line.startswith("procs_running "):
                running = int(line.split()[1])
    return ctxt, running


def postgres_processes() -> list[psutil.Process]:
    out: list[psutil.Process] = []
    for p in psutil.process_iter(["name"]):
        try:
            if str(p.info.get("name") or "").lower().startswith("postgres"):
                out.append(p)
        except (psutil.Error, OSError):
            pass
    return out


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
        self.thread = threading.Thread(target=self._run, name="phase3-light-observer", daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=5.0)

    def _run(self) -> None:
        last_t = time.monotonic()
        last_ctxt, _ = read_proc_scheduler()
        try:
            with psycopg.connect(self.dsn, autocommit=True, application_name="arenyxa-phase3-light-observer") as conn:
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
                    backends = active = 0
                    for state, wet, we, count in rows:
                        n = int(count); backends += n
                        if str(state) == "active": active += n
                        if wet or we: waits[f"{state}|{wet}|{we}"] = n
                    pg_cpu = None
                    pg_proc_count = None
                    if sample_idx % 4 == 0:
                        pg_rows = postgres_processes(); pg_proc_count = len(pg_rows); vals = []
                        for p in pg_rows:
                            try: vals.append(float(p.cpu_percent(interval=None)))
                            except psutil.Error: pass
                        pg_cpu = sum(vals) if vals else 0.0
                    sample_idx += 1
                    self.samples.append({
                        "mono": now, "wall": time.time(), "cpu_total_percent": float(psutil.cpu_percent(interval=None)),
                        "load1": float(os.getloadavg()[0]), "runnable": int(runnable),
                        "ctx_switches_per_s": float(ctxt_rate), "python_cpu_percent": float(self.python.cpu_percent(interval=None)),
                        "python_threads": int(self.python.num_threads()), "postgres_cpu_percent": pg_cpu,
                        "postgres_process_count": pg_proc_count, "backend_count": backends,
                        "active_backend_count": active, "waits": waits,
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
            "cpu_total_percent": dist(vals("cpu_total_percent")), "load1": dist(vals("load1")),
            "runnable": dist(vals("runnable")), "ctx_switches_per_s": dist(vals("ctx_switches_per_s")),
            "python_cpu_percent": dist(vals("python_cpu_percent")), "python_threads": dist(vals("python_threads")),
            "postgres_cpu_percent": dist(vals("postgres_cpu_percent")),
            "postgres_process_count": dist(vals("postgres_process_count")),
            "backend_count": dist(vals("backend_count")), "active_backend_count": dist(vals("active_backend_count")),
            "wait_event_weighted_samples": dict(waits.most_common()),
            "lock_wait_weighted_samples": {k: v for k, v in waits.items() if "|Lock|" in k},
            "wal_wait_weighted_samples": {k: v for k, v in waits.items() if "WAL" in k},
            "observer_errors": [x.get("observer_error") for x in self.samples if x.get("observer_error")],
        }
