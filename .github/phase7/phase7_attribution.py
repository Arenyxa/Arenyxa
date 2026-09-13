"""Arenyxa P99 Phase 7 diagnostic-only execute-wall attribution.

Extends the accepted Phase 6 minimal observer. No production source, SQL,
workload, retry, gate timing, or PostgreSQL configuration is modified.

Phase 7 additions observe the *existing* psycopg 3.3.5 synchronous generator
path. They never call recv/read/PQconsumeInput and never issue SQL. The wait
proxy delegates polling to psycopg's original waiting.wait implementation and
only observes the readiness value that the driver itself is about to consume.
Therefore `first_driver_read_ready` is NOT the kernel's earliest readability
timestamp: scheduler wake-up/reacquisition delay may precede this timestamp.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import statistics
import threading
import time
from typing import Any

import phase6_trace as p6
import phase6_minimal as p6min

PC = time.perf_counter


def pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    values = sorted(float(x) for x in values)
    return values[min(len(values) - 1, max(0, int(round((len(values) - 1) * q))))]


def read_schedstat() -> tuple[int, int, int] | None:
    try:
        fields = Path("/proc/thread-self/schedstat").read_text().split()
        if len(fields) < 3:
            return None
        return int(fields[0]), int(fields[1]), int(fields[2])
    except (OSError, ValueError):
        return None


class Phase7Recorder(p6min.MinimalRecorder):
    def __init__(self, gate, rs, queue, psycopg, full, *, schedstat: bool = False):
        super().__init__(gate, rs, queue, psycopg, full)
        self.schedstat = bool(schedstat)
        self.p7_wait_impl_name = None

    def _ctx(self):
        return getattr(self.tls, "p7ctx", None) if self.active else None

    def _exchange(self):
        return getattr(self.tls, "p7exchange", None) if self.active else None

    def install(self):
        super().install()
        if not self.full:
            return

        import psycopg._cursor_base as cb
        import psycopg.generators as gens
        import psycopg.waiting as waiting

        R = self
        self.p7_wait_impl_name = getattr(waiting.wait, "__name__", type(waiting.wait).__name__)

        phase6_execute = self.pg.Connection.execute

        def connection_execute(conn, query, *args, **kwargs):
            row = R.lease_row()
            health = getattr(R.tls, "health", None)
            is_lease_fast = (
                row is not None
                and health is None
                and "WITH eligible_worker AS" in str(query)
            )
            if not is_lease_fast:
                return phase6_execute(conn, query, *args, **kwargs)

            ctx: dict[str, Any] = {
                "t0": PC(),
                "t6": None,
                "backend_pid": int(conn.info.backend_pid),
                "native_tid": threading.get_native_id(),
                "send_ops": [],
                "exchanges": [],
                "wait_events": 0,
                "read_ready_events": 0,
                "write_ready_events": 0,
                "first_driver_read_ready": None,
                "pending_exchange_kind": None,
                "thread_usage_before": p6.thread_usage(),
                "thread_usage_after": None,
                "sched_before": read_schedstat() if R.schedstat else None,
                "sched_after": None,
                "sched_after_read_end": None,
            }
            previous = getattr(R.tls, "p7ctx", None)
            R.tls.p7ctx = ctx
            try:
                rv = phase6_execute(conn, query, *args, **kwargs)
                ctx["t6"] = PC()
                return rv
            finally:
                if ctx["t6"] is None:
                    ctx["t6"] = PC()
                ctx["thread_usage_after"] = p6.thread_usage()
                if R.schedstat:
                    ctx["sched_after"] = read_schedstat()
                    ctx["sched_after_read_end"] = PC()
                ctx["total_ms"] = (ctx["t6"] - ctx["t0"]) * 1000.0
                before = ctx["thread_usage_before"]
                after = ctx["thread_usage_after"]
                ctx["thread_cpu_ms"] = (after[0] - before[0]) * 1000.0
                ctx["thread_vcsw"] = int(after[1] - before[1])
                ctx["thread_ivcsw"] = int(after[2] - before[2])
                sb, sa = ctx["sched_before"], ctx["sched_after"]
                if sb is not None and sa is not None:
                    ctx["sched_cpu_ms"] = (sa[0] - sb[0]) / 1_000_000.0
                    ctx["sched_runqueue_ms"] = (sa[1] - sb[1]) / 1_000_000.0
                    ctx["sched_timeslices"] = int(sa[2] - sb[2])
                else:
                    ctx["sched_cpu_ms"] = None
                    ctx["sched_runqueue_ms"] = None
                    ctx["sched_timeslices"] = None
                row.setdefault("phase7_executes", []).append(ctx)
                R.tls.p7ctx = previous

        self.patch(self.pg.Connection, "execute", connection_execute)

        BaseCursor = cb.BaseCursor
        for method_name, exchange_kind in (
            ("_execute_send", "query_unprepared"),
            ("_send_prepare", "prepare"),
            ("_send_query_prepared", "query_prepared"),
        ):
            original = getattr(BaseCursor, method_name)

            def send_op(cur, *args, _orig=original, _method=method_name,
                        _kind=exchange_kind, **kwargs):
                ctx = R._ctx()
                if ctx is None:
                    return _orig(cur, *args, **kwargs)
                rec = {"method": _method, "kind": _kind, "begin": PC(), "end": None}
                ctx["send_ops"].append(rec)
                try:
                    return _orig(cur, *args, **kwargs)
                finally:
                    rec["end"] = PC()
                    ctx["pending_exchange_kind"] = _kind

            self.patch(BaseCursor, method_name, send_op)

        original_exchange = cb.execute

        def observed_exchange(pgconn):
            ctx = R._ctx()
            if ctx is None:
                return (yield from original_exchange(pgconn))
            rec: dict[str, Any] = {
                "kind": ctx.pop("pending_exchange_kind", None) or "other",
                "begin": PC(),
                "end": None,
                "flush_begin": None,
                "flush_end": None,
                "first_driver_read_ready": None,
                "read_ready_events": 0,
                "write_ready_events": 0,
                "fetch_returns": [],
                "result_count": None,
            }
            ctx["exchanges"].append(rec)
            previous = getattr(R.tls, "p7exchange", None)
            R.tls.p7exchange = rec
            try:
                results = yield from original_exchange(pgconn)
                rec["result_count"] = len(results)
                return results
            finally:
                rec["end"] = PC()
                R.tls.p7exchange = previous

        self.patch(cb, "execute", observed_exchange)

        original_send = gens._send

        def observed_send(pgconn):
            ex = R._exchange()
            if ex is None:
                return (yield from original_send(pgconn))
            if ex["flush_begin"] is None:
                ex["flush_begin"] = PC()
            try:
                return (yield from original_send(pgconn))
            finally:
                ex["flush_end"] = PC()

        self.patch(gens, "_send", observed_send)

        original_fetch = gens._fetch

        def observed_fetch(pgconn):
            ex = R._exchange()
            begin = PC() if ex is not None else None
            result = yield from original_fetch(pgconn)
            if ex is not None:
                end = PC()
                status = None
                if result is not None:
                    try:
                        status = int(result.status)
                    except (TypeError, ValueError):
                        status = str(result.status)
                ex["fetch_returns"].append({
                    "begin": begin,
                    "end": end,
                    "has_result": result is not None,
                    "status": status,
                })
            return result

        self.patch(gens, "_fetch", observed_fetch)

        original_wait = waiting.wait
        READY_R = waiting.READY_R
        READY_W = waiting.READY_W

        def proxy_generator(gen):
            try:
                state = next(gen)
                while True:
                    ready = yield state
                    now = PC()
                    ctx = R._ctx()
                    ex = R._exchange()
                    if ctx is not None:
                        ctx["wait_events"] += 1
                        if ready & READY_R:
                            ctx["read_ready_events"] += 1
                            if ctx["first_driver_read_ready"] is None:
                                ctx["first_driver_read_ready"] = now
                        if ready & READY_W:
                            ctx["write_ready_events"] += 1
                    if ex is not None:
                        if ready & READY_R:
                            ex["read_ready_events"] += 1
                            if ex["first_driver_read_ready"] is None:
                                ex["first_driver_read_ready"] = now
                        if ready & READY_W:
                            ex["write_ready_events"] += 1
                    state = gen.send(ready)
            except StopIteration as stop:
                return stop.value

        def observed_wait(gen, fileno, interval=0.1):
            ctx = R._ctx()
            if ctx is None:
                return original_wait(gen, fileno, interval=interval)
            return original_wait(proxy_generator(gen), fileno, interval=interval)

        self.patch(waiting, "wait", observed_wait)

    def result(self):
        result = super().result()
        result["phase7_profile"] = "schedstat" if self.schedstat else "core"
        result["phase7_wait_impl"] = self.p7_wait_impl_name
        result["phase7_semantics"] = {
            "socket_consumption_by_observer": False,
            "extra_sql": False,
            "first_driver_read_ready_is_kernel_first_readable": False,
            "pqconsumeinput_directly_observed": False,
            "full_results_collected_boundary": True,
        }
        return result


def correct(r: dict[str, Any]) -> bool:
    return p6.correct(r)


def ordinary_rows(trace: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for row in trace.get("cycles", []):
        if not row.get("success") or row.get("recovery_yes"):
            continue
        classes = [x[0] for x in row.get("sql", [])]
        if classes.count("lease_fast") != 1 or "other_business" in classes:
            continue
        rows.append(row)
    return rows


def trace_metrics(official: dict[str, Any], trace: dict[str, Any]) -> dict[str, Any]:
    rows = ordinary_rows(trace)
    leases = [float(r["lease_ms"]) for r in rows]
    executes = [float(r["ledger"]["execute_ms"]) for r in rows]
    vcsw = [float(r["thread_vcsw"]) for r in rows]
    ivcsw = [float(r["thread_ivcsw"]) for r in rows]
    top1_n = max(1, (len(rows) + 99) // 100) if rows else 0
    top01_n = max(1, (len(rows) + 999) // 1000) if rows else 0
    sorted_rows = sorted(rows, key=lambda r: float(r["lease_ms"]))
    top1 = sorted_rows[-top1_n:] if top1_n else []
    top01 = sorted_rows[-top01_n:] if top01_n else []
    return {
        "p50": float(official["latency_ms"]["p50"]),
        "p95": float(official["latency_ms"]["p95"]),
        "p99": float(official["latency_ms"]["p99"]),
        "throughput": float(official["throughput_jobs_per_second"]),
        "ordinary_n": len(rows),
        "ordinary_lease_p99": pct(leases, .99),
        "ordinary_execute_p99": pct(executes, .99),
        "ordinary_top1_median": statistics.median(float(r["lease_ms"]) for r in top1) if top1 else 0.0,
        "ordinary_top01_median": statistics.median(float(r["lease_ms"]) for r in top01) if top01 else 0.0,
        "thread_vcsw_p50": statistics.median(vcsw) if vcsw else 0.0,
        "thread_ivcsw_p50": statistics.median(ivcsw) if ivcsw else 0.0,
        "recovery_calls": int(trace.get("timed_recovery_invocations", 0)),
    }


def calibration_summary(runs: list[dict[str, Any]], label: str) -> dict[str, Any]:
    off = [r for r in runs if r["mode"] == "OFF"]
    on = [r for r in runs if r["mode"] == "ON"]
    ratio_keys = (
        "p50", "p95", "p99", "ordinary_lease_p99", "ordinary_execute_p99",
        "ordinary_top1_median", "ordinary_top01_median",
    )
    ratios = {}
    for key in ratio_keys:
        den = statistics.median(float(r[key]) for r in off)
        num = statistics.median(float(r[key]) for r in on)
        ratios[key] = num / den if den else None
    off_tps = statistics.median(float(r["throughput"]) for r in off)
    on_tps = statistics.median(float(r["throughput"]) for r in on)
    throughput_ratio = on_tps / off_tps if off_tps else 0.0
    recovery_delta = abs(
        statistics.mean(float(r["recovery_calls"]) for r in on)
        - statistics.mean(float(r["recovery_calls"]) for r in off)
    )
    vcsw_off = statistics.median(float(r["thread_vcsw_p50"]) for r in off)
    vcsw_on = statistics.median(float(r["thread_vcsw_p50"]) for r in on)
    ivcsw_off = statistics.median(float(r["thread_ivcsw_p50"]) for r in off)
    ivcsw_on = statistics.median(float(r["thread_ivcsw_p50"]) for r in on)
    ctx_ratio = max(
        vcsw_on / vcsw_off if vcsw_off else 1.0,
        ivcsw_on / ivcsw_off if ivcsw_off else 1.0,
    )
    limits = {
        "main_latency_ratio_max": 1.10,
        "top1_ratio_max": 1.12,
        "top01_ratio_max": 1.20,
        "throughput_ratio_min": .95,
        "ctx_switch_median_ratio_max": 1.30,
        "recovery_call_delta_max": 6.0,
    }
    accepted = (
        all(ratios[k] is not None and ratios[k] <= limits["main_latency_ratio_max"]
            for k in ("p50", "p95", "p99", "ordinary_lease_p99", "ordinary_execute_p99"))
        and ratios["ordinary_top1_median"] is not None
        and ratios["ordinary_top1_median"] <= limits["top1_ratio_max"]
        and ratios["ordinary_top01_median"] is not None
        and ratios["ordinary_top01_median"] <= limits["top01_ratio_max"]
        and throughput_ratio >= limits["throughput_ratio_min"]
        and ctx_ratio <= limits["ctx_switch_median_ratio_max"]
        and recovery_delta <= limits["recovery_call_delta_max"]
    )
    return {
        "label": label,
        "sequence": [r["mode"] for r in runs],
        "runs": runs,
        "ratios": ratios,
        "throughput_ratio": throughput_ratio,
        "ctx_switch_median_ratio": ctx_ratio,
        "recovery_calls_absolute_delta": recovery_delta,
        "limits": limits,
        "accepted": bool(accepted),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--runs", type=int, default=40)
    ap.add_argument("--max-runs", type=int, default=80)
    ap.add_argument("--min-failures", type=int, default=2)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    root = Path(os.environ.get("GITHUB_WORKSPACE", Path.cwd()))
    hashes = p6.verify(root)

    import psycopg
    import psycopg_pool
    p6.OSObserver = p6min.NoPolling
    from scripts import postgresql_32_worker_gate as gate
    from arenyxa.enterprise import runtime_storage as rs
    from arenyxa.enterprise.distributed import DurableDistributedQueue as Q

    if psycopg.__version__ != "3.3.5":
        raise RuntimeError(f"psycopg version mismatch: {psycopg.__version__}")
    if psycopg_pool.__version__ != "3.3.1":
        raise RuntimeError(f"psycopg_pool version mismatch: {psycopg_pool.__version__}")

    def save(name: str, payload: Any) -> None:
        (args.out / f"{name}.json").write_text(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
        )

    with psycopg.connect(args.dsn, autocommit=True) as c:
        settings = c.execute(
            "SELECT current_setting('server_version_num'),current_setting('max_connections'),"
            "current_setting('fsync'),current_setting('synchronous_commit'),"
            "pg_postmaster_start_time()::text"
        ).fetchone()
    if tuple(map(str, settings[:4])) != ("160015", "256", "on", "on"):
        raise RuntimeError("PostgreSQL contract mismatch")
    save("settings", settings)
    save("source-hashes", hashes)

    first = gate.run_gate(args.dsn, workers=64, concurrency=128, jobs=1024, p99_budget_ms=500.0)
    save("first-run", first)
    if not correct(first):
        raise RuntimeError("First run correctness failure")

    run_serial = 0

    def run_gate_observed(name: str, mode: str, profile: str) -> dict[str, Any]:
        nonlocal run_serial
        run_serial += 1
        p6.verify(root)
        if mode == "OFF":
            recorder = p6min.MinimalRecorder(gate, rs, Q, psycopg, True)
        else:
            recorder = Phase7Recorder(
                gate, rs, Q, psycopg, True, schedstat=(profile == "schedstat")
            )
        recorder.install()
        try:
            official = gate.run_gate(
                args.dsn, workers=64, concurrency=128, jobs=1024, p99_budget_ms=500.0
            )
        finally:
            recorder.restore()
        trace = recorder.result()
        if not correct(official):
            raise RuntimeError(f"Correctness failure: {name}")
        if trace.get("overflow") or not trace.get("exact_cycle_multiset_matches_gate"):
            raise RuntimeError(f"Observer identity/count failure: {name}")
        payload = {
            "serial": run_serial,
            "name": name,
            "mode": mode,
            "profile": profile,
            "official": official,
            "trace": trace,
        }
        save(name, payload)
        metrics = trace_metrics(official, trace)
        metrics.update({"serial": run_serial, "name": name, "mode": mode, "profile": profile})
        print(json.dumps(metrics), flush=True)
        p6.verify(root)
        return metrics

    profiles = ["schedstat", "core"]
    accepted_profile = None
    calibrations = []
    for profile in profiles:
        cal_runs = []
        for i, mode in enumerate(("OFF", "ON", "OFF", "ON"), 1):
            cal_runs.append(run_gate_observed(f"cal-{profile}-{i}-{mode.lower()}", mode, profile))
        cal = calibration_summary(cal_runs, profile)
        save(f"calibration-{profile}", cal)
        calibrations.append(cal)
        if cal["accepted"]:
            accepted_profile = profile
            break

    save("calibrations", calibrations)
    if accepted_profile is None:
        save("verdict", {
            "status": "REJECT_OBSERVER",
            "reason": "Both schedstat and core Phase7 additions failed OFF-ON-OFF-ON calibration",
            "warm_runs": 0,
        })
        return 3

    warm_metrics = []
    target = max(1, args.runs)
    max_runs = max(target, args.max_runs)
    i = 1
    while i <= target:
        m = run_gate_observed(f"warm-{i:03}", "ON", accepted_profile)
        warm_metrics.append(m)
        save("warm-summary", {
            "accepted_profile": accepted_profile,
            "runs": warm_metrics,
            "failures": sum(float(x["p99"]) > 500.0 for x in warm_metrics),
        })
        if i == target:
            failures = sum(float(x["p99"]) > 500.0 for x in warm_metrics)
            if failures < args.min_failures and target < max_runs:
                target = min(max_runs, target + 10)
        i += 1

    with psycopg.connect(args.dsn, autocommit=True) as c:
        final_settings = c.execute(
            "SELECT current_setting('server_version_num'),current_setting('max_connections'),"
            "current_setting('fsync'),current_setting('synchronous_commit'),"
            "pg_postmaster_start_time()::text"
        ).fetchone()
    save("settings-final", final_settings)
    if settings != final_settings:
        raise RuntimeError("PostgreSQL instance/settings changed")
    save("source-hashes-final", p6.verify(root))

    failures = sum(float(x["p99"]) > 500.0 for x in warm_metrics)
    status = "CAPTURE_COMPLETE" if failures >= args.min_failures else "INSUFFICIENT_TAIL_REPRODUCTION"
    save("verdict", {
        "status": status,
        "accepted_profile": accepted_profile,
        "warm_runs": len(warm_metrics),
        "warm_failures": failures,
        "min_failures_requested": args.min_failures,
        "max_runs": max_runs,
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
