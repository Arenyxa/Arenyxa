from __future__ import annotations

import argparse
import json
import statistics
import threading
import time
from pathlib import Path
from typing import Any

import psycopg

from scripts import postgresql_32_worker_gate as gate
from arenyxa.enterprise.distributed import DurableDistributedQueue


class Probe:
    def __init__(self) -> None:
        self.capture = False
        self.active = False
        self.tls = threading.local()
        self.events: list[dict[str, Any]] = []
        self.leases: list[dict[str, Any]] = []
        self.seq = 0
        self.lock = threading.Lock()
        self.window_start: float | None = None
        self.window_end: float | None = None

    def next_id(self) -> int:
        with self.lock:
            self.seq += 1
            return self.seq

    def reset(self, capture: bool) -> None:
        self.capture = capture
        self.active = False
        self.events = []
        self.leases = []
        self.window_start = None
        self.window_end = None

    def add_event(self, row: dict[str, Any]) -> None:
        with self.lock:
            self.events.append(row)

    def add_lease(self, row: dict[str, Any]) -> None:
        with self.lock:
            self.leases.append(row)


P = Probe()


def install_hooks() -> dict[str, Any]:
    orig = {
        "lease": DurableDistributedQueue.lease_next,
        "due": DurableDistributedQueue._recover_expired_leases_if_due,
        "stale": DurableDistributedQueue.recover_stale_worker_leases,
        "expired": DurableDistributedQueue.recover_expired_leases,
        "executor": gate.ThreadPoolExecutor,
    }

    def lease(self, worker_id: str, *, lease_seconds: int = 60):
        if not (P.capture and P.active):
            return orig["lease"](self, worker_id, lease_seconds=lease_seconds)
        cid = P.next_id()
        P.tls.call_id = cid
        st = time.perf_counter()
        result = None
        try:
            result = orig["lease"](self, worker_id, lease_seconds=lease_seconds)
            return result
        finally:
            en = time.perf_counter()
            P.add_lease({
                "call_id": cid,
                "worker_id": str(worker_id),
                "job_id": None if result is None else str(result.job_id),
                "returned": result is not None,
                "start": st,
                "end": en,
                "client_ms": (en - st) * 1000.0,
            })
            P.tls.call_id = None

    def due(self):
        if not (P.capture and P.active and getattr(P.tls, "call_id", None) is not None):
            return orig["due"](self)
        cid = int(P.tls.call_id)
        before_last = float(self._last_expiry_scan_monotonic)
        interval = float(self._expiry_scan_interval_seconds)
        age = time.monotonic() - before_last
        st = time.perf_counter()
        out = orig["due"](self)
        en = time.perf_counter()
        P.add_event({
            "call_id": cid, "kind": "due_check", "start": st, "end": en,
            "elapsed_ms": (en - st) * 1000.0,
            "age_before_s": age, "interval_s": interval,
            "threshold_due": age >= interval,
            "returned_recovered": int(out),
            "last_scan_before": before_last,
            "last_scan_after": float(self._last_expiry_scan_monotonic),
        })
        return out

    def stale(self, now: float | None = None):
        cid = getattr(P.tls, "call_id", None)
        st = time.perf_counter(); out = orig["stale"](self, now=now); en = time.perf_counter()
        if P.capture and P.active and cid is not None:
            P.add_event({"call_id": int(cid), "kind": "recover_stale", "start": st, "end": en, "elapsed_ms": (en-st)*1000.0, "affected": int(out)})
        return out

    def expired(self, now: float | None = None):
        cid = getattr(P.tls, "call_id", None)
        st = time.perf_counter(); out = orig["expired"](self, now=now); en = time.perf_counter()
        if P.capture and P.active and cid is not None:
            P.add_event({"call_id": int(cid), "kind": "recover_expired", "start": st, "end": en, "elapsed_ms": (en-st)*1000.0, "affected": int(out)})
        return out

    class Exec(orig["executor"]):
        def __enter__(self):
            if P.capture:
                P.active = True
                P.window_start = time.perf_counter()
            return super().__enter__()
        def __exit__(self, et, ev, tb):
            try:
                return super().__exit__(et, ev, tb)
            finally:
                if P.capture:
                    P.window_end = time.perf_counter()
                    P.active = False

    DurableDistributedQueue.lease_next = lease
    DurableDistributedQueue._recover_expired_leases_if_due = due
    DurableDistributedQueue.recover_stale_worker_leases = stale
    DurableDistributedQueue.recover_expired_leases = expired
    gate.ThreadPoolExecutor = Exec
    return orig


def restore(o: dict[str, Any]) -> None:
    DurableDistributedQueue.lease_next = o["lease"]
    DurableDistributedQueue._recover_expired_leases_if_due = o["due"]
    DurableDistributedQueue.recover_stale_worker_leases = o["stale"]
    DurableDistributedQueue.recover_expired_leases = o["expired"]
    gate.ThreadPoolExecutor = o["executor"]


def compact(r: dict[str, Any]) -> dict[str, Any]:
    lat = r["latency_ms"]
    return {
        "p50": lat["p50"], "p95": lat["p95"], "p99": lat["p99"], "max": lat["max"],
        "lease_p99": lat["phases"]["lease_next"]["p99"],
        "start_p99": lat["phases"]["start_job"]["p99"],
        "complete_p99": lat["phases"]["complete"]["p99"],
        "throughput": r["throughput_jobs_per_second"], "passed": r["passed"],
    }


def run_once(dsn: str, capture: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    P.reset(capture)
    r = gate.run_gate(dsn, workers=64, concurrency=128, jobs=1024, p99_budget_ms=500.0)
    c = compact(r)
    events_by_call: dict[int, list[dict[str, Any]]] = {}
    for e in P.events:
        events_by_call.setdefault(int(e["call_id"]), []).append(e)
    lease_rows = []
    for l in P.leases:
        es = events_by_call.get(int(l["call_id"]), [])
        due = [e for e in es if e["kind"] == "due_check"]
        stale = [e for e in es if e["kind"] == "recover_stale"]
        expired = [e for e in es if e["kind"] == "recover_expired"]
        lease_rows.append({
            **l,
            "due_checks": due,
            "threshold_due": any(bool(e.get("threshold_due")) for e in due),
            "due_elapsed_ms": sum(float(e["elapsed_ms"]) for e in due),
            "stale_elapsed_ms": sum(float(e["elapsed_ms"]) for e in stale),
            "expired_elapsed_ms": sum(float(e["elapsed_ms"]) for e in expired),
            "recovery_children": len(stale) + len(expired),
            "recovered_rows": sum(int(e.get("affected", 0)) for e in stale + expired),
        })
    return r, {
        "official": r, "compact": c,
        "window": {"start": P.window_start, "end": P.window_end},
        "lease_calls": lease_rows, "raw_events": P.events,
    }


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--dsn", required=True); ap.add_argument("--out", type=Path, required=True); args = ap.parse_args(); args.out.mkdir(parents=True, exist_ok=True)
    with psycopg.connect(args.dsn, autocommit=True) as c:
        vals = c.execute("SELECT current_setting('server_version_num'),current_setting('max_connections'),current_setting('fsync'),current_setting('synchronous_commit')").fetchone()
        assert tuple(map(str, vals)) == ("160015", "256", "on", "on")
    pre = gate.run_gate(args.dsn, workers=64, concurrency=128, jobs=1024, p99_budget_ms=500.0)
    assert (pre.get("storage") or {}).get("backend") == "postgresql" and pre.get("completed") == 1024 and not pre.get("errors")
    (args.out / "precondition.json").write_text(json.dumps(pre, indent=2, sort_keys=True), encoding="utf-8")

    hooks = install_hooks()
    try:
        off = [compact(run_once(args.dsn, False)[0]) for _ in range(2)]
        on = []
        for i in range(2):
            r, t = run_once(args.dsn, True); on.append(compact(r)); (args.out / f"cal-on-{i+1}.json").write_text(json.dumps(t, indent=2, sort_keys=True), encoding="utf-8")
        off_p = statistics.median([x["p99"] for x in off]); on_p = statistics.median([x["p99"] for x in on]); off_t = statistics.median([x["throughput"] for x in off]); on_t = statistics.median([x["throughput"] for x in on])
        calibration = {"off": off, "on": on, "off_p99_median": off_p, "on_p99_median": on_p, "off_throughput_median": off_t, "on_throughput_median": on_t, "p99_ratio": on_p/off_p, "throughput_ratio": on_t/off_t}
        (args.out / "calibration.json").write_text(json.dumps(calibration, indent=2, sort_keys=True), encoding="utf-8")

        runs = []; prev_end = None; failures = 0
        for i in range(1, 21):
            r, t = run_once(args.dsn, True); c = compact(r); calls = t["lease_calls"]
            due_calls = [x for x in calls if x["threshold_due"]]; recovery_calls = [x for x in calls if x["recovery_children"]]; successful = [x for x in calls if x["returned"]]
            normals = sorted([x["client_ms"] for x in successful if not x["recovery_children"]])
            entry = {
                "run": i, **c,
                "gap_from_previous_window_s": None if prev_end is None else float(t["window"]["start"] - prev_end),
                "threshold_due_calls": len(due_calls), "recovery_calls": len(recovery_calls),
                "recovered_rows": sum(int(x["recovered_rows"]) for x in recovery_calls),
                "recovery_lease_median_ms": statistics.median([x["client_ms"] for x in recovery_calls]) if recovery_calls else None,
                "recovery_lease_max_ms": max([x["client_ms"] for x in recovery_calls], default=None),
                "normal_lease_p99_ms": normals[min(len(normals)-1, max(0, round((len(normals)-1)*.99)))] if normals else None,
                "trace_file": f"run-{i:02d}.json",
            }
            if float(c["p99"]) > 500.0: failures += 1
            runs.append(entry); (args.out / entry["trace_file"]).write_text(json.dumps(t, indent=2, sort_keys=True), encoding="utf-8"); print(json.dumps(entry, sort_keys=True), flush=True); prev_end = t["window"]["end"]
        (args.out / "phase3b-recovery-probe-summary.json").write_text(json.dumps({"calibration":calibration,"runs":runs,"warm_failures":failures}, indent=2, sort_keys=True), encoding="utf-8")
    finally:
        restore(hooks)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
