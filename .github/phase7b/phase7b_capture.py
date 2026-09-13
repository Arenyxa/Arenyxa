from __future__ import annotations

import argparse
import gzip
import json
import os
from pathlib import Path

import phase6_minimal
import phase6_trace as p6
from phase7b_lite_observer import BoundaryLiteRecorder
from phase7b_lite_run import calibration_verdict, is_target_row


def strict_correct(result: dict) -> bool:
    if not p6.correct(result):
        return False
    metrics = (result.get("pool") or {}).get("metrics") or []
    return all(int(m.get("acquisition_failures", 0) or 0) == 0 for m in metrics)


def trace_metrics(trace: dict, lite_enabled: bool) -> tuple[dict, dict]:
    target = [r for r in trace["cycles"] if is_target_row(r)]
    lease = [float(r["lease_ms"]) for r in target]
    execute = [float(r["ledger"]["execute_ms"]) for r in target]
    out = {
        "ordinary_target_count": len(target),
        "ordinary_lease": p6.distribution(lease),
        "execute": p6.distribution(execute),
        "health_probe_count": sum(bool(r.get("health_probe_yes")) for r in target),
        "lease_thread_cpu": p6.distribution([r["thread_cpu_ms"] for r in target]),
        "lease_thread_vcsw": p6.distribution([r["thread_vcsw"] for r in target]),
        "lease_thread_ivcsw": p6.distribution([r["thread_ivcsw"] for r in target]),
    }
    if lite_enabled:
        calls = []
        missing = invalid = 0
        for row in target:
            items = row.get("phase7b_calls") or []
            if len(items) != 1 or "summary" not in items[0]:
                missing += 1
                continue
            call = items[0]
            calls.append(call)
            if not call["summary"].get("decomposition_valid"):
                invalid += 1
        valid = [c["summary"] for c in calls if c["summary"].get("decomposition_valid")]
        errors = [abs(float(s["conservation_error_ms"])) for s in valid]
        out.update({
            "phase7b_call_count": len(calls),
            "phase7b_missing": missing,
            "phase7b_invalid": invalid,
            "max_abs_conservation_error_ms": max(errors) if errors else None,
            "pre_result": p6.distribution([s["pre_result_ms"] for s in valid]),
            "post_result": p6.distribution([s["post_result_ms"] for s in valid]),
            "prepared_query_count": sum(s["segment_class"] == "PREPARED_QUERY" for s in valid),
            "prepare_transition_count": sum(s["segment_class"] == "PREPARE_PLUS_PREPARED_QUERY" for s in valid),
            "unprepared_query_count": sum(s["segment_class"] == "UNPREPARED_QUERY" for s in valid),
        })
    return out, {"lease": lease, "execute": execute}


def compact(official: dict, trace: dict, lite_enabled: bool, name: str, mode: str) -> dict:
    base = p6.compact(official, trace)
    base["p999"] = trace["cycle_distribution"]["p999"]
    tm, samples = trace_metrics(trace, lite_enabled)
    base.update(name=name, mode=mode, trace_metrics=tm, _samples=samples)
    return base


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--runs", type=int, default=80)
    args = ap.parse_args()
    if args.runs != 80:
        raise SystemExit("Phase 7B contract requires exactly 80 warm runs")
    args.out.mkdir(parents=True, exist_ok=True)
    root = Path(os.environ.get("GITHUB_WORKSPACE", Path.cwd()))
    source_hashes = p6.verify(root)

    import psycopg
    import psycopg_pool
    from scripts import postgresql_32_worker_gate as gate
    from arenyxa.enterprise import runtime_storage as rs
    from arenyxa.enterprise.distributed import DurableDistributedQueue as Q

    if psycopg.__version__ != "3.3.5" or psycopg_pool.__version__ != "3.3.1":
        raise RuntimeError("driver version contract mismatch")
    p6.OSObserver = phase6_minimal.NoPolling

    def save_json(name: str, payload: dict) -> None:
        (args.out / f"{name}.json").write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")

    def save_payload(name: str, payload: dict) -> None:
        with gzip.open(args.out / f"{name}.json.gz", "wt", encoding="utf-8", compresslevel=6) as f:
            json.dump(payload, f, separators=(",", ":"))

    env = {
        "python": ".".join(map(str, __import__("sys").version_info[:3])),
        "psycopg": psycopg.__version__,
        "psycopg_pool": psycopg_pool.__version__,
        "pq_impl": getattr(psycopg.pq, "__impl__", None),
        "libpq_version": psycopg.pq.version(),
        "postgresql_server_required": "16.15",
        "observer": "BOUNDARY_LITE_PHASE7B",
        "warm_runs_predeclared": 80,
        "zero_extra_sql_observer": True,
        "source_hashes": source_hashes,
        "unobserved": ["T2_PQFLUSH_COMPLETE", "T3_SOCKET_FIRST_READABLE", "T4_PQCONSUMEINPUT_PROGRESS"],
    }
    save_json("environment", env)
    print(json.dumps({"environment": env}, separators=(",", ":")), flush=True)

    # Retained first-use run. It is not part of warm characterization.
    first = gate.run_gate(args.dsn, workers=64, concurrency=128, jobs=1024, p99_budget_ms=500.0)
    save_json("first-use-retained", first)
    if not strict_correct(first):
        raise RuntimeError("first-use correctness hard gate failed")

    def execute_run(name: str, mode: str) -> dict:
        p6.verify(root)
        recorder = (
            phase6_minimal.MinimalRecorder(gate, rs, Q, psycopg, True)
            if mode == "OFF"
            else BoundaryLiteRecorder(gate, rs, Q, psycopg, True)
        )
        recorder.install()
        try:
            official = gate.run_gate(args.dsn, workers=64, concurrency=128, jobs=1024, p99_budget_ms=500.0)
        finally:
            recorder.restore()
        trace = recorder.result()
        save_payload(name, {"official": official, "trace": trace, "mode": mode, "observer": "BOUNDARY_LITE_PHASE7B"})
        p6.verify(root)
        if not strict_correct(official):
            raise RuntimeError(f"correctness hard gate failed: {name}")
        if trace.get("overflow") or not trace.get("exact_cycle_multiset_matches_gate"):
            raise RuntimeError(f"trace identity/count hard gate failed: {name}")
        record = compact(official, trace, mode == "ON", name, mode)
        printable = {k: v for k, v in record.items() if k != "_samples"}
        print(json.dumps(printable, separators=(",", ":")), flush=True)
        return record

    calibration = []
    for index, mode in enumerate(("OFF", "ON", "OFF", "ON"), 1):
        calibration.append(execute_run(f"cal-{index}-{mode.lower()}", mode))
    cal_verdict = calibration_verdict(calibration)
    cal_payload = {
        "sequence": ["OFF", "ON", "OFF", "ON"],
        "runs": [{k: v for k, v in r.items() if k != "_samples"} for r in calibration],
        "verdict": cal_verdict,
    }
    save_json("calibration", cal_payload)
    print(json.dumps({"calibration": cal_verdict}, separators=(",", ":")), flush=True)
    if not cal_verdict["accepted"]:
        save_json("verdict", {
            "status": "CALIBRATION_REJECTED",
            "warm_runs": 0,
            "final_classification": "D — INCONCLUSIVE",
            "source_hashes_final": p6.verify(root),
        })
        return 3

    warm = []
    for i in range(1, 81):
        record = execute_run(f"warm-{i:03d}", "ON")
        record.pop("_samples", None)
        warm.append(record)
        save_json("warm-progress", {"completed": i, "runs": warm})

    failures = [r for r in warm if float(r["p99"]) > 500.0]
    verdict = {
        "status": "CAPTURE_COMPLETE",
        "warm_runs": 80,
        "warm_failures": len(failures),
        "failure_run_names": [r["name"] for r in failures],
        "tail_reproduction": (
            "SUFFICIENT_GENUINE_WARM_FAILURES" if len(failures) >= 2
            else "INSUFFICIENT_TAIL_REPRODUCTION"
        ),
        "source_hashes_final": p6.verify(root),
    }
    save_json("verdict", verdict)
    save_json("warm-summary", {"runs": warm})
    print(json.dumps({"verdict": verdict}, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
