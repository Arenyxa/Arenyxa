from __future__ import annotations

import argparse
import csv
import gzip
import json
import statistics
from pathlib import Path


def qn(values, q):
    vals = sorted(float(v) for v in values)
    if not vals:
        return None
    return vals[min(len(vals)-1, max(0, round((len(vals)-1)*q)))]


def dist(values):
    vals = [float(v) for v in values if v is not None]
    return {
        "count": len(vals),
        "mean": statistics.fmean(vals) if vals else None,
        "p50": qn(vals, .50), "p95": qn(vals, .95), "p99": qn(vals, .99),
        "p999": qn(vals, .999), "max": max(vals) if vals else None,
    }


def corr(rows, field):
    pairs = [(float(r["execute_ms"]), float(r[field])) for r in rows if r.get(field) is not None]
    if len(pairs) < 3:
        return None
    x, y = zip(*pairs)
    if statistics.pstdev(x) == 0 or statistics.pstdev(y) == 0:
        return None
    return statistics.correlation(x, y)


def one_lease_fast(row):
    sql = row.get("sql") or []
    return sum(1 for x in sql if x and x[0] == "lease_fast") == 1 and not any(x and x[0] == "other_business" for x in sql)


def flatten(run_no, run_p99, row):
    calls = row.get("phase7b_calls") or []
    if len(calls) != 1 or "summary" not in calls[0]:
        return None
    call = calls[0]; s = call["summary"]
    if not s.get("decomposition_valid"):
        return None
    task = row.get("task") or [None, None, None]
    slot = task[0]
    cycle_id = (
        f"P7B-R{run_no:03d}-S{int(slot):03d}-A{int(row.get('attempt',0)):03d}"
        if slot is not None else f"P7B-R{run_no:03d}-T{row.get('tid')}-A{row.get('attempt')}"
    )
    return {
        "run": run_no, "run_p99_ms": run_p99, "run_gate": "FAIL" if run_p99 > 500 else "PASS",
        "cycle_id": cycle_id, "client_id": row.get("client_id"), "worker": row.get("worker"),
        "job_id": row.get("job_id"), "tid": row.get("tid"), "attempt": row.get("attempt"),
        "backend_pid": call.get("backend_pid"), "lease_ms": row.get("lease_ms"),
        "execute_ms": s.get("execute_ms"), "pre_result_ms": s.get("pre_result_ms"),
        "post_result_ms": s.get("post_result_ms"), "pre_result_share": s.get("pre_result_share"),
        "post_result_share": s.get("post_result_share"), "segment_class": s.get("segment_class"),
        "send_count": s.get("send_count"), "health_probe_yes": bool(row.get("health_probe_yes")),
        "recovery_yes": bool(row.get("recovery_yes")), "lease_thread_cpu_ms": row.get("thread_cpu_ms"),
        "lease_thread_vcsw": row.get("thread_vcsw"), "lease_thread_ivcsw": row.get("thread_ivcsw"),
        "conservation_error_ms": s.get("conservation_error_ms"),
        "anomaly_count": len(call.get("anomalies") or []),
    }


def aggregate(rows):
    execute_sum = sum(float(r["execute_ms"]) for r in rows)
    pre_sum = sum(float(r["pre_result_ms"]) for r in rows)
    post_sum = sum(float(r["post_result_ms"]) for r in rows)
    return {
        "n": len(rows),
        "distinct_runs": len({r["run"] for r in rows}),
        "execute": dist(r["execute_ms"] for r in rows),
        "pre_result": dist(r["pre_result_ms"] for r in rows),
        "post_result": dist(r["post_result_ms"] for r in rows),
        "pre_result_share": dist(r["pre_result_share"] for r in rows),
        "post_result_share": dist(r["post_result_share"] for r in rows),
        "thread_cpu": dist(r["lease_thread_cpu_ms"] for r in rows),
        "thread_vcsw": dist(r["lease_thread_vcsw"] for r in rows),
        "thread_ivcsw": dist(r["lease_thread_ivcsw"] for r in rows),
        "sum_execute_ms": execute_sum, "sum_pre_result_ms": pre_sum, "sum_post_result_ms": post_sum,
        "aggregate_pre_result_share": pre_sum / execute_sum if execute_sum else None,
        "aggregate_post_result_share": post_sum / execute_sum if execute_sum else None,
        "health_probe_rate": sum(r["health_probe_yes"] for r in rows) / len(rows) if rows else None,
        "segment_counts": {k: sum(r["segment_class"] == k for r in rows) for k in sorted({r["segment_class"] for r in rows})},
    }


def write_csv(path, rows):
    if not rows:
        path.write_text("", encoding="utf-8"); return
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)


def directional_a(agg):
    return bool(agg["n"] and agg["aggregate_pre_result_share"] >= .90 and agg["aggregate_post_result_share"] <= .10)


def directional_b(agg):
    return bool(agg["n"] and agg["aggregate_post_result_share"] >= .90)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--dir", type=Path, required=True); args = ap.parse_args(); d = args.dir
    verdict_path = d / "verdict.json"
    if not verdict_path.exists():
        raise SystemExit("verdict.json missing")
    capture = json.loads(verdict_path.read_text())
    if capture.get("status") != "CAPTURE_COMPLETE":
        (d / "ANALYSIS_STATUS.json").write_text(json.dumps({"status":"NOT_ANALYZED","capture":capture}, indent=2), encoding="utf-8")
        return 0

    ordinary = []; recovery = []; runs = []
    for path in sorted(d.glob("warm-*.json.gz")):
        run_no = int(path.name.split("-")[1].split(".")[0])
        with gzip.open(path, "rt", encoding="utf-8") as f:
            payload = json.load(f)
        official = payload["official"]; trace = payload["trace"]
        run_p99 = float(official["latency_ms"]["p99"])
        runs.append({
            "run": run_no, "p50": official["latency_ms"]["p50"], "p95": official["latency_ms"]["p95"],
            "p99": run_p99, "max": official["latency_ms"]["max"],
            "throughput": official["throughput_jobs_per_second"],
            "lease_p99": official["latency_ms"]["phases"]["lease_next"]["p99"],
            "start_p99": official["latency_ms"]["phases"]["start_job"]["p99"],
            "complete_p99": official["latency_ms"]["phases"]["complete"]["p99"],
            "gate": "FAIL" if run_p99 > 500 else "PASS",
        })
        for row in trace["cycles"]:
            if not row.get("success") or not one_lease_fast(row):
                continue
            flat = flatten(run_no, run_p99, row)
            if flat is None:
                continue
            (recovery if row.get("recovery_yes") else ordinary).append(flat)

    write_csv(d / "PHASE7B_RUNS.csv", runs)
    write_csv(d / "PHASE7B_ORDINARY_ALL.csv", ordinary)
    write_csv(d / "PHASE7B_RECOVERY_CONTROL.csv", recovery)

    execute_values = [r["execute_ms"] for r in ordinary]
    q50, q99, q999 = qn(execute_values,.50), qn(execute_values,.99), qn(execute_values,.999)
    groups = {
        "FAST": [r for r in ordinary if r["execute_ms"] <= q50],
        "MID": [r for r in ordinary if q50 < r["execute_ms"] <= q99],
        "TOP1": [r for r in ordinary if r["execute_ms"] > q99],
        "TOP0.1": [r for r in ordinary if r["execute_ms"] > q999],
    }
    top100 = sorted(ordinary, key=lambda r:r["execute_ms"], reverse=True)[:100]
    fast100 = sorted(ordinary, key=lambda r:r["execute_ms"])[:100]
    write_csv(d / "PHASE7B_TOP100_SLOW.csv", top100); write_csv(d / "PHASE7B_FASTEST100.csv", fast100)
    write_csv(d / "PHASE7B_TOP1.csv", sorted(groups["TOP1"], key=lambda r:r["execute_ms"], reverse=True))
    write_csv(d / "PHASE7B_TOP0_1.csv", sorted(groups["TOP0.1"], key=lambda r:r["execute_ms"], reverse=True))

    passed = [r for r in ordinary if r["run_gate"] == "PASS"]
    failed = [r for r in ordinary if r["run_gate"] == "FAIL"]
    pass_top1 = [r for r in groups["TOP1"] if r["run_gate"] == "PASS"]
    fail_top1 = [r for r in groups["TOP1"] if r["run_gate"] == "FAIL"]
    health = [r for r in ordinary if r["health_probe_yes"]]; nohealth = [r for r in ordinary if not r["health_probe_yes"]]
    prepared = [r for r in ordinary if r["segment_class"] == "PREPARED_QUERY"]
    transition = [r for r in ordinary if r["segment_class"] == "PREPARE_PLUS_PREPARED_QUERY"]
    unprepared = [r for r in ordinary if r["segment_class"] == "UNPREPARED_QUERY"]
    prepared_top1 = [r for r in groups["TOP1"] if r["segment_class"] == "PREPARED_QUERY"]
    prepared_top01 = [r for r in groups["TOP0.1"] if r["segment_class"] == "PREPARED_QUERY"]

    controls = {
        "FAST_vs_TOP1": {"FAST":aggregate(groups["FAST"]), "TOP1":aggregate(groups["TOP1"])},
        "PASS_vs_FAIL": {"PASS":aggregate(passed), "FAIL":aggregate(failed)},
        "PASS_vs_FAIL_TOP1": {"PASS_TOP1":aggregate(pass_top1), "FAIL_TOP1":aggregate(fail_top1)},
        "HEALTH": {"PROBE":aggregate(health), "NO_PROBE":aggregate(nohealth)},
        "RECOVERY": {"ORDINARY":aggregate(ordinary), "RECOVERY":aggregate(recovery)},
        "PREPARED": {
            "PREPARED_QUERY":aggregate(prepared), "PREPARE_TRANSITION":aggregate(transition),
            "UNPREPARED_QUERY":aggregate(unprepared), "PREPARED_TOP1":aggregate(prepared_top1),
            "PREPARED_TOP0_1":aggregate(prepared_top01),
        },
    }
    (d / "PHASE7B_CONTROLS.json").write_text(json.dumps(controls, indent=2), encoding="utf-8")

    group_agg = {k: aggregate(v) for k,v in groups.items()}
    top1, top01 = group_agg["TOP1"], group_agg["TOP0.1"]
    prep_top1, prep_top01 = aggregate(prepared_top1), aggregate(prepared_top01)
    sufficient = capture.get("tail_reproduction") == "SUFFICIENT_GENUINE_WARM_FAILURES"
    if not sufficient:
        candidate = "D — INCONCLUSIVE (INSUFFICIENT TAIL REPRODUCTION)"
    elif directional_a(top1) and directional_a(top01) and directional_a(prep_top1) and directional_a(prep_top01):
        candidate = "A — PRE-FULL-PGRESULT DOMINANT CANDIDATE"
    elif directional_b(top1) and directional_b(top01) and directional_b(prep_top1) and directional_b(prep_top01):
        candidate = "B — POST-FULL-PGRESULT DOMINANT CANDIDATE"
    else:
        candidate = "C — MIXED/CONTRADICTORY CANDIDATE"

    errors = [abs(float(r["conservation_error_ms"])) for r in ordinary]
    summary = {
        "capture": capture,
        "current_host_only": True,
        "ordinary_n": len(ordinary), "recovery_control_n": len(recovery),
        "failure_runs": [r["run"] for r in runs if r["gate"] == "FAIL"],
        "thresholds_execute_ms": {"q50":q50,"q99":q99,"q999":q999},
        "groups": group_agg, "top100": aggregate(top100), "fastest100": aggregate(fast100),
        "controls": controls,
        "correlations_execute_vs": {
            "pre_result": corr(ordinary,"pre_result_ms"), "post_result":corr(ordinary,"post_result_ms"),
            "thread_cpu":corr(ordinary,"lease_thread_cpu_ms"), "vcsw":corr(ordinary,"lease_thread_vcsw"),
            "ivcsw":corr(ordinary,"lease_thread_ivcsw"),
        },
        "max_abs_conservation_error_ms": max(errors) if errors else None,
        "t2":"NOT DIRECTLY OBSERVABLE", "t3":"NOT DIRECTLY OBSERVABLE", "t4":"NOT DIRECTLY OBSERVABLE",
        "mechanical_initial_candidate_before_self_falsification": candidate,
    }
    (d / "PHASE7B_NUMERIC_SUMMARY.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (d / "ANALYSIS_STATUS.json").write_text(json.dumps({"status":"ANALYZED","candidate":candidate}, indent=2), encoding="utf-8")
    print(json.dumps({"analysis":"complete","ordinary":len(ordinary),"candidate":candidate,"failure_runs":summary["failure_runs"]}, separators=(",",":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
