from __future__ import annotations

import statistics
from typing import Iterable


def is_target_row(row: dict) -> bool:
    sql = row.get("sql") or []
    lease_fast = sum(1 for item in sql if item and item[0] == "lease_fast")
    fallback = any(item and item[0] == "other_business" for item in sql)
    return (
        bool(row.get("success"))
        and not bool(row.get("recovery_yes"))
        and lease_fast == 1
        and not fallback
    )


def _quantile_nearest(values: Iterable[float], q: float) -> float | None:
    vals = sorted(float(v) for v in values)
    if not vals:
        return None
    return vals[min(len(vals) - 1, max(0, round((len(vals) - 1) * q)))]


def _distribution(values: Iterable[float]) -> dict:
    vals = [float(v) for v in values]
    return {
        "count": len(vals),
        "p99": _quantile_nearest(vals, .99),
        "p999": _quantile_nearest(vals, .999),
    }


def _med_ratio(on: list[dict], off: list[dict], key: str) -> float | None:
    a = statistics.median(float(x[key]) for x in on)
    b = statistics.median(float(x[key]) for x in off)
    return a / b if b else None


def _pooled(records: list[dict], sample_key: str) -> dict:
    vals: list[float] = []
    for record in records:
        vals.extend(float(v) for v in record["_samples"].get(sample_key, []))
    return _distribution(vals)


def calibration_verdict(records: list[dict]) -> dict:
    if [r.get("mode") for r in records] != ["OFF", "ON", "OFF", "ON"]:
        raise ValueError("calibration sequence must be OFF→ON→OFF→ON")
    off = [r for r in records if r["mode"] == "OFF"]
    on = [r for r in records if r["mode"] == "ON"]
    ratios = {k: _med_ratio(on, off, k) for k in ("p50", "p95", "p99", "throughput")}
    off_lease, on_lease = _pooled(off, "lease"), _pooled(on, "lease")
    off_exec, on_exec = _pooled(off, "execute"), _pooled(on, "execute")

    def ratio(a, b):
        return (a / b) if a is not None and b not in (None, 0) else None

    tail = {
        "cycle_p999_ratio": _med_ratio(on, off, "p999"),
        "ordinary_lease_p99_ratio": ratio(on_lease["p99"], off_lease["p99"]),
        "ordinary_lease_p999_ratio": ratio(on_lease["p999"], off_lease["p999"]),
        "execute_p99_ratio": ratio(on_exec["p99"], off_exec["p99"]),
        "execute_p999_ratio": ratio(on_exec["p999"], off_exec["p999"]),
    }
    recovery_delta = abs(
        statistics.mean(float(x["recovery_calls"]) for x in on)
        - statistics.mean(float(x["recovery_calls"]) for x in off)
    )
    coverage_ok = all(
        x["trace_metrics"].get("phase7b_missing", 1) == 0
        and x["trace_metrics"].get("phase7b_invalid", 1) == 0
        for x in on
    )
    conservation_ok = all(
        float(x["trace_metrics"].get("max_abs_conservation_error_ms") or 0.0) <= 1e-5
        for x in on
    )
    primary_ok = (
        all(ratios[k] is not None for k in ("p50", "p95", "p99", "throughput"))
        and max(float(ratios[k]) for k in ("p50", "p95", "p99")) <= 1.10
        and float(ratios["throughput"]) >= 0.95
        and recovery_delta <= 6.0
    )
    tail_ok = all(v is not None and 0.80 <= float(v) <= 1.20 for v in tail.values())
    return {
        "accepted": bool(primary_ok and tail_ok and coverage_ok and conservation_ok),
        "primary_ratios": ratios,
        "tail_ratios": tail,
        "recovery_calls_absolute_delta": recovery_delta,
        "coverage_ok": coverage_ok,
        "conservation_ok": conservation_ok,
        "off_pooled": {"ordinary_lease": off_lease, "execute": off_exec},
        "on_pooled": {"ordinary_lease": on_lease, "execute": on_exec},
        "limits": {
            "latency_ratio_max": 1.10,
            "throughput_ratio_min": 0.95,
            "recovery_call_delta_max": 6,
            "tail_two_sided_ratio_range": [0.80, 1.20],
            "conservation_error_abs_ms_max": 1e-5,
        },
    }
