"""Validate retained performance evidence and block known tail-latency/invariant regressions."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPORTS = {
    "server": ROOT / "server-performance-report-final20.json",
    "worker": ROOT / "server-worker-performance-report-final20.json",
    "http": ROOT / "server-http-performance-report-final20.json",
}
P99_LIMIT_MS = {"server": 500.0, "worker": 500.0, "http": 500.0}


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def _p99(row: dict[str, Any]) -> float:
    for key in ("execute_p99_ms", "p99_ms"):
        if key in row:
            return float(row[key])
    return float("inf")


def main() -> int:
    checks: list[dict[str, Any]] = []
    failures: list[str] = []
    for name, path in REPORTS.items():
        if not path.is_file():
            failures.append(f"missing retained performance report: {path.name}")
            continue
        try:
            report = _load(path)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            failures.append(f"{path.name}: {type(exc).__name__}: {exc}")
            continue
        levels = report.get("levels")
        if not isinstance(levels, list) or not levels:
            failures.append(f"{path.name}: levels are missing")
            continue
        report_failures: list[str] = []
        if report.get("stable") is not True:
            report_failures.append("report stable != true")
        max_p99 = 0.0
        peak = 0.0
        for index, raw in enumerate(levels):
            if not isinstance(raw, dict):
                report_failures.append(f"level[{index}] is not an object")
                continue
            errors = int(raw.get("errors", 0) or 0)
            if errors:
                report_failures.append(f"level[{index}] errors={errors}")
            if raw.get("stable") is not True:
                report_failures.append(f"level[{index}] stable != true")
            invariants = raw.get("invariants") or {}
            if isinstance(invariants, dict):
                dirty = {key: value for key, value in invariants.items() if value not in (0, 0.0, None, False)}
                if dirty:
                    report_failures.append(f"level[{index}] invariant failures={dirty}")
            p99 = _p99(raw)
            max_p99 = max(max_p99, p99)
            for throughput_key in (
                "execute_ops_per_second", "throughput_jobs_per_second", "throughput_requests_per_second"
            ):
                if throughput_key in raw:
                    peak = max(peak, float(raw[throughput_key]))
        if max_p99 > P99_LIMIT_MS[name]:
            report_failures.append(f"max p99 {max_p99:.3f}ms exceeds {P99_LIMIT_MS[name]:.1f}ms")
        if peak <= 0:
            report_failures.append("no positive throughput observation")
        if report_failures:
            failures.extend(f"{path.name}: {item}" for item in report_failures)
        checks.append({
            "report": path.name,
            "stable": not report_failures,
            "levels": len(levels),
            "max_p99_ms": round(max_p99, 3),
            "peak_observed_throughput": round(peak, 3),
        })

    payload = {
        "schema": "arenyxa.performance-regression-gate/v2",
        "healthy": not failures,
        "checked_reports": len(checks),
        "checks": checks,
        "failures": failures,
    }
    (ROOT / "PERFORMANCE_REGRESSION_GATE.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
