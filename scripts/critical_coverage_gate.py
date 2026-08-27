from __future__ import annotations

"""Release-blocking coverage thresholds for stateful/concurrent P0/P1 modules."""

import json
import sys
from pathlib import Path

THRESHOLDS = {
    "src/arenyxa/application/async_runner.py": 50.0,
    "src/arenyxa/application/headless_developer_access.py": 50.0,
    "src/arenyxa/enterprise/distributed_queue.py": 55.0,
    "src/arenyxa/infrastructure/capture/tcp_reassembly.py": 70.0,
    "src/arenyxa/infrastructure/external_tools.py": 70.0,
}
MIN_AGGREGATE = 58.0


def main(path: str = "coverage.json") -> int:
    report_path = Path(path)
    if not report_path.is_file():
        raise SystemExit(f"critical coverage report missing: {report_path}")
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    files = payload.get("files", {})
    failures: list[str] = []
    for name, threshold in THRESHOLDS.items():
        row = files.get(name)
        if not isinstance(row, dict):
            failures.append(f"{name}=missing")
            continue
        summary = row.get("summary", {})
        value = float(summary.get("percent_covered", 0.0))
        if value + 1e-9 < threshold:
            failures.append(f"{name}={value:.1f}<{threshold:.1f}")
    total = float(payload.get("totals", {}).get("percent_covered", 0.0))
    if total + 1e-9 < MIN_AGGREGATE:
        failures.append(f"critical-aggregate={total:.1f}<{MIN_AGGREGATE:.1f}")
    if failures:
        raise SystemExit("critical coverage gate failed: " + ", ".join(failures))
    print(f"critical coverage gate: PASS · aggregate={total:.1f}% · modules={len(THRESHOLDS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "coverage.json"))
