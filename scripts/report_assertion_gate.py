from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPORT_GLOBS = (
    "*.json",
    "dist/audit/*.json",
)


def _numeric_failure(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


def _scan(value: Any, path: str, failures: list[str]) -> None:
    if isinstance(value, list):
        for index, item in enumerate(value):
            _scan(item, f"{path}[{index}]", failures)
        return
    if not isinstance(value, dict):
        return

    # Only interpret keys with established gate/report semantics. This avoids treating
    # ordinary business data named "status" or "errors" as a release failure.
    for key in ("errors", "failed", "failures_count", "failure_count"):
        if key in value and _numeric_failure(value[key]):
            failures.append(f"{path}.{key}={value[key]}")
    if "stable" in value and value["stable"] is False:
        failures.append(f"{path}.stable=false")
    if "healthy" in value and value["healthy"] is False:
        failures.append(f"{path}.healthy=false")
    if "release_ready" in value and value["release_ready"] is False:
        failures.append(f"{path}.release_ready=false")
    if "local_gate_passed" in value and value["local_gate_passed"] is False:
        failures.append(f"{path}.local_gate_passed=false")
    if "passed" in value and value["passed"] is False and any(
        marker in path.casefold() for marker in ("gate", "validation", "audit")
    ):
        failures.append(f"{path}.passed=false")
    if value.get("status") in {"failed", "failure", "error", "rejected"}:
        failures.append(f"{path}.status={value.get('status')}")

    invariants = value.get("invariants")
    if isinstance(invariants, dict):
        for key, item in invariants.items():
            if item not in (0, 0.0, None, False):
                failures.append(f"{path}.invariants.{key}={item!r}")

    # production_ready=false is expected when real multi-node evidence was not supplied.
    # It becomes a failure only when evidence was explicitly provided and still invalid.
    if value.get("production_ready") is False:
        evidence = value.get("external_evidence")
        if isinstance(evidence, dict) and evidence.get("provided") is True:
            failures.append(f"{path}.production_ready=false with supplied external evidence")

    for key, item in value.items():
        if key == "invariants":
            continue
        _scan(item, f"{path}.{key}", failures)


def main() -> int:
    reports: list[Path] = []
    for pattern in REPORT_GLOBS:
        reports.extend(path for path in ROOT.glob(pattern) if path.is_file())
    reports = sorted(set(reports))
    failures: list[str] = []
    parsed = 0
    for path in reports:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        parsed += 1
        _scan(data, path.relative_to(ROOT).as_posix(), failures)

    payload = {
        "schema": "arenyxa.report-assertion-gate/v2",
        "passed": not failures,
        "parsed_reports": parsed,
        "failures": failures,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
