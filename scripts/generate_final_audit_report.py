"""Generate a fact-based final enterprise audit report from executed gate artifacts."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _read(name: str) -> dict[str, Any] | None:
    path = ROOT / name
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _status(report: dict[str, Any] | None, keys: tuple[str, ...]) -> str:
    if report is None:
        return "not-run"
    for key in keys:
        if key in report:
            value = report[key]
            if value is True:
                return "passed"
            if value is False:
                return "failed"
    return "observed"


def main() -> int:
    enterprise = _read("ENTERPRISE_RELEASE_GATE.json")
    quality = _read("FINAL_QUALITY_GATE.json")
    performance = _read("PERFORMANCE_REGRESSION_GATE.json")
    recovery = _read("FINAL_RECOVERY_VALIDATION.json")
    production_config = _read("PRODUCTION_CONFIG_GATE.json")
    production = _read("production-validation-report.json")

    dimensions = {
        "architecture": _status(enterprise, ("release_ready",)),
        "security": _status(enterprise, ("release_ready",)),
        "performance": _status(performance, ("healthy",)),
        "stability": _status(recovery, ("passed",)),
        "testing": _status(quality, ("passed",)),
        "ci_cd": _status(quality, ("passed",)),
        "data_reliability": _status(recovery, ("passed",)),
        "maintainability": _status(quality, ("passed",)),
        "enterprise_deployment": _status(production_config, ("passed",)),
        "release_quality": _status(enterprise, ("release_ready",)),
    }
    local_ready = enterprise is not None and enterprise.get("release_ready") is True
    production_evidence_complete = bool(production and production.get("production_evidence_complete") is True)
    payload = {
        "schema": "arenyxa.final-enterprise-audit/v2",
        "version": "8.1.1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "local_release_candidate_ready": local_ready,
        "production_evidence_complete": production_evidence_complete,
        "production_certified": bool(local_ready and production_evidence_complete),
        "dimensions": dimensions,
        "evidence": {
            "enterprise_release_gate": enterprise,
            "final_quality_gate": quality,
            "performance_regression_gate": performance,
            "final_recovery_validation": recovery,
            "production_config_gate": production_config,
        },
    }
    destination = ROOT / "FINAL_ENTERPRISE_AUDIT_REPORT.json"
    destination.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if local_ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
