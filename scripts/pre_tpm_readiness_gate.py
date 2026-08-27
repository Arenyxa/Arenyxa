from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from arenyxa.enterprise.production_validation import validate_multi_node_evidence
from arenyxa.infrastructure.process_safety import validated_argv

ROOT = Path(__file__).resolve().parents[1]


def _json_file(path: Path, label: str) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError(f"{label} exceeds 4 MiB")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _run(command: list[str], timeout: int = 300) -> tuple[bool, str]:
    completed = subprocess.run(
        validated_argv(command), cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False,
    )
    return completed.returncode == 0, completed.stdout[-12000:]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Hard prerequisite gate that must pass before Arenyxa Root TPM migration work may begin."
    )
    parser.add_argument("--production-evidence", type=Path, required=True)
    parser.add_argument("--postgres-32w-report", type=Path, required=True)
    parser.add_argument("--report", type=Path, default=ROOT / "PRE_TPM_READINESS_GATE.json")
    args = parser.parse_args()

    checks: list[dict[str, Any]] = []
    evidence = validate_multi_node_evidence(args.production_evidence)
    checks.append({"name": "external-production-chaos-and-soak", "ok": bool(evidence.get("valid")), "detail": evidence})

    pg = _json_file(args.postgres_32w_report, "PostgreSQL 32-worker report")
    pg_latency = pg.get("latency_ms") if isinstance(pg.get("latency_ms"), dict) else {}
    pg_storage = pg.get("storage") if isinstance(pg.get("storage"), dict) else {}
    pg_ok = (
        pg.get("schema") == "arenyxa.postgresql-32-worker-gate/v1"
        and bool(pg.get("passed"))
        and int(pg.get("workers") or 0) >= 32
        and int(pg.get("completed") or 0) == int(pg.get("jobs") or -1)
        and not list(pg.get("errors") or [])
        and str(pg_storage.get("backend") or "").casefold() == "postgresql"
        and int(pg.get("independent_clients") or 0) >= 2
        and bool((pg.get("fencing_probe") or {}).get("passed"))
        and all(int((pg.get("state_invariants") or {}).get(key, 1)) == 0 for key in (
            "inconsistent_lease_rows", "unreceipted_completed_jobs", "implausible_future_leases"
        ))
        and int(pg.get("active_leases_after") or 0) == 0
        and float(pg_latency.get("p99") or 1e30) <= float(pg_latency.get("budget_p99") or 0.0)
    )
    checks.append({"name": "postgresql-32-worker-tail-latency", "ok": pg_ok, "detail": pg})

    commands = (
        ("architecture-debt", [sys.executable, "scripts/architecture_debt_gate.py"]),
        ("professional-quality", [sys.executable, "scripts/quality_20d_gate.py"]),
        ("static-ruff-mypy", [sys.executable, "scripts/static_quality_gate.py"]),
        ("network-extreme", [sys.executable, "-m", "pytest", "-q", "tests/test_v71_network_extreme_protocols.py"]),
        ("distributed-tracing", [sys.executable, "-m", "pytest", "-q", "tests/test_v71_distributed_trace_context.py"]),
        ("external-chaos-contract", [sys.executable, "-m", "pytest", "-q", "tests/test_v71_external_multinode_chaos.py"]),
    )
    for name, command in commands:
        ok, output = _run(command)
        checks.append({"name": name, "ok": ok, "output": output})
        if not ok:
            break

    passed = len(checks) == 2 + len(commands) and all(bool(item["ok"]) for item in checks)
    report = {
        "schema": "arenyxa.pre-tpm-readiness/v1",
        "passed": passed,
        "tpm_root_work_authorized": passed,
        "checks": checks,
    }
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"passed": passed, "tpm_root_work_authorized": passed, "report": str(args.report.resolve())}, indent=2))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
