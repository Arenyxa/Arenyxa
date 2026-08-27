"""Run independent quality gates concurrently and always emit FINAL_GATE_REPORT."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _gate_specs(include_dependency_security: bool) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = [
        {"id": "static-quality", "group": "static", "command": [sys.executable, "scripts/static_quality_gate.py"]},
        {"id": "workflow-contract", "group": "static", "command": [sys.executable, "scripts/workflow_contract_gate.py"]},
        {"id": "architecture-debt", "group": "static", "command": [sys.executable, "scripts/architecture_debt_gate.py"]},
        {"id": "unit-regression", "group": "unit", "command": [sys.executable, "-m", "pytest", "-q", "--disable-warnings", "--maxfail=0"]},
        {"id": "compatibility-shadow", "group": "integration", "command": [sys.executable, "-m", "pytest", "-q", "tests/test_shadow_compatibility.py"]},
        {"id": "phase0-integrity", "group": "integration", "command": [sys.executable, "scripts/phase0_gate.py", "--skip-pytest", "--skip-static"]},
        {"id": "publication", "group": "release", "command": [sys.executable, "scripts/github_publication_gate.py", "--allow-local-artifacts"]},
        {"id": "v8-acceptance", "group": "release", "command": [sys.executable, "scripts/v8_acceptance_gate.py"]},
    ]
    if include_dependency_security:
        specs.append({"id": "dependency-security", "group": "release", "command": [sys.executable, "scripts/dependency_security_gate.py"]})
    return specs


def _run(spec: dict[str, Any], log_dir: Path) -> dict[str, Any]:
    started = time.perf_counter()
    env = os.environ.copy()
    env.setdefault("PYTHONUTF8", "1")
    completed = subprocess.run(
        spec["command"], cwd=ROOT, env=env, text=True, capture_output=True, check=False
    )
    duration = time.perf_counter() - started
    log_path = log_dir / f"{spec['id']}.log"
    log_path.write_text(
        "$ " + " ".join(spec["command"]) + "\n\nSTDOUT\n" + completed.stdout + "\nSTDERR\n" + completed.stderr,
        encoding="utf-8",
    )
    return {
        "id": spec["id"],
        "group": spec["group"],
        "returncode": completed.returncode,
        "duration_seconds": round(duration, 3),
        "log": str(log_path.relative_to(ROOT)),
        "passed": completed.returncode == 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--include-dependency-security", action="store_true")
    parser.add_argument("--report", type=Path, default=ROOT / "dist" / "audit" / "FINAL_GATE_REPORT.json")
    args = parser.parse_args(argv)
    report_path = args.report if args.report.is_absolute() else ROOT / args.report
    report_path.parent.mkdir(parents=True, exist_ok=True)
    log_dir = report_path.parent / "parallel-gate-logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    specs = _gate_specs(args.include_dependency_security)
    results: list[dict[str, Any]] = []
    started = time.perf_counter()
    # All listed gates are independent source/read-only validations. Failures are collected,
    # never used to cancel sibling gates.
    with ThreadPoolExecutor(max_workers=max(1, min(8, int(args.max_workers)))) as executor:
        futures = {executor.submit(_run, spec, log_dir): spec for spec in specs}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                spec = futures[future]
                results.append({
                    "id": spec["id"], "group": spec["group"], "returncode": -1,
                    "duration_seconds": 0.0, "log": "", "passed": False,
                    "runner_error": f"{type(exc).__name__}: {exc}",
                })
    results.sort(key=lambda row: (row["group"], row["id"]))
    report = {
        "schema": "arenyxa.final-gate-report/v1",
        "execution_model": "parallel-independent-no-fail-fast",
        "duration_seconds": round(time.perf_counter() - started, 3),
        "groups": {
            group: {
                "passed": all(row["passed"] for row in results if row["group"] == group),
                "gates": [row["id"] for row in results if row["group"] == group],
            }
            for group in ("static", "unit", "integration", "release")
        },
        "results": results,
        "passed": all(row["passed"] for row in results),
    }
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
