from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Gate:
    name: str
    command: tuple[str, ...]
    timeout: int = 180


def _run(gate: Gate) -> dict[str, object]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            list(gate.command), cwd=ROOT, text=True, encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=gate.timeout, check=False,
            env={**os.environ, "PYTHONUTF8": "1", "PYTHONPATH": str(ROOT / "src") + os.pathsep + os.environ.get("PYTHONPATH", "")},
        )
        output = completed.stdout[-12000:]
        return {
            "name": gate.name, "ok": completed.returncode == 0, "returncode": completed.returncode,
            "seconds": round(time.monotonic() - started, 3), "output": output,
        }
    except subprocess.TimeoutExpired as exc:
        raw = exc.stdout or ""
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace")
        return {
            "name": gate.name, "ok": False, "returncode": 124,
            "seconds": round(time.monotonic() - started, 3),
            "output": (raw + "\nTIMEOUT")[-12000:],
        }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _gates(python: str, *, full: bool, include_legacy: bool = False) -> list[Gate]:
    gates = [
        Gate("01_compileall", (python, "-m", "compileall", "-q", "src", "scripts")),
        Gate("02_static_quality", (python, "scripts/static_quality_gate.py"), 300),
        Gate("02a_strict_quality", (python, "scripts/strict_quality_gate.py")),
        Gate("02b_skip_policy", (python, "scripts/test_skip_policy_gate.py")),
        Gate("02c_report_assertion", (python, "scripts/report_assertion_gate.py")),
        Gate("03_canonical_namespace", (python, "scripts/arenyxa_namespace_gate.py")),
        Gate("04_architecture_debt", (python, "scripts/architecture_debt_gate.py")),
        Gate("06_api_contract", (python, "scripts/api_contract_gate.py")),
        Gate("07_quality_20d", (python, "scripts/quality_20d_gate.py"), 180),
        Gate("08_autopilot_validation", (python, "scripts/autopilot_production_validation.py", "--samples", "200"), 120),
        Gate("09_v81_release_identity", (python, "scripts/verify_v81_release_identity.py")),
        Gate("09a_runtime_diagnostic", (python, "scripts/runtime_diagnostic.py")),
        Gate("09b_production_config", (python, "scripts/production_config_gate.py")),
        Gate("09c_recovery_validation", (python, "scripts/final_recovery_validation.py"), 360),
        Gate("09d_performance_regression", (python, "scripts/performance_regression_gate.py")),
        Gate("10_phase12_static_security", (python, "scripts/phase12_static_security_scan.py")),
        Gate(
            "11_peak_performance_resilience",
            (python, "-m", "pytest", "-q", "tests/test_peak_performance_resilience_hardening.py"),
            240,
        ),
        Gate("12_startup_visual_freeze", (python, "scripts/verify_startup_visual_baseline.py")),
        Gate("13_welcome_window_contract", (python, "scripts/verify_welcome_window_contract.py")),
        Gate("14_main_window_import_contract", (python, "scripts/verify_main_window_import_contract.py")),
        Gate("15_page_runtime_contract", (python, "scripts/verify_page_runtime_contract.py")),
        Gate("16_ui_button_wiring", (python, "scripts/verify_ui_button_connections.py")),
        Gate("16b_root_persistence_contract", (python, "scripts/verify_root_persistence_contract.py")),
        Gate("16_phase1_architecture", (python, "scripts/phase1_gate.py"), 240),
        Gate("17_phase2_web_intelligence", (python, "scripts/phase2_gate.py"), 240),
        Gate("18_phase3_reliability", (python, "scripts/phase3_gate.py"), 240),
        Gate("19_phase4_security", (python, "scripts/phase4_gate.py"), 240),
        Gate("20_phase6_developer_trust", (python, "scripts/phase6_gate.py"), 240),
        Gate("21_phase7_enterprise_identity", (python, "scripts/phase7_gate.py"), 240),
        Gate("22_phase8_10_enterprise", (python, "scripts/phase8_10_gate.py"), 300),
        Gate("23_phase11_12_server_release", (python, "scripts/phase11_12_gate.py"), 300),
    ]
    if include_legacy:
        gates.insert(7, Gate("05_win7_frozen_quality", (python, "scripts/win7_legacy_quality_gate.py")))
    if full:
        gates.extend([
            Gate(
                "23_full_pytest_with_branch_coverage",
                (
                    python, "-m", "pytest", "-q", "--cov=src/arenyxa", "--cov-branch",
                    "--cov-report=json:coverage.json", "--cov-fail-under=0",
                ),
                1200,
            ),
            Gate("24_coverage_threshold", (python, "scripts/coverage_gate.py")),
        ])
    return gates


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Arenyxa final multi-dimensional quality gate.")
    parser.add_argument("--full", action="store_true", help="also run the complete pytest suite")
    parser.add_argument("--include-legacy", action="store_true", help="also run the frozen Windows 7 compatibility lane")
    parser.add_argument("--report", type=Path, default=ROOT / "FINAL_QUALITY_GATE.json")
    args = parser.parse_args(argv)

    results: list[dict[str, object]] = []
    for gate in _gates(sys.executable, full=args.full, include_legacy=args.include_legacy):
        print(f"\n=== {gate.name} ===", flush=True)
        result = _run(gate)
        results.append(result)
        print(result["output"], flush=True)
        print("PASS" if result["ok"] else "FAIL", flush=True)
        if not result["ok"]:
            break

    startup_files = [
        ROOT / "src/arenyxa/presentation/startup_splash.py",
        ROOT / "src/arenyxa/presentation/startup_motion_math.py",
    ]
    report = {
        "schema": "arenyxa.final-quality-gate/v2",
        "python": sys.version,
        "full": bool(args.full),
        "include_legacy": bool(args.include_legacy),
        "passed": all(bool(item["ok"]) for item in results) and len(results) == len(_gates(sys.executable, full=args.full, include_legacy=args.include_legacy)),
        "dimensions_completed": len(results),
        "dimensions_expected": len(_gates(sys.executable, full=args.full, include_legacy=args.include_legacy)),
        "startup_sha256": {str(path.relative_to(ROOT)): _sha256(path) for path in startup_files},
        "results": results,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nReport: {args.report}")
    print("FINAL QUALITY GATE: PASS" if report["passed"] else "FINAL QUALITY GATE: FAIL")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
