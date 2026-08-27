"""Aggregate release-critical Arenyxa v8.1 gates without placeholder success states."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

GATES = (
    ("release_identity", "scripts/verify_v81_release_identity.py", 120),
    ("runtime_diagnostic", "scripts/runtime_diagnostic.py", 120),
    ("production_config", "scripts/production_config_gate.py", 120),
    ("recovery", "scripts/final_recovery_validation.py", 360),
    ("performance", "scripts/performance_regression_gate.py", 120),
    ("security", "scripts/phase12_static_security_scan.py", 180),
    ("architecture", "scripts/architecture_debt_gate.py", 180),
    ("api_contract", "scripts/api_contract_gate.py", 180),
    ("cli_contract", "scripts/verify_cli_contract.py", 180),
    ("fuzz_smoke", "scripts/fuzz_smoke_gate.py", 300),
    ("skip_policy", "scripts/test_skip_policy_gate.py", 180),
)


def main() -> int:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONUTF8"] = "1"
    results: list[dict[str, object]] = []
    for name, script, timeout in GATES:
        started = time.monotonic()
        try:
            completed = subprocess.run(
                [sys.executable, script], cwd=ROOT, env=env, check=False,
                text=True, encoding="utf-8", errors="replace",
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
            )
            result = {
                "name": name,
                "ok": completed.returncode == 0,
                "returncode": completed.returncode,
                "seconds": round(time.monotonic() - started, 3),
                "output_tail": completed.stdout[-6000:],
            }
        except subprocess.TimeoutExpired as exc:
            output = exc.stdout or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", "replace")
            result = {
                "name": name, "ok": False, "returncode": 124,
                "seconds": round(time.monotonic() - started, 3),
                "output_tail": (output + "\nTIMEOUT")[-6000:],
            }
        results.append(result)
        if not result["ok"]:
            break

    release_ready = len(results) == len(GATES) and all(bool(item["ok"]) for item in results)
    payload = {
        "schema": "arenyxa.enterprise-release-gate/v2",
        "version": "8.1",
        "release_ready": release_ready,
        "checks_completed": len(results),
        "checks_expected": len(GATES),
        "checks": results,
        "production_evidence_note": (
            "This gate validates the local release candidate. Multi-node production certification "
            "still requires an explicit evidence file through production_release_gate.py."
        ),
    }
    report = ROOT / "ENTERPRISE_RELEASE_GATE.json"
    report.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if release_ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
