"""Dependency integrity, CVE and SBOM release gate."""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.metadata as metadata
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from arenyxa.infrastructure.streaming_io import sha256_file

ROOT = Path(__file__).resolve().parents[1]


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)


def _verify_installed_record_hashes() -> dict[str, Any]:
    verified = 0
    unhashed = 0
    failures: list[dict[str, str]] = []
    distributions = 0
    for distribution in metadata.distributions():
        name = (distribution.metadata.get("Name") or "").casefold()
        if name == "arenyxa":
            continue
        record = distribution.read_text("RECORD")
        if not record:
            continue
        distributions += 1
        for row in csv.reader(record.splitlines()):
            if len(row) < 2 or not row[1]:
                unhashed += 1
                continue
            algorithm, separator, encoded = row[1].partition("=")
            if not separator or algorithm != "sha256":
                unhashed += 1
                continue
            target = distribution.locate_file(row[0])
            if not target.is_file():
                failures.append({"distribution": name, "path": row[0], "error": "missing"})
                continue
            digest = bytes.fromhex(sha256_file(target))
            actual = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
            if actual != encoded:
                failures.append({"distribution": name, "path": row[0], "error": "sha256-mismatch"})
            else:
                verified += 1
    return {
        "distributions_with_record": distributions,
        "verified_files": verified,
        "unhashed_record_rows": unhashed,
        "failures": failures[:200],
        "passed": not failures and verified > 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist" / "security")
    parser.add_argument("--skip-audit", action="store_true")
    args = parser.parse_args(argv)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    checks: dict[str, Any] = {}
    pip_check = _run([sys.executable, "-m", "pip", "check"])
    checks["pip_check"] = {"returncode": pip_check.returncode, "output": (pip_check.stdout + pip_check.stderr)[-8000:]}

    record_check = _verify_installed_record_hashes()
    checks["installed_record_hashes"] = record_check

    audit_ok = True
    if not args.skip_audit:
        audit_path = args.output_dir / "pip-audit.json"
        audit = _run([sys.executable, "-m", "pip_audit", "--format", "json", "--output", str(audit_path)])
        checks["pip_audit"] = {"returncode": audit.returncode, "output": (audit.stdout + audit.stderr)[-8000:], "report": str(audit_path)}
        # Failing on every known vulnerable dependency is stricter than failing only Critical CVEs.
        audit_ok = audit.returncode == 0

    sbom_path = args.output_dir / "SBOM.cdx.json"
    sbom = _run([sys.executable, "-m", "cyclonedx_py", "environment", "--of", "JSON", "-o", str(sbom_path)])
    checks["sbom"] = {"returncode": sbom.returncode, "output": (sbom.stdout + sbom.stderr)[-8000:], "path": str(sbom_path)}

    passed = pip_check.returncode == 0 and record_check["passed"] and audit_ok and sbom.returncode == 0 and sbom_path.is_file()
    report = {
        "schema": "arenyxa.dependency-security-gate/v1",
        "policy": "Any known pip-audit vulnerability fails CI; this is stricter than Critical-only failure.",
        "checks": checks,
        "passed": passed,
    }
    report_path = args.output_dir / "DEPENDENCY_SECURITY_REPORT.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
