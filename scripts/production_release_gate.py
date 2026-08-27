from __future__ import annotations

import argparse
import json
from pathlib import Path

from arenyxa.enterprise.production_validation import ProductionValidationSuite


def main() -> int:
    parser = argparse.ArgumentParser(description="Arenyxa production release gate with mandatory external evidence.")
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--report", type=Path, default=Path("PRODUCTION_RELEASE_GATE.json"))
    parser.add_argument("--local-soak-jobs", type=int, default=512)
    args = parser.parse_args()
    if not args.evidence.is_file():
        parser.error("--evidence must reference a real multi-node evidence file")
    report = ProductionValidationSuite(soak_jobs=args.local_soak_jobs).run(args.evidence)
    payload = report.to_dict()
    args.report.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({
        "production_ready": payload["production_ready"],
        "local_gate_passed": payload["local_gate_passed"],
        "external_evidence": payload["external_evidence"],
        "report": str(args.report.resolve()),
    }, ensure_ascii=False, indent=2))
    return 0 if payload["production_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
