from __future__ import annotations

import argparse
import json
from pathlib import Path

from arenyxa.enterprise.production_validation import ProductionValidationSuite


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Arenyxa isolated production/chaos validation gates.")
    parser.add_argument("--soak-jobs", type=int, default=256, help="bounded local durable-queue soak jobs (32..10000)")
    parser.add_argument("--multi-node-evidence", type=Path, default=None, help="optional real Server+2 Worker evidence JSON")
    parser.add_argument("--output", type=Path, default=Path("production-validation-report.json"), help="JSON report destination")
    args = parser.parse_args()

    def progress(message: str) -> None:
        print("[production-validation] " + message, flush=True)

    report = ProductionValidationSuite(args.soak_jobs).run(args.multi_node_evidence, progress)
    payload = report.to_dict()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    print("report=" + str(args.output.resolve()))
                                                                                                  
                                                                                                    
                                     
    if not report.local_gate_passed:
        return 2
    if args.multi_node_evidence is not None and not report.production_evidence_complete:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
