from __future__ import annotations

import argparse
import json
from pathlib import Path

from arenyxa.application.autopilot_validation import AutopilotProductionValidator


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Arenyxa local Autopilot learning stability boundaries")
    parser.add_argument("--samples", type=int, default=200)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    report = AutopilotProductionValidator(args.samples).run()
    payload = report.to_dict()
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    print(text)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text + "\n", encoding="utf-8")
    return 0 if report.stable else 1


if __name__ == "__main__":
    raise SystemExit(main())
