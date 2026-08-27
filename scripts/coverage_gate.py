from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "coverage.json"
MIN_TOTAL = 35.0
MIN_BRANCH = 25.0


def main() -> int:
    if not REPORT.is_file():
        print("coverage gate: coverage.json is missing; run pytest --cov=src/arenyxa --cov-branch --cov-report=json")
        return 2
    payload = json.loads(REPORT.read_text(encoding="utf-8"))
    totals = payload.get("totals", {})
    total = float(totals.get("percent_covered", 0.0))
    branches = int(totals.get("num_branches", 0) or 0)
    covered_branches = int(totals.get("covered_branches", 0) or 0)
    branch_percent = (covered_branches / branches * 100.0) if branches else 100.0
    ok = total >= MIN_TOTAL and branch_percent >= MIN_BRANCH
    print(json.dumps({
        "ok": ok,
        "statement_and_branch_percent": round(total, 2),
        "branch_percent": round(branch_percent, 2),
        "minimum_total_percent": MIN_TOTAL,
        "minimum_branch_percent": MIN_BRANCH,
    }, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
