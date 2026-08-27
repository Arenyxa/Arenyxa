from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arenyxa.enterprise.server_performance import ServerConcurrencyValidator


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Arenyxa bounded server concurrency and thread-safety validation.")
    parser.add_argument("--jobs", type=int, default=192)
    parser.add_argument("--workers", default="1,2,4,8,16,32")
    parser.add_argument("--output", type=Path, default=Path("server-performance-report.json"))
    args = parser.parse_args()
    levels = [int(item.strip()) for item in args.workers.split(",") if item.strip()]
    report = ServerConcurrencyValidator(jobs_per_level=args.jobs, worker_levels=levels).run()
    payload = report.to_dict()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if report.stable else 2


if __name__ == "__main__":
    raise SystemExit(main())
