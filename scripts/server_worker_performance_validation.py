from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from arenyxa.enterprise.server_worker_performance import WorkerSlotConcurrencyValidator


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Arenyxa Enterprise Worker-slot concurrency validation.")
    parser.add_argument("--jobs", type=int, default=192)
    parser.add_argument("--slots", default="1,2,4,8,16,32")
    parser.add_argument("--output", type=Path, default=Path("server-worker-performance-report.json"))
    args = parser.parse_args()
    levels = tuple(int(item.strip()) for item in args.slots.split(",") if item.strip())
    report = WorkerSlotConcurrencyValidator(jobs_per_level=args.jobs, slot_levels=levels).run().to_dict()
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["stable"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
