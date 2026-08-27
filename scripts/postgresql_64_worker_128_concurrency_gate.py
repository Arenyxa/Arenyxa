"""Release gate for the v8 PostgreSQL connection-pool storm scenario."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from postgresql_32_worker_gate import run_gate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Arenyxa PostgreSQL 64-worker / 128-concurrency pool gate")
    parser.add_argument("--dsn", default=os.environ.get("ARENYXA_POSTGRES_TEST_DSN", ""))
    parser.add_argument("--jobs", type=int, default=1024)
    parser.add_argument("--p99-ms", type=float, default=float(os.environ.get("ARENYXA_POSTGRES_64W_128C_P99_MS", "500")))
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    if not str(args.dsn).strip():
        parser.error("--dsn or ARENYXA_POSTGRES_TEST_DSN is required")
    result = run_gate(
        str(args.dsn),
        workers=64,
        concurrency=128,
        jobs=max(256, int(args.jobs)),
        p99_budget_ms=max(1.0, float(args.p99_ms)),
    )
    encoded = json.dumps(result, ensure_ascii=False, sort_keys=True)
    print(encoded)
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return 0 if bool(result.get("passed")) else 2


if __name__ == "__main__":
    raise SystemExit(main())
