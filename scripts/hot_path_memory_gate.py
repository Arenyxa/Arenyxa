"""Large-file memory gate for Arenyxa streaming hot paths.

Default validates 100 MiB, 500 MiB and 1 GiB inputs.  Files are sparse-created where the
filesystem supports it, but every byte is read by sha256_file, so the measured memory bound is
representative without requiring a 1 GiB Python allocation.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arenyxa.infrastructure.streaming_io import sha256_file
MIB = 1024 * 1024


def _measure(size_bytes: int, directory: Path) -> dict[str, object]:
    path = directory / f"memory-{size_bytes}.bin"
    with path.open("wb") as stream:
        stream.truncate(size_bytes)
        stream.flush()
        os.fsync(stream.fileno())
    tracemalloc.start()
    started = time.perf_counter()
    digest = sha256_file(path)
    elapsed = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    path.unlink(missing_ok=True)
    return {
        "input_bytes": size_bytes,
        "input_mib": round(size_bytes / MIB, 1),
        "peak_python_bytes": peak,
        "peak_python_mib": round(peak / MIB, 3),
        "duration_seconds": round(elapsed, 3),
        "sha256": digest,
        "passed": peak <= 16 * MIB,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes-mib", default="100,500,1024")
    parser.add_argument("--report", type=Path, default=ROOT / "dist" / "audit" / "HOT_PATH_MEMORY_REPORT.json")
    args = parser.parse_args(argv)
    sizes = [int(part.strip()) for part in str(args.sizes_mib).split(",") if part.strip()]
    if not sizes or any(size <= 0 or size > 4096 for size in sizes):
        raise SystemExit("sizes must be between 1 MiB and 4096 MiB")
    report_path = args.report if args.report.is_absolute() else ROOT / args.report
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="arenyxa-memory-gate-") as raw:
        cases = [_measure(size * MIB, Path(raw)) for size in sizes]
    report = {
        "schema": "arenyxa.hot-path-memory-gate/v1",
        "algorithm": "streaming-sha256-o-chunk-memory",
        "limit_python_mib": 16,
        "cases": cases,
        "passed": all(bool(case["passed"]) for case in cases),
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
