from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arenyxa.enterprise.server_http_performance import ServerHTTPConcurrencyValidator


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Arenyxa Enterprise HTTP/TLS server concurrency on loopback.")
    parser.add_argument("--requests", type=int, default=80)
    parser.add_argument("--clients", default="1,4,8,16,32")
    parser.add_argument("--output", type=Path, default=Path("server-http-performance-report.json"))
    args = parser.parse_args()
    levels = tuple(int(item.strip()) for item in args.clients.split(",") if item.strip())
    report = ServerHTTPConcurrencyValidator(requests_per_level=args.requests, client_levels=levels).run().to_dict()
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["stable"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
