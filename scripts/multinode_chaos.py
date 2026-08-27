from __future__ import annotations

import argparse
import json
from pathlib import Path

from arenyxa.enterprise.external_chaos import ExternalChaosRunner, SSHCommandExecutor


def main() -> int:
    parser = argparse.ArgumentParser(description="Run explicitly configured Arenyxa multi-node chaos operations over SSH.")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("multinode-chaos-evidence.json"))
    parser.add_argument("--allow-disruptive-production-chaos", action="store_true")
    args = parser.parse_args()
    if not args.allow_disruptive_production_chaos:
        parser.error("--allow-disruptive-production-chaos is required")
    payload = json.loads(args.plan.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        parser.error("plan must be a JSON object")
    runner = ExternalChaosRunner(SSHCommandExecutor())
    evidence = runner.run(payload, allow_disruptive=True, progress=lambda text: print(text, flush=True))
    args.output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    print("evidence=" + str(args.output.resolve()))
    return 0 if all(item.get("status") == "passed" for item in evidence["scenarios"].values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
