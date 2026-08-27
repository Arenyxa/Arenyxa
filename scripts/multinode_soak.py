from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from arenyxa.enterprise.external_chaos import SSHCommandExecutor, parse_chaos_plan
from arenyxa.enterprise.external_soak import ExternalSoakRunner
from arenyxa.enterprise.production_validation import MULTI_NODE_EVIDENCE_SCHEMA


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect >=24h real multi-node Arenyxa production soak evidence.")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--chaos-evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("multinode-production-evidence.json"))
    parser.add_argument("--duration-hours", type=float, default=24.0)
    parser.add_argument("--sample-interval-seconds", type=float, default=60.0)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    evidence = json.loads(args.chaos_evidence.read_text(encoding="utf-8"))
    if not isinstance(plan, dict) or not isinstance(evidence, dict):
        parser.error("plan and chaos evidence must be JSON objects")
    if evidence.get("schema") != MULTI_NODE_EVIDENCE_SCHEMA:
        parser.error("chaos evidence schema does not match the current production evidence contract")

    nodes, _scenarios, deployment = parse_chaos_plan(plan)
    expected_nodes = {
        node.host_id: (node.role, node.target_id)
        for node in nodes.values()
    }
    actual_nodes = {}
    for raw in evidence.get("nodes") if isinstance(evidence.get("nodes"), list) else []:
        if isinstance(raw, dict):
            actual_nodes[str(raw.get("host_id") or "")] = (
                str(raw.get("role") or "").casefold(), str(raw.get("target_id") or "").casefold()
            )
    if actual_nodes != expected_nodes:
        parser.error("chaos evidence topology does not match the supplied plan")
    if dict(evidence.get("deployment") or {}) != deployment:
        parser.error("chaos evidence deployment does not match the supplied plan")
    if not str(evidence.get("campaign_id") or ""):
        parser.error("chaos evidence is missing campaign_id")

    runner = ExternalSoakRunner(SSHCommandExecutor())
    evidence["soak"] = runner.run(
        plan, nodes, duration_hours=args.duration_hours,
        sample_interval_seconds=args.sample_interval_seconds,
        progress=lambda text: print(text, flush=True),
    )
    evidence["finished_at"] = _utc_now()
    args.output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    print("evidence=" + str(args.output.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
