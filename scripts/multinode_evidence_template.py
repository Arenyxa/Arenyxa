from __future__ import annotations

import argparse
import json
from pathlib import Path

from arenyxa.enterprise.production_validation import MULTI_NODE_EVIDENCE_SCHEMA, REQUIRED_EXTERNAL_SCENARIOS


def _verification(host_id: str, role: str, target_id: str) -> dict:
    return {
        "node_id": host_id,
        "role": role,
        "target_id": target_id,
        "healthy": False,
        "storage_backend": "postgresql",
        "tls_minimum": "TLSv1.3",
        "protocol_version": 2,
        "state_invariants": {
            "inconsistent_lease_rows": 0,
            "unreceipted_completed_jobs": 0,
            "implausible_future_leases": 0,
        },
        "duplicate_terminal_receipts": 0,
        "uncaught_errors": 0,
        "output_sha256": "",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a strict Arenyxa multi-host production evidence template")
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    nodes = [
        {"host_id": "server-host", "role": "server", "target_id": "<sha256-of-server-ssh-target>"},
        {"host_id": "worker-host-a", "role": "worker", "target_id": "<sha256-of-worker-a-ssh-target>"},
        {"host_id": "worker-host-b", "role": "worker", "target_id": "<sha256-of-worker-b-ssh-target>"},
    ]
    payload = {
        "schema": MULTI_NODE_EVIDENCE_SCHEMA,
        "campaign_id": "<generated-by-multinode_chaos.py>",
        "started_at": "",
        "finished_at": "",
        "deployment": {"storage_backend": "postgresql", "tls_minimum": "TLSv1.3", "protocol_version": 2},
        "nodes": nodes,
        "scenarios": {
            name: {
                "status": "pending",
                "evidence_id": "",
                "operations": [],
                "verification": [_verification(node["host_id"], node["role"], node["target_id"]) for node in nodes],
            }
            for name in REQUIRED_EXTERNAL_SCENARIOS
        },
        "soak": {
            "duration_hours": 0.0,
            "uncaught_errors": 0,
            "invariant_violations": 0,
            "duplicate_terminal_receipts": 0,
            "probe_failures": 0,
            "sample_count": 0,
            "sampled_nodes": [],
            "evidence_id": "",
        },
    }
    args.path.parent.mkdir(parents=True, exist_ok=True)
    args.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(args.path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
