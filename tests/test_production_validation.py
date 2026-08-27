from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from arenyxa.enterprise.production_validation import (
    MULTI_NODE_EVIDENCE_SCHEMA,
    ProductionValidationSuite,
    REQUIRED_EXTERNAL_SCENARIOS,
    validate_multi_node_evidence,
)


def test_validation_workspace_cleanup_retries_transient_windows_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import arenyxa.enterprise.production_validation as module

    root = tmp_path / "validation-root"
    root.mkdir()
    (root / "distributed.sqlite").write_bytes(b"db")
    real_rmtree = module.shutil.rmtree
    attempts = 0

    def flaky_rmtree(path: Path) -> None:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise PermissionError("simulated sharing violation")
        real_rmtree(path)

    monkeypatch.setattr(module.shutil, "rmtree", flaky_rmtree)
    module._remove_validation_root(root, timeout_seconds=1.0)
    assert attempts == 3
    assert not root.exists()


def test_local_production_validation_gate_exercises_real_queue(tmp_path: Path) -> None:
    report = ProductionValidationSuite(soak_jobs=32).run()
    assert report.local_gate_passed
    assert not report.production_evidence_complete
    assert not report.production_ready
    names = {item.name for item in report.local_items}
    assert "hard-crash-idempotent-recovery" in names
    assert "hard-crash-non-idempotent-fence" in names
    assert "lost-terminal-response-replay" in names
    assert "concurrent-lease-exclusivity" in names
    assert "checkpoint-restart-durability" in names
    assert "clock-corruption-fail-closed" in names
    assert "bounded-soak-consistency" in names


def _strict_evidence() -> dict:
    nodes = [
        {"host_id": "server-host", "role": "server", "target_id": "1" * 64},
        {"host_id": "worker-host-a", "role": "worker", "target_id": "2" * 64},
        {"host_id": "worker-host-b", "role": "worker", "target_id": "3" * 64},
    ]
    verification = [
        {
            "node_id": node["host_id"],
            "role": node["role"],
            "target_id": node["target_id"],
            "healthy": True,
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
            "output_sha256": "a" * 64,
        }
        for node in nodes
    ]
    scenarios = {}
    for name in REQUIRED_EXTERNAL_SCENARIOS:
        operations = [{"node_id": "server-host", "phase": "operation", "returncode": 0, "output_sha256": "b" * 64}]
        canonical = json.dumps(
            {"operations": operations, "verification": verification},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
        scenarios[name] = {
            "status": "passed",
            "evidence_id": hashlib.sha256(canonical).hexdigest(),
            "operations": operations,
            "verification": verification,
        }
    return {
        "schema": MULTI_NODE_EVIDENCE_SCHEMA,
        "campaign_id": "c" * 64,
        "started_at": "2026-08-22T00:00:00+00:00",
        "finished_at": "2026-08-23T01:00:00+00:00",
        "deployment": {"storage_backend": "postgresql", "tls_minimum": "TLSv1.3", "protocol_version": 2},
        "nodes": nodes,
        "scenarios": scenarios,
        "soak": {
            "duration_hours": 24.0,
            "uncaught_errors": 0,
            "invariant_violations": 0,
            "duplicate_terminal_receipts": 0,
            "probe_failures": 0,
            "sample_count": 288,
            "sampled_nodes": ["server-host", "worker-host-a", "worker-host-b"],
            "evidence_id": "d" * 64,
        },
    }


def test_multi_node_evidence_requires_real_topology_all_chaos_and_24h_soak(tmp_path: Path) -> None:
    evidence = _strict_evidence()
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    result = validate_multi_node_evidence(path)
    assert result["valid"] is True
    assert result["nodes"] == 3
    assert result["sample_count"] == 288

    evidence["soak"]["duration_hours"] = 23.99
    path.write_text(json.dumps(evidence), encoding="utf-8")
    assert validate_multi_node_evidence(path)["status"] == "soak_incomplete"


def test_multi_node_evidence_rejects_self_asserted_pass_without_verification(tmp_path: Path) -> None:
    evidence = _strict_evidence()
    name = REQUIRED_EXTERNAL_SCENARIOS[0]
    evidence["scenarios"][name] = {"status": "passed", "evidence_id": "e" * 64}
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    assert validate_multi_node_evidence(path)["status"] == "scenario_evidence_incomplete"


def test_multi_node_evidence_rejects_digest_tampering(tmp_path: Path) -> None:
    evidence = _strict_evidence()
    name = REQUIRED_EXTERNAL_SCENARIOS[0]
    evidence["scenarios"][name]["verification"][0]["healthy"] = False
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    assert validate_multi_node_evidence(path)["status"] == "scenario_verification_unhealthy"


def test_multi_node_evidence_rejects_sqlite_and_weak_tls(tmp_path: Path) -> None:
    base = _strict_evidence()
    path = tmp_path / "evidence.json"
    base["deployment"]["storage_backend"] = "sqlite"
    path.write_text(json.dumps(base), encoding="utf-8")
    assert validate_multi_node_evidence(path)["status"] == "non_production_storage"
    base = _strict_evidence()
    base["deployment"]["tls_minimum"] = "TLSv1.2"
    path.write_text(json.dumps(base), encoding="utf-8")
    assert validate_multi_node_evidence(path)["status"] == "tls_policy_incomplete"

