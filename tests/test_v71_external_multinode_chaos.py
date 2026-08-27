from __future__ import annotations

import json

import pytest

from arenyxa.enterprise.external_chaos import CommandResult, ExternalChaosRunner, parse_chaos_plan
from arenyxa.enterprise.production_validation import REQUIRED_EXTERNAL_SCENARIOS


class _FakeExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def run(self, node, argv, timeout_seconds):
        self.calls.append((node.host_id, tuple(argv)))
        if argv and str(argv[0]).endswith("probe"):
            payload = {
                "host_id": node.host_id,
                "role": node.role,
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
            }
            return CommandResult(0, json.dumps(payload), "", 0.01)
        return CommandResult(0, "ok", "", 0.01)


def _plan() -> dict:
    nodes = [
        {"host_id": "server-a", "role": "server", "ssh_target": "server.example"},
        {"host_id": "worker-a", "role": "worker", "ssh_target": "worker-a.example"},
        {"host_id": "worker-b", "role": "worker", "ssh_target": "worker-b.example"},
    ]
    scenarios = {
        name: [{"node_id": "server-a" if "server" in name or name == "network_partition" else "worker-a", "argv": ["/opt/arenyxa/chaos", name], "cleanup_argv": ["/opt/arenyxa/chaos", "cleanup", name]}]
        for name in REQUIRED_EXTERNAL_SCENARIOS
    }
    return {
        "deployment": {"storage_backend": "postgresql", "tls_minimum": "TLSv1.3", "protocol_version": 2},
        "nodes": nodes,
        "scenarios": scenarios,
        "verification_probes": [
            {"node_id": "server-a", "argv": ["/opt/arenyxa/probe"]},
            {"node_id": "worker-a", "argv": ["/opt/arenyxa/probe"]},
            {"node_id": "worker-b", "argv": ["/opt/arenyxa/probe"]},
        ],
        "soak_probes": [
            {"node_id": "server-a", "argv": ["/opt/arenyxa/probe"]},
            {"node_id": "worker-a", "argv": ["/opt/arenyxa/probe"]},
            {"node_id": "worker-b", "argv": ["/opt/arenyxa/probe"]},
        ],
    }


def test_external_chaos_requires_explicit_disruptive_confirmation() -> None:
    with pytest.raises(PermissionError):
        ExternalChaosRunner(_FakeExecutor()).run(_plan(), allow_disruptive=False)


def test_external_chaos_generates_hashed_per_scenario_operator_evidence() -> None:
    executor = _FakeExecutor()
    evidence = ExternalChaosRunner(executor).run(_plan(), allow_disruptive=True)
    assert set(evidence["scenarios"]) == set(REQUIRED_EXTERNAL_SCENARIOS)
    assert all(row["status"] == "passed" for row in evidence["scenarios"].values())
    assert all(len(row["evidence_id"]) == 64 for row in evidence["scenarios"].values())
    assert all(len(row["verification"]) == 3 for row in evidence["scenarios"].values())
    assert all(all(item["healthy"] for item in row["verification"]) for row in evidence["scenarios"].values())
    # operation + cleanup + three independent post-cleanup probes per scenario
    assert len(executor.calls) == len(REQUIRED_EXTERNAL_SCENARIOS) * 5
    assert evidence["soak"]["duration_hours"] == 0.0
    assert len({node["target_id"] for node in evidence["nodes"]}) == 3


def test_external_chaos_plan_rejects_unsafe_or_incomplete_topology() -> None:
    plan = _plan()
    plan["nodes"] = plan["nodes"][:2]
    with pytest.raises(ValueError):
        parse_chaos_plan(plan)


def test_external_chaos_plan_rejects_alias_targets_and_missing_verification() -> None:
    plan = _plan()
    plan["nodes"][2]["ssh_target"] = plan["nodes"][1]["ssh_target"]
    with pytest.raises(ValueError, match="distinct SSH targets"):
        parse_chaos_plan(plan)

    plan = _plan()
    plan.pop("verification_probes")
    with pytest.raises(ValueError, match="post-cleanup verification"):
        parse_chaos_plan(plan)


def test_external_chaos_fails_scenario_when_post_cleanup_invariant_probe_fails() -> None:
    class BrokenProbeExecutor(_FakeExecutor):
        def run(self, node, argv, timeout_seconds):
            result = super().run(node, argv, timeout_seconds)
            if argv and str(argv[0]).endswith("probe") and node.host_id == "worker-b":
                payload = json.loads(result.stdout)
                payload["state_invariants"]["inconsistent_lease_rows"] = 1
                return CommandResult(0, json.dumps(payload), "", 0.01)
            return result

    evidence = ExternalChaosRunner(BrokenProbeExecutor()).run(_plan(), allow_disruptive=True)
    assert all(row["status"] == "failed" for row in evidence["scenarios"].values())


def test_soak_summary_refuses_to_hide_probe_or_invariant_failures() -> None:
    from arenyxa.enterprise.external_soak import summarize_soak_samples

    summary = summarize_soak_samples([
        {"node_id": "server-a", "probe_ok": True, "payload": {"healthy": True, "uncaught_errors": 0, "invariant_violations": 0, "duplicate_terminal_receipts": 0}},
        {"node_id": "worker-a", "probe_ok": True, "payload": {"healthy": False, "uncaught_errors": 0, "invariant_violations": 0, "duplicate_terminal_receipts": 0}},
        {"node_id": "worker-b", "probe_ok": False, "error": "worker unreachable"},
    ], duration_seconds=24 * 3600)
    assert summary["duration_hours"] == 24.0
    assert summary["uncaught_errors"] >= 1
    assert summary["invariant_violations"] >= 1
    assert summary["probe_failures"] == 1
    assert summary["sampled_nodes"] == ["server-a", "worker-a", "worker-b"]
    assert len(summary["evidence_id"]) == 64


def test_external_soak_api_requires_real_24h_duration() -> None:
    from arenyxa.enterprise.external_soak import ExternalSoakRunner

    class NoopExecutor:
        pass

    runner = ExternalSoakRunner(NoopExecutor())
    try:
        runner.run({}, {}, duration_hours=23.99)
    except ValueError as exc:
        assert "24 wall-clock hours" in str(exc)
    else:
        raise AssertionError("short production soak must be rejected")
