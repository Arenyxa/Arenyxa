from __future__ import annotations

import time
from pathlib import Path

import pytest

from arenyxa.application.extraction_studio import ExtractionLivePicker
from arenyxa.application.terminal_workspace import TerminalWorkspaceManager
from arenyxa.application.workflow_inspector import WorkflowExecutionInspector
from arenyxa.infrastructure.capture.proxy import ProxyFlow, summarize_proxy_flows


def test_proxy_session_summary_tracks_latency_hosts_and_rewrites() -> None:
    flows = [
        ProxyFlow(
            id="a", sequence=1, started_at="2026-08-18T00:00:00Z", client="local", scheme="https",
            method="GET", host="example.com", port=443, target="/a", status=200, duration_ms=10,
            request_bytes=100, response_bytes=200, tls_intercepted=True, completed_at="done",
            rewrite_rule_ids=["r1"], response_raw=b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
        ),
        ProxyFlow(
            id="b", sequence=2, started_at="2026-08-18T00:00:01Z", client="local", scheme="https",
            method="POST", host="example.com", port=443, target="/b", status=500, duration_ms=90,
            request_bytes=300, response_bytes=400, error="upstream", completed_at="done",
            response_raw=b"HTTP/1.1 500 Error\r\nContent-Type: text/plain\r\n\r\nno",
        ),
    ]
    summary = summarize_proxy_flows(flows)
    assert summary.flow_count == 2
    assert summary.error_count == 1
    assert summary.rewritten_flow_count == 1
    assert summary.response_bytes == 600
    assert summary.hosts[0] == {"host": "example.com", "flows": 2}
    assert summary.status_families["2xx"] == 1
    assert summary.status_families["5xx"] == 1
    assert summary.duration_p95_ms == 90.0


class _WorkflowStore:
    def get_workflow_execution(self, execution_id: str):
        if execution_id != "exec-1":
            return None
        return {
            "id": "exec-1",
            "workflow_id": "flow-1",
            "state": "completed",
            "started_at": "s",
            "updated_at": "u",
            "finished_at": "f",
            "processed_inputs": 10,
            "staged_outputs": 8,
            "error_count": 2,
            "checkpoint_json": '{"cursor": 10}',
            "error_code": None,
            "error_message": None,
            "definition_json": '{"nodes":[{"id":"source","kind":"source","config":{}},{"id":"map","kind":"map","config":{"fields":{"title":"name"}}}]}',
        }

    def get_workflow_node_executions(self, execution_id: str):
        return [
            {"node_id": "source", "input_count": 10, "output_count": 10, "error_count": 0, "state": "completed"},
            {"node_id": "map", "input_count": 10, "output_count": 8, "error_count": 2, "state": "completed"},
        ]


def test_workflow_execution_inspector_exposes_node_metrics() -> None:
    result = WorkflowExecutionInspector(_WorkflowStore()).inspect("exec-1")
    assert result.output_ratio == 0.8
    assert result.error_rate == 0.2
    assert result.nodes[1].node_id == "map"
    assert result.nodes[1].error_rate == 0.2
    assert "map" in result.error_nodes
    assert result.checkpoint == {"cursor": 10}


def test_extraction_picker_field_names_are_stable() -> None:
    assert ExtractionLivePicker._field_name("div", {"data-testid": "Product Price"}, "") == "product_price"
    assert ExtractionLivePicker._field_name("h1", {}, "Hello World") == "hello_world"
    assert ExtractionLivePicker._field_name("img", {}, "") == "img"


def test_terminal_workspace_runs_multiple_python_sessions(tmp_path: Path) -> None:
    manager = TerminalWorkspaceManager(tmp_path)
    one = manager.create(title="Alpha", mode="python-session", pane="primary")
    two = manager.create(title="Beta", mode="python-session", pane="secondary")
    try:
        manager.start(one["id"])
        manager.start(two["id"])
        manager.send(one["id"], "x = 7")
        manager.send(one["id"], "print('alpha', x)")
        manager.send(two["id"], "x = 11")
        manager.send(two["id"], "print('beta', x)")
        deadline = time.time() + 5
        while time.time() < deadline:
            if "alpha 7" in manager.output(one["id"]) and "beta 11" in manager.output(two["id"]):
                break
            time.sleep(0.05)
        assert "alpha 7" in manager.output(one["id"])
        assert "beta 11" in manager.output(two["id"])
        assert len(manager.list()) == 2
    finally:
        manager.close_all()


def test_terminal_workspace_limits_sessions(tmp_path: Path) -> None:
    manager = TerminalWorkspaceManager(tmp_path)
    try:
        for index in range(manager.MAX_SESSIONS):
            manager.create(title=str(index), mode="python-session")
        with pytest.raises(RuntimeError):
            manager.create(title="too-many", mode="python-session")
    finally:
        manager.close_all()


def test_conpty_backend_is_platform_gated() -> None:
    from arenyxa.application.windows_conpty import WindowsConPtySession
    if __import__("os").name != "nt":
        assert WindowsConPtySession.supported() is False


def test_fleet_telemetry_detects_capacity_and_invariants() -> None:
    from arenyxa.enterprise.fleet_telemetry import FleetTelemetryAnalyzer
    snapshot = {
        "queue": {
            "database_integrity": "ok",
            "storage_capabilities": {"backend": "sqlite-single-host"},
            "state_invariants": {"bad_leases": 1},
        },
        "workers": [
            {"worker_id": "w1", "state": "online", "max_slots": 4, "active_leases": 4, "heartbeat_at": "2026-08-18T12:00:00+00:00"},
            {"worker_id": "w2", "state": "online", "max_slots": 8, "active_leases": 8, "heartbeat_at": "2026-08-18T12:00:00+00:00"},
        ],
        "jobs": [{"state": "queued", "attempt": 1} for _ in range(60)],
    }
    now = __import__("datetime").datetime(2026, 8, 18, 12, 0, 30, tzinfo=__import__("datetime").timezone.utc)
    result = FleetTelemetryAnalyzer().analyze(snapshot, now=now)
    assert result.total_slots == 12
    assert result.active_slots == 12
    assert result.queued_jobs == 60
    assert result.invariant_violations == 1
    assert result.severity == "critical"
    assert any("PostgreSQL" in item for item in result.warnings)
