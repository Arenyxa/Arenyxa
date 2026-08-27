from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from arenyxa.application.extraction_recipe import (
    ExtractionInteractionStep,
    ExtractionLoopSpec,
    ExtractionPaginationSpec,
    ExtractionRecipe,
    ExtractionRecipeCompiler,
)
from arenyxa.application.extraction_studio import ExtractionField
from arenyxa.application.extraction_runtime import ExtractionRecipeExecutor
from arenyxa.application.packet_analytics import PacketAdvancedAnalyzer
from arenyxa.application.proxy_deep_inspector import ProxyDeepInspector
from arenyxa.application.terminal_workspace import TerminalWorkspaceManager
from arenyxa.application.workflow_trace import WorkflowRuntimeTrace
from arenyxa.application.workflow_debugger import WorkflowSafeDebugger
from arenyxa.application.workflows import WorkflowEngine
from arenyxa.application.workflow_graph import WorkflowGraphModel
from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.models import NetworkEvent, Workflow, WorkflowNode
from arenyxa.enterprise.fleet_live import FleetLiveTelemetry
from arenyxa.infrastructure.capture.proxy import ProxyFlow


def test_extraction_recipe_compiles_loop_pagination_and_interactions() -> None:
    recipe = ExtractionRecipe(
        name="Catalog",
        source_url="https://example.test/products",
        fields=[
            ExtractionField("title", "css", "h2.title", required=True),
            ExtractionField("href", "css", "a.detail", attribute="href"),
        ],
        steps=[
            ExtractionInteractionStep("accept", "click", "button.accept", optional=True),
            ExtractionInteractionStep("search", "input", "input[name=q]", "camera"),
        ],
        loop=ExtractionLoopSpec("article.card", 500, "href"),
        pagination=ExtractionPaginationSpec("next_button", selector="a.next", maximum_pages=25),
        max_records=5000,
    )
    compiler = ExtractionRecipeCompiler()
    workflow = compiler.compile(recipe)
    kinds = [node["kind"] for node in workflow["nodes"]]
    assert kinds[:5] == ["browser", "browser_action", "browser_action", "loop", "extract"]
    assert "paginate" in kinds
    assert workflow["nodes"][-1]["kind"] == "sink"
    assert workflow["nodes"][-1]["next_ids"] == []
    assert workflow["metadata"]["runtime"] == "arenyxa.extraction_recipe"
    assert workflow["metadata"]["flow_role"] == "runtime-draft"
    assert compiler.validate(recipe) == []


def test_extraction_recipe_warns_on_multiple_without_loop() -> None:
    recipe = ExtractionRecipe(
        "Feed",
        "https://example.test/feed",
        [ExtractionField("links", "css", "a", multiple=True)],
        pagination=ExtractionPaginationSpec("page_parameter", parameter="page", maximum_pages=1500),
    )
    warnings = ExtractionRecipeCompiler().validate(recipe)
    assert any("Multiple-value" in item for item in warnings)
    assert any("1,000 pages" in item for item in warnings)


def test_extraction_recipe_rejects_invalid_step_kind() -> None:
    recipe = ExtractionRecipe(
        "Bad",
        "https://example.test",
        [ExtractionField("title", "css", "title")],
        steps=[ExtractionInteractionStep("x", "shell", value="whoami")],
    )
    with pytest.raises(ValueError):
        recipe.normalized()


def _flow(flow_id: str, request: bytes, response: bytes, *, status: int = 200, duration: float = 50.0) -> ProxyFlow:
    return ProxyFlow(
        id=flow_id,
        sequence=1 if flow_id == "left" else 2,
        started_at="2026-08-18T00:00:00+00:00",
        completed_at="2026-08-18T00:00:01+00:00",
        client="127.0.0.1:1234",
        scheme="https",
        method="POST",
        host="api.example.test",
        port=443,
        target="/v1/items?limit=10&token=secret-token",
        request_raw=request,
        response_raw=response,
        status=status,
        duration_ms=duration,
        request_bytes=len(request),
        response_bytes=len(response),
        tls_intercepted=True,
    )


def test_proxy_deep_inspector_redacts_sensitive_parameters_and_headers() -> None:
    request = (
        b"POST /v1/items?limit=10&token=secret-token HTTP/1.1\r\n"
        b"Host: api.example.test\r\nAuthorization: Bearer abc\r\n"
        b"Content-Type: application/json\r\nCookie: session=xyz; theme=dark\r\n\r\n"
        b'{"name":"camera","password":"dont-show"}'
    )
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Strict-Transport-Security: max-age=31536000\r\n"
        b"Set-Cookie: sid=abc; Secure; HttpOnly; SameSite=Lax\r\n\r\n{}"
    )
    result = ProxyDeepInspector().inspect(_flow("left", request, response))
    assert result.request_headers["Authorization"] == "<redacted>"
    sensitive = {item.name: item.value_preview for item in result.parameters if item.sensitive}
    assert sensitive["token"] == "<redacted>"
    assert sensitive["password"] == "<redacted>"
    assert any(item["name"] == "sid" and item["secure"] for item in result.cookies)
    assert result.security_headers["strict-transport-security"] is True


def test_proxy_deep_compare_and_timeline() -> None:
    left = _flow("left", b"GET /?a=1 HTTP/1.1\r\nHost: x\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n", duration=10)
    right = _flow("right", b"GET /?a=2 HTTP/1.1\r\nHost: x\r\n\r\n", b"HTTP/1.1 404 Not Found\r\n\r\n", status=404, duration=40)
    inspector = ProxyDeepInspector()
    comparison = inspector.compare(left, right)
    assert comparison["status_changed"] is True
    assert comparison["latency_delta_ms"] == 30.0
    timeline = inspector.timeline([left, right])
    assert len(timeline) == 2
    assert timeline[1]["offset"] == 1


def test_packet_advanced_analytics_groups_protocols_conversations_and_anomalies() -> None:
    rows = [
        NetworkEvent(
            session_id="cap",
            source_type=CaptureSource.SYSTEM,
            protocol="TCP",
            direction="outbound",
            size=1500,
            host="8.8.8.8",
            method="GET",
            status=200,
            timing={"duration_ms": 25},
            metadata={"src": "10.0.0.2", "dst": "8.8.8.8", "src_port": 50000, "dst_port": 443, "highest_protocol": "TLS"},
        ),
        NetworkEvent(
            session_id="cap",
            source_type=CaptureSource.SYSTEM,
            protocol="TCP",
            direction="outbound",
            size=17 * 1024 * 1024,
            host="8.8.8.8",
            status=500,
            timing={"duration_ms": 6000},
            metadata={"src": "10.0.0.2", "dst": "8.8.8.8", "src_port": 50000, "dst_port": 443, "highest_protocol": "TLS", "error": "reset"},
        ),
    ]
    result = PacketAdvancedAnalyzer().analyze(rows)
    assert result.event_count == 2
    assert result.protocols[0]["protocol"] == "TLS"
    assert result.private_endpoint_count == 1
    assert result.public_endpoint_count == 1
    kinds = {row["kind"] for row in result.anomalies}
    assert {"error", "slow", "large-transfer"}.issubset(kinds)
    assert result.duration_p95_ms >= 25


def _fleet_snapshot(*, stale: int = 0, failed: int = 0, queued: int = 0, invariant: int = 0) -> dict:
    workers = [
        {"worker_id": "worker-a", "state": "healthy", "max_slots": 8, "active_leases": 4, "heartbeat_at": "2020-01-01T00:00:00+00:00" if stale else "2099-01-01T00:00:00+00:00"},
    ]
    jobs = []
    jobs.extend({"job_id": f"q-{i}", "state": "queued", "attempt": 0} for i in range(queued))
    jobs.extend({"job_id": f"f-{i}", "state": "failed", "attempt": 2} for i in range(failed))
    return {
        "workers": workers,
        "jobs": jobs,
        "queue": {"state_invariants": {"violations": invariant}, "storage_capabilities": {"backend": "postgresql"}},
    }


def test_fleet_live_telemetry_records_change_events() -> None:
    live = FleetLiveTelemetry()
    live.ingest(_fleet_snapshot(), sampled_at=1.0)
    result = live.ingest(_fleet_snapshot(stale=1, failed=2, queued=3), sampled_at=2.0)
    assert result["sample_count"] == 2
    kinds = {row["kind"] for row in result["events"]}
    assert "baseline" in kinds
    assert "stale-workers" in kinds
    assert "failed-jobs" in kinds
    assert "queue-depth" in kinds


class _TraceStore:
    def get_workflow_execution(self, execution_id: str):
        return {
            "id": execution_id,
            "workflow_id": "flow-1",
            "state": "running",
            "definition_json": json.dumps({
                "nodes": [
                    {"id": "source", "kind": "source", "config": {}, "next_ids": ["map"]},
                    {"id": "map", "kind": "map", "config": {}, "next_ids": ["sink"]},
                    {"id": "sink", "kind": "sink", "config": {}, "next_ids": []},
                ]
            }),
            "processed_inputs": 10,
            "staged_outputs": 8,
            "error_count": 1,
            "checkpoint_json": "{}",
            "started_at": "a",
            "updated_at": "b",
            "finished_at": None,
            "error_code": "",
            "error_message": "",
        }

    def get_workflow_node_executions(self, execution_id: str):
        return [
            {"node_id": "source", "state": "completed", "input_count": 10, "output_count": 10, "error_count": 0},
            {"node_id": "map", "state": "running", "input_count": 10, "output_count": 8, "error_count": 1},
            {"node_id": "sink", "state": "pending", "input_count": 8, "output_count": 0, "error_count": 0},
        ]


def test_workflow_runtime_trace_assigns_lanes_and_step_plan() -> None:
    runtime = WorkflowRuntimeTrace(_TraceStore())
    trace = runtime.trace("exec-1")
    lanes = {row["node_id"]: row["lane"] for row in trace["nodes"]}
    assert lanes == {"source": 0, "map": 1, "sink": 2}
    plan = runtime.step_plan("exec-1")
    assert [row["node_id"] for row in plan["next_nodes"]] == ["map", "sink"]
    assert plan["can_continue"] is True


def test_terminal_workspace_metadata_controls(tmp_path: Path) -> None:
    workspace = TerminalWorkspaceManager(tmp_path)
    state = workspace.create(title="Python A", mode="python-session", pane="primary")
    session_id = state["id"]
    renamed = workspace.rename(session_id, "Python Data")
    assert renamed["title"] == "Python Data"
    moved = workspace.move(session_id, "bottom")
    assert moved["pane"] == "bottom"
    resized = workspace.resize(session_id, 160, 48)
    assert resized["columns"] == 160
    assert resized["rows"] == 48
    assert workspace.close(session_id) is True


def test_terminal_workspace_persistent_sessions_remain_isolated(tmp_path: Path) -> None:
    workspace = TerminalWorkspaceManager(tmp_path)
    left = workspace.create(title="left", mode="python-session")
    right = workspace.create(title="right", mode="python-session")
    workspace.start(left["id"])
    workspace.start(right["id"])
    workspace.send(left["id"], "marker = 'LEFT'")
    workspace.send(right["id"], "marker = 'RIGHT'")
    workspace.send(left["id"], "print(marker)")
    workspace.send(right["id"], "print(marker)")
    deadline = time.time() + 5
    while time.time() < deadline:
        if "LEFT" in workspace.output(left["id"]) and "RIGHT" in workspace.output(right["id"]):
            break
        time.sleep(0.05)
    assert "LEFT" in workspace.output(left["id"])
    assert "RIGHT" not in workspace.output(left["id"])
    assert "RIGHT" in workspace.output(right["id"])
    workspace.close_all()


def test_original_ui_surfaces_new_professional_capabilities() -> None:
    root = Path(__file__).resolve().parents[1]
    extraction = (root / "src/arenyxa/presentation/pages/extraction.py").read_text(encoding="utf-8")
    proxy = (root / "src/arenyxa/presentation/pages/proxy.py").read_text(encoding="utf-8")
    tools = "\n".join((root / rel).read_text(encoding="utf-8") for rel in (
        "src/arenyxa/presentation/pages/tools.py",
        "src/arenyxa/presentation/pages/tools_automation.py",
        "src/arenyxa/presentation/pages/tools_platform.py",
        "src/arenyxa/presentation/pages/tools_console.py",
    ))
    fleet = (root / "src/arenyxa/presentation/pages/server_ops.py").read_text(encoding="utf-8")
    network = (root / "src/arenyxa/presentation/pages/network.py").read_text(encoding="utf-8")
    assert '"Recipe Builder"' in extraction
    assert 'Compile Flow Draft' in extraction
    assert '"Deep Analysis"' in proxy
    assert '"Runtime Trace"' in tools and '"Step Plan"' in tools
    assert '"Visual Graph"' in tools and 'Sync Raw → Graph' in tools
    assert '"Live Telemetry & Events"' in fleet
    assert '"Advanced Analytics"' in network
    assert "intercepting proxy suite" not in proxy
    assert "Structured Extraction" not in extraction

from arenyxa.application.command_runtime import ArenyxaCommandRuntime
from arenyxa.application.mitm_analytics import MitmFlowAnalyzer
from arenyxa.infrastructure.capture.mitm_engine import MitmEvent


def test_mitm_flow_analytics_unifies_protocols_replay_and_anomalies() -> None:
    rows = [
        MitmEvent(1, 1.0, "request", "flow-1", "HTTP", "request", method="GET", url="https://a.test/", host="a.test", size=200, intercepted=True),
        MitmEvent(2, 2.0, "response", "flow-1", "HTTP", "response", url="https://a.test/", host="a.test", status=503, size=1000, replay="server"),
        MitmEvent(3, 3.0, "message", "flow-2", "WebSocket", "message", host="a.test", direction="server->client", size=17 * 1024 * 1024),
    ]
    result = MitmFlowAnalyzer().analyze(rows)
    assert result.event_count == 3
    assert result.unique_flows == 2
    assert result.intercepted_events == 1
    assert result.replay_events == 1
    assert result.status_families["5xx"] == 1
    kinds = {row["kind"] for row in result.anomalies}
    assert "server-error" in kinds
    assert "large-message" in kinds


def test_command_tree_exposes_completion_round_capabilities() -> None:
    tree = ArenyxaCommandRuntime.COMMAND_TREE
    assert "analytics" in tree["packet"]
    assert {"recipe-validate", "recipe-compile", "recipe-run"}.issubset(tree["extraction"])
    assert {"trace", "step-plan", "safe-debug"}.issubset(tree["flow"])
    assert {"live", "events"}.issubset(tree["fleet"])
    assert {"deep-inspect", "compare", "timeline"}.issubset(tree["proxy"])
    assert "analytics" in tree["mitm"]
    assert {"session-rename", "session-move", "session-resize", "session-interrupt"}.issubset(tree["terminal"])


def test_original_terminal_shell_sessions_have_real_split_panes() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/arenyxa/presentation/pages/tools.py").read_text(encoding="utf-8") + (root / "src/arenyxa/presentation/pages/tools_terminal_workspace.py").read_text(encoding="utf-8")
    assert "workspace_primary_tabs" in source
    assert "workspace_secondary_tabs" in source
    assert "workspace_bottom_tabs" in source
    assert "QSplitter(Qt.Orientation.Horizontal)" in source
    assert "QSplitter(Qt.Orientation.Vertical)" in source


def test_extraction_runtime_parameter_pagination_and_secret_resolution() -> None:
    executor = ExtractionRecipeExecutor()
    url = executor._page_parameter_url("https://example.test/items?q=camera&page=1", "page", 3)
    assert "page=3" in url
    assert "q=camera" in url
    assert executor._resolve_value("${secret.user}", lambda key: "alice" if key == "user" else None) == "alice"
    assert executor._resolve_value("literal", None) == "literal"
    assert executor._record_identity({"id": 7, "title": "A"}, "id") == "7"


def test_windows_native_qualification_includes_terminal_and_picker_evidence() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "scripts/windows_native_qualification.py").read_text(encoding="utf-8")
    for marker in (
        "conpty_powershell_session",
        "conpty_cmd_session",
        "conpty_resize",
        "playwright_chromium_launch",
        "terminal_split_panes",
        "extraction_picker_visible_overlay",
    ):
        assert marker in source
    assert 'SCHEMA = "arenyxa.windows-native-qualification/v2"' in source


def test_workflow_graph_model_layout_edit_and_cycle_guard() -> None:
    model = WorkflowGraphModel({
        "name": "Graph",
        "nodes": [
            {"id": "source", "kind": "source", "config": {}, "next_ids": ["sink"]},
            {"id": "sink", "kind": "sink", "config": {}, "next_ids": []},
        ],
    })
    layout = model.layout()
    lanes = {row["id"]: row["lane"] for row in layout["nodes"]}
    assert lanes == {"source": 0, "sink": 1}
    model.add_node("validate", "validate", config={"required": ["title"]})
    model.disconnect("source", "sink")
    model.connect("source", "validate")
    model.connect("validate", "sink")
    snapshot = model.snapshot()
    assert next(row for row in snapshot["nodes"] if row["id"] == "validate")["next_ids"] == ["sink"]
    with pytest.raises(ValueError, match="cycle"):
        model.connect("sink", "source")
    assert next(row for row in model.snapshot()["nodes"] if row["id"] == "sink")["next_ids"] == []
    model.remove_node("validate")
    assert {row["id"] for row in model.snapshot()["nodes"]} == {"source", "sink"}


def test_workflow_graph_model_rejects_missing_refs_and_last_node_removal() -> None:
    with pytest.raises(ValueError, match="missing node"):
        WorkflowGraphModel({
            "name": "Broken",
            "nodes": [{"id": "a", "kind": "source", "config": {}, "next_ids": ["missing"]}],
        })
    model = WorkflowGraphModel({"name": "One", "nodes": [{"id": "only", "kind": "sink", "config": {}, "next_ids": []}]})
    with pytest.raises(ValueError, match="cannot be empty"):
        model.remove_node("only")
    assert model.snapshot()["nodes"][0]["id"] == "only"


def test_flow_graph_canvas_is_original_arenyxa_surface() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/arenyxa/presentation/flow_graph.py").read_text(encoding="utf-8")
    assert "FlowGraphCanvas" in source
    assert "cubicTo" in source
    assert "nodeSelected" in source
    for third_party_marker in ("Workflow Automation", "Node-RED", "React Flow"):
        assert third_party_marker not in source


def test_packet_tcp_stream_quality_surfaces_retransmission_loss_and_rtt() -> None:
    rows = [
        NetworkEvent(
            session_id="cap-tcp",
            source_type=CaptureSource.SYSTEM,
            protocol="TCP",
            direction="outbound",
            size=1200,
            metadata={
                "transport": "tcp",
                "tcp_stream": 7,
                "src": "10.0.0.2",
                "dst": "203.0.113.8",
                "tcp_analysis": ["retransmission", "duplicate_ack"],
                "tcp_ack_rtt_ms": 12.5,
                "tcp_bytes_in_flight": 4096,
            },
        ),
        NetworkEvent(
            session_id="cap-tcp",
            source_type=CaptureSource.SYSTEM,
            protocol="TCP",
            direction="inbound",
            size=800,
            metadata={
                "transport": "tcp",
                "tcp_stream": 7,
                "src": "203.0.113.8",
                "dst": "10.0.0.2",
                "tcp_analysis": ["lost_segment", "zero_window"],
                "tcp_ack_rtt_ms": 410.0,
                "tcp_bytes_in_flight": 8192,
            },
        ),
    ]
    quality = PacketAdvancedAnalyzer().analyze(rows).tcp_quality
    assert quality.stream_count == 1
    assert quality.packet_count == 2
    assert quality.retransmissions == 1
    assert quality.lost_segments == 1
    assert quality.duplicate_acks == 1
    assert quality.zero_window == 1
    assert quality.ack_rtt_p95_ms == 410.0
    stream = quality.streams[0]
    assert stream.key == "tcp:7"
    assert stream.bytes_in_flight_max == 8192
    assert stream.severity in {"warning", "critical"}
    assert any("retransmission" in item for item in stream.warnings)
    assert any("ACK RTT" in item for item in stream.warnings)


def test_extraction_runtime_supports_professional_interaction_actions() -> None:
    calls: list[tuple[str, object]] = []

    class Locator:
        @property
        def first(self):
            return self

        def hover(self, *, timeout: int) -> None:
            calls.append(("hover", timeout))

        def press(self, value: str, *, timeout: int) -> None:
            calls.append(("press", (value, timeout)))

        def check(self, *, timeout: int) -> None:
            calls.append(("check", timeout))

        def uncheck(self, *, timeout: int) -> None:
            calls.append(("uncheck", timeout))

        def dblclick(self, *, timeout: int) -> None:
            calls.append(("double_click", timeout))

        def focus(self, *, timeout: int) -> None:
            calls.append(("focus", timeout))

    class Page:
        def locator(self, selector: str) -> Locator:
            calls.append(("selector", selector))
            return Locator()

    executor = ExtractionRecipeExecutor()
    steps = [
        ExtractionInteractionStep("hover", "hover", "#menu", timeout_ms=1200),
        ExtractionInteractionStep("press", "press", "#query", "Enter", timeout_ms=1300),
        ExtractionInteractionStep("check", "check", "#agree", timeout_ms=1400),
        ExtractionInteractionStep("uncheck", "uncheck", "#agree", timeout_ms=1500),
        ExtractionInteractionStep("double", "double_click", ".row", timeout_ms=1600),
        ExtractionInteractionStep("focus", "focus", "#query", timeout_ms=1700),
    ]
    executed = executor._run_steps(Page(), [item.normalized() for item in steps], None, None)
    assert executed == 6
    names = [name for name, _value in calls]
    for expected in ("hover", "press", "check", "uncheck", "double_click", "focus"):
        assert expected in names


def test_extraction_navigation_resolves_target_before_browser_navigation() -> None:
    checks: list[tuple[str, bool]] = []

    class Guard:
        def check_target(self, host: str, *, resolve_dns: bool = True) -> None:
            checks.append((host, resolve_dns))

    class Page:
        def goto(self, url: str, *, wait_until: str, timeout: int) -> None:
            checks.append((url, wait_until == "domcontentloaded" and timeout == 5000))

    executor = ExtractionRecipeExecutor()
    executor.guard = Guard()  # type: ignore[assignment]
    executor._navigate(Page(), "https://example.test/items", 5000)
    assert checks[0] == ("example.test", True)
    assert checks[1] == ("https://example.test/items", True)


def test_workflow_safe_debugger_pauses_at_breakpoint_with_bounded_queue_preview() -> None:
    workflow = Workflow(
        "Debug",
        [
            WorkflowNode("source", {}, id="source", next_ids=["map"]),
            WorkflowNode("map", {"constants": {"checked": True}}, id="map", next_ids=["validate"]),
            WorkflowNode("validate", {"required": ["title"]}, id="validate", next_ids=["sink"], failure_ids=["errors"]),
            WorkflowNode("sink", {}, id="sink"),
            WorkflowNode("sink", {}, id="errors"),
        ],
        id="flow-debug",
    )
    debugger = WorkflowSafeDebugger(WorkflowEngine(buffer_size=50))
    report = debugger.simulate(
        workflow,
        [{"title": "A"}, {"title": ""}],
        breakpoints=["validate"],
    )
    assert report.state == "paused"
    assert report.breakpoint == "validate"
    assert report.steps_executed == 2
    assert [row.node_id for row in report.traces[:2]] == ["source", "map"]
    assert report.traces[-1].state == "breakpoint"
    assert report.pending_nodes[0]["node_id"] == "validate"
    assert report.pending_nodes[0]["queued_records"] == 2


def test_workflow_safe_debugger_routes_validation_failures_and_completes() -> None:
    workflow = Workflow(
        "Debug Complete",
        [
            WorkflowNode("source", {}, id="source", next_ids=["validate"]),
            WorkflowNode("validate", {"required": ["title"]}, id="validate", next_ids=["sink"], failure_ids=["errors"]),
            WorkflowNode("sink", {}, id="sink"),
            WorkflowNode("sink", {}, id="errors"),
        ],
        id="flow-debug-complete",
    )
    report = WorkflowSafeDebugger(WorkflowEngine(buffer_size=50)).simulate(
        workflow, [{"title": "A"}, {"title": ""}]
    )
    assert report.state == "completed"
    assert len(report.outputs) == 2
    assert len(report.errors) == 1
    assert any(row.node_id == "validate" and row.error_count == 1 for row in report.traces)


def test_workflow_safe_debugger_blocks_side_effectful_nodes() -> None:
    workflow = Workflow(
        "Blocked",
        [WorkflowNode("http", {"url": "https://example.test"}, id="http")],
        id="flow-blocked",
    )
    engine = WorkflowEngine()
    engine.register("http", lambda item, config: [{**item, "network": True}])
    report = WorkflowSafeDebugger(engine).simulate(workflow, [{"id": 1}])
    assert report.state == "blocked"
    assert report.breakpoint == "http"
    assert report.blocked_nodes == ["http"]
    assert report.outputs == []
