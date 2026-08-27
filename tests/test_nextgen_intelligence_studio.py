from __future__ import annotations

import json
from pathlib import Path

import pytest

from arenyxa.application.nextgen import (
    ActivityCenter,
    AdaptiveRateLimiter,
    BrowserAction,
    BrowserRecorderService,
    DataQualityStudio,
    DataSourceDiscovery,
    ProjectEnvironmentService,
    ProtocolInspector,
    RequestCodeGenerator,
    SecretVault,
    SelectorFingerprint,
    SelectorStudio,
    SmartPathV2,
    WorkflowDebugger,
    WorkflowTemplateLibrary,
    WorkflowVariables,
)
from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import FetchResponse, NetworkEvent, RequestSpec, Workflow, WorkflowNode


def _response(body: str, content_type: str = "text/html") -> FetchResponse:
    return FetchResponse(
        url="https://example.com",
        final_url="https://example.com",
        status=200,
        headers={"Content-Type": content_type},
        body=body.encode(),
        elapsed_ms=12.5,
        encoding="utf-8",
        content_type=content_type,
    )


def _event(url: str, *, protocol: str = "http", metadata=None, response_headers=None) -> NetworkEvent:
    return NetworkEvent(
        session_id="capture-1",
        source_type=CaptureSource.BROWSER,
        protocol=protocol,
        direction="out",
        size=123,
        method="GET",
        url=url,
        status=200,
        metadata=metadata or {},
        response_headers=response_headers or {},
    )


def test_selector_studio_candidates_and_healing() -> None:
    studio = SelectorStudio()
    old = "<html><body><section><button data-testid='checkout' class='btn css-a1b2c3d4'>Checkout</button></section></body></html>"
    result = studio.analyze(old, "button[data-testid='checkout']")
    assert result["matches"] == 1
    assert result["candidates"][0]["score"] >= 0.9
    fp = SelectorFingerprint(**result["fingerprint"])
    new = "<html><body><main><div><button data-testid='checkout' class='new-class'>Checkout</button></div></main></body></html>"
    healed = studio.heal(new, fp)
    assert healed
    assert healed[0].confidence >= 0.8
    assert "checkout" in healed[0].selector


def test_browser_recorder_generates_workflow_and_code() -> None:
    recorder = BrowserRecorderService()
    actions = [BrowserAction("goto", url="https://example.com"), BrowserAction("click", selector="#go")]
    workflow = recorder.to_workflow(actions)
    assert len(workflow.nodes) == 2
    assert workflow.nodes[0].kind == "browser_action"
    py = recorder.to_playwright(actions, "python")
    js = recorder.to_playwright(actions, "javascript")
    assert "page.goto" in py and "locator" in py
    assert "await page.goto" in js


def test_request_code_generator_targets() -> None:
    spec = RequestSpec(
        "https://example.com/api",
        method="POST",
        query={"page": "1"},
        headers={"X-Test": "yes"},
        cookies={"session": "abc"},
        body='{"x":1}',
    )
    generator = RequestCodeGenerator()
    for target in ("curl", "python", "httpx", "fetch", "axios", "powershell", "playwright"):
        code = generator.generate(spec, target)
        assert "example.com" in code


def test_data_source_discovery_and_smartpath_prefers_api() -> None:
    response = _response("<html><script id='__NEXT_DATA__'>{}</script></html>")
    events = [_event("https://example.com/api/products", response_headers={"content-type": "application/json"}) for _ in range(3)]
    sources = DataSourceDiscovery().discover(response, events)
    assert any(item.kind == "nextjs" for item in sources)
    assert any(item.kind == "xhr-json" for item in sources)
    plan = SmartPathV2().analyze(response, events)
    assert plan.recommended_engine == "api"
    assert plan.data_sources


def test_protocol_inspector_graphql_websocket_sse() -> None:
    inspector = ProtocolInspector()
    gql = _event("https://example.com/graphql", metadata={"operationName": "Products", "variables": {"n": 1}})
    ws = _event("wss://example.com/socket", protocol="wss", metadata={"opcode": 1, "payload_preview": "hi"})
    sse = _event("https://example.com/events", response_headers={"content-type": "text/event-stream"})
    assert inspector.graphql([gql])[0]["operation"] == "Products"
    assert inspector.websocket([ws])[0]["opcode"] == 1
    assert inspector.sse([sse])


def test_adaptive_rate_limiter_backoff_and_recovery() -> None:
    limiter = AdaptiveRateLimiter(1, 8, 8)
    decision = limiter.observe(429, 100, retry_after=2)
    assert decision.concurrency < 8
    assert decision.delay_seconds >= 2
    for _ in range(20):
        decision = limiter.observe(200, 100)
    assert decision.mode in {"recover", "steady"}


def test_data_quality_schema_and_duplicates() -> None:
    report = DataQualityStudio().analyze([
        {"url": "https://a.test", "price": 10, "email": "a@example.com"},
        {"url": "https://a.test", "price": 10, "email": "a@example.com"},
        {"url": "https://b.test", "price": 9999, "email": None},
    ])
    assert report["duplicates"] == 1
    assert report["schema"]["url"]["type"] == "url"
    assert report["schema"]["email"]["observed_types"]["email"] == 2


def test_secret_vault_is_encrypted_and_project_env_excludes_secret_keys(tmp_path: Path) -> None:
    vault = SecretVault(tmp_path / "secure")
    vault.set("api.token", "super-secret")
    assert vault.get("api.token") == "super-secret"
    assert "super-secret" not in vault.vault_path.read_text(errors="ignore")
    assert vault.names() == ["api.token"]
    assert vault.delete("api.token") is True

    projects = ProjectEnvironmentService(tmp_path / "projects")
    projects.ensure("demo")
    projects.save_environment("demo", {"BASE_URL": "https://example.com", "API_TOKEN": "do-not-export"})
    loaded = projects.load_environment("demo")
    assert loaded == {"BASE_URL": "https://example.com"}


def test_workflow_variables_and_debugger_breakpoint() -> None:
    resolver = WorkflowVariables()
    value = resolver.resolve(
        {"url": "${project.base_url}/api", "auth": "${secret.token}"},
        {"project": {"base_url": "https://example.com"}},
        lambda name: "abc" if name == "token" else None,
    )
    assert value == {"url": "https://example.com/api", "auth": "abc"}

    workflow = Workflow(
        name="debug",
        nodes=[
            WorkflowNode(kind="source", config={}, id="source", next_ids=["validate"]),
            WorkflowNode(kind="validate", config={"required": ["title"]}, id="validate", next_ids=["sink"]),
            WorkflowNode(kind="sink", config={}, id="sink"),
        ],
    )
    debugger = WorkflowDebugger()
    debugger.prepare(workflow, [{"title": "Arenyxa"}], ["validate"])
    first = debugger.step()
    assert first.state == "stepped"
    hit = debugger.step()
    assert hit.state == "breakpoint"
    after = debugger.step(ignore_breakpoint=True)
    assert after.node_id == "validate"


def test_templates_and_activity_center_are_bounded() -> None:
    templates = WorkflowTemplateLibrary().templates()
    assert "ecommerce-product" in templates and "api-pagination" in templates
    activity = ActivityCenter(capacity=100)
    for index in range(150):
        activity.publish("test", f"event {index}")
    snapshot = activity.snapshot(200)
    assert len(snapshot) == 100
    assert snapshot[-1].message == "event 149"


def test_http_workbench_variables_actions_and_assertions() -> None:
    from arenyxa.application.nextgen import HttpRequestWorkbench, RequestAssertion

    class FakeFetcher:
        def fetch(self, spec):
            assert spec.url == "https://example.com/api"
            assert spec.headers["X-Token"] == "abc"
            return FetchResponse(
                url=spec.url,
                final_url=spec.url,
                status=201,
                headers={"Content-Type": "application/json", "X-Mode": "test"},
                body=b'{"ok":true,"data":{"id":1}}',
                elapsed_ms=5.0,
                encoding="utf-8",
                content_type="application/json",
            )

    workbench = HttpRequestWorkbench()
    workbench.fetcher = FakeFetcher()
    spec = workbench.apply_variables(RequestSpec("${base}/api"), {"base": "https://example.com"})
    spec = workbench.apply_actions(spec, [{"action": "set_header", "name": "X-Token", "value": "abc"}])
    result = workbench.send_with_assertions(
        spec,
        [
            RequestAssertion("status_eq", 201),
            RequestAssertion("body_contains", '"ok":true'),
            RequestAssertion("header_equals", "test", "X-Mode"),
            RequestAssertion("json_path_exists", "data.id"),
        ],
    )
    assert result["passed"] is True
    assert all(item["passed"] for item in result["assertions"])


def test_distributed_worker_registry_keeps_token_out_of_worker_file(tmp_path: Path) -> None:
    from arenyxa.application.nextgen import DistributedWorker, DistributedWorkerService, SecretVault

    vault = SecretVault(tmp_path / "secure")
    service = DistributedWorkerService(tmp_path / "workers", vault)
    worker = DistributedWorker("local-1", "Local", "http://127.0.0.1:8787", "worker.local.token", True, 2)
    service.upsert(worker, "very-secret-token")
    assert vault.get("worker.local.token") == "very-secret-token"
    assert "very-secret-token" not in service.path.read_text(encoding="utf-8")
    plan = service.partition(list(range(8)))
    assert set(plan) == {"local", "local-1"}
    assert sum(len(values) for values in plan.values()) == 8


def test_distributed_worker_rejects_plain_http_remote(tmp_path: Path) -> None:
    from arenyxa.application.nextgen import DistributedWorker, DistributedWorkerService, SecretVault
    import pytest

    service = DistributedWorkerService(tmp_path / "workers", SecretVault(tmp_path / "secure"))
    with pytest.raises(ValueError):
        service.upsert(DistributedWorker("remote", "Remote", "http://192.0.2.1:8787", "worker.remote.token"))


def test_production_workflow_engine_resolves_scoped_and_secret_variables() -> None:
    from arenyxa.application.workflows import WorkflowEngine

    workflow = Workflow(
        name="variables",
        nodes=[
            WorkflowNode(
                kind="map",
                id="map",
                config={"constants": {"url": "${project.base_url}", "token": "${secret.api}"}},
            )
        ],
    )
    result = WorkflowEngine().execute(
        workflow,
        [{"source": 1}],
        scopes={"project": {"base_url": "https://example.com"}},
        secret_resolver=lambda name: "secret-value" if name == "api" else None,
    )
    assert result.outputs == [{"source": 1, "url": "https://example.com", "token": "secret-value"}]


def test_workflow_debugger_streams_and_bounds_input_queue() -> None:
    workflow = Workflow(
        name="bounded-debug",
        nodes=[WorkflowNode(kind="source", config={}, id="source")],
    )
    debugger = WorkflowDebugger(buffer_size=3)

    consumed = 0

    def inputs():
        nonlocal consumed
        for index in range(100):
            consumed += 1
            yield {"index": index}

    with pytest.raises(ArenyxaError) as caught:
        debugger.prepare(workflow, inputs())
    assert caught.value.code == "WORKFLOW_DEBUGGER_BUFFER_LIMIT"
    assert caught.value.context["area"] == "queue"
                                                                                        
                                                            
    assert consumed == 4
    assert len(debugger.queue) == 0
    assert debugger.finished is True


def test_workflow_debugger_bounds_fanout_and_terminal_history() -> None:
    fanout = Workflow(
        name="fanout-debug",
        nodes=[
            WorkflowNode(kind="source", config={}, id="source", next_ids=["sink-a", "sink-b"]),
            WorkflowNode(kind="sink", config={}, id="sink-a"),
            WorkflowNode(kind="sink", config={}, id="sink-b"),
        ],
    )
    debugger = WorkflowDebugger(buffer_size=1)
    debugger.prepare(fanout, [{"value": 1}])
    with pytest.raises(ArenyxaError) as caught:
        debugger.step()
    assert caught.value.code == "WORKFLOW_DEBUGGER_BUFFER_LIMIT"
    assert caught.value.context["area"] == "queue"
    assert debugger.finished is True
    assert len(debugger.queue) == 0

    terminal = Workflow(
        name="terminal-debug",
        nodes=[WorkflowNode(kind="sink", config={}, id="sink")],
    )
    debugger = WorkflowDebugger(buffer_size=1)
    debugger.prepare(terminal, [{"value": 1}])
    assert debugger.step().state == "completed"
    assert debugger.outputs == [{"value": 1}]
    with pytest.raises(ArenyxaError) as caught:
        debugger.retry_node("sink", {"value": 2})
        debugger.step()
    assert caught.value.code == "WORKFLOW_DEBUGGER_BUFFER_LIMIT"
    assert caught.value.context["area"] == "outputs"
