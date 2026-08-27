from dataclasses import asdict
from pathlib import Path

import pytest

from arenyxa.application.nextgen import BrowserAction, BrowserRecorderService, SelectorStudio, SmartPathV2
from arenyxa.application.web_intelligence import WebIntelligenceCenter, WebTimeMachine
from arenyxa.application.competitive import ContextBridgeService, WebIntelligenceEngine
from arenyxa.application.nextgen import DataSourceDiscovery, ProtocolInspector, RequestCodeGenerator
from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.models import FetchResponse, NetworkEvent, Workflow, WorkflowNode


def response(body: str, content_type: str = "text/html") -> FetchResponse:
    return FetchResponse(
        url="https://example.test/products",
        final_url="https://example.test/products",
        status=200,
        headers={"Content-Type": content_type},
        body=body.encode(),
        elapsed_ms=15.0,
        encoding="utf-8",
        content_type=content_type,
    )


def event(url: str, method: str = "GET", headers=None, response_headers=None, metadata=None) -> NetworkEvent:
    return NetworkEvent(
        session_id="cap-1",
        source_type=CaptureSource.BROWSER,
        protocol="https",
        direction="out",
        size=100,
        method=method,
        url=url,
        status=200,
        request_headers=headers or {},
        response_headers=response_headers or {"content-type": "application/json"},
        metadata=metadata or {"resource_type": "xhr"},
    )


def center(tmp_path: Path) -> WebIntelligenceCenter:
    smart = SmartPathV2()
    bridge = ContextBridgeService(RequestCodeGenerator())
    return WebIntelligenceCenter(
        intelligence=WebIntelligenceEngine(smart),
        sources=DataSourceDiscovery(),
        protocols=ProtocolInspector(),
        context_bridge=bridge,
        selector=SelectorStudio(),
        recorder=BrowserRecorderService(),
        time_machine=WebTimeMachine(tmp_path / "time-machine.json"),
    )


def test_smartpath_phase2_has_explainable_static_api_browser_path() -> None:
    result = SmartPathV2().analyze(
        response("<html><body>products</body></html>"),
        [event("https://example.test/api/products")],
    )
    assert [item["stage"] for item in result.execution_path] == [
        "static-html", "structured-endpoint", "browser-discovery-fallback"
    ]
    assert result.execution_path[1]["available"] is True
    assert result.execution_path[2]["decision"] in {"execute", "fallback"}


def test_web_intelligence_center_unifies_capture_protocol_and_safe_replay(tmp_path: Path) -> None:
    events = [
        event("https://example.test/api/products"),
        event("https://example.test/graphql", metadata={"resource_type": "graphql", "operationName": "Products"}),
    ]
    report = center(tmp_path).analyze(response("[]", "application/json"), events)
    assert report.recommended_engine == "api"
    assert report.data_sources
    assert report.endpoints[0].safe_to_replay is True
    assert report.graphql and report.graphql[0]["operation"] == "Products"
    assert report.decision_trace


def test_sensitive_query_header_and_non_idempotent_requests_are_never_auto_replayed(tmp_path: Path) -> None:
    service = center(tmp_path)
    sensitive = event(
        "https://example.test/api/me?token=super-secret&q=ok",
        headers={"Authorization": "Bearer also-secret", "X-Test": "1"},
    )
    candidate = service.classify_endpoint(sensitive)
    assert candidate is not None
    assert candidate.safe_to_replay is False
    assert candidate.persistable is False
    assert "super-secret" not in candidate.url
    assert "also-secret" not in str(asdict(candidate))
    with pytest.raises(ValueError, match="人工审查"):
        service.event_to_workflow(sensitive)
    reviewed = service.event_to_workflow(sensitive, require_safe=False)
    assert "super-secret" not in str(asdict(reviewed))
    assert "also-secret" not in str(asdict(reviewed))

    post = service.classify_endpoint(event("https://example.test/api/update", method="POST"))
    assert post is not None and post.safe_to_replay is False and post.review_required is True


def test_safe_capture_candidate_converts_to_redacted_workflow(tmp_path: Path) -> None:
    service = center(tmp_path)
    captured = event("https://example.test/api/products", headers={"X-Test": "1"})
    workflow = service.event_to_workflow(captured)
    payload = str(asdict(workflow))
    assert workflow.nodes[0].kind == "source"
    assert workflow.nodes[0].config["web_intelligence"]["sensitive_material_omitted"] is True
    assert "Authorization" not in payload and "Cookie" not in payload


def test_selector_recovery_uses_structure_history_and_separates_review_from_auto_apply() -> None:
    studio = SelectorStudio()
    old = '<main><section><button data-testid="buy">Buy now</button></section></main>'
    fingerprint = studio.analyze(old, 'button[data-testid="buy"]')["fingerprint"]
    new = '<main><section><div><button data-testid="buy">Buy now</button></div></section></main>'
    review = studio.heal_with_policy(
        new,
        fingerprint,
        history=[{"selector": 'button[data-testid="buy"]', "success": True}] * 3,
        auto_apply=False,
    )
    assert review["mode"] == "review-only" and review["selected"] is None
    assert review["candidates"]
    assert review["candidates"][0]["uniqueness_risk"] == "low"
    assert any("历史证据" in item for item in review["candidates"][0]["evidence"])

    auto = studio.heal_with_policy(
        new,
        fingerprint,
        history=[{"selector": 'button[data-testid="buy"]', "success": True}] * 3,
        auto_apply=True,
        min_confidence=0.80,
    )
    assert auto["selected"] is not None
    assert auto["selected"]["match_count"] == 1


def test_browser_recorder_semantic_compiler_recognizes_product_stages() -> None:
    recorder = BrowserRecorderService()
    actions = [
        BrowserAction("goto", url="https://example.test/login"),
        BrowserAction("fill", selector='input[name="email"]', value="user@example.test"),
        BrowserAction("click", selector='button[data-testid="login"]'),
        BrowserAction("fill", selector='input[type="search"]', value="camera"),
        BrowserAction("press", selector='input[type="search"]', value="Enter"),
        BrowserAction("click", selector='a[rel="next"]', metadata={"role": "pagination"}),
        BrowserAction("assert_text", selector=".result-list", value="camera", metadata={"purpose": "extract"}),
        BrowserAction("download", selector="#export"),
    ]
    stages = recorder.compile_semantics(actions)
    kinds = [item.kind for item in stages]
    assert "login" in kinds
    assert "search" in kinds
    assert "pagination" in kinds
    assert "extraction" in kinds
    assert "download" in kinds
    workflow = recorder.to_semantic_workflow(actions)
    assert any("semantic_stage" in node.config for node in workflow.nodes)


def test_time_machine_links_exact_evidence_by_hash_without_persisting_raw_content(tmp_path: Path) -> None:
    service = WebTimeMachine(tmp_path / "time-machine.json")
    workflow = Workflow(name="demo", nodes=[WorkflowNode(kind="sink", config={}, id="sink")])
    entry = service.record(
        url="https://example.test/page?token=secret-token&q=ok",
        dom="<html>private-dom-content</html>",
        response=response('{"private":"response-content"}', "application/json"),
        selector="#product",
        workflow=workflow,
        dataset_revision="revision_42",
        metadata={"source": "test", "nested": {"api_token": "metadata-secret", "safe": "ok"}},
    )
    assert entry.dom_sha256 and entry.response_sha256 and entry.workflow_definition_sha256
    assert entry.dataset_revision == "revision_42"
    persisted = (tmp_path / "time-machine.json").read_text(encoding="utf-8")
    assert "secret-token" not in persisted
    assert "private-dom-content" not in persisted
    assert "response-content" not in persisted
    assert "metadata-secret" not in persisted
    assert service.history(url="https://example.test/page?token=anything&q=ok")
