from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

import pytest

from arenyxa.application.competitive import (
    CompatibilityLab,
    ContextBridgeService,
    ReliabilityAdvisor,
    WebIntelligenceEngine,
    WorkflowPortabilityService,
)
from arenyxa.application.nextgen import RequestCodeGenerator, SmartPathV2
from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.models import FetchResponse, NetworkEvent, Workflow, WorkflowNode


def _response(body: str, content_type: str = "text/html", status: int = 200) -> FetchResponse:
    return FetchResponse(
        url="https://example.com",
        final_url="https://example.com",
        status=status,
        headers={"Content-Type": content_type},
        body=body.encode(),
        elapsed_ms=100.0,
        encoding="utf-8",
        content_type=content_type,
    )


def _event(url: str, *, headers=None, response_headers=None, protocol: str = "https") -> NetworkEvent:
    return NetworkEvent(
        session_id="capture-1",
        source_type=CaptureSource.BROWSER,
        protocol=protocol,
        direction="out",
        size=512,
        method="GET",
        url=url,
        status=200,
        request_headers=headers or {},
        response_headers=response_headers or {"content-type": "application/json"},
    )


def test_explainable_blueprint_contains_decision_trace_costs_and_fallback() -> None:
    engine = WebIntelligenceEngine(SmartPathV2())
    response = _response("<html><script id='__NEXT_DATA__'>{}</script></html>")
    events = [_event("https://example.com/api/products") for _ in range(4)]
    blueprint = engine.analyze(response, events)
    assert blueprint.recommended_engine == "api"
    assert blueprint.confidence > 0.6
    assert any(item.code == "API_DISCOVERED" for item in blueprint.decision_trace)
    assert blueprint.fallback_chain
    assert {item.engine for item in blueprint.engine_estimates} == {"api", "http", "browser", "distributed"}
    selected = next(item for item in blueprint.engine_estimates if item.engine == "api")
    browser = next(item for item in blueprint.engine_estimates if item.engine == "browser")
    assert selected.resource_efficiency > browser.resource_efficiency
    assert blueprint.workflow.nodes[0].config["engine"] == "api"


def test_blueprint_reports_session_and_rate_limit_risks() -> None:
    engine = WebIntelligenceEngine(SmartPathV2())
    response = _response("<html>" + "<script>x=1</script>" * 25 + "</html>", status=429)
    events = [_event("https://example.com/page", headers={"Cookie": "session=secret"}, response_headers={"content-type": "text/html"})]
    blueprint = engine.analyze(response, events)
    codes = {item["code"] for item in blueprint.risk_flags}
    assert "RATE_LIMIT" in codes
    assert "SESSION_DEPENDENCY" in codes


def test_context_bridge_omits_sensitive_headers_and_builds_reviewable_bundle() -> None:
    event = _event(
        "https://example.com/api/items",
        headers={"Authorization": "Bearer secret", "Cookie": "sid=secret", "X-Test": "1"},
    )
    bridge = ContextBridgeService(RequestCodeGenerator())
    spec = bridge.event_to_request(event)
    assert spec.headers == {"X-Test": "1"}
    assert spec.cookies == {}
    bundle = bridge.event_bundle(event)
    assert bundle["sensitive_material_omitted"] is True
    assert "secret" not in str(bundle)
    assert "curl" in bundle["code"] and "python" in bundle["code"]
    assert bundle["workflow"]["nodes"][0]["kind"] == "source"


def test_portable_workflow_round_trip_is_deterministic_and_rejects_tampering() -> None:
    service = WorkflowPortabilityService()
    workflow = Workflow(
        name="Portable",
        id="portable",
        nodes=[
            WorkflowNode(kind="source", config={"base": "${project.base_url}", "token": "${secret.api_token}"}, id="source", next_ids=["sink"]),
            WorkflowNode(kind="sink", config={}, id="sink"),
        ],
    )
    first = service.dumps(workflow)
    second = service.dumps(workflow)
    assert first == second
    loaded = service.load(first)
    assert loaded.name == workflow.name
    assert [node.id for node in loaded.nodes] == ["source", "sink"]

    tampered = first.replace("Portable", "Tampered", 1)
    with pytest.raises(ValueError, match="SHA-256"):
        service.load(tampered)


def test_portable_workflow_rejects_inline_secrets() -> None:
    service = WorkflowPortabilityService()
    workflow = Workflow(
        name="Unsafe",
        nodes=[WorkflowNode(kind="source", config={"api_token": "plain-secret"}, id="source")],
    )
    with pytest.raises(ValueError, match="内联秘密"):
        service.dumps(workflow)


def test_compatibility_lab_offline_baseline_is_deterministic() -> None:
    lab = CompatibilityLab(WebIntelligenceEngine(SmartPathV2()))
    report = lab.run()
    assert report["scope"] == "offline deterministic fixtures"
    assert report["cases"] >= 6
    assert report["pass_rate"] == 1.0
    assert report["engine_accuracy"] == 1.0
    assert report["source_recall"] == 1.0
    assert "实时第三方网站" in report["disclaimer"]


def test_reliability_advisor_prioritizes_rate_limit_selector_and_schema() -> None:
    result = ReliabilityAdvisor().assess(
        current_quality=72,
        baseline_quality=96,
        selector_confidence=0.55,
        error_rate=0.18,
        schema_changes=3,
        rate_limited=True,
    )
    actions = [item["action"] for item in result["actions"]]
    assert result["reliability_score"] < 80
    assert actions[0] == "adaptive-rate-limit"
    assert "selector-self-heal" in actions
    assert "schema-diff" in actions
    assert "smartpath-replan" in actions
