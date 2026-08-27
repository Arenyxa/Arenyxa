from __future__ import annotations

from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.models import NetworkEvent
from arenyxa.infrastructure.capture.professional import (
    FlowWorkbench,
    NoCodeExtractionPlanner,
    PassiveSecurityAuditor,
    ProfessionalAnalysisSuite,
    ProtocolWorkbench,
)


def event(**kwargs):
    base = dict(session_id="capture_1", source_type=CaptureSource.HTTP_RUNNER, protocol="https", direction="out", size=256)
    base.update(kwargs)
    return NetworkEvent(**base)


def test_protocol_workbench_filters_and_groups() -> None:
    events = [
        event(flow_ref="f1", host="api.example", method="GET", status=200, url="https://api.example/v1/items", response_headers={"content-type": "application/json"}),
        event(flow_ref="f1", host="api.example", method="GET", status=200, url="https://api.example/v1/items?page=2", response_headers={"content-type": "application/json"}),
        event(flow_ref="f2", protocol="websocket", host="stream.example", url="wss://stream.example/socket"),
    ]
    analysis = ProtocolWorkbench().analyze(events, 'http.host == "api.example"')
    assert analysis.total_events == 2
    assert analysis.protocols == {"https": 2}
    assert analysis.conversations[0].events == 2
    assert any("api.example" in item for item in analysis.suggested_filters)


def test_no_code_planner_prefers_captured_structured_api() -> None:
    events = [event(host="api.example", method="GET", status=200, url="https://api.example/items?page=2", response_headers={"content-type": "application/json"})]
    plan = NoCodeExtractionPlanner().build(events, "https://example/app")
    assert plan.recommended_mode == "api"
    assert plan.structured_sources
    assert plan.pagination[0]["parameter"] == "page"
    assert any(step["kind"] == "capture_structured_source" for step in plan.steps)


def test_passive_security_auditor_reports_only_observed_configuration() -> None:
    item = event(
        protocol="http",
        host="example.com",
        method="GET",
        url="http://example.com/account",
        request_headers={"Authorization": "Bearer redacted"},
        response_headers={"Content-Type": "text/html", "Set-Cookie": "sid=abc", "Server": "demo"},
    )
    findings = PassiveSecurityAuditor().audit([item])
    codes = {finding.code for finding in findings}
    assert "TRANSPORT_PLAINTEXT" in codes
    assert "AUTH_OVER_PLAINTEXT" in codes
    assert "CSP_MISSING" in codes
    assert "COOKIE_HTTPONLY_MISSING" in codes


def test_flow_workbench_redacts_captured_credentials() -> None:
    item = event(host="example.com", method="GET", url="https://example.com/api", request_headers={"Authorization": "Bearer secret", "Accept": "application/json"})
    snapshot = FlowWorkbench().prepare_event(item)
    assert "Bearer secret" not in str(snapshot.request)
    assert snapshot.unresolved_secrets


def test_professional_suite_unifies_network_extraction_and_passive_audit() -> None:
    events = [event(host="api.example", method="GET", status=200, url="https://api.example/items?cursor=abc", response_headers={"content-type": "application/json"})]
    result = ProfessionalAnalysisSuite().analyze(events, source_url="https://example/app")
    assert result.protocol.total_events == 1
    assert result.extraction.recommended_mode == "api"
    assert isinstance(result.passive_findings, list)
