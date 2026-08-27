from __future__ import annotations

from pathlib import Path

import pytest

from arenyxa.application.extraction_studio import ExtractionField, ExtractionStudioService
from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import NetworkEvent
from arenyxa.infrastructure.capture.professional import MessageCodec, MessageComparer
from arenyxa.security.network_guard import NetworkGuardPolicy, NetworkUseGuard


def _event(url: str) -> NetworkEvent:
    return NetworkEvent(
        session_id="capture-test",
        source_type=CaptureSource.BROWSER,
        protocol="http",
        direction="outbound",
        size=128,
        method="GET",
        url=url,
        host="example.com",
        status=200,
        response_headers={"content-type": "application/json"},
    )


def test_extraction_studio_discovers_api_and_compiles_workflow() -> None:
    service = ExtractionStudioService()
    result = service.analyze(
        [_event("https://example.com/api/items?page=1&limit=20")],
        source_url="https://example.com/products",
        fields=[ExtractionField("title", "css", ".product-title", required=True)],
    )
    assert result.recommended_mode == "api"
    assert result.discovered_sources
    assert result.pagination
    assert result.workflow_draft["schema"] == "arenyxa.extraction-workflow/v1"
    assert any(node["kind"] == "extract" for node in result.workflow_draft["nodes"])


def test_extraction_field_rejects_unknown_selector() -> None:
    with pytest.raises(ValueError):
        ExtractionField("x", "unknown", "value").normalized()


def test_message_codec_and_comparer_are_bounded_local_tools() -> None:
    codec = MessageCodec()
    encoded = codec.transform("hello world", "base64", "encode")
    decoded = codec.transform(encoded.output, "base64", "decode")
    assert decoded.output == "hello world"
    compared = MessageComparer().compare("a\nb", "a\nc")
    assert compared.equal is False
    assert compared.changed_lines == 2
    assert "-b" in compared.unified_diff and "+c" in compared.unified_diff


def test_network_guard_blocks_multiple_metadata_forms() -> None:
    guard = NetworkUseGuard(NetworkGuardPolicy())
    for target in ("169.254.169.254", "100.100.100.200", "fd00:ec2::254", "metadata.google.internal"):
        with pytest.raises(ArenyxaError) as captured:
            guard.check_target(target, resolve_dns=False)
        assert captured.value.code == "NETWORK_PROTECTED_TARGET"


def test_network_guard_rejects_high_cardinality_target_churn() -> None:
    policy = NetworkGuardPolicy(
        max_concurrent_connections=4,
        max_global_connects_per_minute=20,
        max_target_connects_per_minute=10,
        max_distinct_targets_per_minute=2,
        max_tracked_targets=2,
    )
    guard = NetworkUseGuard(policy)
    with guard.connection("127.0.0.1"):
        pass
    with guard.connection("127.0.0.2"):
        pass
    with pytest.raises(ArenyxaError) as captured:
        with guard.connection("127.0.0.3"):
            pass
    assert captured.value.code == "NETWORK_TARGET_FANOUT_LIMIT"
    assert guard.snapshot()["tracked_targets"] <= 2


def test_independent_extraction_navigation_is_wired() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "src" / "arenyxa" / "presentation" / "main_window_registry.py").read_text(encoding="utf-8")
    assert '("extraction", "⌗", "nav.extraction", ExtractionStudioPage, "core")' in source
    assert "ProfessionalSuitePage" not in source


def test_proxy_autoresponder_is_persistent_bounded_and_avoids_upstream(tmp_path, monkeypatch) -> None:
    from arenyxa.infrastructure.capture.proxy import InterceptingProxy

    proxy = InterceptingProxy(tmp_path / "proxy")
    rule = proxy.add_autoresponder_rule(
        "api.example.com", "/v1/*", method="GET", status=201,
        reason="Created Locally", content_type="application/json", body='{"source":"local"}',
    )
    assert rule["status"] == 201
    reopened = InterceptingProxy(tmp_path / "proxy")
    assert reopened.autoresponder_rules()[0]["id"] == rule["id"]

    class Client:
        def __init__(self) -> None:
            self.payload = b""
        def sendall(self, value: bytes) -> None:
            self.payload += value

    def forbidden_upstream(*_args, **_kwargs):
        raise AssertionError("AutoResponder must not open an upstream socket")

    import arenyxa.infrastructure.capture.proxy as proxy_module
    monkeypatch.setattr(proxy_module.socket, "create_connection", forbidden_upstream)
    client = Client()
    reopened._handle_http(
        client, "127.0.0.1",
        b"GET http://api.example.com/v1/users HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n",
        scheme_hint="http",
    )
    assert b"HTTP/1.1 201 Created Locally" in client.payload
    assert b"X-Arenyxa-AutoResponder: 1" in client.payload
    assert b'{"source":"local"}' in client.payload
    assert reopened.history()[-1].status == 201

    with pytest.raises(ValueError):
        reopened.add_autoresponder_rule("api.example.com", "/huge", body="x" * (2 * 1024 * 1024 + 1))


def test_proxy_page_exposes_rules_autoresponder_workspace() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "src" / "arenyxa" / "presentation" / "pages" / "proxy.py").read_text(encoding="utf-8")
    assert '"Rules Engine"' in source
    assert "add_autoresponder_rule" in source


def test_proxy_match_replace_rules_are_persistent_bounded_and_recalculate_length(tmp_path) -> None:
    from arenyxa.infrastructure.capture.proxy import InterceptingProxy

    proxy = InterceptingProxy(tmp_path / "proxy-rewrite")
    header_rule = proxy.add_match_replace_rule(
        "request", "header", "old", "new", host_pattern="api.example.com",
        path_pattern="/v1/*", method="POST", header_name="X-Test",
    )
    body_rule = proxy.add_match_replace_rule(
        "request", "body", "alpha", "alpha-expanded", host_pattern="api.example.com",
        path_pattern="/v1/*", method="POST",
    )
    raw = (
        b"POST /v1/items HTTP/1.1\r\nHost: api.example.com\r\nX-Test: old-value\r\n"
        b"Content-Length: 5\r\n\r\nalpha"
    )
    rewritten, applied = proxy._apply_match_replace(raw, "request", "POST", "api.example.com", "/v1/items")
    assert set(applied) == {header_rule["id"], body_rule["id"]}
    assert b"X-Test: new-value" in rewritten
    assert rewritten.endswith(b"alpha-expanded")
    assert b"Content-Length: 14\r\n" in rewritten

    reopened = InterceptingProxy(tmp_path / "proxy-rewrite")
    assert len(reopened.match_replace_rules()) == 2
    assert reopened.remove_match_replace_rule(header_rule["id"]) is True
    assert len(reopened.match_replace_rules()) == 1

    with pytest.raises(ValueError):
        reopened.add_match_replace_rule("request", "header", "x", "bad\r\nInjected: 1", header_name="X-Test")


def test_proxy_page_exposes_match_replace_workspace() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "src" / "arenyxa" / "presentation" / "pages" / "proxy.py").read_text(encoding="utf-8")
    assert '"Match / Replace"' in source
    assert "add_match_replace_rule" in source
