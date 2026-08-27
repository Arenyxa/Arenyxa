from __future__ import annotations

from pathlib import Path

import pytest

from arenyxa.application.command_runtime import CommandRuntimeError
from arenyxa.application.developer_safety import DEVELOPER_TERMS_VERSION
from arenyxa.application.professional_pivot import ProfessionalPivotService
from arenyxa.bootstrap import bootstrap
from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.models import CaptureSession, NetworkEvent


@pytest.fixture()
def context(tmp_path: Path):
    value = bootstrap(tmp_path / "runtime", start_scheduler=False)
    value.settings.developer_mode = True
    value.settings.developer_terms_version = DEVELOPER_TERMS_VERSION
    value.settings.developer_terms_accepted_at = "2026-08-18T12:00:00+00:00"
    value.settings.save(value.paths.root / "settings.json")
    try:
        yield value
    finally:
        value.shutdown()


def _captured_exchange(context):
    session = CaptureSession("pivot", CaptureSource.BROWSER)
    context.store.save_capture(session)
    event = NetworkEvent(
        session.id,
        CaptureSource.BROWSER,
        "https",
        "bidirectional",
        2048,
        id="pivot-event",
        request_ref="pivot-request",
        flow_ref="pivot-flow",
        method="POST",
        url="https://api.example.test/v1/items?token=do-not-leak&page=2",
        host="api.example.test",
        status=503,
        request_headers={"Authorization": "Bearer do-not-leak", "X-Trace": "safe-trace"},
        response_headers={"Content-Type": "application/json", "Set-Cookie": "session=do-not-leak"},
        timing={"total_ms": 1250.0},
        response_body_ref="body-response",
    )
    context.store.append_network_events([event])
    exchange = context.store.get_http_exchange_by_event(event.id)
    assert exchange is not None
    return event, exchange


def test_professional_pivot_is_redacted_bounded_and_side_effect_free(context) -> None:
    event, exchange = _captured_exchange(context)
    service = ProfessionalPivotService(context.store)
    artifact = service.from_request(exchange["request_id"])
    assert artifact is not None
    snapshot = artifact.snapshot()
    serialized = repr(snapshot)
    assert "do-not-leak" not in serialized
    assert snapshot["request"]["headers"]["Authorization"] == "<redacted>"
    assert snapshot["request"]["query"]["token"] == "<redacted>"
    assert snapshot["response"]["headers"]["Set-Cookie"] == "<redacted>"
    assert snapshot["analysis"]["error_response"] is True
    assert snapshot["analysis"]["slow_response"] is True
    assert {action["workspace"] for action in snapshot["actions"]} >= {
        "Packet Intelligence", "Proxy", "Extraction Lab", "Flow Designer"
    }
    assert context.store.get_http_exchange_by_event(event.id) == exchange


def test_professional_pivot_cli_supports_request_and_event(context) -> None:
    event, exchange = _captured_exchange(context)
    runtime = context.command_runtime
    assert runtime.complete("pi") == ["pivot"]
    request_result = runtime.execute(f"pivot request {exchange['request_id']}")["data"]
    event_result = runtime.execute(f"pivot event {event.id}")["data"]
    assert request_result["request"]["request_id"] == event_result["request"]["request_id"]
    assert request_result["source_kind"] == "request"
    assert event_result["source_kind"] == "event"
    with pytest.raises(CommandRuntimeError) as captured:
        runtime.execute("pivot event missing-event")
    assert captured.value.code == "PIVOT_SOURCE_NOT_FOUND"
