from __future__ import annotations

import json

from arenyxa.application.advanced import (
    ApiMapper,
    PerformanceProfiler,
    SecurityAnalyzer,
    SmartExecutionPlanner,
    WebsiteIntelligenceMapper,
)
from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.models import CaptureSession, FetchResponse, NetworkEvent
from arenyxa.infrastructure.capture.filtering import FilterEngine, FilterSyntaxError
from arenyxa.infrastructure.capture.har import HarAnalyzer


def event(**overrides) -> NetworkEvent:
    values = {
        "session_id": "capture_test",
        "source_type": CaptureSource.BROWSER,
        "protocol": "https",
        "direction": "bidirectional",
        "size": 640,
        "method": "GET",
        "url": "https://api.example.com/api/items/42?page=2",
        "status": 500,
        "host": "api.example.com",
        "timing": {"total_ms": 120.0},
        "response_headers": {"content-type": "application/json"},
    }
    values.update(overrides)
    return NetworkEvent(**values)


def test_filter_engine_is_deterministic_and_does_not_eval() -> None:
    predicate = FilterEngine().compile('http.host endsWith ".example.com" && http.status >= 400')
    assert predicate(event()) is True
    assert predicate(event(status=200)) is False
    try:
        FilterEngine().compile("__import__('os')")
    except FilterSyntaxError:
        pass
    else:
        raise AssertionError("unsafe expression was accepted")


def test_har_analysis(tmp_path) -> None:
    har = {
        "log": {
            "pages": [{"title": "https://example.com"}],
            "entries": [
                {
                    "startedDateTime": "2026-01-01T00:00:00Z",
                    "time": 75,
                    "request": {"method": "GET", "url": "https://example.com/api", "headers": []},
                    "response": {
                        "status": 200,
                        "headers": [],
                        "bodySize": 99,
                        "content": {"size": 99, "mimeType": "application/json"},
                    },
                    "timings": {"wait": 50, "receive": 25},
                }
            ],
        }
    }
    path = tmp_path / "session.har"
    path.write_text(json.dumps(har), encoding="utf-8")
    events, summary = HarAnalyzer.load(path, CaptureSession("HAR", CaptureSource.HAR_IMPORT))
    assert len(events) == summary.request_count == 1
    assert summary.total_bytes == 99
    assert summary.timing_p95_ms == 75


def test_advanced_platform_analysis() -> None:
    events = [event(), event(url="https://api.example.com/api/items/99?page=3", status=200)]
    response = FetchResponse(
        "https://example.com",
        "https://example.com",
        200,
        {"Content-Type": "application/json"},
        b"{}",
        20,
        "utf-8",
        "application/json",
    )
    assert SmartExecutionPlanner().plan(response, events).engine == "api"
    assert ApiMapper().analyze(events)[0]["path"] == "/api/items/{id}"
    assert WebsiteIntelligenceMapper().build(events).nodes
    assert PerformanceProfiler().summarize(events)["failed"] == 1
    assert any(finding["code"].startswith("SEC_HEADER") for finding in SecurityAnalyzer().analyze(response))
