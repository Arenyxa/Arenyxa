from __future__ import annotations

import json

from arenyxa.application.extraction_studio import ExtractionDryRun, ExtractionField
from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.models import NetworkEvent


def _event(ref: str, content_type: str) -> NetworkEvent:
    return NetworkEvent("capture", CaptureSource.BROWSER, "HTTP", "response", 10, response_body_ref=ref, response_headers={"content-type": content_type})


def test_jsonpath_local_dry_run_extracts_without_network() -> None:
    body = json.dumps({"items": [{"name": "A"}, {"name": "B"}]}).encode()
    result = ExtractionDryRun().preview(
        [_event("body-json", "application/json")],
        [ExtractionField("names", "jsonpath", "$.items[*].name", multiple=True)],
        lambda ref, limit: body if ref == "body-json" else None,
    )
    assert result.records == [{"names": ["A", "B"]}]


def test_html_local_dry_run_supports_css_and_xpath() -> None:
    body = b"<html><body><h1 data-id='7'>Title</h1><p>Hello</p></body></html>"
    result = ExtractionDryRun().preview(
        [_event("body-html", "text/html")],
        [ExtractionField("title", "css", "h1"), ExtractionField("id", "xpath", "//h1", attribute="data-id")],
        lambda ref, limit: body,
    )
    assert result.records[0]["title"] == "Title"
    assert result.records[0]["id"] == "7"


def test_dry_run_is_bounded_to_stored_bodies() -> None:
    result = ExtractionDryRun().preview([], [ExtractionField("x", "css", "x")], lambda ref, limit: None)
    assert result.records == []
    assert result.warnings
