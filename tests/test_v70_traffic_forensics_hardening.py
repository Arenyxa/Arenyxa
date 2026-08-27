from __future__ import annotations

from pathlib import Path

import pytest

from arenyxa.application.traffic_forensics import TrafficForensicsAnalyzer
from arenyxa.infrastructure.capture.professional import MessageCodec


def _event(index: int, **overrides):
    event = {
        "id": f"event-{index}",
        "timestamp": f"2026-08-19T00:00:{index:02d}+00:00",
        "protocol": "http",
        "host": "api.example.test",
        "url": "https://api.example.test/v1/items",
        "method": "GET",
        "status": 200,
        "size": 1024,
        "flow_ref": f"flow-{index // 2}",
        "timing": {"duration_ms": 20 + index},
        "request_headers": {},
        "sensitivity": [],
        "metadata": {},
    }
    event.update(overrides)
    return event


def test_pytest_configuration_discovers_src_layout() -> None:
    source = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert 'pythonpath = ["src"]' in source


def test_message_codec_rejects_invalid_mode_operation_pairs() -> None:
    codec = MessageCodec()
    assert codec.transform('{"b":1,"a":2}', "json", "format").output.startswith("{\n")
    with pytest.raises(ValueError, match="Unsupported url codec operation"):
        codec.transform("a%20b", "url", "format")
    with pytest.raises(ValueError, match="Unsupported json codec operation"):
        codec.transform("{}", "json", "decode")


def test_traffic_forensics_is_bounded_and_redacts_sensitive_values() -> None:
    events = [_event(i) for i in range(12)]
    for index in range(5):
        events[index]["status"] = 503
        events[index]["timing"] = {"duration_ms": 3_000 + index}
    events[5].update(
        url="http://api.example.test/login",
        request_headers={"Authorization": "Bearer top-secret", "Cookie": "session=secret"},
        sensitivity=["credential"],
    )
    events[6]["size"] = 12 * 1024 * 1024

    snapshot = TrafficForensicsAnalyzer().analyze(events, timeline_limit=5).as_dict()
    assert snapshot["event_count"] == 12
    assert snapshot["flow_count"] == 6
    assert len(snapshot["timeline"]) == 5
    kinds = {item["kind"] for item in snapshot["findings"]}
    assert {"host-error-spike", "host-latency-spike", "plaintext-sensitive", "large-transfer"}.issubset(kinds)
    serialized = str(snapshot)
    assert "top-secret" not in serialized
    assert "session=secret" not in serialized
    plaintext = next(item for item in snapshot["findings"] if item["kind"] == "plaintext-sensitive")
    assert plaintext["evidence"]["header_names"] == ["authorization", "cookie"]


def test_professional_suite_exposes_independent_traffic_forensics_tab() -> None:
    root = Path(__file__).resolve().parents[1]
    suite = (root / "src/arenyxa/presentation/pages/professional_suite.py").read_text(encoding="utf-8")
    page = (root / "src/arenyxa/presentation/pages/traffic_forensics.py").read_text(encoding="utf-8")
    assert 'self.tabs.addTab(self.forensics_page, "Traffic Forensics")' in suite
    assert 'PageHeader(\n                "Traffic Forensics"' in page
    assert "iter_network_events" in page
    assert "atomic_write_json" in page



def test_welcome_contract_gate_tracks_split_navigation_module() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "scripts/verify_welcome_window_contract.py").read_text(encoding="utf-8")
    assert 'main_window_navigation.py' in source
    assert 'window_surface = main_window + "\\n" + navigation' in source
    assert '"modal execution": "dialog.exec()" in window_surface' in source
