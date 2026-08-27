from __future__ import annotations

from pathlib import Path

import pytest

from arenyxa.application.developer_safety import DEVELOPER_TERMS_VERSION
from arenyxa.bootstrap import bootstrap
from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.capture.packet_lab import OfflinePacketLab


@pytest.fixture()
def context(tmp_path: Path):
    value = bootstrap(tmp_path / "runtime", start_scheduler=False)
    value.settings.developer_mode = True
    value.settings.developer_terms_version = DEVELOPER_TERMS_VERSION
    value.settings.developer_terms_accepted_at = "2026-08-22T12:00:00+00:00"
    value.settings.save(value.paths.root / "settings.json")
    try:
        yield value
    finally:
        value.shutdown()


def _sample_pcap(path: Path) -> Path:
    packet = OfflinePacketLab.ipv4_udp(
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        src_port=40000,
        dst_port=53,
        payload=b"arenyxa-phase3",
    )
    OfflinePacketLab.write_pcap(path, packet, linktype=101, timestamp=1.0)
    return path


def test_phase3_traffic_control_is_bootstrapped_and_cli_connected(context) -> None:
    assert context.traffic_control is not None
    assert context.local_control_session is not None
    assert {"data.read", "data.export", "capture.run", "replay.run"}.issubset(
        context.local_control_session.granted_capabilities
    )

    payload = context.command_runtime.execute("traffic status")["data"]
    assert payload["schema"] == "arenyxa.traffic-control/v1"
    assert payload["capture"]["queue"]["capacity"] == context.capture.queue_capacity
    assert payload["capture"]["queue"]["size"] <= payload["capture"]["queue"]["capacity"]
    assert payload["proxy"]["running"] is False
    assert payload["mitm"]["running"] is False

    # Existing compatibility commands now consume the same Phase 3 service.
    assert context.command_runtime.execute("proxy status")["data"] == payload["proxy"]
    assert context.command_runtime.execute("mitm status")["data"] == payload["mitm"]


def test_phase3_protocol_catalog_and_existing_packet_command_share_service(context, monkeypatch) -> None:
    traffic = context.traffic_control
    assert traffic is not None
    calls = {"count": 0}
    original = traffic.protocol_catalog

    def wrapped(**kwargs):
        calls["count"] += 1
        return original(**kwargs)

    monkeypatch.setattr(traffic, "protocol_catalog", wrapped)
    compatibility = context.command_runtime.execute("packet protocols --limit 200")["data"]
    canonical = context.command_runtime.execute("traffic protocols --limit 200")["data"]
    assert calls["count"] == 2
    assert compatibility["registry"]["protocol_names"] >= 80
    assert canonical["registry"]["protocol_names"] == compatibility["registry"]["protocol_names"]

    fields = context.command_runtime.execute("traffic fields --contains frame.number --limit 20")["data"]
    assert any(row["abbreviation"] == "frame.number" for row in fields["fields"])


def test_phase3_capture_analysis_runs_as_bounded_persistent_job(context) -> None:
    capture = _sample_pcap(context.paths.projects / "phase3-sample.pcap")
    result = context.command_runtime.execute(
        f"traffic analyze {capture.name} --timeout 30 --wait"
    )["data"]
    assert result["state"] == "succeeded"
    assert result["kind"] == "capture-analysis"
    assert result["result"]["path"] == str(capture)
    assert len(result["result"]["sha256"]) == 64
    assert "capture" in result["result"]
    assert "statistics" in result["result"]

    stored = context.store.get_platform_job(result["id"])
    assert stored is not None and stored["state"] == "succeeded"
    valid, reason = context.security.audit.verify()
    assert valid is True, reason


def test_phase3_corrupt_capture_failure_isolated_to_job(context) -> None:
    broken = context.paths.projects / "broken-phase3.pcap"
    broken.write_bytes(b"this-is-not-a-pcap")
    traffic = context.traffic_control
    assert traffic is not None
    session = context.local_control_session
    assert session is not None

    job = traffic.submit_capture_analysis(
        broken,
        session=session,
        surface="test",
        timeout_seconds=10,
    )
    completed = context.job_system.wait(job["id"], 10)
    assert completed["state"] == "failed"
    assert completed["error_code"]

    # One malformed capture must not take down capture/proxy/protocol services.
    status = traffic.status(session=session, surface="test")
    assert status["capture"]["healthy"] is True
    assert status["proxy"]["running"] is False
    assert traffic.protocol_catalog(session=session, surface="test", limit=20)["count"] > 0


def test_phase3_input_budgets_and_path_confinement_fail_closed(context, tmp_path: Path) -> None:
    traffic = context.traffic_control
    session = context.local_control_session
    assert traffic is not None and session is not None

    with pytest.raises(ArenyxaError) as oversized:
        traffic.decode_protocol(
            "dns",
            b"x" * (4 * 1024 * 1024 + 1),
            session=session,
            surface="test",
        )
    assert oversized.value.code == "PROTOCOL_BUDGET_EXCEEDED"

    outside = tmp_path / "outside.pcap"
    _sample_pcap(outside)
    with pytest.raises(ArenyxaError) as escaped:
        traffic.submit_capture_analysis(outside, session=session, surface="test")
    assert escaped.value.code == "TRAFFIC_PATH_OUTSIDE_ALLOWED_ROOT"


def test_phase3_proxy_history_is_bounded_and_audited(context) -> None:
    traffic = context.traffic_control
    session = context.local_control_session
    assert traffic is not None and session is not None
    page = traffic.proxy_history(
        session=session,
        surface="test",
        page=1,
        page_size=100_000,
    )
    assert isinstance(page, dict)
    assert len(page.get("items", [])) <= 1000
    valid, reason = context.security.audit.verify()
    assert valid is True, reason
