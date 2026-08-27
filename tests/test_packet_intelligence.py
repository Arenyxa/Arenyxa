from __future__ import annotations

from pathlib import Path

from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.models import CaptureSession
from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine, PacketExecutionProfile


def test_packet_summary_maps_packet_analysis_fields(tmp_path: Path, monkeypatch) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"pcapng")
    engine = PacketAnalysisEngine("tshark")
    engine._supported_field_cache = set(engine.SUMMARY_FIELDS)
    values = {field: "" for field in engine.SUMMARY_FIELDS}
    values.update({
        "frame.number": "42",
        "frame.time_epoch": "1786233600.125",
        "frame.len": "512",
        "frame.cap_len": "512",
        "frame.protocols": "eth:ethertype:ip:tcp:tls:http2",
        "_ws.col.Protocol": "HTTP2",
        "_ws.col.Info": "HEADERS[1]: GET /api",
        "ip.src": "10.0.0.2",
        "ip.dst": "203.0.113.9",
        "tcp.srcport": "53000",
        "tcp.dstport": "443",
        "tcp.stream": "7",
        "http2.streamid": "1",
        "tls.handshake.extensions_server_name": "example.com",
        "http.request.method": "GET",
        "http.request.uri": "/api",
        "http.response.code": "200",
        "tcp.analysis.retransmission": "1",
        "tcp.analysis.bytes_in_flight": "4096",
        "tcp.analysis.ack_rtt": "0.0125",
    })
    line = "\t".join(f'"{values[field]}"' for field in engine.SUMMARY_FIELDS)
    monkeypatch.setattr(engine, "_run_tshark", lambda *args, **kwargs: line + "\n")
    packets = engine.packet_summaries(capture)
    assert len(packets) == 1
    packet = packets[0]
    assert packet.frame_number == 42
    assert packet.protocol == "HTTP2"
    assert packet.tcp_stream == 7
    assert packet.http2_stream == 1
    assert packet.host == "example.com"
    assert packet.tcp_analysis == ["retransmission"]
    assert packet.metadata["tcp_bytes_in_flight"] == 4096
    assert packet.metadata["tcp_ack_rtt_ms"] == 12.5


def test_follow_stream_uses_supported_packet_analysis_follow_tap(tmp_path: Path, monkeypatch) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"pcapng")
    engine = PacketAnalysisEngine("tshark")
    seen = {}

    def fake_tap(capture_value, tap, profile):
        seen["capture"] = Path(capture_value)
        seen["tap"] = tap
        return "stream"

    monkeypatch.setattr(engine, "_tap", fake_tap)
    assert engine.follow_stream(capture, "http2", "3,9", "hex") == "stream"
    assert seen["tap"] == "follow,http2,hex,3,9"


def test_execution_profile_maps_decode_as_preferences_and_decryption(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    keylog = tmp_path / "keys.log"
    keytab = tmp_path / "krb.keytab"
    capture.write_bytes(b"pcapng")
    keylog.write_text("CLIENT_RANDOM", encoding="utf-8")
    keytab.write_bytes(b"keytab")
    engine = PacketAnalysisEngine("tshark")
    profile = PacketExecutionProfile(
        configuration_profile="Enterprise",
        decode_as=("tcp.port==8888,http",),
        preferences={"tcp.desegment_tcp_streams": "TRUE"},
        name_resolution="dmNst",
        keytab=str(keytab),
        tls_keylog=str(keylog),
        enabled_protocols=("eth", "ip", "tcp", "http"),
        disabled_heuristics=("foo",),
    )
    args = engine._base_read_args(capture.resolve(), profile)
    assert ["-C", "Enterprise"] == args[args.index("-C"):args.index("-C") + 2]
    assert "tcp.port==8888,http" in args
    assert "tcp.desegment_tcp_streams:TRUE" in args
    assert "tls.keylog_file:" + str(keylog.resolve()) in args
    assert str(keytab.resolve()) in args
    assert "eth,ip,tcp,http" in args
    assert "foo" in args


def test_imported_packet_becomes_network_event_with_raw_provenance(tmp_path: Path, monkeypatch) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"pcapng")
    engine = PacketAnalysisEngine("tshark")
    engine._supported_field_cache = set(engine.SUMMARY_FIELDS)
    values = {field: "" for field in engine.SUMMARY_FIELDS}
    values.update({
        "frame.number": "1",
        "frame.time_epoch": "1786233600.0",
        "frame.len": "100",
        "frame.cap_len": "100",
        "frame.protocols": "eth:ip:tcp:http",
        "_ws.col.Protocol": "HTTP",
        "_ws.col.Info": "GET /",
        "ip.src": "10.0.0.2",
        "ip.dst": "203.0.113.9",
        "tcp.srcport": "50000",
        "tcp.dstport": "80",
        "tcp.stream": "0",
        "http.host": "example.com",
        "http.request.method": "GET",
        "http.request.uri": "/",
    })
    line = "\t".join(f'"{values[field]}"' for field in engine.SUMMARY_FIELDS)
    monkeypatch.setattr(engine, "_run_tshark", lambda *args, **kwargs: line + "\n")
    session = CaptureSession("pcap", CaptureSource.PCAP_IMPORT)
    events = engine.to_network_events(capture, session)
    assert len(events) == 1
    event = events[0]
    assert event.source_type is CaptureSource.PCAP_IMPORT
    assert event.url == "http://example.com/"
    assert event.flow_ref == "tcp:0"
    assert event.metadata["frame_number"] == 1
    assert event.metadata["raw_capture_path"] == str(capture.resolve())


def test_custom_statistics_tap_rejects_newlines(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"pcapng")
    engine = PacketAnalysisEngine("tshark")
    try:
        engine.statistics_tap(capture, "io,phs\n-z expert")
    except ValueError as exc:
        assert "invalid statistics tap" in str(exc)
    else:
        raise AssertionError("newline-bearing tap must be rejected")
