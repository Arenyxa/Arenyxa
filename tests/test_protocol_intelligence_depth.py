from __future__ import annotations

import socket
import struct
from pathlib import Path

import pytest

from arenyxa.application.network_terminal import NetworkTerminalToolkit
from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine
from arenyxa.infrastructure.capture.protocol_intelligence import ProtocolIntelligenceEngine


def _ethernet(payload: bytes, ether_type: int = 0x0800) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", ether_type) + payload


def _ipv4(payload: bytes, protocol: int, source: bytes = b"\x0a\x00\x00\x01", destination: bytes = b"\x5d\xb8\xd8\x22") -> bytes:
    total = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0x4000, 64, protocol, 0, source, destination)
    return header + payload


def _tcp(payload: bytes, source_port: int, destination_port: int) -> bytes:
    return struct.pack("!HHIIBBHHH", source_port, destination_port, 100, 200, 0x50, 0x18, 65535, 0, 0) + payload


def _udp(payload: bytes, source_port: int, destination_port: int) -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload


def _dns_query(name: str) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 0xBEEF, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)


def test_native_decoder_extracts_ethernet_ipv4_tcp_http() -> None:
    http = b"GET /deep HTTP/1.1\r\nHost: example.test\r\nUser-Agent: Arenyxa-Test\r\n\r\n"
    frame = _ethernet(_ipv4(_tcp(http, 52000, 80), 6))
    decoded = ProtocolIntelligenceEngine().decode_frame(frame)

    assert decoded.protocols[:3] == ("ethernet", "ipv4", "tcp")
    assert decoded.application_protocol == "http"
    assert decoded.flow_key.startswith("tcp:")
    http_layer = decoded.layers[-1]
    assert http_layer.name == "http"
    assert http_layer.fields["method"] == "GET"
    assert http_layer.fields["target"] == "/deep"
    assert http_layer.fields["host"] == "example.test"


def test_native_decoder_handles_vlan_udp_dns() -> None:
    dns = _dns_query("www.example.test")
    ip = _ipv4(_udp(dns, 53000, 53), 17)
    ethernet_header = bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", 0x8100)
    vlan = struct.pack("!HH", 42, 0x0800)
    decoded = ProtocolIntelligenceEngine().decode_frame(ethernet_header + vlan + ip)

    assert "vlan" in decoded.protocols
    assert decoded.application_protocol == "dns"
    vlan_layer = next(layer for layer in decoded.layers if layer.name == "vlan")
    assert vlan_layer.fields["vlan_id"] == 42
    dns_layer = decoded.layers[-1]
    assert dns_layer.fields["question_records"][0]["name"] == "www.example.test"
    assert dns_layer.fields["transaction_id"] == 0xBEEF


def test_native_decoder_ipv6_udp_coap() -> None:
    coap = bytes([0x41, 0x01, 0x12, 0x34, 0xAA])
    udp = _udp(coap, 40000, 5683)
    first_word = 6 << 28
    source = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    destination = socket.inet_pton(socket.AF_INET6, "2001:db8::2")
    ipv6 = struct.pack("!IHBB16s16s", first_word, len(udp), 17, 64, source, destination) + udp
    decoded = ProtocolIntelligenceEngine().decode_frame(_ethernet(ipv6, 0x86DD))

    assert decoded.protocols[:3] == ("ethernet", "ipv6", "udp")
    assert decoded.application_protocol == "coap"
    coap_layer = decoded.layers[-1]
    assert coap_layer.fields["message_id"] == 0x1234


def test_native_decoder_tls_client_hello_extracts_sni_and_alpn() -> None:
    sni_name = b"example.test"
    sni_value = struct.pack("!H", 3 + len(sni_name)) + b"\x00" + struct.pack("!H", len(sni_name)) + sni_name
    sni = struct.pack("!HH", 0, len(sni_value)) + sni_value
    alpn_value = struct.pack("!H", 3) + b"\x02h2"
    alpn = struct.pack("!HH", 16, len(alpn_value)) + alpn_value
    extensions = sni + alpn
    hello = (
        b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" +
        b"\x01\x00" + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    tls = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    decoded = ProtocolIntelligenceEngine().decode_frame(_ethernet(_ipv4(_tcp(tls, 54000, 443), 6)))

    assert decoded.application_protocol == "tls"
    assert decoded.encrypted is True
    tls_layer = decoded.layers[-1]
    assert tls_layer.fields["server_name"] == "example.test"
    assert tls_layer.fields["alpn"] == ["h2"]


def test_native_decoder_safely_stops_on_dns_compression_loop() -> None:
    dns = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
    decoded = ProtocolIntelligenceEngine().decode_frame(_ethernet(_ipv4(_udp(dns, 50000, 53), 17)))

    assert decoded.truncated is True
    assert decoded.warnings
    assert decoded.protocols[:3] == ("ethernet", "ipv4", "udp")


def test_packet_summary_preserves_deep_dissector_fields_and_http2_fallbacks() -> None:
    packet = PacketAnalysisEngine._packet_from_row(
        {
            "frame.number": "7",
            "frame.time_epoch": "1700000000.0",
            "frame.len": "123",
            "frame.cap_len": "123",
            "frame.protocols": "eth:ip:tcp:tls:http2",
            "_ws.col.Protocol": "HTTP2",
            "ip.src": "10.0.0.1",
            "ip.dst": "10.0.0.2",
            "tcp.srcport": "50000",
            "tcp.dstport": "443",
            "tcp.stream": "3",
            "http2.streamid": "9",
            "http2.headers.method": "POST",
            "http2.headers.path": "/rpc",
            "http2.headers.status": "201",
            "http2.headers.authority": "api.example.test",
            "tls.handshake.extensions_alpn_str": "h2",
            "tcp.window_size_value": "65535",
        }
    )
    assert packet is not None
    assert packet.method == "POST"
    assert packet.uri == "/rpc"
    assert packet.status == 201
    assert packet.host == "api.example.test"
    assert packet.metadata["dissector_fields"]["tls.handshake.extensions_alpn_str"] == "h2"
    assert packet.metadata["dissector_fields"]["tcp.window_size_value"] == "65535"


def test_packet_engine_extract_fields_is_bounded_and_validated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"capture")
    engine = PacketAnalysisEngine("packet-decoder")
    monkeypatch.setattr(engine, "_supported_fields", lambda: {"frame.number", "dns.qry.name"})
    monkeypatch.setattr(engine, "_run_tshark", lambda *args, **kwargs: '"1"\t"example.test"\n')

    rows = engine.extract_fields(capture, ["frame.number", "dns.qry.name"], limit=10)
    assert rows == [{"frame.number": "1", "dns.qry.name": "example.test"}]
    with pytest.raises(ValueError):
        engine.extract_fields(capture, ["not.a.real.field"])


def test_network_terminal_resolver_is_deduplicated_and_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 443, 0, 0)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: rows)
    result = NetworkTerminalToolkit.resolve("localhost", port=443)
    assert result["result_count"] == 2
    assert {row["family"] for row in result["results"]} == {"ipv4", "ipv6"}


def test_network_terminal_service_protocol_and_input_guards() -> None:
    assert NetworkTerminalToolkit.protocol("tcp")["number"] == 6
    service = NetworkTerminalToolkit.service(80, protocol="tcp")
    assert service["port"] == 80
    with pytest.raises(ValueError):
        NetworkTerminalToolkit.resolve("bad host name")
    with pytest.raises(ValueError):
        NetworkTerminalToolkit.tcp_probe("localhost", 70000)


def test_packet_capabilities_report_native_coverage_without_external_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = PacketAnalysisEngine("")
    assert engine.available is False
    capabilities = engine.capabilities()
    assert capabilities.native_protocol_count >= 40
    assert "dns" in capabilities.native_protocols
    coverage = engine.protocol_coverage()
    assert coverage["native_protocol_count"] == capabilities.native_protocol_count
    assert coverage["combined_protocol_count"] >= coverage["native_protocol_count"]


def test_streaming_packet_iterator_parses_lines_without_materializing_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"capture")
    engine = PacketAnalysisEngine("packet-decoder")
    engine._supported_field_cache = {"frame.number", "frame.time_epoch", "frame.len", "frame.cap_len", "frame.protocols", "_ws.col.Protocol"}
    lines = iter([
        '"1"\t"1700000000"\t"60"\t"60"\t"eth:ip:udp:dns"\t"DNS"',
        '"2"\t"1700000001"\t"64"\t"64"\t"eth:ip:tcp:tls"\t"TLS"',
    ])
    monkeypatch.setattr(engine, "_iter_tshark_lines", lambda *args, **kwargs: lines)
    packets = list(engine.iter_packet_summaries(capture, limit=2))
    assert [packet.frame_number for packet in packets] == [1, 2]
    assert [packet.protocol for packet in packets] == ["DNS", "TLS"]


def _write_pcap(path: Path, frame: bytes) -> None:
    global_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    packet_header = struct.pack("<IIII", 1_700_000_000, 123456, len(frame), len(frame))
    path.write_bytes(global_header + packet_header + frame)


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    padding = b"\x00" * ((4 - len(body) % 4) % 4)
    length = 12 + len(body) + len(padding)
    return struct.pack("<II", block_type, length) + body + padding + struct.pack("<I", length)


def _write_pcapng(path: Path, frame: bytes) -> None:
    section_body = b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1)
    section = _pcapng_block(0x0A0D0D0A, section_body)
    interface = _pcapng_block(1, struct.pack("<HHI", 1, 0, 65535))
    ticks = 1_700_000_000_123_456
    enhanced_body = struct.pack(
        "<IIIII", 0, (ticks >> 32) & 0xFFFFFFFF, ticks & 0xFFFFFFFF, len(frame), len(frame)
    ) + frame
    enhanced = _pcapng_block(6, enhanced_body)
    path.write_bytes(section + interface + enhanced)


def test_native_capture_reader_and_packet_engine_fallback_support_pcap(tmp_path: Path) -> None:
    from arenyxa.infrastructure.capture.native_capture import NativeCaptureReader

    http = b"GET /native HTTP/1.1\r\nHost: native.example\r\n\r\n"
    frame = _ethernet(_ipv4(_tcp(http, 51000, 80), 6))
    capture = tmp_path / "native.pcap"
    _write_pcap(capture, frame)

    packet = next(iter(NativeCaptureReader().iter_packets(capture, limit=10)))
    assert packet.link_type == "ethernet"
    assert packet.frame_number == 1
    assert abs(packet.timestamp_epoch - 1_700_000_000.123456) < 0.00001

    engine = PacketAnalysisEngine("not-present")
    engine.executable = ""
    summaries = engine.packet_summaries(capture)
    assert len(summaries) == 1
    assert summaries[0].protocol == "http"
    assert summaries[0].host == "native.example"
    assert summaries[0].method == "GET"
    assert summaries[0].metadata["native_decode"] is True
    tree = engine.packet_tree(capture, 1)
    assert tree["application_protocol"] == "http"
    filtered = engine.filtered_packets_json(capture, protocols=["http"])
    assert len(filtered) == 1


def test_native_capture_reader_supports_pcapng_enhanced_packets(tmp_path: Path) -> None:
    from arenyxa.infrastructure.capture.native_capture import NativeCaptureReader

    dns = _dns_query("pcapng.example")
    frame = _ethernet(_ipv4(_udp(dns, 53000, 53), 17))
    capture = tmp_path / "native.pcapng"
    _write_pcapng(capture, frame)
    reader = NativeCaptureReader()
    packets = list(reader.iter_packets(capture, limit=10))
    assert len(packets) == 1
    assert packets[0].link_type == "ethernet"
    assert abs(packets[0].timestamp_epoch - 1_700_000_000.123456) < 0.00001
    info = reader.inspect(capture)
    assert info.format == "pcapng"
    assert info.packet_count == 1
    assert info.link_types == ("ethernet",)

    engine = PacketAnalysisEngine("not-present")
    engine.executable = ""
    events = engine.to_network_events(capture, __import__("arenyxa.domain.models", fromlist=["CaptureSession"]).CaptureSession("native", __import__("arenyxa.domain.enums", fromlist=["CaptureSource"]).CaptureSource.PCAP_IMPORT))
    assert len(events) == 1
    assert events[0].protocol == "dns"
    assert events[0].host == "pcapng.example"
    assert events[0].flow_ref and events[0].flow_ref.startswith("udp:")


def test_native_decoder_supports_loopback_ppp_and_wifi_snap() -> None:
    dns = _dns_query("link.example")
    ipv4 = _ipv4(_udp(dns, 53000, 53), 17)

    loopback = struct.pack("<I", 2) + ipv4
    decoded_loopback = ProtocolIntelligenceEngine().decode_frame(loopback, link_type="null")
    assert decoded_loopback.protocols[:2] == ("loopback", "ipv4")
    assert decoded_loopback.application_protocol == "dns"

    ppp = b"\xff\x03\x00\x21" + ipv4
    decoded_ppp = ProtocolIntelligenceEngine().decode_frame(ppp, link_type="ppp-hdlc")
    assert decoded_ppp.protocols[:2] == ("ppp", "ipv4")
    assert decoded_ppp.application_protocol == "dns"

    radiotap = b"\x00\x00\x08\x00\x00\x00\x00\x00"
    frame_control = struct.pack("<H", 0x0008)
    wifi_header = frame_control + b"\x00\x00" + bytes.fromhex(
        "00112233445566778899aabb102030405060"
    ) + b"\x00\x00"
    llc_snap = b"\xaa\xaa\x03\x00\x00\x00\x08\x00"
    decoded_wifi = ProtocolIntelligenceEngine().decode_frame(radiotap + wifi_header + llc_snap + ipv4, link_type="radiotap")
    assert decoded_wifi.protocols[:3] == ("radiotap", "ieee80211", "llc-snap")
    assert decoded_wifi.application_protocol == "dns"


def test_native_capture_inspect_does_not_materialize_full_file_and_reports_truncation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from arenyxa.infrastructure.capture.native_capture import NativeCaptureReader

    frame = _ethernet(_ipv4(_udp(_dns_query("budget.example"), 53000, 53), 17))
    capture = tmp_path / "budget.pcap"
    global_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    packet_header = struct.pack("<IIII", 1_700_000_000, 0, len(frame), len(frame))
    capture.write_bytes(global_header + packet_header + frame + packet_header + frame)

    def forbidden_read_bytes(self: Path) -> bytes:
        raise AssertionError("inspect must not materialize the capture file")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)
    info = NativeCaptureReader().inspect(capture, scan_limit=1)
    assert info.packet_count == 1
    assert info.truncated is True


def test_native_statistics_remain_available_without_external_runtime(tmp_path: Path) -> None:
    frame = _ethernet(_ipv4(_udp(_dns_query("stats.example"), 53000, 53), 17))
    capture = tmp_path / "stats.pcap"
    _write_pcap(capture, frame)
    engine = PacketAnalysisEngine("")

    full = engine.full_statistics(capture)
    hierarchy = __import__("json").loads(full.protocol_hierarchy)
    assert hierarchy["layers"]
    assert any(row["key"] == "dns" for row in hierarchy["layers"])
    endpoints = __import__("json").loads(full.endpoints)
    assert endpoints
    service = __import__("json").loads(full.service_statistics)
    assert service["applications"][0]["key"] == "dns"


def test_native_stream_quality_marks_retransmission_without_unbounded_state(tmp_path: Path) -> None:
    payload = b"GET /flow HTTP/1.1\r\nHost: flow.example\r\n\r\n"
    frame = _ethernet(_ipv4(_tcp(payload, 51000, 80), 6))
    capture = tmp_path / "flow.pcap"
    global_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    packet1 = struct.pack("<IIII", 1_700_000_000, 0, len(frame), len(frame)) + frame
    packet2 = struct.pack("<IIII", 1_700_000_001, 0, len(frame), len(frame)) + frame
    capture.write_bytes(global_header + packet1 + packet2)

    engine = PacketAnalysisEngine("")
    packets = list(engine.iter_packet_summaries(capture, limit=10))
    assert packets[0].tcp_analysis == []
    assert "retransmission" in packets[1].tcp_analysis
    assert packets[1].metadata["native_tcp_analysis"] == packets[1].tcp_analysis


def test_native_decoder_deepens_bgp_snmp_smb_and_overlay_protocols() -> None:
    engine = ProtocolIntelligenceEngine()

    bgp = b"\xff" * 16 + struct.pack("!HB", 19, 4)
    bgp_decoded = engine.decode_frame(_ethernet(_ipv4(_tcp(bgp, 50000, 179), 6)))
    assert bgp_decoded.application_protocol == "bgp"
    assert bgp_decoded.layers[-1].fields["message_name"] == "keepalive"

    snmp = b"\x30\x0d\x02\x01\x00\x04\x06public\xa0\x00"
    snmp_decoded = engine.decode_frame(_ethernet(_ipv4(_udp(snmp, 50000, 161), 17)))
    assert snmp_decoded.application_protocol == "snmp"
    snmp_fields = snmp_decoded.layers[-1].fields
    assert snmp_fields["community_present"] is True
    assert "community" not in snmp_fields

    smb = bytearray(64)
    smb[:4] = b"\xfeSMB"
    struct.pack_into("<H", smb, 4, 64)
    struct.pack_into("<H", smb, 12, 5)
    struct.pack_into("<Q", smb, 24, 42)
    smb_decoded = engine.decode_frame(_ethernet(_ipv4(_tcp(bytes(smb), 50000, 445), 6)))
    assert smb_decoded.application_protocol == "smb"
    assert smb_decoded.layers[-1].fields["command"] == 5
    assert smb_decoded.layers[-1].fields["message_id"] == 42

    inner = _ethernet(_ipv4(_udp(_dns_query("overlay.example"), 53000, 53), 17))
    vxlan = b"\x08\x00\x00\x00\x00\x00\x2a\x00" + inner
    vxlan_decoded = engine.decode_frame(_ethernet(_ipv4(_udp(vxlan, 40000, 4789), 17)))
    assert "vxlan" in vxlan_decoded.protocols
    assert vxlan_decoded.application_protocol == "dns"
    vxlan_layer = next(layer for layer in vxlan_decoded.layers if layer.name == "vxlan")
    assert vxlan_layer.fields["vni"] == 42


def test_native_catalog_has_broad_core_but_does_not_claim_external_protocols() -> None:
    names = {row["protocol"] for row in ProtocolIntelligenceEngine().protocol_catalog()}
    assert len(names) >= 70
    for required in {"ethernet", "ieee80211", "ipv4", "ipv6", "tcp", "udp", "tls", "quic", "dns", "bgp", "snmp", "smb", "vxlan", "geneve", "gtp", "rpc", "nfs"}:
        assert required in names


def _tcp_with_sequence(payload: bytes, source_port: int, destination_port: int, sequence: int, flags: int = 0x18) -> bytes:
    return struct.pack("!HHIIBBHHH", source_port, destination_port, sequence, 200, 0x50, flags, 65535, 0, 0) + payload


def test_native_tcp_reassembly_recognizes_http_split_across_segments(tmp_path: Path) -> None:
    part1 = b"GET /split HTTP/1.1\r\nHo"
    part2 = b"st: reassembled.example\r\nUser-Agent: Arenyxa-Test\r\n\r\n"
    frame1 = _ethernet(_ipv4(_tcp_with_sequence(part1, 51000, 80, 1000), 6))
    frame2 = _ethernet(_ipv4(_tcp_with_sequence(part2, 51000, 80, 1000 + len(part1)), 6))
    capture = tmp_path / "reassembled.pcap"
    global_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    records = []
    for index, frame in enumerate((frame1, frame2)):
        records.append(struct.pack("<IIII", 1_700_000_000 + index, 0, len(frame), len(frame)) + frame)
    capture.write_bytes(global_header + b"".join(records))

    engine = PacketAnalysisEngine("")
    packets = list(engine.iter_packet_summaries(capture, limit=10))
    assert len(packets) == 2
    probe = packets[1].metadata["native_tcp_reassembly"]
    assert probe["application_protocol"] == "http"
    assert probe["contiguous_bytes"] == len(part1) + len(part2)
    assert probe["pending_bytes"] == 0
    http_layer = next(layer for layer in probe["layers"] if layer["name"] == "http")
    assert http_layer["fields"]["host"] == "reassembled.example"
    assert packets[1].protocol == "http"


def test_tcp_reassembly_buffers_out_of_order_and_never_exposes_payload_in_diagnostics() -> None:
    from arenyxa.infrastructure.capture.tcp_reassembly import TcpReassemblyManager

    manager = TcpReassemblyManager()
    key = ("10.0.0.1", 50000, "10.0.0.2", 80)
    first = manager.feed(key, sequence=1000, payload=b"GET / HTTP/1.1\r\n", flags={"ack"})
    future = manager.feed(key, sequence=1040, payload=b"late", flags={"ack"})
    gap_fill = manager.feed(key, sequence=1016, payload=b"Host: x\r\n\r\n" + b"z" * 12, flags={"ack"})

    assert first.pending_bytes == 0
    assert future.out_of_order is True
    assert future.gap is True
    assert future.pending_bytes == 4
    assert gap_fill.contiguous_bytes >= 16
    diagnostics = manager.diagnostics
    assert diagnostics["retained_bytes"] <= diagnostics["max_global_bytes"]
    assert "GET" not in str(diagnostics)


def test_native_decoder_routes_and_tunnels_have_structured_metadata() -> None:
    engine = ProtocolIntelligenceEngine()
    ospf = struct.pack("!BBH4s4sHHQ", 2, 1, 24, socket.inet_aton("10.0.0.1"), socket.inet_aton("0.0.0.0"), 0x1234, 0, 0)
    ospf_decoded = engine.decode_frame(_ethernet(_ipv4(ospf, 89)))
    assert ospf_decoded.protocols[-1] == "ospf"
    assert ospf_decoded.layers[-1].fields["router_id"] == "10.0.0.1"

    inner = _ipv4(_udp(_dns_query("tunnel.example"), 53000, 53), 17)
    tunneled = engine.decode_frame(_ethernet(_ipv4(inner, 4)))
    assert "ip-in-ip" in tunneled.protocols
    assert tunneled.application_protocol == "dns"


def test_native_decoder_websocket_and_industrial_handshakes() -> None:
    engine = ProtocolIntelligenceEngine()
    websocket = b"GET /chat HTTP/1.1\r\nHost: ws.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
    ws_decoded = engine.decode_frame(_ethernet(_ipv4(_tcp(websocket, 51000, 80), 6)))
    assert ws_decoded.application_protocol == "websocket"
    assert ws_decoded.protocols[-1] == "websocket"

    opcua = b"HEL" + b"F" + struct.pack("<I", 8)
    opcua_decoded = engine.decode_frame(_ethernet(_ipv4(_tcp(opcua, 51000, 4840), 6)))
    assert opcua_decoded.application_protocol == "opcua"
    assert opcua_decoded.layers[-1].fields["message_type"] == "HEL"
