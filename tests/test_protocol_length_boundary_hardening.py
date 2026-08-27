from __future__ import annotations

import ipaddress
import struct

from arenyxa.infrastructure.capture.protocol_intelligence import ProtocolIntelligenceEngine


def _tcp(payload: bytes, source_port: int = 50000, destination_port: int = 80) -> bytes:
    return struct.pack("!HHIIBBHHH", source_port, destination_port, 1, 0, 0x50, 0x18, 65535, 0, 0) + payload


def _udp(payload: bytes, *, declared_length: int | None = None) -> bytes:
    length = 8 + len(payload) if declared_length is None else declared_length
    return struct.pack("!HHHH", 53000, 53, length, 0) + payload


def _ipv4(payload: bytes, protocol: int, *, total_length: int | None = None, flags_fragment: int = 0) -> bytes:
    declared = 20 + len(payload) if total_length is None else total_length
    return (
        struct.pack("!BBHHHBBH", 0x45, 0, declared, 1, flags_fragment, 64, protocol, 0)
        + ipaddress.IPv4Address("192.0.2.1").packed
        + ipaddress.IPv4Address("198.51.100.2").packed
        + payload
    )


def _ipv6(payload: bytes, next_header: int, *, payload_length: int | None = None) -> bytes:
    declared = len(payload) if payload_length is None else payload_length
    return (
        struct.pack("!IHBB", 6 << 28, declared, next_header, 64)
        + ipaddress.IPv6Address("2001:db8::1").packed
        + ipaddress.IPv6Address("2001:db8::2").packed
        + payload
    )


def test_ipv4_rejects_total_length_smaller_than_header() -> None:
    decoded = ProtocolIntelligenceEngine().decode_frame(_ipv4(b"", 6, total_length=19), link_type="raw-ip")
    assert decoded.truncated is True
    assert "tcp" not in decoded.protocols
    assert any("total length" in warning for warning in decoded.warnings)


def test_ipv4_does_not_decode_application_bytes_beyond_declared_total_length() -> None:
    http = b"GET /hidden HTTP/1.1\r\nHost: hidden.test\r\n\r\n"
    packet = _ipv4(_tcp(http), 6, total_length=40)
    decoded = ProtocolIntelligenceEngine().decode_frame(packet, link_type="raw-ip")
    assert "tcp" in decoded.protocols
    assert "http" not in decoded.protocols


def test_initial_ipv4_fragment_retains_transport_metadata_without_false_application_decode() -> None:
    http = b"GET /fragment HTTP/1.1\r\nHost: fragment.test\r\n\r\n"
    packet = _ipv4(_tcp(http), 6, flags_fragment=0x2000)
    decoded = ProtocolIntelligenceEngine().decode_frame(packet, link_type="raw-ip")
    assert "tcp" in decoded.protocols
    assert "http" not in decoded.protocols
    assert any("until reassembly" in warning for warning in decoded.warnings)


def test_udp_rejects_impossible_nonzero_length() -> None:
    decoded = ProtocolIntelligenceEngine().decode_frame(_ipv4(_udp(b"dns", declared_length=7), 17), link_type="raw-ip")
    assert decoded.truncated is True
    assert "dns" not in decoded.protocols
    assert any("UDP length" in warning for warning in decoded.warnings)


def test_ipv6_extension_cannot_read_past_declared_payload_boundary() -> None:
    # The Hop-by-Hop header declares 16 bytes while the IPv6 header exposes only 8.
    extension = bytes((6, 1)) + b"\x00" * 14 + _tcp(b"")
    decoded = ProtocolIntelligenceEngine().decode_frame(
        _ipv6(extension, 0, payload_length=8),
        link_type="raw-ip",
    )
    assert decoded.truncated is True
    assert "tcp" not in decoded.protocols


def test_ipv6_zero_payload_length_without_jumbo_option_does_not_decode_trailing_bytes() -> None:
    decoded = ProtocolIntelligenceEngine().decode_frame(
        _ipv6(_tcp(b"GET / HTTP/1.1\r\n\r\n"), 6, payload_length=0),
        link_type="raw-ip",
    )
    assert "tcp" not in decoded.protocols
    assert "http" not in decoded.protocols
    assert any("Jumbo Payload" in warning for warning in decoded.warnings)


def test_initial_ipv6_fragment_skips_application_decode_until_reassembly() -> None:
    fragment_header = struct.pack("!BBHI", 6, 0, 1, 1234)
    payload = fragment_header + _tcp(b"GET /fragment HTTP/1.1\r\n\r\n")
    decoded = ProtocolIntelligenceEngine().decode_frame(_ipv6(payload, 44), link_type="raw-ip")
    assert "ipv6-fragment" in decoded.protocols
    assert "tcp" in decoded.protocols
    assert "http" not in decoded.protocols
    assert any("until reassembly" in warning for warning in decoded.warnings)
