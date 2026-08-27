from __future__ import annotations

import struct

from arenyxa.infrastructure.capture.protocol_core_registry import PORT_HINTS
from arenyxa.infrastructure.capture.protocol_deep_application import (
    decode_amqp_frame,
    decode_kafka_message,
    decode_protobuf_message,
)
from arenyxa.infrastructure.capture.protocol_intelligence import ProtocolIntelligenceEngine


def test_protobuf_decoder_extracts_bounded_wire_metadata_without_payload() -> None:
    message = b"\x08\x96\x01\x12\x05hello"
    decoded = decode_protobuf_message(message)
    assert decoded["field_count"] == 2
    assert decoded["fields"][0]["value"] == 150
    assert decoded["fields"][1]["length"] == 5
    assert "hello" not in repr(decoded)


def test_amqp_protocol_header_and_frame_decoder() -> None:
    assert decode_amqp_frame(b"AMQP\x00\x00\x09\x01")["version"] == "0.9.1"
    payload = b"fixture"
    frame = b"\x01" + struct.pack("!HI", 7, len(payload)) + payload + b"\xce"
    decoded = decode_amqp_frame(frame)
    assert decoded["channel"] == 7
    assert decoded["payload_bytes"] == len(payload)
    assert "fixture" not in repr(decoded)


def test_kafka_request_header_decoder_and_port_registration() -> None:
    client = b"arenyxa"
    body = struct.pack("!hhih", 18, 3, 42, len(client)) + client
    message = struct.pack("!i", len(body)) + body
    decoded = decode_kafka_message(message)
    assert decoded["api_key"] == 18
    assert decoded["correlation_id"] == 42
    assert decoded["client_id"] == "arenyxa"
    assert PORT_HINTS[9092] == "kafka"


def _extension(extension_type: int, value: bytes) -> bytes:
    return struct.pack("!HH", extension_type, len(value)) + value


def test_tls_client_hello_exposes_ja3_ja4_sni_alpn_and_cipher_intelligence() -> None:
    host = b"example.test"
    sni_entry = b"\x00" + len(host).to_bytes(2, "big") + host
    sni = len(sni_entry).to_bytes(2, "big") + sni_entry
    alpn_name = b"h2"
    alpn = (len(alpn_name) + 1).to_bytes(2, "big") + bytes([len(alpn_name)]) + alpn_name
    groups = b"\x00\x02\x00\x1d"
    signatures = b"\x00\x04\x04\x03\x08\x04"
    versions = b"\x04\x03\x04\x03\x03"
    extensions = b"".join(
        (
            _extension(0, sni),
            _extension(10, groups),
            _extension(13, signatures),
            _extension(16, alpn),
            _extension(43, versions),
        )
    )
    body = (
        b"\x03\x03"
        + bytes(32)
        + b"\x00"
        + b"\x00\x04\x13\x01\x13\x02"
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    decoded = ProtocolIntelligenceEngine()._modern_tls_client_hello(body)
    assert decoded["server_name"] == "example.test"
    assert decoded["alpn"] == ["h2"]
    assert decoded["ja3"] and len(decoded["ja3_md5"]) == 32
    assert decoded["ja4"].startswith("t13d")
    assert decoded["cipher_suites"] == ["0x1301", "0x1302"]

