from __future__ import annotations

import struct

import pytest

from arenyxa.infrastructure.capture.protocol_dns import decode_dns_message
from arenyxa.infrastructure.capture.protocol_quic_initial import decrypt_quic_initial
from arenyxa.infrastructure.capture.protocol_websocket import (
    decode_websocket_stream,
)


def _dns_header(*, questions: int = 0, answers: int = 0, authorities: int = 0, additionals: int = 0) -> bytes:
    return struct.pack("!HHHHHH", 1, 0x8180, questions, answers, authorities, additionals)


def test_dns_rejects_section_counts_above_native_budget() -> None:
    with pytest.raises(ValueError, match="question count"):
        decode_dns_message(_dns_header(questions=65))
    with pytest.raises(ValueError, match="resource record count"):
        decode_dns_message(_dns_header(answers=257))


def test_dns_name_cannot_consume_bytes_past_its_rdata() -> None:
    # One NS answer declares a one-byte RDATA containing a non-terminal label
    # length. The following bytes must not be consumed as part of that name.
    packet = (
        _dns_header(answers=1)
        + b"\x00"
        + struct.pack("!HHIH", 2, 1, 60, 1)
        + b"\x01"
        + b"x\x00"
    )
    with pytest.raises(ValueError, match="resource record boundary"):
        decode_dns_message(packet)


def test_websocket_flags_rsv_and_invalid_close_payload() -> None:
    rsv = decode_websocket_stream(b"\xc1\x00")
    assert rsv["frames"][0]["protocol_error"] == "reserved-bits-without-negotiated-extension"
    close = decode_websocket_stream(b"\x88\x01x")
    assert close["frames"][0]["protocol_error"] == "invalid-close-payload"


def test_websocket_fragmented_message_has_aggregate_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "arenyxa.infrastructure.capture.protocol_websocket.MAX_WEBSOCKET_PAYLOAD_BYTES", 3
    )
    decoded = decode_websocket_stream(b"\x01\x02ab\x80\x02cd")
    assert decoded["frames"][1]["protocol_error"] == "fragmented-message-budget"
    assert decoded["fragmentation_open"] is False


def test_quic_rejects_out_of_range_packet_number_hint() -> None:
    with pytest.raises(ValueError, match="62-bit"):
        decrypt_quic_initial(b"", largest_packet_number=1 << 62)


def _h2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    return len(payload).to_bytes(3, "big") + bytes((frame_type, flags)) + stream_id.to_bytes(4, "big") + payload


def test_http2_reassembly_budget_is_shared_across_streams(monkeypatch: pytest.MonkeyPatch) -> None:
    from hpack import Encoder

    from arenyxa.infrastructure.capture.protocol_http2_stream import decode_http2_stream

    monkeypatch.setattr(
        "arenyxa.infrastructure.capture.protocol_http2_stream.MAX_HTTP2_REASSEMBLY_BYTES", 8
    )
    encoder = Encoder()
    header_values = [
        (b":method", b"POST"),
        (b":scheme", b"https"),
        (b":authority", b"svc.example"),
        (b":path", b"/call"),
        (b"content-type", b"application/grpc"),
    ]
    first_headers = _h2_frame(1, 0x04, 1, encoder.encode(header_values))
    second_headers = _h2_frame(1, 0x04, 3, encoder.encode(header_values))
    incomplete = b"\x00\x00\x00\x00\x08x"
    decoded = decode_http2_stream(
        first_headers
        + _h2_frame(0, 0, 1, incomplete)
        + second_headers
        + _h2_frame(0, 0, 3, incomplete)
    )
    assert decoded["frames"][-1]["decode_error"] == "gRPC reassembly buffer exceeds safety bound"
    assert decoded["pending_reassembly_bytes"] == len(incomplete)


def test_http2_rejects_header_frames_on_connection_stream() -> None:
    from arenyxa.infrastructure.capture.protocol_http2_stream import decode_http2_stream

    decoded = decode_http2_stream(_h2_frame(1, 0x04, 0, b""))
    assert decoded["frames"][0]["protocol_error"] == "header-frame-on-stream-zero"
