from __future__ import annotations

import struct
from pathlib import Path

import pytest

from arenyxa.infrastructure.capture.native_capture import NativeCaptureReader


def _block(block_type: int, body: bytes, endian: str = "<") -> bytes:
    padding = b"\x00" * ((4 - len(body) % 4) % 4)
    total = 12 + len(body) + len(padding)
    return struct.pack(endian + "II", block_type, total) + body + padding + struct.pack(endian + "I", total)


def _section(endian: str = "<") -> bytes:
    byte_order_magic = struct.pack(endian + "I", 0x1A2B3C4D)
    return _block(0x0A0D0D0A, byte_order_magic + struct.pack(endian + "HHq", 1, 0, -1), endian)


def _interface(*, snaplen: int = 65535, options: bytes = b"", endian: str = "<") -> bytes:
    return _block(1, struct.pack(endian + "HHI", 1, 0, snaplen) + options, endian)


def test_pcapng_unknown_empty_block_is_skipped_without_struct_error(tmp_path: Path) -> None:
    capture = tmp_path / "unknown-empty.pcapng"
    empty_unknown = struct.pack("<III", 0x00000BAD, 12, 12)
    packet = b"abc"
    simple = _block(3, struct.pack("<I", len(packet)) + packet)
    capture.write_bytes(_section() + _interface() + empty_unknown + simple)

    rows = list(NativeCaptureReader().iter_packets(capture))
    assert len(rows) == 1
    assert rows[0].data == packet


def test_pcapng_simple_packet_excludes_alignment_padding_using_snaplen(tmp_path: Path) -> None:
    capture = tmp_path / "simple-padding.pcapng"
    packet = bytes(range(63))
    simple = _block(3, struct.pack("<I", 100) + packet)
    capture.write_bytes(_section() + _interface(snaplen=63) + simple)

    row = next(iter(NativeCaptureReader().iter_packets(capture)))
    assert row.captured_length == 63
    assert row.original_length == 100
    assert row.data == packet


def test_pcapng_enhanced_packet_honors_interface_timestamp_offset(tmp_path: Path) -> None:
    capture = tmp_path / "timestamp-offset.pcapng"
    ts_resolution = struct.pack("<HH", 9, 1) + b"\x06\x00\x00\x00"
    ts_offset = struct.pack("<HHq", 14, 8, 5)
    end_options = struct.pack("<HH", 0, 0)
    packet = b"frame"
    ticks = 1_250_000
    enhanced_body = (
        struct.pack("<IIIII", 0, 0, ticks, len(packet), len(packet))
        + packet
    )
    capture.write_bytes(
        _section()
        + _interface(options=ts_resolution + ts_offset + end_options)
        + _block(6, enhanced_body)
    )

    row = next(iter(NativeCaptureReader().iter_packets(capture)))
    assert row.timestamp_epoch == pytest.approx(6.25)
    assert row.data == packet


def test_pcapng_obsolete_packet_block_remains_supported(tmp_path: Path) -> None:
    capture = tmp_path / "obsolete-packet.pcapng"
    packet = b"legacy"
    ticks = 2_000_000
    packet_body = struct.pack("<HHIIII", 0, 0, 0, ticks, len(packet), len(packet)) + packet
    capture.write_bytes(_section() + _interface() + _block(2, packet_body))

    row = next(iter(NativeCaptureReader().iter_packets(capture)))
    assert row.timestamp_epoch == pytest.approx(2.0)
    assert row.data == packet


def test_pcapng_big_endian_section_and_packets_are_decoded(tmp_path: Path) -> None:
    capture = tmp_path / "big-endian.pcapng"
    packet = b"network"
    enhanced_body = struct.pack(">IIIII", 0, 0, 1_000_000, len(packet), len(packet)) + packet
    capture.write_bytes(_section(">") + _interface(endian=">") + _block(6, enhanced_body, ">"))

    row = next(iter(NativeCaptureReader().iter_packets(capture)))
    assert row.timestamp_epoch == pytest.approx(1.0)
    assert row.data == packet


def test_pcap_and_pcapng_reject_capture_lengths_that_violate_declared_bounds(tmp_path: Path) -> None:
    classic = tmp_path / "bad.pcap"
    classic.write_bytes(
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHiIII", 2, 4, 0, 0, 4, 1)
        + struct.pack("<IIII", 1, 0, 5, 5)
        + b"12345"
    )
    with pytest.raises(ValueError, match="packet exceeds"):
        list(NativeCaptureReader().iter_packets(classic))

    enhanced = tmp_path / "bad.pcapng"
    body = struct.pack("<IIIII", 0, 0, 0, 5, 5) + b"12345"
    enhanced.write_bytes(_section() + _interface(snaplen=4) + _block(6, body))
    with pytest.raises(ValueError, match="packet exceeds"):
        list(NativeCaptureReader().iter_packets(enhanced))
