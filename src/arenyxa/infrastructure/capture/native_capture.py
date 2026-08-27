from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import BinaryIO, Iterable

from arenyxa.compat import dataclass


@dataclass(frozen=True, slots=True)
class NativeCapturePacket:
    frame_number: int
    timestamp_epoch: float
    captured_length: int
    original_length: int
    link_type_id: int
    link_type: str
    data: bytes
    interface_id: int = 0


@dataclass(frozen=True, slots=True)
class NativeCaptureInfo:
    format: str
    file_size: int
    packet_count: int
    captured_bytes: int
    original_bytes: int
    first_timestamp_epoch: float | None
    last_timestamp_epoch: float | None
    link_types: tuple[str, ...]
    truncated: bool = False


class NativeCaptureReader:
    """Streaming classic-PCAP and PCAPNG reader with strict byte budgets."""

    MAX_PACKET_BYTES = 16 * 1024 * 1024
    MAX_BLOCK_BYTES = 32 * 1024 * 1024
    MAX_PACKETS = 1_000_000
    LINK_TYPES = {
        0: "null",
        1: "ethernet",
        3: "ax25",
        6: "token-ring",
        7: "arcnet",
        8: "slip",
        9: "ppp",
        10: "fddi",
        12: "raw-ip",
        50: "ppp-hdlc",
        51: "ppp-ether",
        100: "atm-rfc1483",
        101: "raw-ip",
        104: "cisco-hdlc",
        105: "ieee80211",
        107: "frame-relay",
        108: "loopback",
        113: "linux-sll",
        117: "pflog",
        119: "prism",
        127: "radiotap",
        129: "arcnet-linux",
        163: "ieee80211-avs",
        166: "ppp-pppd",
        169: "gprs-llc",
        187: "bluetooth-hci-h4-phdr",
        189: "usb-linux",
        192: "ppi",
        195: "ieee802154-fcs",
        201: "bluetooth-hci-h4",
        202: "usb-linux-mmap",
        203: "fibre-channel-2",
        204: "fibre-channel-2-delims",
        220: "usb-ip",
        227: "socketcan",
        228: "ipv4",
        229: "ipv6",
        230: "ieee802154",
        239: "nflog",
        249: "usbpcap",
        251: "bluetooth-le-ll",
        252: "netlink",
        253: "bluetooth-linux-monitor",
        256: "profibus-dl",
        276: "linux-sll2",
    }
    PCAP_MAGIC = {
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
    }
    PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"

    def iter_packets(self, capture: Path | str, *, limit: int = 200_000) -> Iterable[NativeCapturePacket]:
        path = self._path(capture)
        bounded = max(0, min(int(limit), self.MAX_PACKETS))
        with path.open("rb") as handle:
            prefix = handle.read(4)
            handle.seek(0)
            if prefix in self.PCAP_MAGIC:
                yield from self._iter_pcap(handle, bounded)
            elif prefix == self.PCAPNG_SHB:
                yield from self._iter_pcapng(handle, bounded)
            else:
                raise ValueError("unsupported capture format: expected PCAP or PCAPNG")

    def inspect(self, capture: Path | str, *, scan_limit: int = MAX_PACKETS) -> NativeCaptureInfo:
        path = self._path(capture)
        packet_count = 0
        captured_bytes = 0
        original_bytes = 0
        first: float | None = None
        last: float | None = None
        link_types: set[str] = set()
        bounded = max(1, min(int(scan_limit), self.MAX_PACKETS))
        truncated = False
        probe_limit = min(self.MAX_PACKETS, bounded + 1)
        for packet in self.iter_packets(path, limit=probe_limit):
            if packet_count >= bounded:
                truncated = True
                break
            packet_count += 1
            captured_bytes += packet.captured_length
            original_bytes += packet.original_length
            link_types.add(packet.link_type)
            if packet.timestamp_epoch > 0:
                first = packet.timestamp_epoch if first is None else min(first, packet.timestamp_epoch)
                last = packet.timestamp_epoch if last is None else max(last, packet.timestamp_epoch)
        if bounded == self.MAX_PACKETS and packet_count >= self.MAX_PACKETS:
            truncated = True
        with path.open("rb") as handle:
            prefix = handle.read(4)
        format_name = "pcapng" if prefix == self.PCAPNG_SHB else "pcap"
        return NativeCaptureInfo(
            format=format_name,
            file_size=path.stat().st_size,
            packet_count=packet_count,
            captured_bytes=captured_bytes,
            original_bytes=original_bytes,
            first_timestamp_epoch=first,
            last_timestamp_epoch=last,
            link_types=tuple(sorted(link_types)),
            truncated=truncated,
        )

    def _iter_pcap(self, handle: BinaryIO, limit: int) -> Iterable[NativeCapturePacket]:
        header = handle.read(24)
        if len(header) != 24:
            raise ValueError("truncated PCAP global header")
        endian, fraction_scale = self.PCAP_MAGIC.get(header[:4], ("", 0.0))
        if not endian:
            raise ValueError("invalid PCAP magic")
        major, minor, _zone, _sigfigs, snaplen, link_type_id = struct.unpack(endian + "HHiIII", header[4:24])
        if major != 2 or minor > 4:
            raise ValueError(f"unsupported PCAP version: {major}.{minor}")
        if snaplen <= 0 or snaplen > self.MAX_PACKET_BYTES:
            raise ValueError("PCAP snaplen exceeds the native capture budget")
        link_type = self.LINK_TYPES.get(link_type_id, f"linktype-{link_type_id}")
        frame_number = 0
        while frame_number < limit:
            packet_header = handle.read(16)
            if not packet_header:
                return
            if len(packet_header) != 16:
                raise ValueError("truncated PCAP packet header")
            seconds, fraction, captured_length, original_length = struct.unpack(endian + "IIII", packet_header)
            if captured_length > self.MAX_PACKET_BYTES or captured_length > snaplen:
                raise ValueError("PCAP packet exceeds the native packet byte budget")
            if captured_length > original_length:
                raise ValueError("PCAP captured length exceeds the original packet length")
            if fraction >= int(fraction_scale):
                raise ValueError("PCAP packet timestamp fraction is invalid")
            data = handle.read(captured_length)
            if len(data) != captured_length:
                raise ValueError("truncated PCAP packet payload")
            frame_number += 1
            timestamp = float(seconds) + float(fraction) / fraction_scale
            yield NativeCapturePacket(
                frame_number=frame_number,
                timestamp_epoch=timestamp,
                captured_length=captured_length,
                original_length=original_length,
                link_type_id=link_type_id,
                link_type=link_type,
                data=data,
            )

    def _iter_pcapng(self, handle: BinaryIO, limit: int) -> Iterable[NativeCapturePacket]:
        endian = "<"
        interfaces: list[tuple[int, str, float, float, int]] = []
        frame_number = 0
        while frame_number < limit:
            block_prefix = handle.read(12)
            if not block_prefix:
                return
            if len(block_prefix) != 12:
                raise ValueError("truncated PCAPNG block header")
            block_type_raw = block_prefix[:4]
            if block_type_raw == self.PCAPNG_SHB:
                bom = block_prefix[8:12]
                if bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    raise ValueError("invalid PCAPNG byte-order magic")
                block_length = struct.unpack(endian + "I", block_prefix[4:8])[0]
                self._validate_block_length(block_length, minimum=28)
                remainder = handle.read(block_length - 12)
                if len(remainder) != block_length - 12 or struct.unpack(endian + "I", remainder[-4:])[0] != block_length:
                    raise ValueError("invalid PCAPNG section block length")
                section_body = block_prefix[8:12] + remainder[:-4]
                major, minor = struct.unpack_from(endian + "HH", section_body, 4)
                if major != 1:
                    raise ValueError(f"unsupported PCAPNG section version: {major}.{minor}")
                interfaces = []
                continue
            block_type = struct.unpack(endian + "I", block_type_raw)[0]
            block_length = struct.unpack(endian + "I", block_prefix[4:8])[0]
            self._validate_block_length(block_length, minimum=12)
            if block_length == 12:
                if struct.unpack(endian + "I", block_prefix[8:12])[0] != block_length:
                    raise ValueError("PCAPNG block length trailer mismatch")
                body = b""
            else:
                remainder = handle.read(block_length - 12)
                if len(remainder) != block_length - 12:
                    raise ValueError("truncated PCAPNG block")
                if len(remainder) < 4 or struct.unpack(endian + "I", remainder[-4:])[0] != block_length:
                    raise ValueError("PCAPNG block length trailer mismatch")
                body = block_prefix[8:12] + remainder[:-4]
            if block_type == 1:
                if len(body) < 8:
                    raise ValueError("truncated PCAPNG interface block")
                link_type_id = struct.unpack_from(endian + "H", body, 0)[0]
                snaplen = struct.unpack_from(endian + "I", body, 4)[0]
                if snaplen > self.MAX_PACKET_BYTES:
                    raise ValueError("PCAPNG interface snaplen exceeds the native packet byte budget")
                resolution, timestamp_offset = self._pcapng_interface_timing(body[8:], endian)
                effective_snaplen = snaplen or self.MAX_PACKET_BYTES
                interfaces.append((
                    link_type_id,
                    self.LINK_TYPES.get(link_type_id, f"linktype-{link_type_id}"),
                    resolution,
                    timestamp_offset,
                    effective_snaplen,
                ))
                continue
            if block_type == 6:
                if len(body) < 20:
                    raise ValueError("truncated PCAPNG enhanced packet block")
                interface_id, ts_high, ts_low, captured_length, original_length = struct.unpack_from(endian + "IIIII", body, 0)
                if interface_id >= len(interfaces):
                    raise ValueError("PCAPNG packet references an unknown interface")
                link_type_id, link_type, resolution, timestamp_offset, snaplen = interfaces[interface_id]
                padded_length = (captured_length + 3) & ~3
                if (
                    captured_length > self.MAX_PACKET_BYTES
                    or captured_length > snaplen
                    or captured_length > original_length
                    or 20 + padded_length > len(body)
                ):
                    raise ValueError("PCAPNG packet exceeds the native packet byte budget")
                ticks = (int(ts_high) << 32) | int(ts_low)
                timestamp = timestamp_offset + float(ticks) * resolution
                frame_number += 1
                yield NativeCapturePacket(
                    frame_number=frame_number,
                    timestamp_epoch=timestamp,
                    captured_length=captured_length,
                    original_length=original_length,
                    link_type_id=link_type_id,
                    link_type=link_type,
                    data=bytes(body[20:20 + captured_length]),
                    interface_id=interface_id,
                )
                continue
            if block_type == 2:
                if len(body) < 20:
                    raise ValueError("truncated PCAPNG obsolete packet block")
                interface_id, _drops = struct.unpack_from(endian + "HH", body, 0)
                ts_high, ts_low, captured_length, original_length = struct.unpack_from(endian + "IIII", body, 4)
                if interface_id >= len(interfaces):
                    raise ValueError("PCAPNG packet references an unknown interface")
                link_type_id, link_type, resolution, timestamp_offset, snaplen = interfaces[interface_id]
                padded_length = (captured_length + 3) & ~3
                if (
                    captured_length > self.MAX_PACKET_BYTES
                    or captured_length > snaplen
                    or captured_length > original_length
                    or 20 + padded_length > len(body)
                ):
                    raise ValueError("PCAPNG packet exceeds the native packet byte budget")
                ticks = (int(ts_high) << 32) | int(ts_low)
                frame_number += 1
                yield NativeCapturePacket(
                    frame_number=frame_number,
                    timestamp_epoch=timestamp_offset + float(ticks) * resolution,
                    captured_length=captured_length,
                    original_length=original_length,
                    link_type_id=link_type_id,
                    link_type=link_type,
                    data=bytes(body[20:20 + captured_length]),
                    interface_id=interface_id,
                )
                continue
            if block_type == 3:
                if not interfaces or len(body) < 4:
                    continue
                original_length = struct.unpack_from(endian + "I", body, 0)[0]
                link_type_id, link_type, _resolution, _timestamp_offset, snaplen = interfaces[0]
                captured_length = min(original_length, snaplen)
                padded_length = (captured_length + 3) & ~3
                if len(body) - 4 != padded_length:
                    raise ValueError("PCAPNG simple packet length does not match interface snaplen")
                if captured_length > self.MAX_PACKET_BYTES:
                    raise ValueError("PCAPNG simple packet exceeds the native packet byte budget")
                frame_number += 1
                yield NativeCapturePacket(
                    frame_number=frame_number,
                    timestamp_epoch=0.0,
                    captured_length=captured_length,
                    original_length=original_length,
                    link_type_id=link_type_id,
                    link_type=link_type,
                    data=bytes(body[4:4 + captured_length]),
                    interface_id=0,
                )

    @classmethod
    def _validate_block_length(cls, value: int, *, minimum: int) -> None:
        if value < minimum or value % 4 or value > cls.MAX_BLOCK_BYTES:
            raise ValueError("invalid PCAPNG block length")

    @staticmethod
    def _pcapng_interface_timing(options: bytes, endian: str) -> tuple[float, float]:
        cursor = 0
        resolution = 1e-6
        timestamp_offset = 0.0
        while cursor + 4 <= len(options):
            code, length = struct.unpack_from(endian + "HH", options, cursor)
            cursor += 4
            if code == 0:
                if length != 0:
                    raise ValueError("invalid PCAPNG end-of-options marker")
                break
            padded_length = (length + 3) & ~3
            if cursor + padded_length > len(options):
                raise ValueError("truncated PCAPNG interface option")
            value = options[cursor:cursor + length]
            cursor += padded_length
            if code == 9:
                if len(value) != 1:
                    raise ValueError("invalid PCAPNG timestamp-resolution option")
                raw = value[0]
                if raw & 0x80:
                    exponent = raw & 0x7F
                    resolution = 2.0 ** (-exponent)
                else:
                    resolution = 10.0 ** (-raw)
            elif code == 14:
                if len(value) != 8:
                    raise ValueError("invalid PCAPNG timestamp-offset option")
                timestamp_offset = float(struct.unpack(endian + "q", value)[0])
        return resolution, timestamp_offset

    @staticmethod
    def _pcapng_timestamp_resolution(options: bytes, endian: str) -> float:
        return NativeCaptureReader._pcapng_interface_timing(options, endian)[0]

    @staticmethod
    def _path(capture: Path | str) -> Path:
        path = Path(capture).expanduser().resolve()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(path)
        if not os.access(path, os.R_OK):
            raise PermissionError(path)
        return path
