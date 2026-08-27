from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from arenyxa.infrastructure.capture.protocol_intelligence import ProtocolIntelligenceEngine

TSHARK = shutil.which("tshark")
pytestmark = pytest.mark.skipif(TSHARK is None, reason="TShark protocol parity backend is not installed")


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4_header(protocol: int, payload_bytes: int, source: bytes, destination: bytes, identification: int) -> bytes:
    header = bytearray(struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + payload_bytes, identification, 0x4000, 64, protocol, 0, source, destination,
    ))
    struct.pack_into("!H", header, 10, _checksum(bytes(header)))
    return bytes(header)


def _ethernet(payload: bytes, ether_type: int = 0x0800) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", ether_type) + payload


def _udp_frame(payload: bytes, source_port: int, destination_port: int, identification: int = 1) -> bytes:
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
    ip = _ipv4_header(17, len(udp), b"\xc0\x00\x02\x01", b"\xc6\x33\x64\x35", identification)
    return _ethernet(ip + udp)


def _tcp_frame(payload: bytes, source_port: int, destination_port: int, identification: int = 2) -> bytes:
    tcp = struct.pack("!HHIIHHHH", source_port, destination_port, 1, 1, 0x5018, 65535, 0, 0) + payload
    ip = _ipv4_header(6, len(tcp), b"\xc0\x00\x02\x01", b"\xc6\x33\x64\x35", identification)
    return _ethernet(ip + tcp)


def _pcap(path: Path, frames: list[bytes]) -> None:
    data = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
    for index, frame in enumerate(frames, start=1):
        data += struct.pack("<IIII", index, 0, len(frame), len(frame)) + frame
    path.write_bytes(bytes(data))


def _dns_query() -> bytes:
    return (
        struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0)
        + b"\x07example\x03com\x00"
        + struct.pack("!HH", 1, 1)
    )


def _extension(kind: int, value: bytes) -> bytes:
    return struct.pack("!HH", kind, len(value)) + value


def _tls_client_hello() -> bytes:
    random = bytes(range(32))
    ciphers = struct.pack("!HH", 0x1301, 0x1302)
    name = b"example.com"
    sni = struct.pack("!H", 3 + len(name)) + b"\x00" + struct.pack("!H", len(name)) + name
    alpn = b"\x00\x03\x02h2"
    versions = b"\x04\x03\x04\x03\x03"
    extensions = _extension(0, sni) + _extension(16, alpn) + _extension(43, versions)
    hello = b"\x03\x03" + random + b"\x00" + struct.pack("!H", len(ciphers)) + ciphers + b"\x01\x00" + struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def _tshark_fields(path: Path, display_filter: str, fields: list[str]) -> list[list[str]]:
    command = [str(TSHARK), "-n", "-r", str(path), "-Y", display_filter, "-T", "fields"]
    for field in fields:
        command.extend(("-e", field))
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30, check=False)
    assert completed.returncode == 0, completed.stderr[-4000:]
    rows = []
    for line in completed.stdout.splitlines():
        values = line.split("\t")
        values += [""] * (len(fields) - len(values))
        rows.append(values[: len(fields)])
    return rows


def test_dns_native_fields_match_tshark_on_identical_wire_frame(tmp_path: Path) -> None:
    frame = _udp_frame(_dns_query(), 53000, 53)
    native = ProtocolIntelligenceEngine().decode_frame(frame, link_type="ethernet")
    dns = next(layer.fields for layer in native.layers if layer.name == "dns")
    path = tmp_path / "dns.pcap"
    _pcap(path, [frame])
    rows = _tshark_fields(path, "dns", ["dns.id", "dns.qry.name", "dns.qry.type"])
    assert rows
    assert int(rows[0][0], 0) == dns["transaction_id"] == 0x4242
    assert rows[0][1].rstrip(".") == dns["question_records"][0]["name"] == "example.com"
    assert int(rows[0][2]) == dns["question_records"][0]["type"] == 1


def test_tls_clienthello_native_sni_and_alpn_match_tshark(tmp_path: Path) -> None:
    hello = _tls_client_hello()
    frame = _tcp_frame(hello, 54000, 443)
    native = ProtocolIntelligenceEngine().decode_frame(frame, link_type="ethernet")
    tls = next(layer.fields for layer in native.layers if layer.name == "tls")
    path = tmp_path / "tls.pcap"
    _pcap(path, [frame])
    rows = _tshark_fields(path, "tls.handshake.type == 1", ["tls.handshake.extensions_server_name", "tls.handshake.extensions_alpn_str"])
    assert rows
    assert rows[0][0] == tls["server_name"] == "example.com"
    assert "h2" in rows[0][1].split(",")
    assert "h2" in tls["alpn"]


def _ospfv2_hello() -> bytes:
    import ipaddress

    body = (
        ipaddress.IPv4Address("255.255.255.0").packed
        + struct.pack("!HBBI", 10, 0x02, 7, 40)
        + ipaddress.IPv4Address("192.0.2.254").packed
        + ipaddress.IPv4Address("192.0.2.253").packed
        + ipaddress.IPv4Address("10.0.0.2").packed
    )
    packet = bytearray(
        struct.pack("!BBH", 2, 1, 24 + len(body))
        + ipaddress.IPv4Address("10.0.0.1").packed
        + ipaddress.IPv4Address("0.0.0.0").packed
        + struct.pack("!HH", 0, 0)
        + b"\x00" * 8
        + body
    )
    # For AuType 0, the authentication field is excluded from the OSPFv2
    # checksum. This fixture only needs a standards-shaped checksum so both
    # independent dissectors see identical wire bytes without checksum noise.
    checksum_data = bytes(packet[:16]) + b"\x00" * 8 + bytes(packet[24:])
    struct.pack_into("!H", packet, 12, _checksum(checksum_data))
    return bytes(packet)


def test_ospfv2_hello_native_control_plane_fields_match_tshark(tmp_path: Path) -> None:
    import ipaddress

    ospf = _ospfv2_hello()
    ip = _ipv4_header(
        89,
        len(ospf),
        ipaddress.IPv4Address("192.0.2.1").packed,
        ipaddress.IPv4Address("224.0.0.5").packed,
        3,
    )
    frame = _ethernet(ip + ospf)
    native = ProtocolIntelligenceEngine().decode_frame(frame, link_type="ethernet")
    fields = next(layer.fields for layer in native.layers if layer.name == "ospf")
    path = tmp_path / "ospfv2-hello.pcap"
    _pcap(path, [frame])
    rows = _tshark_fields(
        path,
        "ospf.msg == 1",
        [
            "ospf.version",
            "ospf.msg",
            "ospf.hello.network_mask",
            "ospf.hello.hello_interval",
            "ospf.hello.router_dead_interval",
            "ospf.hello.router_priority",
            "ospf.hello.designated_router",
        ],
    )
    assert rows
    assert int(rows[0][0]) == fields["version"] == 2
    assert int(rows[0][1]) == fields["packet_type"] == 1
    assert rows[0][2] == fields["network_mask"] == "255.255.255.0"
    assert int(rows[0][3]) == fields["hello_interval_seconds"] == 10
    assert int(rows[0][4]) == fields["router_dead_interval_seconds"] == 40
    assert int(rows[0][5]) == fields["router_priority"] == 7
    assert rows[0][6] == fields["designated_router"] == "192.0.2.254"
