from __future__ import annotations

import ipaddress
import struct
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from arenyxa.compat import dataclass


@dataclass(frozen=True, slots=True)
class PacketArtifact:
    link_type: str
    protocol: str
    length: int
    hex: str
    metadata: dict[str, Any]

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


class OfflinePacketLab:
    """Bounded offline packet construction for protocol development and test fixtures.

    The lab intentionally does not transmit packets. It creates deterministic frame bytes
    or PCAP fixtures that can be inspected, fuzzed, or replayed only through explicitly
    separate capture tooling.
    """

    MAX_PAYLOAD = 1024 * 1024

    @staticmethod
    def checksum(payload: bytes) -> int:
        if len(payload) % 2:
            payload += b"\x00"
        total = sum(struct.unpack(f"!{len(payload) // 2}H", payload))
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return (~total) & 0xFFFF

    @staticmethod
    def _ipv4(value: str) -> bytes:
        address = ipaddress.ip_address(value)
        if address.version != 4:
            raise ValueError("IPv4 address required")
        return address.packed

    @staticmethod
    def _ipv6(value: str) -> bytes:
        address = ipaddress.ip_address(value)
        if address.version != 6:
            raise ValueError("IPv6 address required")
        return address.packed

    @staticmethod
    def _mac(value: str) -> bytes:
        parts = str(value).replace("-", ":").split(":")
        if len(parts) != 6:
            raise ValueError("MAC address must contain six octets")
        try:
            raw = bytes(int(part, 16) for part in parts)
        except ValueError as exc:
            raise ValueError("invalid MAC address") from exc
        if len(raw) != 6:
            raise ValueError("invalid MAC address")
        return raw

    @classmethod
    def _payload(cls, payload: bytes | bytearray | memoryview | str) -> bytes:
        raw = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
        if len(raw) > cls.MAX_PAYLOAD:
            raise ValueError("packet payload exceeds 1 MiB safety budget")
        return raw

    @classmethod
    def ipv4_udp(
        cls,
        *,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        payload: bytes | str = b"",
        ttl: int = 64,
        identification: int = 0,
    ) -> PacketArtifact:
        data = cls._payload(payload)
        src = cls._ipv4(src_ip)
        dst = cls._ipv4(dst_ip)
        sport = cls._port(src_port)
        dport = cls._port(dst_port)
        udp_length = 8 + len(data)
        udp_header = struct.pack("!HHHH", sport, dport, udp_length, 0)
        pseudo = src + dst + struct.pack("!BBH", 0, 17, udp_length)
        udp_checksum = cls.checksum(pseudo + udp_header + data)
        udp_header = struct.pack("!HHHH", sport, dport, udp_length, udp_checksum)
        ip_header = cls._ipv4_header(src, dst, 17, len(udp_header) + len(data), ttl, identification)
        packet = ip_header + udp_header + data
        return PacketArtifact("raw-ip", "udp", len(packet), packet.hex(), {
            "src_ip": src_ip, "dst_ip": dst_ip, "src_port": sport, "dst_port": dport,
            "ttl": ttl, "udp_checksum": udp_checksum,
        })

    @classmethod
    def ipv4_tcp(
        cls,
        *,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        payload: bytes | str = b"",
        seq: int = 0,
        ack: int = 0,
        flags: int = 0x02,
        window: int = 64240,
        ttl: int = 64,
        identification: int = 0,
    ) -> PacketArtifact:
        data = cls._payload(payload)
        src = cls._ipv4(src_ip)
        dst = cls._ipv4(dst_ip)
        sport = cls._port(src_port)
        dport = cls._port(dst_port)
        offset_flags = (5 << 12) | (int(flags) & 0x1FF)
        header = struct.pack("!HHIIHHHH", sport, dport, int(seq) & 0xFFFFFFFF, int(ack) & 0xFFFFFFFF, offset_flags, int(window) & 0xFFFF, 0, 0)
        pseudo = src + dst + struct.pack("!BBH", 0, 6, len(header) + len(data))
        tcp_checksum = cls.checksum(pseudo + header + data)
        header = struct.pack("!HHIIHHHH", sport, dport, int(seq) & 0xFFFFFFFF, int(ack) & 0xFFFFFFFF, offset_flags, int(window) & 0xFFFF, tcp_checksum, 0)
        ip_header = cls._ipv4_header(src, dst, 6, len(header) + len(data), ttl, identification)
        packet = ip_header + header + data
        return PacketArtifact("raw-ip", "tcp", len(packet), packet.hex(), {
            "src_ip": src_ip, "dst_ip": dst_ip, "src_port": sport, "dst_port": dport,
            "flags": int(flags) & 0x1FF, "seq": int(seq) & 0xFFFFFFFF, "ack": int(ack) & 0xFFFFFFFF,
            "tcp_checksum": tcp_checksum,
        })

    @classmethod
    def ipv4_icmp_echo(
        cls,
        *,
        src_ip: str,
        dst_ip: str,
        payload: bytes | str = b"",
        identifier: int = 0,
        sequence: int = 0,
        ttl: int = 64,
    ) -> PacketArtifact:
        data = cls._payload(payload)
        header = struct.pack("!BBHHH", 8, 0, 0, int(identifier) & 0xFFFF, int(sequence) & 0xFFFF)
        checksum = cls.checksum(header + data)
        header = struct.pack("!BBHHH", 8, 0, checksum, int(identifier) & 0xFFFF, int(sequence) & 0xFFFF)
        src = cls._ipv4(src_ip)
        dst = cls._ipv4(dst_ip)
        ip_header = cls._ipv4_header(src, dst, 1, len(header) + len(data), ttl, 0)
        packet = ip_header + header + data
        return PacketArtifact("raw-ip", "icmp", len(packet), packet.hex(), {
            "src_ip": src_ip, "dst_ip": dst_ip, "identifier": int(identifier) & 0xFFFF,
            "sequence": int(sequence) & 0xFFFF, "icmp_checksum": checksum,
        })

    @classmethod
    def ipv6_udp(
        cls, *, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
        payload: bytes | str = b"", hop_limit: int = 64,
    ) -> PacketArtifact:
        data = cls._payload(payload)
        src = cls._ipv6(src_ip)
        dst = cls._ipv6(dst_ip)
        sport = cls._port(src_port)
        dport = cls._port(dst_port)
        length = 8 + len(data)
        header = struct.pack("!HHHH", sport, dport, length, 0)
        pseudo = src + dst + struct.pack("!I3xB", length, 17)
        checksum = cls.checksum(pseudo + header + data) or 0xFFFF
        header = struct.pack("!HHHH", sport, dport, length, checksum)
        packet = cls._ipv6_header(src, dst, 17, len(header) + len(data), hop_limit) + header + data
        return PacketArtifact("raw-ip", "udp6", len(packet), packet.hex(), {
            "src_ip": src_ip, "dst_ip": dst_ip, "src_port": sport, "dst_port": dport,
            "hop_limit": max(1, min(255, int(hop_limit))), "udp_checksum": checksum,
        })

    @classmethod
    def ipv6_tcp(
        cls, *, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
        payload: bytes | str = b"", seq: int = 0, ack: int = 0,
        flags: int = 0x02, window: int = 64240, hop_limit: int = 64,
    ) -> PacketArtifact:
        data = cls._payload(payload)
        src = cls._ipv6(src_ip)
        dst = cls._ipv6(dst_ip)
        sport = cls._port(src_port)
        dport = cls._port(dst_port)
        offset_flags = (5 << 12) | (int(flags) & 0x1FF)
        header = struct.pack("!HHIIHHHH", sport, dport, int(seq) & 0xFFFFFFFF, int(ack) & 0xFFFFFFFF,
                             offset_flags, int(window) & 0xFFFF, 0, 0)
        length = len(header) + len(data)
        pseudo = src + dst + struct.pack("!I3xB", length, 6)
        checksum = cls.checksum(pseudo + header + data)
        header = struct.pack("!HHIIHHHH", sport, dport, int(seq) & 0xFFFFFFFF, int(ack) & 0xFFFFFFFF,
                             offset_flags, int(window) & 0xFFFF, checksum, 0)
        packet = cls._ipv6_header(src, dst, 6, length, hop_limit) + header + data
        return PacketArtifact("raw-ip", "tcp6", len(packet), packet.hex(), {
            "src_ip": src_ip, "dst_ip": dst_ip, "src_port": sport, "dst_port": dport,
            "flags": int(flags) & 0x1FF, "tcp_checksum": checksum,
        })

    @classmethod
    def ipv6_icmp_echo(
        cls, *, src_ip: str, dst_ip: str, payload: bytes | str = b"",
        identifier: int = 0, sequence: int = 0, hop_limit: int = 64,
    ) -> PacketArtifact:
        data = cls._payload(payload)
        src = cls._ipv6(src_ip)
        dst = cls._ipv6(dst_ip)
        header = struct.pack("!BBHHH", 128, 0, 0, int(identifier) & 0xFFFF, int(sequence) & 0xFFFF)
        length = len(header) + len(data)
        pseudo = src + dst + struct.pack("!I3xB", length, 58)
        checksum = cls.checksum(pseudo + header + data)
        header = struct.pack("!BBHHH", 128, 0, checksum, int(identifier) & 0xFFFF, int(sequence) & 0xFFFF)
        packet = cls._ipv6_header(src, dst, 58, length, hop_limit) + header + data
        return PacketArtifact("raw-ip", "icmp6", len(packet), packet.hex(), {
            "src_ip": src_ip, "dst_ip": dst_ip, "identifier": int(identifier) & 0xFFFF,
            "sequence": int(sequence) & 0xFFFF, "icmpv6_checksum": checksum,
        })

    @classmethod
    def arp_request(cls, *, src_mac: str, src_ip: str, target_ip: str) -> PacketArtifact:
        sender_mac = cls._mac(src_mac)
        sender_ip = cls._ipv4(src_ip)
        target = cls._ipv4(target_ip)
        arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, sender_mac, sender_ip, b"\x00" * 6, target)
        frame = b"\xff" * 6 + sender_mac + struct.pack("!H", 0x0806) + arp
        return PacketArtifact("ethernet", "arp", len(frame), frame.hex(), {
            "operation": "request", "src_mac": src_mac, "src_ip": src_ip, "target_ip": target_ip,
        })

    @staticmethod
    def _dns_name(name: str) -> bytes:
        text = str(name or "").strip().rstrip(".")
        if not text or len(text.encode("idna")) > 253:
            raise ValueError("DNS name must be 1..253 bytes")
        encoded = bytearray()
        for label in text.split("."):
            raw = label.encode("idna")
            if not raw or len(raw) > 63:
                raise ValueError("DNS labels must be 1..63 bytes")
            encoded.append(len(raw))
            encoded.extend(raw)
        encoded.append(0)
        return bytes(encoded)

    @classmethod
    def dns_query(
        cls, *, src_ip: str, dst_ip: str, name: str, src_port: int = 53000,
        dst_port: int = 53, query_type: int = 1, transaction_id: int = 0xA77A,
    ) -> PacketArtifact:
        qtype = int(query_type)
        if not 1 <= qtype <= 65535:
            raise ValueError("DNS query type must fit uint16")
        dns = struct.pack("!HHHHHH", int(transaction_id) & 0xFFFF, 0x0100, 1, 0, 0, 0)
        dns += cls._dns_name(name) + struct.pack("!HH", qtype, 1)
        artifact = cls.ipv4_udp(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, payload=dns)
        return PacketArtifact(artifact.link_type, "dns", artifact.length, artifact.hex, {
            **artifact.metadata, "query": str(name), "query_type": qtype, "transaction_id": int(transaction_id) & 0xFFFF,
        })

    @classmethod
    def dhcp_discover(
        cls, *, client_mac: str, transaction_id: int = 0xA77A0001,
        hostname: str = "arenyxa-lab",
    ) -> PacketArtifact:
        mac = cls._mac(client_mac)
        host = str(hostname or "arenyxa-lab").encode("ascii", errors="strict")
        if not host or len(host) > 63:
            raise ValueError("DHCP hostname must be 1..63 ASCII bytes")
        bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, int(transaction_id) & 0xFFFFFFFF,
                            0, 0x8000, b"\x00" * 4, b"\x00" * 4, b"\x00" * 4, b"\x00" * 4,
                            mac + b"\x00" * 10, b"\x00" * 64, b"\x00" * 128)
        options = b"\x63\x82\x53\x63" + b"\x35\x01\x01" + bytes((12, len(host))) + host + b"\x37\x03\x01\x03\x06\xff"
        artifact = cls.ipv4_udp(src_ip="0.0.0.0", dst_ip="255.255.255.255", src_port=68, dst_port=67, payload=bootp + options)
        return PacketArtifact(artifact.link_type, "dhcp", artifact.length, artifact.hex, {
            **artifact.metadata, "client_mac": client_mac, "transaction_id": int(transaction_id) & 0xFFFFFFFF,
            "message_type": "discover", "hostname": hostname,
        })

    @classmethod
    def http_request(
        cls, *, src_ip: str, dst_ip: str, host: str, target: str = "/", method: str = "GET",
        src_port: int = 49152, dst_port: int = 80, body: bytes | str = b"",
    ) -> PacketArtifact:
        method_value = str(method or "GET").upper()
        host_value = str(host or "").strip()
        target_value = str(target or "/").strip()
        if not method_value.isalpha() or len(method_value) > 16:
            raise ValueError("invalid HTTP method")
        if not host_value or any(ch in host_value for ch in "\r\n") or len(host_value) > 255:
            raise ValueError("invalid HTTP Host header")
        if not target_value.startswith("/") or any(ch in target_value for ch in "\r\n") or len(target_value) > 4096:
            raise ValueError("invalid HTTP request target")
        payload = cls._payload(body)
        head = f"{method_value} {target_value} HTTP/1.1\r\nHost: {host_value}\r\nConnection: close\r\n"
        if payload:
            head += f"Content-Length: {len(payload)}\r\n"
        request = head.encode("ascii") + b"\r\n" + payload
        artifact = cls.ipv4_tcp(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
                                payload=request, flags=0x18)
        return PacketArtifact(artifact.link_type, "http", artifact.length, artifact.hex, {
            **artifact.metadata, "host": host_value, "target": target_value, "method": method_value,
        })

    @classmethod
    def tls_client_hello(
        cls, *, src_ip: str, dst_ip: str, server_name: str, src_port: int = 49152, dst_port: int = 443,
    ) -> PacketArtifact:
        host = str(server_name or "").strip().encode("idna")
        if not host or len(host) > 253:
            raise ValueError("TLS server name must be 1..253 bytes")
        random_bytes = bytes.fromhex("a77a" * 16)
        sni_name = struct.pack("!BH", 0, len(host)) + host
        sni = struct.pack("!HHH", 0, len(sni_name) + 2, len(sni_name)) + sni_name
        supported_versions_body = b"\x04\x03\x04\x03\x03"
        supported_versions = struct.pack("!HH", 43, len(supported_versions_body)) + supported_versions_body
        extensions = sni + supported_versions
        hello_body = b"\x03\x03" + random_bytes + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
        hello_body += struct.pack("!H", len(extensions)) + extensions
        handshake = b"\x01" + len(hello_body).to_bytes(3, "big") + hello_body
        record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
        artifact = cls.ipv4_tcp(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
                                payload=record, flags=0x18)
        return PacketArtifact(artifact.link_type, "tls-client-hello", artifact.length, artifact.hex, {
            **artifact.metadata, "server_name": host.decode("ascii"), "record_version": "TLS1.0-compat",
            "client_version": "TLS1.2", "supported_versions": ["TLS1.3", "TLS1.2"],
        })

    @classmethod
    def ethernet(cls, payload: bytes | bytearray | memoryview, *, src_mac: str, dst_mac: str, ethertype: int = 0x0800) -> PacketArtifact:
        data = cls._payload(payload)
        if not 0 <= int(ethertype) <= 0xFFFF:
            raise ValueError("ethertype must fit uint16")
        frame = cls._mac(dst_mac) + cls._mac(src_mac) + struct.pack("!H", int(ethertype)) + data
        return PacketArtifact("ethernet", "ethernet", len(frame), frame.hex(), {
            "src_mac": src_mac, "dst_mac": dst_mac, "ethertype": int(ethertype),
        })

    @staticmethod
    def write_pcap(path: Path | str, packet: PacketArtifact | bytes, *, linktype: int = 101, timestamp: float | None = None) -> Path:
        destination = Path(path)
        raw = bytes.fromhex(packet.hex) if isinstance(packet, PacketArtifact) else bytes(packet)
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("single packet exceeds 16 MiB PCAP budget")
        destination.parent.mkdir(parents=True, exist_ok=True)
        ts = time.time() if timestamp is None else float(timestamp)
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 16 * 1024 * 1024, int(linktype))
        record = struct.pack("<IIII", sec, usec, len(raw), len(raw)) + raw
        with destination.open("wb") as stream:
            stream.write(global_header)
            stream.write(record)
        return destination

    @staticmethod
    def _port(value: int) -> int:
        port = int(value)
        if not 0 < port <= 65535:
            raise ValueError("port must be in 1..65535")
        return port

    @staticmethod
    def _ipv6_header(src: bytes, dst: bytes, next_header: int, payload_length: int, hop_limit: int) -> bytes:
        length = int(payload_length)
        if length < 0 or length > 65535:
            raise ValueError("IPv6 payload exceeds 65535-byte non-jumbo budget")
        return struct.pack(
            "!IHBB16s16s", 6 << 28, length, int(next_header) & 0xFF,
            max(1, min(255, int(hop_limit))), src, dst,
        )

    @classmethod
    def _ipv4_header(cls, src: bytes, dst: bytes, protocol: int, payload_length: int, ttl: int, identification: int) -> bytes:
        ttl_value = max(1, min(255, int(ttl)))
        total_length = 20 + int(payload_length)
        if total_length > 65535:
            raise ValueError("IPv4 packet exceeds 65535 bytes")
        header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, total_length, int(identification) & 0xFFFF, 0, ttl_value, int(protocol) & 0xFF, 0, src, dst,
        )
        checksum = cls.checksum(header)
        return struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, total_length, int(identification) & 0xFFFF, 0, ttl_value, int(protocol) & 0xFF, checksum, src, dst,
        )
