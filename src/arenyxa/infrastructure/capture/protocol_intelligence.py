from __future__ import annotations

import ipaddress
import struct
from typing import Any

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.protocol_application import ApplicationProtocolMixin
from arenyxa.infrastructure.capture.protocol_deep_application import decode_sctp_chunks
from arenyxa.infrastructure.capture.protocol_ipv6_extensions import decode_ipv6_routing_header
from arenyxa.infrastructure.capture.protocol_icmp import decode_icmp_message
from arenyxa.infrastructure.capture.protocol_ospf import decode_ospf_packet
from arenyxa.infrastructure.capture.protocol_l2_control import decode_eapol, decode_lldp
from arenyxa.infrastructure.capture.protocol_l2_enterprise import decode_cdp, decode_slow_protocol, decode_stp_bpdu
from arenyxa.infrastructure.capture.protocol_routing_control import decode_igmp, decode_pim, decode_vrrp
from arenyxa.infrastructure.capture.protocol_isis_ldp import decode_isis_pdu
from arenyxa.infrastructure.capture.protocol_ipsec import decode_ah_packet, decode_esp_packet
from arenyxa.infrastructure.capture.protocol_core_registry import (
    ETHERTYPES,
    IP_PROTOCOLS,
    PORT_HINTS,
)

@dataclass(slots=True)
class ProtocolLayer:
    name: str
    offset: int
    length: int
    fields: dict[str, Any]

@dataclass(slots=True)
class ProtocolDecodeResult:
    frame_length: int
    link_type: str
    protocols: tuple[str, ...]
    layers: list[ProtocolLayer]
    application_protocol: str
    encrypted: bool
    truncated: bool
    warnings: list[str]
    flow_key: str = ""

class ProtocolIntelligenceEngine(ApplicationProtocolMixin):
    """Bounded native packet decoder for high-value network protocol metadata.

    Arenyxa's external dissector bridge remains the broadest decoding path. This
    native engine provides deterministic, dependency-free parsing for core
    Ethernet/IP/transport protocols and a conservative set of common application
    protocols. It intentionally extracts metadata rather than payload secrets.
    """

    MAX_FRAME_BYTES = 16 * 1024 * 1024
    MAX_LAYERS = 48
    MAX_VLAN_TAGS = 4
    MAX_MPLS_LABELS = 8
    MAX_IPV6_EXTENSIONS = 16
    MAX_DNS_NAME_DEPTH = 8
    MAX_DNS_NAME_CHARS = 255
    MAX_TEXT_LINE = 2048

    ETHERTYPES = ETHERTYPES
    IP_PROTOCOLS = IP_PROTOCOLS
    PORT_HINTS = PORT_HINTS

    def decode_frame(self, frame: bytes | bytearray | memoryview, *, link_type: str = "ethernet") -> ProtocolDecodeResult:
        raw = bytes(frame)
        if not raw:
            raise ValueError("frame is empty")
        if len(raw) > self.MAX_FRAME_BYTES:
            raise ValueError("frame exceeds the native decoder byte budget")
        result = ProtocolDecodeResult(
            frame_length=len(raw),
            link_type=str(link_type).casefold(),
            protocols=(),
            layers=[],
            application_protocol="",
            encrypted=False,
            truncated=False,
            warnings=[],
        )
        try:
            if result.link_type in {"ethernet", "eth", "en10mb"}:
                self._ethernet(raw, 0, result)
            elif result.link_type in {"raw", "raw-ip", "ip"}:
                self._network_by_version(raw, 0, result)
            elif result.link_type in {"linux-sll", "sll"}:
                self._linux_sll(raw, result)
            elif result.link_type in {"linux-sll2", "sll2"}:
                self._linux_sll2(raw, result)
            elif result.link_type in {"null", "loopback"}:
                self._loopback(raw, result)
            elif result.link_type in {"ppp", "ppp-hdlc"}:
                self._ppp(raw, result)
            elif result.link_type in {"radiotap", "ieee80211-radiotap"}:
                self._radiotap(raw, result)
            elif result.link_type in {"ieee80211", "802.11", "wifi"}:
                self._ieee80211(raw, 0, result)
            else:
                result.warnings.append(f"unsupported native link type: {result.link_type}")
        except (IndexError, struct.error, ValueError) as exc:
            result.truncated = True
            result.warnings.append(f"decode stopped safely: {type(exc).__name__}: {str(exc)[:160]}")
        result.protocols = tuple(layer.name for layer in result.layers)
        if not result.application_protocol:
            result.application_protocol = self._last_application(result)
        return result

    def decode_application_payload(
        self, payload: bytes | bytearray | memoryview, *, source_port: int, destination_port: int, transport: str = "tcp"
    ) -> ProtocolDecodeResult:
        raw = bytes(payload)
        if len(raw) > self.MAX_FRAME_BYTES:
            raise ValueError("application payload exceeds the native decoder byte budget")
        result = ProtocolDecodeResult(
            frame_length=len(raw),
            link_type=f"{str(transport).casefold()}-stream",
            protocols=(),
            layers=[],
            application_protocol="",
            encrypted=False,
            truncated=False,
            warnings=[],
        )
        try:
            self._application(raw, 0, int(source_port), int(destination_port), str(transport).casefold(), result)
        except (IndexError, struct.error, ValueError) as exc:
            result.truncated = True
            result.warnings.append(f"stream decode stopped safely: {type(exc).__name__}: {str(exc)[:160]}")
        result.protocols = tuple(layer.name for layer in result.layers)
        if not result.application_protocol:
            result.application_protocol = self._last_application(result)
        return result

    def decode_http2_stream(self, payload: bytes | bytearray | memoryview) -> dict[str, Any]:
        """Decode a sequential cleartext/decrypted HTTP/2 direction with HPACK state."""
        raw = bytes(payload)
        if len(raw) > self.MAX_FRAME_BYTES:
            raise ValueError("HTTP/2 stream exceeds the native decoder byte budget")
        from arenyxa.infrastructure.capture.protocol_http2_stream import decode_http2_stream

        return decode_http2_stream(raw)

    def decode_websocket_stream(self, payload: bytes | bytearray | memoryview) -> dict[str, Any]:
        """Decode an already-identified WebSocket frame stream without retaining payload bytes."""
        raw = bytes(payload)
        if len(raw) > self.MAX_FRAME_BYTES:
            raise ValueError("WebSocket stream exceeds the native decoder byte budget")
        from arenyxa.infrastructure.capture.protocol_websocket import decode_websocket_stream

        return decode_websocket_stream(raw)

    def decode_http3_stream(self, payload: bytes | bytearray | memoryview) -> ProtocolDecodeResult:
        """Decode already-decrypted HTTP/3 stream bytes without claiming QUIC decryption."""
        raw = bytes(payload)
        if len(raw) > self.MAX_FRAME_BYTES:
            raise ValueError("HTTP/3 stream exceeds the native decoder byte budget")
        result = ProtocolDecodeResult(
            frame_length=len(raw), link_type="quic-decrypted-stream", protocols=(), layers=[],
            application_protocol="", encrypted=False, truncated=False, warnings=[],
        )
        try:
            self._add_http3_stream(raw, 0, result)
        except (IndexError, struct.error, ValueError) as exc:
            result.truncated = True
            result.warnings.append(f"HTTP/3 decode stopped safely: {type(exc).__name__}: {str(exc)[:160]}")
        result.protocols = tuple(layer.name for layer in result.layers)
        return result

    @staticmethod
    def decode_doh_body(payload: bytes | bytearray | memoryview) -> dict[str, Any]:
        from arenyxa.infrastructure.capture.protocol_encrypted_dns import decode_doh_body

        return decode_doh_body(bytes(payload))

    @staticmethod
    def decode_doq_stream(payload: bytes | bytearray | memoryview) -> dict[str, Any]:
        from arenyxa.infrastructure.capture.protocol_encrypted_dns import decode_doq_stream

        return decode_doq_stream(bytes(payload))

    @staticmethod
    def expert_findings(decoded: ProtocolDecodeResult) -> list[dict[str, Any]]:
        """Return bounded passive forensic diagnostics for one native decode result."""
        from arenyxa.infrastructure.capture.protocol_expert import analyze_protocol_decode

        return [finding.as_dict() for finding in analyze_protocol_decode(decoded)]

    def protocol_catalog(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        native = {
            "ethernet", "vlan", "mpls", "arp", "loopback", "ppp", "radiotap", "ieee80211",
            "ipv4", "ipv6", "icmp", "icmpv6", "igmp", "ospf", "isis", "vrrp", "pim", "eigrp", "bfd", "bfd-echo",
            "ip-in-ip", "ipv6-in-ipv4", "tcp", "udp", "sctp", "dccp", "gre", "ah", "esp",
            "pppoe", "lldp", "eapol", "stp", "rstp", "mstp", "lacp", "cdp",
            "dns", "mdns", "llmnr", "nbns", "dhcp", "dhcpv6", "tls", "http", "http2", "http3", "quic", "doh", "dot", "doq", "grpc", "ssh", "smtp",
            "pop3", "imap", "ftp", "rtsp", "sip", "ntp", "stun", "coap", "ssdp", "syslog",
            "radius", "mqtt", "amqp", "kafka", "protobuf", "redis", "modbus-tcp", "bacnet-ip", "tftp", "rtp", "rtcp",
            "snmp", "ldap", "smb", "kerberos", "bgp", "rpc", "nfs", "mysql", "postgresql",
            "mongodb", "memcached", "rdp", "ike", "l2tp", "rip", "ldp", "gtp", "pfcp", "diameter", "vxlan", "geneve", "wireguard",
            "websocket", "sse", "socks", "rfb", "opcua", "iec104", "dnp3", "s7comm", "turn-channel-data",
        }
        deep = {
            "dns", "mdns", "llmnr", "nbns", "tls", "http", "http2", "http3", "quic", "doh", "doq",
            "grpc", "protobuf", "websocket", "ssh", "tcp", "ipv4", "ipv6", "icmp", "icmpv6", "sctp", "bgp", "mqtt", "amqp", "kafka", "mpls",
            "modbus-tcp", "iec104", "dnp3", "lldp", "eapol", "ospf", "isis", "ldp", "stp", "rstp", "mstp", "lacp", "cdp", "igmp", "vrrp", "pim", "bfd",
            "dhcp", "dhcpv6", "radius", "snmp", "coap", "stun", "turn-channel-data", "bacnet-ip", "opcua", "vxlan", "geneve", "ike", "wireguard", "l2tp", "gtp", "pfcp", "diameter",
        }
        for name in sorted(native):
            rows.append({
                "protocol": name, "native": True,
                "mode": "native-deep" if name in deep else "structured-metadata",
            })
        return rows

    def _ethernet(self, raw: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(raw, offset, 14)
        destination, source, ether_type = struct.unpack_from("!6s6sH", raw, offset)
        self._add(result, "ethernet", offset, 14, {
            "source": self._mac(source),
            "destination": self._mac(destination),
            "ethertype": f"0x{ether_type:04x}",
        })
        cursor = offset + 14
        tags = 0
        while ether_type in {0x8100, 0x88A8} and tags < self.MAX_VLAN_TAGS:
            self._need(raw, cursor, 4)
            tci, ether_type = struct.unpack_from("!HH", raw, cursor)
            self._add(result, "vlan", cursor, 4, {
                "priority": (tci >> 13) & 0x7,
                "dei": bool((tci >> 12) & 0x1),
                "vlan_id": tci & 0x0FFF,
                "ethertype": f"0x{ether_type:04x}",
            })
            cursor += 4
            tags += 1
        if ether_type <= 1500:
            self._llc(raw, cursor, result, declared_length=ether_type)
            return
        if ether_type in {0x8847, 0x8848}:
            self._mpls(raw, cursor, result)
            return
        if ether_type == 0x0800:
            self._ipv4(raw, cursor, result)
        elif ether_type == 0x86DD:
            self._ipv6(raw, cursor, result)
        elif ether_type == 0x0806:
            self._arp(raw, cursor, result)
        elif ether_type in {0x8863, 0x8864}:
            self._pppoe(raw, cursor, result, session=ether_type == 0x8864)
        elif ether_type == 0x88CC:
            self._add(result, "lldp", cursor, len(raw) - cursor, decode_lldp(raw[cursor:]))
        elif ether_type == 0x888E:
            self._eapol(raw, cursor, result)
        elif ether_type == 0x8809:
            fields = decode_slow_protocol(raw[cursor:])
            name = "lacp" if fields.get("subtype_name") == "lacp" else "slow-protocols"
            self._add(result, name, cursor, len(raw) - cursor, fields)
            result.application_protocol = name

    def _llc(self, raw: bytes, offset: int, result: ProtocolDecodeResult, *, declared_length: int) -> None:
        available = min(max(0, int(declared_length)), max(0, len(raw) - offset))
        self._need(raw, offset, min(3, available))
        if available < 3:
            raise ValueError("truncated IEEE 802.2 LLC header")
        dsap, ssap, control = raw[offset], raw[offset + 1], raw[offset + 2]
        self._add(result, "llc", offset, 3, {"dsap": f"0x{dsap:02x}", "ssap": f"0x{ssap:02x}", "control": f"0x{control:02x}"})
        payload_offset = offset + 3
        payload_end = offset + available
        if dsap == 0x42 and ssap == 0x42 and control == 0x03:
            fields = decode_stp_bpdu(raw[payload_offset:payload_end])
            name = str(fields.get("protocol_name") or "stp")
            self._add(result, name, payload_offset, payload_end - payload_offset, fields)
            result.application_protocol = name
            return
        if dsap == 0xFE and ssap == 0xFE and control == 0x03:
            fields = decode_isis_pdu(raw[payload_offset:payload_end])
            self._add(result, "isis", payload_offset, payload_end - payload_offset, fields)
            result.application_protocol = "isis"
            return
        if dsap == 0xAA and ssap == 0xAA and control == 0x03:
            self._need(raw, payload_offset, 5)
            oui = raw[payload_offset:payload_offset + 3]
            pid = struct.unpack_from("!H", raw, payload_offset + 3)[0]
            self._add(result, "snap", payload_offset, 5, {"oui": oui.hex(":"), "pid": f"0x{pid:04x}"})
            snap_payload = payload_offset + 5
            if oui == b"\x00\x00\x0c" and pid == 0x2000:
                fields = decode_cdp(raw[snap_payload:payload_end])
                self._add(result, "cdp", snap_payload, payload_end - snap_payload, fields)
                result.application_protocol = "cdp"

    def _linux_sll(self, raw: bytes, result: ProtocolDecodeResult) -> None:
        self._need(raw, 0, 16)
        packet_type, address_type, address_len = struct.unpack_from("!HHH", raw, 0)
        protocol = struct.unpack_from("!H", raw, 14)[0]
        self._add(result, "linux-sll", 0, 16, {
            "packet_type": packet_type,
            "address_type": address_type,
            "address_length": address_len,
            "protocol": f"0x{protocol:04x}",
        })
        self._dispatch_ethertype(raw, 16, protocol, result)

    def _linux_sll2(self, raw: bytes, result: ProtocolDecodeResult) -> None:
        self._need(raw, 0, 20)
        protocol = struct.unpack_from("!H", raw, 0)[0]
        interface_index = struct.unpack_from("!I", raw, 4)[0]
        self._add(result, "linux-sll2", 0, 20, {"protocol": f"0x{protocol:04x}", "interface_index": interface_index})
        self._dispatch_ethertype(raw, 20, protocol, result)

    def _loopback(self, raw: bytes, result: ProtocolDecodeResult) -> None:
        self._need(raw, 0, 4)
        little = struct.unpack_from("<I", raw, 0)[0]
        big = struct.unpack_from(">I", raw, 0)[0]
        ipv4_families = {2}
        ipv6_families = {10, 24, 28, 30}
        family = little if little in ipv4_families | ipv6_families else big
        self._add(result, "loopback", 0, 4, {"address_family": family})
        if family in ipv4_families:
            self._ipv4(raw, 4, result)
        elif family in ipv6_families:
            self._ipv6(raw, 4, result)

    def _ppp(self, raw: bytes, result: ProtocolDecodeResult) -> None:
        cursor = 0
        if len(raw) >= 2 and raw[:2] == b"\xff\x03":
            cursor = 2
        self._need(raw, cursor, 1)
        first = raw[cursor]
        if first & 0x01:
            protocol = first
            protocol_length = 1
        else:
            self._need(raw, cursor, 2)
            protocol = struct.unpack_from("!H", raw, cursor)[0]
            protocol_length = 2
        self._add(result, "ppp", 0, cursor + protocol_length, {"protocol": f"0x{protocol:04x}"})
        payload_offset = cursor + protocol_length
        if protocol in {0x0021, 0x21}:
            self._ipv4(raw, payload_offset, result)
        elif protocol in {0x0057, 0x57}:
            self._ipv6(raw, payload_offset, result)
        elif protocol in {0xC021, 0x8021, 0x8057}:
            self._add(result, "ppp-control", payload_offset, max(0, len(raw) - payload_offset), {"protocol": f"0x{protocol:04x}"})

    def _radiotap(self, raw: bytes, result: ProtocolDecodeResult) -> None:
        self._need(raw, 0, 8)
        version = raw[0]
        header_length = struct.unpack_from("<H", raw, 2)[0]
        present = struct.unpack_from("<I", raw, 4)[0]
        if version != 0 or header_length < 8 or header_length > len(raw):
            raise ValueError("invalid radiotap header")
        self._add(result, "radiotap", 0, header_length, {
            "version": version,
            "header_length": header_length,
            "present_bitmap": f"0x{present:08x}",
        })
        self._ieee80211(raw, header_length, result)

    def _ieee80211(self, raw: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(raw, offset, 2)
        frame_control = struct.unpack_from("<H", raw, offset)[0]
        frame_type = (frame_control >> 2) & 0x3
        subtype = (frame_control >> 4) & 0xF
        to_ds = bool((frame_control >> 8) & 0x1)
        from_ds = bool((frame_control >> 9) & 0x1)
        protected = bool((frame_control >> 14) & 0x1)
        header_length = 24 if frame_type in {0, 2} else (16 if subtype in {8, 9, 10, 11} else 10)
        if frame_type == 2 and to_ds and from_ds:
            header_length = 30
        if frame_type == 2 and (subtype & 0x8):
            header_length += 2
        self._need(raw, offset, header_length)
        fields: dict[str, Any] = {
            "type": frame_type,
            "subtype": subtype,
            "to_ds": to_ds,
            "from_ds": from_ds,
            "protected": protected,
            "retry": bool((frame_control >> 11) & 0x1),
        }
        if header_length >= 24:
            fields.update({
                "address1": self._mac(raw[offset + 4:offset + 10]),
                "address2": self._mac(raw[offset + 10:offset + 16]),
                "address3": self._mac(raw[offset + 16:offset + 22]),
            })
        self._add(result, "ieee80211", offset, header_length, fields)
        payload_offset = offset + header_length
        if protected:
            result.encrypted = True
            return
        if frame_type != 2 or payload_offset + 8 > len(raw):
            return
        if raw[payload_offset:payload_offset + 3] == b"\xaa\xaa\x03":
            ether_type = struct.unpack_from("!H", raw, payload_offset + 6)[0]
            self._add(result, "llc-snap", payload_offset, 8, {"ethertype": f"0x{ether_type:04x}"})
            self._dispatch_ethertype(raw, payload_offset + 8, ether_type, result)

    def _dispatch_ethertype(self, raw: bytes, offset: int, ether_type: int, result: ProtocolDecodeResult) -> None:
        if ether_type == 0x0800:
            self._ipv4(raw, offset, result)
        elif ether_type == 0x86DD:
            self._ipv6(raw, offset, result)
        elif ether_type == 0x0806:
            self._arp(raw, offset, result)

    def _mpls(self, raw: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        cursor = offset
        labels: list[dict[str, Any]] = []
        special_names = {
            0: "ipv4-explicit-null",
            1: "router-alert",
            2: "ipv6-explicit-null",
            3: "implicit-null",
            7: "entropy-label-indicator",
            13: "generic-associated-channel",
            14: "oam-alert",
            15: "extension-label",
        }
        for _index in range(self.MAX_MPLS_LABELS):
            self._need(raw, cursor, 4)
            value = struct.unpack_from("!I", raw, cursor)[0]
            label = (value >> 12) & 0xFFFFF
            row: dict[str, Any] = {
                "label": label,
                "traffic_class": (value >> 9) & 0x7,
                "bottom_of_stack": bool((value >> 8) & 0x1),
                "ttl": value & 0xFF,
            }
            if label <= 15:
                row["special_purpose"] = True
                row["special_purpose_name"] = special_names.get(label, "unassigned-special-purpose")
            labels.append(row)
            cursor += 4
            if row["bottom_of_stack"]:
                break
        for index, row in enumerate(labels[:-1]):
            if row["label"] == 7:
                labels[index + 1]["entropy_label"] = True
                row["entropy_label_value"] = labels[index + 1]["label"]
            elif row["label"] == 15:
                row["extended_special_purpose_label"] = labels[index + 1]["label"]
                labels[index + 1]["extended_special_purpose_value"] = True
        bottom_seen = bool(labels and labels[-1]["bottom_of_stack"])
        fields = {
            "labels": labels,
            "label_count": len(labels),
            "bottom_of_stack_seen": bottom_seen,
            "label_budget_reached": not bottom_seen and len(labels) >= self.MAX_MPLS_LABELS,
        }
        self._add(result, "mpls", offset, cursor - offset, fields)
        if cursor < len(raw):
            self._network_by_version(raw, cursor, result)

    def _arp(self, raw: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(raw, offset, 8)
        hardware, protocol, hardware_len, protocol_len, opcode = struct.unpack_from("!HHBBH", raw, offset)
        cursor = offset + 8
        needed = hardware_len * 2 + protocol_len * 2
        self._need(raw, cursor, needed)
        sender_hw = raw[cursor:cursor + hardware_len]
        cursor += hardware_len
        sender_proto = raw[cursor:cursor + protocol_len]
        cursor += protocol_len
        target_hw = raw[cursor:cursor + hardware_len]
        cursor += hardware_len
        target_proto = raw[cursor:cursor + protocol_len]
        fields: dict[str, Any] = {
            "hardware_type": hardware,
            "protocol_type": f"0x{protocol:04x}",
            "opcode": opcode,
        }
        if hardware_len == 6:
            fields["sender_mac"] = self._mac(sender_hw)
            fields["target_mac"] = self._mac(target_hw)
        if protocol == 0x0800 and protocol_len == 4:
            fields["sender_ip"] = str(ipaddress.IPv4Address(sender_proto))
            fields["target_ip"] = str(ipaddress.IPv4Address(target_proto))
            result.flow_key = f"arp:{fields['sender_ip']}->{fields['target_ip']}"
        self._add(result, "arp", offset, min(len(raw) - offset, 8 + needed), fields)

    def _ipv4(self, raw: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(raw, offset, 20)
        first, dscp_ecn, total_length, identification, flags_fragment, ttl, protocol, checksum = struct.unpack_from("!BBHHHBBH", raw, offset)
        version = first >> 4
        ihl = (first & 0x0F) * 4
        if version != 4 or ihl < 20:
            raise ValueError("invalid IPv4 header")
        self._need(raw, offset, ihl)
        if total_length < ihl:
            raise ValueError("IPv4 total length is smaller than the header length")
        source = str(ipaddress.IPv4Address(raw[offset + 12:offset + 16]))
        destination = str(ipaddress.IPv4Address(raw[offset + 16:offset + 20]))
        flags = (flags_fragment >> 13) & 0x7
        fragment_offset = flags_fragment & 0x1FFF
        available_total = len(raw) - offset
        effective_total = min(available_total, total_length)
        if total_length > available_total:
            result.truncated = True
            result.warnings.append("IPv4 packet is shorter than its declared total length")
        self._add(result, "ipv4", offset, ihl, {
            "source": source,
            "destination": destination,
            "header_length": ihl,
            "total_length": total_length,
            "dscp": dscp_ecn >> 2,
            "ecn": dscp_ecn & 0x3,
            "identification": identification,
            "dont_fragment": bool(flags & 0x2),
            "more_fragments": bool(flags & 0x1),
            "fragment_offset": fragment_offset,
            "ttl": ttl,
            "protocol_number": protocol,
            "protocol": self.IP_PROTOCOLS.get(protocol, str(protocol)),
            "checksum": f"0x{checksum:04x}",
        })
        payload_offset = offset + ihl
        payload_end = offset + effective_total
        if fragment_offset:
            result.warnings.append("non-initial IPv4 fragment: transport decoding skipped")
            return
        initial_fragment = bool(flags & 0x1)
        if initial_fragment:
            result.warnings.append("initial IPv4 fragment: application decoding skipped until reassembly")
        self._transport(
            raw[:payload_end], payload_offset, protocol, source, destination, result,
            decode_application=not initial_fragment,
        )

    def _ipv6(self, raw: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(raw, offset, 40)
        first_word = struct.unpack_from("!I", raw, offset)[0]
        if first_word >> 28 != 6:
            raise ValueError("invalid IPv6 header")
        payload_length, next_header, hop_limit = struct.unpack_from("!HBB", raw, offset + 4)
        source = str(ipaddress.IPv6Address(raw[offset + 8:offset + 24]))
        destination = str(ipaddress.IPv6Address(raw[offset + 24:offset + 40]))
        self._add(result, "ipv6", offset, 40, {
            "source": source,
            "destination": destination,
            "traffic_class": (first_word >> 20) & 0xFF,
            "flow_label": first_word & 0xFFFFF,
            "payload_length": payload_length,
            "next_header": next_header,
            "hop_limit": hop_limit,
        })
        cursor = offset + 40
        available_payload = max(0, len(raw) - cursor)
        if payload_length:
            payload_end = cursor + min(available_payload, payload_length)
            if payload_length > available_payload:
                result.truncated = True
                result.warnings.append("IPv6 packet is shorter than its declared payload length")
        else:
            jumbo_length = self._ipv6_jumbo_payload_length(raw, cursor) if next_header == 0 else None
            if jumbo_length is None:
                payload_end = cursor
                if available_payload:
                    result.warnings.append("IPv6 zero payload length has no valid Jumbo Payload option")
            else:
                payload_end = cursor + min(available_payload, jumbo_length)
                if jumbo_length > available_payload:
                    result.truncated = True
                    result.warnings.append("IPv6 jumbogram is shorter than its declared payload length")
        bounded = raw[:payload_end]
        extension_count = 0
        non_initial_fragment = False
        initial_fragment = False
        while next_header in {0, 43, 44, 51, 60, 135} and cursor < payload_end:
            if extension_count >= self.MAX_IPV6_EXTENSIONS:
                result.warnings.append("IPv6 extension-header budget reached")
                return
            extension_count += 1
            if next_header == 44:
                self._need(bounded, cursor, 8)
                following = bounded[cursor]
                fragment_field = struct.unpack_from("!H", bounded, cursor + 2)[0]
                fragment_offset = (fragment_field >> 3) & 0x1FFF
                more = bool(fragment_field & 0x1)
                fragment_id = struct.unpack_from("!I", bounded, cursor + 4)[0]
                self._add(result, "ipv6-fragment", cursor, 8, {
                    "next_header": following,
                    "fragment_offset": fragment_offset,
                    "more_fragments": more,
                    "identification": fragment_id,
                })
                cursor += 8
                next_header = following
                non_initial_fragment = fragment_offset != 0
                initial_fragment = fragment_offset == 0 and more
                continue
            if next_header == 51:
                fields = decode_ah_packet(bounded[cursor:payload_end])
                following = int(fields["next_header"])
                extension_length = int(fields["header_length"])
                self._add(result, "ah", cursor, extension_length, fields)
                cursor += extension_length
                next_header = following
                continue
            self._need(bounded, cursor, 2)
            following = bounded[cursor]
            extension_length = (bounded[cursor + 1] + 1) * 8
            self._need(bounded, cursor, extension_length)
            name = {0: "ipv6-hop-by-hop", 43: "ipv6-routing", 60: "ipv6-destination", 135: "ipv6-mobility"}.get(next_header, "ipv6-extension")
            extension_fields: dict[str, Any] = {"next_header": following}
            if next_header == 43:
                extension_fields.update(decode_ipv6_routing_header(bounded[cursor:cursor + extension_length]))
            self._add(result, name, cursor, extension_length, extension_fields)
            cursor += extension_length
            next_header = following
        if non_initial_fragment:
            result.warnings.append("non-initial IPv6 fragment: transport decoding skipped")
            return
        if initial_fragment:
            result.warnings.append("initial IPv6 fragment: application decoding skipped until reassembly")
        self._transport(
            bounded, cursor, next_header, source, destination, result,
            decode_application=not initial_fragment,
        )

    @staticmethod
    def _ipv6_jumbo_payload_length(raw: bytes, offset: int) -> int | None:
        if offset < 0 or offset + 2 > len(raw):
            return None
        header_length = (raw[offset + 1] + 1) * 8
        if header_length < 8 or offset + header_length > len(raw):
            return None
        cursor = offset + 2
        end = offset + header_length
        while cursor < end:
            option_type = raw[cursor]
            cursor += 1
            if option_type == 0:
                continue
            if cursor >= end:
                return None
            option_length = raw[cursor]
            cursor += 1
            if cursor + option_length > end:
                return None
            if option_type == 0xC2 and option_length == 4:
                value = struct.unpack_from("!I", raw, cursor)[0]
                return value if value > 65535 else None
            cursor += option_length
        return None

    def _network_by_version(self, raw: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(raw, offset, 1)
        version = raw[offset] >> 4
        if version == 4:
            self._ipv4(raw, offset, result)
        elif version == 6:
            self._ipv6(raw, offset, result)
        else:
            result.warnings.append(f"unrecognized network-layer version nibble: {version}")

    def _transport(
        self,
        raw: bytes,
        offset: int,
        protocol: int,
        source: str,
        destination: str,
        result: ProtocolDecodeResult,
        *,
        decode_application: bool = True,
    ) -> None:
        if protocol == 6:
            self._tcp(raw, offset, source, destination, result, decode_application=decode_application)
        elif protocol == 17:
            self._udp(raw, offset, source, destination, result, decode_application=decode_application)
        elif protocol == 1:
            self._icmp(raw, offset, result, ipv6=False)
        elif protocol == 58:
            self._icmp(raw, offset, result, ipv6=True)
        elif protocol == 132:
            self._sctp(raw, offset, source, destination, result)
        elif protocol == 47:
            self._gre(raw, offset, result)
        elif protocol == 50:
            fields = decode_esp_packet(raw[offset:])
            self._add(result, "esp", offset, len(raw) - offset, fields)
            result.encrypted = True
        elif protocol == 51:
            self._ah(raw, offset, result)
        elif protocol == 33:
            self._dccp(raw, offset, source, destination, result)
        elif protocol == 4:
            self._add(result, "ip-in-ip", offset, 0, {"inner": "ipv4"})
            self._ipv4(raw, offset, result)
        elif protocol == 41:
            self._add(result, "ipv6-in-ipv4", offset, 0, {"inner": "ipv6"})
            self._ipv6(raw, offset, result)
        elif protocol == 2:
            self._igmp(raw, offset, result)
        elif protocol == 88:
            self._eigrp(raw, offset, result)
        elif protocol == 89:
            self._ospf(raw, offset, result)
        elif protocol == 103:
            self._pim(raw, offset, result)
        elif protocol == 112:
            self._vrrp(raw, offset, result, ipv6=":" in source)
        elif protocol == 137:
            self._add(result, "mpls-in-ip", offset, len(raw) - offset, {"payload_bytes": len(raw) - offset})
            self._mpls(raw, offset, result)

    def _igmp(self, raw: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_igmp(raw[offset:])
        self._add(result, "igmp", offset, len(raw) - offset, fields)

    def _ospf(self, raw: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(raw, offset, 16)
        fields = decode_ospf_packet(raw[offset:])
        effective = min(int(fields["packet_length"]), len(raw) - offset)
        self._add(result, "ospf", offset, effective, fields)

    def _vrrp(self, raw: bytes, offset: int, result: ProtocolDecodeResult, *, ipv6: bool) -> None:
        fields = decode_vrrp(raw[offset:], ipv6=ipv6)
        self._add(result, "vrrp", offset, len(raw) - offset, fields)

    def _pim(self, raw: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_pim(raw[offset:])
        self._add(result, "pim", offset, len(raw) - offset, fields)

    def _eigrp(self, raw: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(raw, offset, 20)
        version, opcode, checksum, flags, sequence, acknowledgement, autonomous_system = struct.unpack_from(
            "!BBHIIII", raw, offset
        )
        self._add(result, "eigrp", offset, len(raw) - offset, {
            "version": version,
            "opcode": opcode,
            "checksum": f"0x{checksum:04x}",
            "flags": f"0x{flags:08x}",
            "sequence": sequence,
            "acknowledgement": acknowledgement,
            "autonomous_system": autonomous_system,
        })

    def _tcp(
        self,
        raw: bytes,
        offset: int,
        source: str,
        destination: str,
        result: ProtocolDecodeResult,
        *,
        decode_application: bool = True,
    ) -> None:
        self._need(raw, offset, 20)
        source_port, destination_port, sequence, acknowledgement, data_offset_flags, flags, window, checksum, urgent = struct.unpack_from("!HHIIBBHHH", raw, offset)
        header_length = (data_offset_flags >> 4) * 4
        if header_length < 20:
            raise ValueError("invalid TCP header length")
        self._need(raw, offset, header_length)
        flag_names = [name for bit, name in ((0x01, "fin"), (0x02, "syn"), (0x04, "rst"), (0x08, "psh"), (0x10, "ack"), (0x20, "urg"), (0x40, "ece"), (0x80, "cwr")) if flags & bit]
        fields: dict[str, Any] = {
            "source_port": source_port,
            "destination_port": destination_port,
            "sequence": sequence,
            "acknowledgement": acknowledgement,
            "header_length": header_length,
            "flags": flag_names,
            "window": window,
            "checksum": f"0x{checksum:04x}",
            "urgent_pointer": urgent,
        }
        payload = raw[offset + header_length:]
        fields["payload_length"] = len(payload)
        if header_length > 20:
            fields["options"] = self._tcp_options(raw[offset + 20:offset + header_length])
        self._add(result, "tcp", offset, header_length, fields)
        result.flow_key = self._flow_key("tcp", source, source_port, destination, destination_port)
        if decode_application:
            self._application(payload, offset + header_length, source_port, destination_port, "tcp", result)

    def _udp(
        self,
        raw: bytes,
        offset: int,
        source: str,
        destination: str,
        result: ProtocolDecodeResult,
        *,
        decode_application: bool = True,
    ) -> None:
        self._need(raw, offset, 8)
        source_port, destination_port, length, checksum = struct.unpack_from("!HHHH", raw, offset)
        available_length = len(raw) - offset
        if length != 0 and length < 8:
            raise ValueError("invalid UDP length")
        effective_length = available_length if length == 0 else min(available_length, length)
        if length > available_length:
            result.truncated = True
            result.warnings.append("UDP datagram is shorter than its declared length")
        self._add(result, "udp", offset, 8, {
            "source_port": source_port,
            "destination_port": destination_port,
            "length": length,
            "checksum": f"0x{checksum:04x}",
        })
        result.flow_key = self._flow_key("udp", source, source_port, destination, destination_port)
        payload = raw[offset + 8:offset + effective_length]
        if decode_application:
            self._application(payload, offset + 8, source_port, destination_port, "udp", result)

    def _sctp(self, raw: bytes, offset: int, source: str, destination: str, result: ProtocolDecodeResult) -> None:
        self._need(raw, offset, 12)
        source_port, destination_port, verification_tag, checksum = struct.unpack_from("!HHII", raw, offset)
        chunks = decode_sctp_chunks(raw, offset + 12)
        self._add(result, "sctp", offset, 12, {
            "source_port": source_port,
            "destination_port": destination_port,
            "verification_tag": verification_tag,
            "checksum": f"0x{checksum:08x}",
            "chunks": chunks,
        })
        result.flow_key = self._flow_key("sctp", source, source_port, destination, destination_port)

    def _dccp(self, raw: bytes, offset: int, source: str, destination: str, result: ProtocolDecodeResult) -> None:
        self._need(raw, offset, 12)
        source_port, destination_port = struct.unpack_from("!HH", raw, offset)
        data_offset = raw[offset + 4] * 4
        packet_type = (raw[offset + 8] >> 1) & 0x0F
        self._add(result, "dccp", offset, max(12, min(data_offset, len(raw) - offset)), {
            "source_port": source_port,
            "destination_port": destination_port,
            "data_offset": data_offset,
            "packet_type": packet_type,
        })
        result.flow_key = self._flow_key("dccp", source, source_port, destination, destination_port)

    def _icmp(self, raw: bytes, offset: int, result: ProtocolDecodeResult, *, ipv6: bool) -> None:
        fields = decode_icmp_message(raw[offset:], ipv6=ipv6)
        name = "icmpv6" if ipv6 else "icmp"
        self._add(result, name, offset, min(len(raw) - offset, 256), fields)

    def _gre(self, raw: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(raw, offset, 4)
        flags_version, protocol = struct.unpack_from("!HH", raw, offset)
        header_length = 4
        if flags_version & 0x8000:
            header_length += 4
        if flags_version & 0x2000:
            header_length += 4
        if flags_version & 0x1000:
            header_length += 4
        self._need(raw, offset, header_length)
        self._add(result, "gre", offset, header_length, {
            "flags_version": f"0x{flags_version:04x}",
            "protocol": f"0x{protocol:04x}",
        })
        if protocol in {0x0800, 0x86DD}:
            self._dispatch_ethertype(raw, offset + header_length, protocol, result)

    def _ah(self, raw: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_ah_packet(raw[offset:])
        self._add(result, "ah", offset, int(fields["header_length"]), fields)

    def _pppoe(self, raw: bytes, offset: int, result: ProtocolDecodeResult, *, session: bool) -> None:
        self._need(raw, offset, 6)
        version_type, code, session_id, length = struct.unpack_from("!BBHH", raw, offset)
        self._add(result, "pppoe", offset, 6, {
            "version": version_type >> 4,
            "type": version_type & 0x0F,
            "code": code,
            "session_id": session_id,
            "payload_length": length,
            "session": session,
        })
        if session and offset + 8 <= len(raw):
            ppp_protocol = struct.unpack_from("!H", raw, offset + 6)[0]
            if ppp_protocol == 0x0021:
                self._ipv4(raw, offset + 8, result)
            elif ppp_protocol == 0x0057:
                self._ipv6(raw, offset + 8, result)

    def _eapol(self, raw: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(raw, offset, 4)
        fields = decode_eapol(raw[offset:])
        self._add(result, "eapol", offset, min(len(raw) - offset, 4 + int(fields["payload_length"])), fields)

    def _add(self, result: ProtocolDecodeResult, name: str, offset: int, length: int, fields: dict[str, Any]) -> None:
        if len(result.layers) >= self.MAX_LAYERS:
            if "layer budget reached" not in result.warnings:
                result.warnings.append("layer budget reached")
            return
        result.layers.append(ProtocolLayer(name=name, offset=max(0, int(offset)), length=max(0, int(length)), fields=fields))

    @staticmethod
    def _need(raw: bytes, offset: int, length: int) -> None:
        if offset < 0 or length < 0 or offset + length > len(raw):
            raise ValueError("truncated packet")

    @staticmethod
    def _mac(value: bytes) -> str:
        return ":".join(f"{byte:02x}" for byte in value)

    @staticmethod
    def _flow_key(transport: str, source: str, source_port: int, destination: str, destination_port: int) -> str:
        left = f"{source}:{source_port}"
        right = f"{destination}:{destination_port}"
        first, second = sorted((left, right))
        return f"{transport}:{first}<->{second}"

    @staticmethod
    def _int(value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return None

    @staticmethod
    def _last_application(result: ProtocolDecodeResult) -> str:
        transport = {"ethernet", "linux-sll", "linux-sll2", "vlan", "mpls", "arp", "ipv4", "ipv6", "ipv6-fragment", "ipv6-hop-by-hop", "ipv6-routing", "ipv6-destination", "ipv6-mobility", "tcp", "udp", "sctp", "dccp", "icmp", "icmpv6", "gre", "ah", "esp"}
        for layer in reversed(result.layers):
            if layer.name not in transport:
                return layer.name
        return ""
