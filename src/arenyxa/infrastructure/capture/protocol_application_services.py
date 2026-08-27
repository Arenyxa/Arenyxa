from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import hashlib
import ipaddress
import struct
from typing import Any, TYPE_CHECKING

from arenyxa.infrastructure.capture.protocol_modern import ModernProtocolMixin
from arenyxa.infrastructure.capture.protocol_dns import decode_dns_message
from arenyxa.infrastructure.capture.protocol_routing_control import decode_bfd_control
from arenyxa.infrastructure.capture.protocol_isis_ldp import decode_ldp_pdu
from arenyxa.infrastructure.capture.protocol_enterprise_access import (
    decode_dhcpv4,
    decode_dhcpv6,
    decode_radius,
    decode_snmp,
)
from arenyxa.infrastructure.capture.protocol_ipsec import decode_esp_packet, decode_ike_message
from arenyxa.infrastructure.capture.protocol_l2tp import decode_l2tp_packet
from arenyxa.infrastructure.capture.protocol_gtp import decode_gtp_packet
from arenyxa.infrastructure.capture.protocol_mobile_core import decode_diameter_message, decode_pfcp_packet
from arenyxa.infrastructure.capture.protocol_coap import decode_coap_message
from arenyxa.infrastructure.capture.protocol_stun import decode_stun_message, decode_turn_channel_data, looks_like_turn_channel_data
from arenyxa.infrastructure.capture.protocol_bacnet import decode_bacnet_ip
from arenyxa.infrastructure.capture.protocol_opcua import decode_opcua_tcp
from arenyxa.infrastructure.capture.protocol_realtime_media import decode_rtp_or_rtcp, decode_sip_message
from arenyxa.infrastructure.capture.protocol_wireguard import decode_wireguard_message
from arenyxa.infrastructure.capture.protocol_enterprise_directory import (
    decode_kerberos_message,
    decode_ldap_message,
    decode_smb_message,
)
from arenyxa.infrastructure.capture.protocol_deep_application import (
    decode_amqp_frame,
    decode_bgp_message,
    decode_dnp3_link,
    decode_iec104_apdu,
    decode_kafka_message,
    decode_modbus_tcp,
    decode_mqtt_packet,
    decode_ssh_kexinit,
)

if TYPE_CHECKING:
    from arenyxa.infrastructure.capture.protocol_intelligence import ProtocolDecodeResult


class ApplicationProtocolServiceMixin:
    def _socks(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(data, 0, 2)
        version = data[0]
        fields: dict[str, Any] = {"version": version}
        if version == 5:
            second = data[1]
            if len(data) >= 4 and data[2] == 0 and second in {1, 2, 3}:
                fields.update({"message": "request", "command": second, "address_type": data[3]})
            else:
                fields.update({"message": "method-negotiation", "method_count": second})
        elif version == 4:
            fields.update({"message": "request", "command": data[1]})
        else:
            raise ValueError("unrecognized SOCKS version")
        self._add(result, "socks", offset, min(len(data), 32), fields)
        result.application_protocol = "socks"

    def _rfb(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(data, 0, 12)
        banner = data[:12].decode("ascii", errors="replace").strip()
        if not banner.startswith("RFB "):
            raise ValueError("invalid RFB banner")
        self._add(result, "rfb", offset, 12, {"banner": banner[:32]})
        result.application_protocol = "rfb"

    def _opcua(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_opcua_tcp(data)
        self._add(result, "opcua", offset, int(fields["decoded_length"]), fields)
        result.application_protocol = "opcua"

    def _iec104(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_iec104_apdu(data)
        self._add(result, "iec104", offset, min(len(data), 2 + int(fields["apdu_length"])), fields)
        result.application_protocol = "iec104"

    def _dnp3(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_dnp3_link(data)
        self._add(result, "dnp3", offset, min(len(data), max(10, 10 + int(fields["length"]))), fields)
        result.application_protocol = "dnp3"

    def _s7comm(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(data, 0, 7)
        if data[0] != 3 or data[1] != 0:
            raise ValueError("invalid TPKT header")
        tpkt_length = struct.unpack_from("!H", data, 2)[0]
        cotp_length = data[4]
        s7_offset = 5 + cotp_length
        fields: dict[str, Any] = {"tpkt_length": tpkt_length, "cotp_header_length": cotp_length}
        if s7_offset < len(data) and data[s7_offset] == 0x32 and s7_offset + 10 <= len(data):
            fields.update({
                "protocol_id": 0x32,
                "rosctr": data[s7_offset + 1],
                "pdu_reference": struct.unpack_from("!H", data, s7_offset + 4)[0],
                "parameter_length": struct.unpack_from("!H", data, s7_offset + 6)[0],
                "data_length": struct.unpack_from("!H", data, s7_offset + 8)[0],
            })
        self._add(result, "s7comm", offset, min(len(data), max(7, tpkt_length)), fields)
        result.application_protocol = "s7comm"

    def _bgp(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_bgp_message(data)
        self._add(result, "bgp", offset, int(fields["length"]), fields)
        result.application_protocol = "bgp"

    def _snmp(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_snmp(data)
        self._add(result, "snmp", offset, min(len(data), int(fields.get("message_bytes") or len(data))), fields)
        result.application_protocol = "snmp"

    def _ldap(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_ldap_message(data)
        self._add(result, "ldap", offset, min(len(data), int(fields.get("message_bytes") or len(data))), fields)
        result.application_protocol = "ldap"

    def _smb(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_smb_message(data)
        consumed = min(len(data), max(32, 64 if fields.get("dialect") == "smb2+" else 32))
        self._add(result, "smb", offset, consumed, fields)
        result.application_protocol = "smb"

    def _kerberos(self, data: bytes, offset: int, result: ProtocolDecodeResult, *, tcp: bool) -> None:
        fields = decode_kerberos_message(data, tcp=tcp)
        marker = 4 if tcp else 0
        self._add(result, "kerberos", offset + marker, min(len(data) - marker, int(fields.get("message_bytes") or len(data))), fields)
        result.application_protocol = "kerberos"

    def _mysql(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(data, 0, 5)
        length = int.from_bytes(data[:3], "little")
        sequence = data[3]
        if length > len(data) - 4:
            raise ValueError("truncated MySQL packet")
        payload = data[4:4 + length]
        fields: dict[str, Any] = {"packet_length": length, "sequence": sequence}
        if payload and payload[0] == 10:
            end = payload.find(b"\x00", 1, min(len(payload), 257))
            fields["packet_type"] = "server-greeting"
            if end > 1:
                fields["server_version"] = payload[1:end].decode("ascii", errors="replace")[:255]
        elif payload:
            commands = {1: "quit", 2: "init-db", 3: "query", 14: "ping", 22: "stmt-prepare", 23: "stmt-execute"}
            fields["command"] = commands.get(payload[0], payload[0])
        self._add(result, "mysql", offset, min(len(data), 4 + length), fields)
        result.application_protocol = "mysql"

    def _postgresql(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(data, 0, 5)
        fields: dict[str, Any] = {}
        if data[:1] in b"QPBEDSXCRZTNKA":
            message_type = chr(data[0])
            length = struct.unpack_from("!I", data, 1)[0]
            if length < 4 or length + 1 > len(data):
                raise ValueError("truncated PostgreSQL message")
            fields.update({"message_type": message_type, "length": length})
            consumed = length + 1
        else:
            length, code = struct.unpack_from("!II", data, 0)
            if length < 8 or length > len(data):
                raise ValueError("truncated PostgreSQL startup message")
            fields.update({"length": length, "startup_code": code, "protocol_major": code >> 16, "protocol_minor": code & 0xFFFF})
            if code == 80877103:
                fields["request"] = "ssl"
            elif code == 80877102:
                fields["request"] = "cancel"
            consumed = length
        self._add(result, "postgresql", offset, consumed, fields)
        result.application_protocol = "postgresql"

    def _mongodb(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(data, 0, 16)
        length, request_id, response_to, opcode = struct.unpack_from("<iiii", data, 0)
        if length < 16 or length > len(data):
            raise ValueError("invalid MongoDB message length")
        names = {1: "reply", 2001: "update", 2002: "insert", 2004: "query", 2005: "get-more", 2006: "delete", 2007: "kill-cursors", 2010: "command", 2011: "command-reply", 2012: "compressed", 2013: "msg"}
        self._add(result, "mongodb", offset, length, {"request_id": request_id, "response_to": response_to, "opcode": opcode, "operation": names.get(opcode, "unknown")})
        result.application_protocol = "mongodb"

    def _memcached(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        if data[:1] in {b"\x80", b"\x81"}:
            self._need(data, 0, 24)
            magic, opcode, key_length, extras_length, _dtype, status, body_length, opaque, cas = struct.unpack_from("!BBHBBHIIQ", data, 0)
            fields = {"mode": "binary", "request": magic == 0x80, "opcode": opcode, "key_length": key_length, "extras_length": extras_length, "status": status, "body_length": body_length, "opaque": opaque, "cas": cas}
        else:
            line = self._line(data)[:512]
            token = line.split(None, 1)[0].decode("ascii", errors="replace") if line else ""
            if not token:
                raise ValueError("invalid memcached message")
            fields = {"mode": "ascii", "command_or_response": token.casefold(), "line_length": len(line)}
        self._add(result, "memcached", offset, min(len(data), 512), fields)
        result.application_protocol = "memcached"

    def _rdp(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(data, 0, 4)
        if data[0] != 3:
            raise ValueError("invalid RDP TPKT version")
        length = struct.unpack_from("!H", data, 2)[0]
        if length < 4 or length > len(data):
            raise ValueError("invalid RDP TPKT length")
        fields = {"tpkt_version": data[0], "length": length}
        if len(data) >= 7:
            fields["x224_length"] = data[4]
            fields["x224_type"] = data[5]
        self._add(result, "rdp", offset, length, fields)
        result.application_protocol = "rdp"

    def _ike(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_ike_message(data)
        marker = 4 if bool(fields.get("nat_traversal_marker")) else 0
        self._add(result, "ike", offset + marker, int(fields["length"]), fields)
        result.application_protocol = "ike"
        result.encrypted = bool(fields.get("encrypted_payload_present"))

    def _ipsec_natt(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_esp_packet(data, nat_traversal=True)
        self._add(result, "ipsec-nat-t", offset, 0, {"udp_encapsulation": True})
        self._add(result, "esp", offset, len(data), fields)
        result.application_protocol = "esp"
        result.encrypted = True

    def _l2tp(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_l2tp_packet(data)
        self._add(result, "l2tp", offset, int(fields["decoded_length"]), fields)
        result.application_protocol = "l2tp"

    def _rip(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(data, 0, 4)
        command, version, zero = struct.unpack_from("!BBH", data, 0)
        entries = max(0, (len(data) - 4) // 20)
        self._add(result, "rip", offset, len(data), {"command": command, "version": version, "reserved": zero, "route_entries": min(entries, 1024)})
        result.application_protocol = "rip"

    def _gtp(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_gtp_packet(data)
        self._add(result, "gtp", offset, int(fields["decoded_length"]), fields)
        result.application_protocol = "gtp"
        payload_offset = fields.get("user_payload_offset")
        if isinstance(payload_offset, int) and 0 <= payload_offset < int(fields["decoded_length"]):
            self._network_by_version(data, payload_offset, result)

    def _pfcp(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_pfcp_packet(data)
        self._add(result, "pfcp", offset, int(fields["decoded_length"]), fields)
        result.application_protocol = "pfcp"

    def _diameter(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        cursor = 0
        messages = 0
        while cursor < len(data) and messages < 32:
            fields = decode_diameter_message(data[cursor:])
            decoded_length = int(fields["decoded_length"] or 0)
            if decoded_length <= 0:
                raise ValueError("Diameter decoder made no forward progress")
            fields["stream_message_index"] = messages
            self._add(result, "diameter", offset + cursor, decoded_length, fields)
            cursor += decoded_length
            messages += 1
        if cursor != len(data):
            result.warnings.append("Diameter stream contains trailing or over-budget bytes")
        result.application_protocol = "diameter"

    def _vxlan(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(data, 0, 8)
        flags = data[0]
        vni = int.from_bytes(data[4:7], "big")
        reserved_bytes = data[1:4] + data[7:8]
        self._add(result, "vxlan", offset, 8, {
            "flags": flags,
            "vni": vni,
            "instance_valid": bool(flags & 0x08),
            "reserved_flag_bits": flags & 0xF7,
            "reserved_bytes_nonzero": any(reserved_bytes),
        })
        result.application_protocol = "vxlan"
        if len(data) > 8:
            self._ethernet(data, 8, result)

    def _geneve(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(data, 0, 8)
        version = data[0] >> 6
        option_length = (data[0] & 0x3F) * 4
        protocol_type = struct.unpack_from("!H", data, 2)[0]
        vni = int.from_bytes(data[4:7], "big")
        header_length = 8 + option_length
        self._need(data, 0, header_length)
        option_rows: list[dict[str, Any]] = []
        cursor = 8
        malformed = False
        while cursor + 4 <= header_length and len(option_rows) < 128:
            option_class = struct.unpack_from("!H", data, cursor)[0]
            raw_type = data[cursor + 2]
            length_flags = data[cursor + 3]
            option_data_length = (length_flags & 0x1F) * 4
            total = 4 + option_data_length
            if cursor + total > header_length:
                malformed = True
                break
            value = data[cursor + 4:cursor + total]
            option_rows.append({
                "class": f"0x{option_class:04x}",
                "type": raw_type & 0x7F,
                "critical": bool(raw_type & 0x80),
                "reserved": (length_flags >> 5) & 0x07,
                "data_bytes": len(value),
                "data_sha256": hashlib.sha256(b"arenyxa-geneve-option/v1\x00" + value).hexdigest(),
                "data_retained": False,
            })
            cursor += total
        if cursor != header_length:
            malformed = True
        self._add(result, "geneve", offset, header_length, {
            "version": version,
            "option_length": option_length,
            "protocol_type": f"0x{protocol_type:04x}",
            "vni": vni,
            "oam": bool(data[1] & 0x80),
            "critical": bool(data[1] & 0x40),
            "reserved_bits": data[1] & 0x3F,
            "reserved_byte": data[7],
            "options": option_rows,
            "option_count": len(option_rows),
            "options_malformed": malformed,
            "critical_option_count": sum(1 for row in option_rows if row["critical"]),
        })
        result.application_protocol = "geneve"
        if protocol_type == 0x6558 and len(data) > header_length:
            self._ethernet(data, header_length, result)
        elif protocol_type in {0x0800, 0x86DD}:
            self._dispatch_ethertype(data, header_length, protocol_type, result)
