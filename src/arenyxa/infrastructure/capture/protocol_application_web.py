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


class ApplicationProtocolWebMixin:
    def _wireguard(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_wireguard_message(data)
        self._add(result, "wireguard", offset, len(data), fields)
        result.application_protocol = "wireguard"
        result.encrypted = True

    def _rpc(self, data: bytes, offset: int, result: ProtocolDecodeResult, *, nfs_hint: bool) -> None:
        cursor = 0
        if len(data) >= 8:
            record = struct.unpack_from("!I", data, 0)[0]
            if record & 0x80000000 and (record & 0x7FFFFFFF) <= len(data) - 4:
                cursor = 4
        self._need(data, cursor, 8)
        xid, message_type = struct.unpack_from("!II", data, cursor)
        fields: dict[str, Any] = {"xid": xid, "message_type": "call" if message_type == 0 else "reply" if message_type == 1 else message_type}
        if message_type == 0 and len(data) >= cursor + 24:
            rpc_version, program, version, procedure = struct.unpack_from("!IIII", data, cursor + 8)
            fields.update({"rpc_version": rpc_version, "program": program, "program_version": version, "procedure": procedure})
            if program == 100003:
                nfs_hint = True
        name = "nfs" if nfs_hint else "rpc"
        self._add(result, name, offset + cursor, len(data) - cursor, fields)
        result.application_protocol = name

    def _dns(self, data: bytes, offset: int, result: ProtocolDecodeResult, name: str) -> None:
        fields = decode_dns_message(data)
        self._add(result, name, offset, len(data), fields)
        result.application_protocol = name

    def _dns_name(self, data: bytes, cursor: int) -> tuple[str, int]:
        labels: list[str] = []
        position = cursor
        resume = cursor
        jumped = False
        seen: set[int] = set()
        for _depth in range(self.MAX_DNS_NAME_DEPTH * 16):
            if position >= len(data):
                raise ValueError("truncated DNS name")
            length = data[position]
            if length == 0:
                if not jumped:
                    resume = position + 1
                return ".".join(labels)[: self.MAX_DNS_NAME_CHARS], resume
            if length & 0xC0 == 0xC0:
                if position + 1 >= len(data):
                    raise ValueError("truncated DNS compression pointer")
                pointer = ((length & 0x3F) << 8) | data[position + 1]
                if pointer >= len(data) or pointer in seen:
                    raise ValueError("invalid DNS compression pointer")
                seen.add(pointer)
                if not jumped:
                    resume = position + 2
                    jumped = True
                position = pointer
                continue
            if length & 0xC0:
                raise ValueError("invalid DNS label length")
            position += 1
            if length > 63 or position + length > len(data):
                raise ValueError("invalid DNS label")
            label = data[position:position + length].decode("ascii", errors="replace")
            labels.append(label)
            if sum(len(item) + 1 for item in labels) > self.MAX_DNS_NAME_CHARS:
                raise ValueError("DNS name exceeds budget")
            position += length
            if not jumped:
                resume = position
        raise ValueError("DNS name depth budget exceeded")

    def _dhcp(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_dhcpv4(data)
        self._add(result, "dhcp", offset, len(data), fields)
        result.application_protocol = "dhcp"

    def _dhcpv6(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_dhcpv6(data)
        self._add(result, "dhcpv6", offset, len(data), fields)
        result.application_protocol = "dhcpv6"

    def _tls(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(data, 0, 5)
        content_type, major, minor, length = struct.unpack_from("!BBBH", data, 0)
        fields: dict[str, Any] = {
            "content_type": content_type,
            "legacy_version": f"0x{major:02x}{minor:02x}",
            "record_length": length,
        }
        layer_len = min(len(data), 5 + length)
        if content_type == 22 and len(data) >= 9:
            handshake_type = data[5]
            handshake_length = int.from_bytes(data[6:9], "big")
            fields["handshake_type"] = handshake_type
            fields["handshake_length"] = handshake_length
            body = data[9:min(len(data), 9 + handshake_length)]
            if handshake_type == 1:
                fields.update(self._tls_client_hello(body))
            elif handshake_type == 2:
                fields.update(self._tls_server_hello(body))
            elif handshake_type == 11:
                from arenyxa.infrastructure.capture.protocol_tls_certificate import decode_tls12_certificate_list

                certificates = decode_tls12_certificate_list(body)
                if certificates:
                    fields["certificate_chain"] = certificates
                    fields["certificate_count"] = len(certificates)
        self._add(result, "tls", offset, layer_len, fields)
        result.application_protocol = "tls"
        result.encrypted = content_type in {20, 21, 23} or content_type == 22

    def _tls_client_hello(self, body: bytes) -> dict[str, Any]:
        return self._modern_tls_client_hello(body)

    def _tls_server_hello(self, body: bytes) -> dict[str, Any]:
        return self._modern_tls_server_hello(body)

    def _http(self, data: bytes, offset: int, result: ProtocolDecodeResult, hint: str) -> None:
        line = self._line(data).decode("latin-1", errors="replace")[: self.MAX_TEXT_LINE]
        fields: dict[str, Any] = {"start_line": line}
        parts = line.split()
        if line.startswith("HTTP/") and len(parts) >= 2:
            fields["version"] = parts[0]
            fields["status"] = self._int(parts[1])
        elif len(parts) >= 3:
            fields["method"] = parts[0][:32]
            fields["target"] = parts[1][:2048]
            fields["version"] = parts[2][:32]
        headers = self._bounded_headers(data)
        for key in ("host", "content-type", "content-length", "user-agent", "upgrade"):
            if key in headers:
                fields[key.replace("-", "_")] = headers[key]
        name = "rtsp" if hint == "rtsp" or "RTSP/" in line else "http"
        self._add(result, name, offset, min(len(data), 8192), fields)
        upgrade = str(fields.get("upgrade") or "").casefold()
        content_type = str(fields.get("content_type") or "").casefold()
        if name == "http" and upgrade == "websocket":
            self._add(result, "websocket", offset, 0, {"handshake": True})
            result.application_protocol = "websocket"
        elif name == "http" and "text/event-stream" in content_type:
            self._add(result, "sse", offset, 0, {"handshake": True})
            result.application_protocol = "sse"
        else:
            result.application_protocol = name

    def _quic(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = self._modern_quic_header(data)
        if fields.get("packet_type") == "Initial" and fields.get("version_name") in {"v1", "v2"}:
            try:
                from arenyxa.infrastructure.capture.protocol_quic_initial import decrypt_quic_initial

                initial = decrypt_quic_initial(data, role="client")
                crypto = initial.pop("crypto_stream_bytes", b"")
                if crypto[:1] == b"\x01" and len(crypto) >= 4:
                    hello_length = int.from_bytes(crypto[1:4], "big")
                    if 4 + hello_length <= len(crypto):
                        hello = self._modern_tls_client_hello(crypto[4:4 + hello_length])
                        initial["client_hello"] = hello
                        alpn = {str(item).casefold() for item in hello.get("alpn", [])}
                        hints: list[str] = []
                        if any(item.startswith("h3") for item in alpn):
                            hints.append("http3")
                        if "doq" in alpn:
                            hints.append("doq")
                        if hints:
                            fields["alpn_application_hints"] = hints
                fields["initial_decryption"] = initial
            except (ValueError, RuntimeError):
                # A server Initial needs the original client DCID and malformed/cropped captures
                # can be undecryptable. The protected-header metadata remains useful.
                record_current_exception(__name__, 'ApplicationProtocolMixin._quic:790')
        self._add(result, "quic", offset, min(len(data), 256), fields)
        result.application_protocol = "quic"
        result.encrypted = True

    def _ntp(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(data, 0, 48)
        first = data[0]
        self._add(result, "ntp", offset, 48, {
            "leap_indicator": first >> 6,
            "version": (first >> 3) & 0x7,
            "mode": first & 0x7,
            "stratum": data[1],
            "poll": data[2],
            "precision": struct.unpack_from("!b", data, 3)[0],
        })
        result.application_protocol = "ntp"

    def _stun(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        if looks_like_turn_channel_data(data):
            fields = decode_turn_channel_data(data)
            self._add(result, "turn-channel-data", offset, int(fields["decoded_length"]), fields)
            result.application_protocol = "turn-channel-data"
            return
        fields = decode_stun_message(data)
        self._add(result, "stun", offset, int(fields["decoded_length"]), fields)
        result.application_protocol = "stun"

    def _coap(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_coap_message(data)
        self._add(result, "coap", offset, int(fields["decoded_length"]), fields)
        result.application_protocol = "coap"

    def _bacnet(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_bacnet_ip(data)
        self._add(result, "bacnet-ip", offset, int(fields["decoded_length"]), fields)
        result.application_protocol = "bacnet-ip"

    def _radius(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_radius(data)
        self._add(result, "radius", offset, int(fields["length"]), fields)
        result.application_protocol = "radius"

    def _tftp(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        self._need(data, 0, 2)
        opcode = int.from_bytes(data[:2], "big")
        self._add(result, "tftp", offset, min(len(data), 64), {"opcode": opcode})
        result.application_protocol = "tftp"

    def _syslog(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        line = self._line(data).decode("utf-8", errors="replace")
        pri = None
        if line.startswith("<") and ">" in line[:8]:
            pri = self._int(line[1:line.index(">")] )
        self._add(result, "syslog", offset, min(len(data), self.MAX_TEXT_LINE), {
            "priority": pri,
            "facility": None if pri is None else pri // 8,
            "severity": None if pri is None else pri % 8,
            "message_preview": line[:512],
        })
        result.application_protocol = "syslog"

    def _text_protocol(self, data: bytes, offset: int, result: ProtocolDecodeResult, hint: str) -> None:
        line = self._line(data).decode("utf-8", errors="replace")[: self.MAX_TEXT_LINE]
        self._add(result, hint, offset, min(len(data), self.MAX_TEXT_LINE), {"start_line": line})
        result.application_protocol = hint

    def _mqtt(self, data: bytes, offset: int, result: ProtocolDecodeResult, hint: str) -> None:
        fields = decode_mqtt_packet(data)
        name = "mqtt" if hint in {"mqtt", "mqtts"} else hint
        self._add(result, name, offset, min(len(data), int(fields["packet_bytes"])), fields)
        result.application_protocol = name

    def _modbus(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_modbus_tcp(data)
        self._add(result, "modbus-tcp", offset, min(len(data), 6 + int(fields["length"])), fields)
        result.application_protocol = "modbus-tcp"

    def _sip(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        fields = decode_sip_message(data)
        self._add(result, "sip", offset, len(data), fields)
        result.application_protocol = "sip"

    def _rtp(self, data: bytes, offset: int, result: ProtocolDecodeResult) -> None:
        name, fields = decode_rtp_or_rtcp(data)
        self._add(result, name, offset, len(data), fields)
        result.application_protocol = name

    def _tcp_options(self, data: bytes) -> list[dict[str, Any]]:
        options: list[dict[str, Any]] = []
        cursor = 0
        for _index in range(40):
            if cursor >= len(data):
                break
            kind = data[cursor]
            if kind == 0:
                options.append({"kind": 0, "name": "end"})
                break
            if kind == 1:
                options.append({"kind": 1, "name": "nop"})
                cursor += 1
                continue
            if cursor + 2 > len(data):
                break
            length = data[cursor + 1]
            if length < 2 or cursor + length > len(data):
                break
            value = data[cursor + 2:cursor + length]
            row: dict[str, Any] = {"kind": kind, "length": length}
            if kind == 2 and len(value) == 2:
                row.update({"name": "mss", "value": int.from_bytes(value, "big")})
            elif kind == 3 and len(value) == 1:
                row.update({"name": "window-scale", "value": value[0]})
            elif kind == 4:
                row["name"] = "sack-permitted"
            elif kind == 8 and len(value) == 8:
                row.update({"name": "timestamp", "tsval": int.from_bytes(value[:4], "big"), "tsecr": int.from_bytes(value[4:], "big")})
            options.append(row)
            cursor += length
        return options

    def _tlv8(self, data: bytes, offset: int, limit: int) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        cursor = offset
        while cursor < len(data) and len(rows) < limit:
            code = data[cursor]
            cursor += 1
            if code == 255:
                break
            if code == 0:
                continue
            if cursor >= len(data):
                break
            length = data[cursor]
            cursor += 1
            if cursor + length > len(data):
                break
            rows.append({"code": code, "value": data[cursor:cursor + length]})
            cursor += length
        return rows

    def _bounded_headers(self, data: bytes) -> dict[str, str]:
        boundary = data.find(b"\r\n\r\n", 0, 64 * 1024)
        if boundary < 0:
            boundary = min(len(data), 64 * 1024)
        text = data[:boundary].decode("latin-1", errors="replace")
        rows: dict[str, str] = {}
        for line in text.split("\r\n")[1:129]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            name = key.strip().casefold()
            if name in {"host", "content-type", "content-length", "user-agent", "upgrade"}:
                rows[name] = value.strip()[:2048]
        return rows

    def _looks_http(self, data: bytes) -> bool:
        prefixes = (b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"CONNECT ", b"TRACE ", b"HTTP/")
        return any(data.startswith(prefix) for prefix in prefixes)

    def _looks_tls(self, data: bytes) -> bool:
        return len(data) >= 5 and data[0] in {20, 21, 22, 23} and data[1] == 3 and data[2] <= 4 and int.from_bytes(data[3:5], "big") <= 18432

    def _looks_stun(self, data: bytes) -> bool:
        return len(data) >= 20 and not (data[0] & 0xC0) and data[4:8] == b"\x21\x12\xA4\x42"

    def _looks_quic(self, data: bytes, transport: str) -> bool:
        return transport == "udp" and len(data) >= 6 and bool(data[0] & 0x40) and bool(data[0] & 0x80)

    def _looks_rtp(self, data: bytes) -> bool:
        return len(data) >= 12 and (data[0] >> 6) == 2 and (data[0] & 0x0F) <= 15

    def _line(self, data: bytes) -> bytes:
        position = data.find(b"\n", 0, self.MAX_TEXT_LINE)
        if position < 0:
            position = min(len(data), self.MAX_TEXT_LINE)
        return data[:position].rstrip(b"\r")
