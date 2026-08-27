from __future__ import annotations
from arenyxa.infrastructure.capture.protocol_application_services import ApplicationProtocolServiceMixin
from arenyxa.infrastructure.capture.protocol_application_web import ApplicationProtocolWebMixin
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


class ApplicationProtocolMixin(ApplicationProtocolServiceMixin, ApplicationProtocolWebMixin, ModernProtocolMixin):
    """Bounded application/tunnel dissectors used by the native protocol engine."""

    def _application(self, payload: bytes, offset: int, source_port: int, destination_port: int, transport: str, result: ProtocolDecodeResult) -> None:
        if not payload or len(result.layers) >= self.MAX_LAYERS:
            return
        ports = {source_port, destination_port}
        hint = self.PORT_HINTS.get(destination_port) or self.PORT_HINTS.get(source_port) or ""
        if self._application_discovery(payload, offset, ports, transport, result):
            return
        if self._application_secure_services(payload, offset, ports, transport, hint, result):
            return
        if self._application_overlay_services(payload, offset, ports, transport, hint, result):
            return
        self._application_dynamic_fallback(
            payload, offset, source_port, destination_port, transport, hint, result
        )

    def _application_discovery(
        self,
        payload: bytes,
        offset: int,
        ports: set[int],
        transport: str,
        result: ProtocolDecodeResult,
    ) -> bool:
        if 53 in ports or 5353 in ports or 5355 in ports or (137 in ports and transport == "udp"):
            data = payload[2:] if transport == "tcp" and len(payload) >= 2 else payload
            if 5353 in ports:
                dns_name = "mdns"
            elif 5355 in ports:
                dns_name = "llmnr"
            elif 137 in ports:
                dns_name = "nbns"
            else:
                dns_name = "dns"
            self._dns(data, offset + (2 if data is not payload else 0), result, dns_name)
            return True
        if ports & {67, 68}:
            self._dhcp(payload, offset, result)
            return True
        if ports & {546, 547}:
            self._dhcpv6(payload, offset, result)
            return True
        if 123 in ports and transport == "udp":
            self._ntp(payload, offset, result)
            return True
        if ports & {3784, 4784} and transport == "udp":
            fields = decode_bfd_control(payload)
            self._add(result, "bfd", offset, int(fields["length"]), fields)
            result.application_protocol = "bfd"
            return True
        if 3785 in ports and transport == "udp":
            self._add(result, "bfd-echo", offset, len(payload), {"echo_payload_bytes": len(payload), "payload_retained": False})
            result.application_protocol = "bfd-echo"
            return True
        if ports & {3478, 5349} and (self._looks_stun(payload) or looks_like_turn_channel_data(payload)):
            self._stun(payload, offset, result)
            return True
        if ports & {5683, 5684} and transport == "udp":
            self._coap(payload, offset, result)
            return True
        if 47808 in ports and transport == "udp":
            self._bacnet(payload, offset, result)
            return True
        if ports & {1812, 1813} and transport == "udp":
            self._radius(payload, offset, result)
            return True
        if 69 in ports and transport == "udp":
            self._tftp(payload, offset, result)
            return True
        if 514 in ports and transport == "udp":
            self._syslog(payload, offset, result)
            return True
        return False

    def _application_secure_services(
        self,
        payload: bytes,
        offset: int,
        ports: set[int],
        transport: str,
        hint: str,
        result: ProtocolDecodeResult,
    ) -> bool:
        if self._looks_tls(payload):
            self._tls(payload, offset, result)
            return True
        if payload.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
            frames = self._http2_frame_rows(payload, start=24)
            self._add(result, "http2", offset, min(len(payload), 24 + sum(9 + int(row["length"]) for row in frames)), {
                "client_preface": True, "frames": frames, "frame_count": len(frames),
            })
            result.application_protocol = "http2"
            return True
        if self._looks_http(payload):
            self._http(payload, offset, result, hint)
            return True
        if payload.startswith(b"SSH-"):
            banner = self._line(payload).decode("ascii", errors="replace")
            self._add(result, "ssh", offset, len(self._line(payload)), {"banner": banner[:256]})
            result.application_protocol = "ssh"
            return True
        if hint == "ssh" and len(payload) >= 6:
            try:
                kex = decode_ssh_kexinit(payload)
            except ValueError:
                record_current_exception(__name__, 'ApplicationProtocolMixin._application_secure_services:154')
            else:
                self._add(result, "ssh", offset, min(len(payload), 4 + int(kex["packet_length"])), kex)
                result.application_protocol = "ssh"
                return True
        if self._looks_quic(payload, transport) and hint in {"", "tls", "dns-over-tls"}:
            self._quic(payload, offset, result)
            return True
        if 179 in ports and transport == "tcp":
            self._bgp(payload, offset, result)
            return True
        if 646 in ports and transport in {"tcp", "udp"}:
            fields = decode_ldp_pdu(payload)
            self._add(result, "ldp", offset, min(len(payload), int(fields["pdu_length"]) + 4), fields)
            result.application_protocol = "ldp"
            return True
        if ports & {161, 162}:
            self._snmp(payload, offset, result)
            return True
        if ports & {389, 636}:
            if hint == "ldaps" and self._looks_tls(payload):
                self._tls(payload, offset, result)
            else:
                self._ldap(payload, offset, result)
            return True
        if ports & {139, 445}:
            self._smb(payload, offset, result)
            return True
        if 88 in ports:
            self._kerberos(payload, offset, result, tcp=transport == "tcp")
            return True
        if 3306 in ports and transport == "tcp":
            self._mysql(payload, offset, result)
            return True
        if 5432 in ports and transport == "tcp":
            self._postgresql(payload, offset, result)
            return True
        if 27017 in ports and transport == "tcp":
            self._mongodb(payload, offset, result)
            return True
        if 11211 in ports:
            self._memcached(payload, offset, result)
            return True
        if 3389 in ports and transport == "tcp":
            self._rdp(payload, offset, result)
            return True
        return False

    def _application_overlay_services(
        self,
        payload: bytes,
        offset: int,
        ports: set[int],
        transport: str,
        hint: str,
        result: ProtocolDecodeResult,
    ) -> bool:
        if ports & {500, 4500} and transport == "udp":
            if 4500 in ports and payload == b"\xff":
                self._add(result, "ipsec-nat-keepalive", offset, 1, {"keepalive": True})
                result.application_protocol = "ipsec-nat-keepalive"
            elif 4500 in ports and not payload.startswith(b"\x00\x00\x00\x00"):
                self._ipsec_natt(payload, offset, result)
            else:
                self._ike(payload, offset, result)
            return True
        if 1701 in ports and transport == "udp":
            self._l2tp(payload, offset, result)
            return True
        if 520 in ports and transport == "udp":
            self._rip(payload, offset, result)
            return True
        if ports & {2123, 2152} and transport == "udp":
            self._gtp(payload, offset, result)
            return True
        if 8805 in ports and transport == "udp":
            self._pfcp(payload, offset, result)
            return True
        if 3868 in ports and transport == "tcp":
            self._diameter(payload, offset, result)
            return True
        if 4789 in ports and transport == "udp":
            self._vxlan(payload, offset, result)
            return True
        if 6081 in ports and transport == "udp":
            self._geneve(payload, offset, result)
            return True
        if 51820 in ports and transport == "udp":
            self._wireguard(payload, offset, result)
            return True
        if 1080 in ports and transport == "tcp":
            self._socks(payload, offset, result)
            return True
        if 5900 in ports and transport == "tcp" and payload.startswith(b"RFB "):
            self._rfb(payload, offset, result)
            return True
        if 4840 in ports and transport == "tcp":
            self._opcua(payload, offset, result)
            return True
        if 2404 in ports and transport == "tcp":
            self._iec104(payload, offset, result)
            return True
        if 20000 in ports:
            self._dnp3(payload, offset, result)
            return True
        if 102 in ports and transport == "tcp":
            self._s7comm(payload, offset, result)
            return True
        if 2049 in ports:
            self._rpc(payload, offset, result, nfs_hint=True)
            return True
        if 111 in ports:
            self._rpc(payload, offset, result, nfs_hint=False)
            return True
        if hint == "sip":
            self._sip(payload, offset, result)
            return True
        if hint in {"rtsp", "smtp", "pop3", "imap", "ftp", "telnet", "xmpp", "ssdp"}:
            self._text_protocol(payload, offset, result, hint)
            return True
        if hint in {"mqtt", "mqtts"}:
            self._mqtt(payload, offset, result, hint)
            return True
        if hint in {"amqp", "amqps"}:
            fields = decode_amqp_frame(payload)
            self._add(result, "amqp", offset, min(len(payload), int(fields["frame_bytes"])), fields)
            result.application_protocol = "amqp"
            return True
        if hint == "kafka":
            fields = decode_kafka_message(payload)
            self._add(result, "kafka", offset, min(len(payload), int(fields["frame_bytes"])), fields)
            result.application_protocol = "kafka"
            return True
        if hint == "redis" and payload[:1] in b"+-:$*_#,(!=%~>":
            self._add(result, "redis", offset, min(len(payload), 64), {"frame_prefix": chr(payload[0])})
            result.application_protocol = "redis"
            return True
        if 502 in ports and len(payload) >= 8:
            self._modbus(payload, offset, result)
            return True
        if transport == "udp" and self._looks_rtp(payload):
            self._rtp(payload, offset, result)
            return True
        return False

    def _application_dynamic_fallback(
        self,
        payload: bytes,
        offset: int,
        source_port: int,
        destination_port: int,
        transport: str,
        hint: str,
        result: ProtocolDecodeResult,
    ) -> None:
        # Runtime protocol plugins participate only after native high-confidence
        # dissectors had the first opportunity to claim the payload. Matching is
        # declarative (transport/port/magic) and the decoder itself remains in the
        # existing PluginSandbox, so extension does not weaken the capture boundary.
        from arenyxa.infrastructure.capture.protocol_registry import global_protocol_registry

        dynamic = global_protocol_registry().decode_matching(
            payload,
            transport=transport,
            source_port=source_port,
            destination_port=destination_port,
        )
        if dynamic is not None:
            protocol_name, fields, source = dynamic
            fields = dict(fields)
            fields.setdefault("detected_by", "runtime-protocol-registry")
            fields.setdefault("decoder_source", source)
            self._add(result, protocol_name, offset, len(payload), fields)
            result.application_protocol = protocol_name
            return
        if hint:
            self._add(result, hint, offset, min(len(payload), 32), {
                "detected_by": "well-known-port", "payload_bytes": len(payload),
            })
            result.application_protocol = hint

























































