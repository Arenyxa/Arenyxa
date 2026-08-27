from __future__ import annotations

import hashlib
import ipaddress
import struct
from typing import Any

from arenyxa.infrastructure.capture.protocol_evpn import decode_evpn_nlri
from arenyxa.infrastructure.capture.protocol_bgp_tunnel import (
    decode_bgp_tunnel_encapsulation_attribute,
    decode_pmsi_tunnel_attribute,
)


_BGP_MESSAGE_NAMES = {1: "open", 2: "update", 3: "notification", 4: "keepalive", 5: "route-refresh"}
_BGP_ORIGIN_NAMES = {0: "igp", 1: "egp", 2: "incomplete"}
_BGP_CAP_NAMES = {
    1: "multiprotocol",
    2: "route-refresh",
    5: "extended-next-hop",
    6: "extended-message",
    64: "graceful-restart",
    65: "four-octet-asn",
    69: "add-path",
    70: "enhanced-route-refresh",
    71: "long-lived-graceful-restart",
    73: "fqdn",
}
_MQTT_PACKET_NAMES = {
    1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC", 6: "PUBREL",
    7: "PUBCOMP", 8: "SUBSCRIBE", 9: "SUBACK", 10: "UNSUBSCRIBE", 11: "UNSUBACK",
    12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT", 15: "AUTH",
}
_MODBUS_FUNCTIONS = {
    1: "read-coils", 2: "read-discrete-inputs", 3: "read-holding-registers", 4: "read-input-registers",
    5: "write-single-coil", 6: "write-single-register", 8: "diagnostics", 15: "write-multiple-coils",
    16: "write-multiple-registers", 22: "mask-write-register", 23: "read-write-multiple-registers",
    43: "encapsulated-interface-transport",
}
_SCTP_CHUNK_NAMES = {
    0: "DATA", 1: "INIT", 2: "INIT_ACK", 3: "SACK", 4: "HEARTBEAT", 5: "HEARTBEAT_ACK",
    6: "ABORT", 7: "SHUTDOWN", 8: "SHUTDOWN_ACK", 9: "ERROR", 10: "COOKIE_ECHO",
    11: "COOKIE_ACK", 14: "SHUTDOWN_COMPLETE", 15: "AUTH", 64: "I_DATA", 130: "RE_CONFIG",
}
_IEC104_TYPE_NAMES = {
    1: "M_SP_NA_1", 3: "M_DP_NA_1", 5: "M_ST_NA_1", 7: "M_BO_NA_1", 9: "M_ME_NA_1",
    11: "M_ME_NB_1", 13: "M_ME_NC_1", 30: "M_SP_TB_1", 31: "M_DP_TB_1", 34: "M_ME_TD_1",
    35: "M_ME_TE_1", 36: "M_ME_TF_1", 45: "C_SC_NA_1", 46: "C_DC_NA_1", 48: "C_SE_NA_1",
    49: "C_SE_NB_1", 50: "C_SE_NC_1", 58: "C_SC_TA_1", 59: "C_DC_TA_1", 100: "C_IC_NA_1",
    101: "C_CI_NA_1", 103: "C_CS_NA_1", 105: "C_RP_NA_1",
}


def _need(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError(f"truncated {label}")


def _hash_text(value: bytes, domain: bytes) -> str:
    return hashlib.sha256(domain + b"\x00" + value).hexdigest()


def _prefixes_v4(data: bytes, *, limit: int = 2048) -> list[str]:
    rows: list[str] = []
    cursor = 0
    while cursor < len(data) and len(rows) < limit:
        prefix_length = data[cursor]
        cursor += 1
        if prefix_length > 32:
            raise ValueError("invalid BGP IPv4 prefix length")
        octets = (prefix_length + 7) // 8
        _need(data, cursor, octets, "BGP prefix")
        packed = data[cursor:cursor + octets] + b"\x00" * (4 - octets)
        cursor += octets
        rows.append(f"{ipaddress.IPv4Address(packed)}/{prefix_length}")
    if cursor != len(data):
        raise ValueError("BGP NLRI exceeds bounded prefix count")
    return rows


def _prefixes_v6(data: bytes, *, limit: int = 2048) -> list[str]:
    rows: list[str] = []
    cursor = 0
    while cursor < len(data) and len(rows) < limit:
        prefix_length = data[cursor]
        cursor += 1
        if prefix_length > 128:
            raise ValueError("invalid BGP IPv6 prefix length")
        octets = (prefix_length + 7) // 8
        _need(data, cursor, octets, "BGP IPv6 prefix")
        packed = data[cursor:cursor + octets] + b"\x00" * (16 - octets)
        cursor += octets
        rows.append(f"{ipaddress.IPv6Address(packed)}/{prefix_length}")
    if cursor != len(data):
        raise ValueError("BGP IPv6 NLRI exceeds bounded prefix count")
    return rows


def _mp_nlri(afi: int, safi: int, payload: bytes) -> list[Any]:
    if afi == 25 and safi == 70:
        return decode_evpn_nlri(payload)
    if safi != 1:
        return []
    if afi == 1:
        return _prefixes_v4(payload)
    if afi == 2:
        return _prefixes_v6(payload)
    return []


def _mp_next_hops(afi: int, raw: bytes) -> list[str]:
    rows: list[str] = []
    if afi == 1 and len(raw) % 4 == 0:
        for pos in range(0, len(raw), 4):
            rows.append(str(ipaddress.IPv4Address(raw[pos:pos + 4])))
    elif afi == 2 and len(raw) in {16, 32}:
        for pos in range(0, len(raw), 16):
            rows.append(str(ipaddress.IPv6Address(raw[pos:pos + 16])))
    elif afi == 25:
        # EVPN MP_REACH uses an IPv4 or IPv6 advertising-PE address as the BGP
        # next hop even though the NLRI AFI itself is L2VPN (25).
        if len(raw) == 4:
            rows.append(str(ipaddress.IPv4Address(raw)))
        elif len(raw) in {16, 32}:
            for pos in range(0, len(raw), 16):
                rows.append(str(ipaddress.IPv6Address(raw[pos:pos + 16])))
    return rows


def _bgp_capabilities(optional: bytes) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    cursor = 0
    while cursor + 2 <= len(optional) and len(rows) < 256:
        parameter_type, parameter_length = optional[cursor], optional[cursor + 1]
        cursor += 2
        _need(optional, cursor, parameter_length, "BGP optional parameter")
        parameter = optional[cursor:cursor + parameter_length]
        cursor += parameter_length
        if parameter_type != 2:
            rows.append({"parameter_type": parameter_type, "length": parameter_length})
            continue
        inner = 0
        while inner + 2 <= len(parameter) and len(rows) < 256:
            code, length = parameter[inner], parameter[inner + 1]
            inner += 2
            _need(parameter, inner, length, "BGP capability")
            value = parameter[inner:inner + length]
            inner += length
            row: dict[str, Any] = {"code": code, "name": _BGP_CAP_NAMES.get(code, f"capability-{code}"), "length": length}
            if code == 1 and length == 4:
                afi, _reserved, safi = struct.unpack("!HBB", value)
                row.update({"afi": afi, "safi": safi})
            elif code == 65 and length == 4:
                row["asn4"] = struct.unpack("!I", value)[0]
            elif code == 69 and length % 4 == 0:
                tuples = []
                for pos in range(0, length, 4):
                    afi, safi, mode = struct.unpack_from("!HBB", value, pos)
                    tuples.append({"afi": afi, "safi": safi, "mode": mode})
                row["families"] = tuples[:128]
            rows.append(row)
    return rows



_BGP_TUNNEL_TYPES = {
    1: "l2tpv3-over-ip",
    2: "gre",
    7: "ip-in-ip",
    8: "vxlan",
    9: "nvgre",
    10: "mpls",
    11: "mpls-in-gre",
    12: "vxlan-gpe",
}


def _bgp_extended_communities(value: bytes) -> tuple[list[dict[str, Any]], bool]:
    rows: list[dict[str, Any]] = []
    if len(value) % 8:
        return rows, True
    for pos in range(0, len(value), 8):
        raw = value[pos:pos + 8]
        kind, subtype = raw[0], raw[1]
        row: dict[str, Any] = {"type": f"0x{kind:02x}", "subtype": f"0x{subtype:02x}"}
        if kind in {0x00, 0x40} and subtype in {0x02, 0x03}:
            global_admin, local_admin = struct.unpack_from("!HI", raw, 2)
            row.update({
                "name": "route-target" if subtype == 0x02 else "route-origin",
                "format": "two-octet-as-specific",
                "transitive": kind == 0x00,
                "global_administrator": global_admin,
                "local_administrator": local_admin,
                "value": f"{global_admin}:{local_admin}",
            })
        elif kind in {0x01, 0x41} and subtype in {0x02, 0x03}:
            global_admin = str(ipaddress.IPv4Address(raw[2:6]))
            local_admin = struct.unpack_from("!H", raw, 6)[0]
            row.update({
                "name": "route-target" if subtype == 0x02 else "route-origin",
                "format": "ipv4-address-specific",
                "transitive": kind == 0x01,
                "global_administrator": global_admin,
                "local_administrator": local_admin,
                "value": f"{global_admin}:{local_admin}",
            })
        elif kind in {0x02, 0x42} and subtype in {0x02, 0x03}:
            global_admin, local_admin = struct.unpack_from("!IH", raw, 2)
            row.update({
                "name": "route-target" if subtype == 0x02 else "route-origin",
                "format": "four-octet-as-specific",
                "transitive": kind == 0x02,
                "global_administrator": global_admin,
                "local_administrator": local_admin,
                "value": f"{global_admin}:{local_admin}",
            })
        elif kind == 0x06 and subtype == 0x00:
            row.update({
                "name": "mac-mobility",
                "flags": raw[2],
                "sticky": bool(raw[2] & 0x01),
                "reserved": raw[3],
                "sequence": struct.unpack_from("!I", raw, 4)[0],
            })
        elif kind == 0x06 and subtype == 0x01:
            label24 = int.from_bytes(raw[5:8], "big")
            row.update({
                "name": "esi-label",
                "flags": raw[2],
                "single_active": bool(raw[2] & 0x01),
                "reserved_bytes_nonzero": any(raw[3:5]),
                "label20": label24 >> 4,
                "field24": label24,
            })
        elif kind == 0x06 and subtype == 0x02:
            row.update({
                "name": "es-import",
                "value": ":".join(f"{part:02x}" for part in raw[2:8]),
            })
        elif kind == 0x03 and subtype == 0x0D:
            row.update({
                "name": "default-gateway",
                "reserved_nonzero": any(raw[2:8]),
            })
        elif kind == 0x03 and subtype == 0x0C:
            tunnel_type = struct.unpack_from("!H", raw, 6)[0]
            row.update({
                "name": "encapsulation",
                "tunnel_type": tunnel_type,
                "tunnel_type_name": _BGP_TUNNEL_TYPES.get(tunnel_type, f"tunnel-{tunnel_type}"),
                "reserved_nonzero": any(raw[2:6]),
            })
        else:
            row.update({
                "name": "extended-community",
                "value_sha256": hashlib.sha256(b"arenyxa-bgp-ext-community/v1\x00" + raw[2:]).hexdigest(),
                "value_retained": False,
            })
        rows.append(row)
    return rows, False

def _bgp_as_path(value: bytes, width: int, label: str) -> list[dict[str, Any]]:
    segments: list[dict[str, Any]] = []
    pos = 0
    while pos + 2 <= len(value) and len(segments) < 128:
        segment_type, count = value[pos], value[pos + 1]
        pos += 2
        need = count * width
        _need(value, pos, need, f"BGP {label} segment")
        fmt = "H" if width == 2 else "I"
        asns = list(struct.unpack_from(f"!{count}{fmt}", value, pos)) if count else []
        pos += need
        segments.append({"type": "set" if segment_type == 1 else "sequence" if segment_type == 2 else segment_type, "asns": asns})
    return segments


def _decode_bgp_attribute(code: int, value: bytes, row: dict[str, Any]) -> None:
    length = len(value)
    if code == 1 and length == 1:
        row.update({"name": "ORIGIN", "origin": _BGP_ORIGIN_NAMES.get(value[0], f"unknown-{value[0]}")})
    elif code in {2, 17}:
        row.update({"name": "AS_PATH" if code == 2 else "AS4_PATH", "segments": _bgp_as_path(value, 2 if code == 2 else 4, "AS_PATH" if code == 2 else "AS4_PATH")})
    elif code == 3 and length == 4:
        row.update({"name": "NEXT_HOP", "next_hop": str(ipaddress.IPv4Address(value))})
    elif code in {4, 5} and length == 4:
        row.update({"name": "MED" if code == 4 else "LOCAL_PREF", "value": struct.unpack("!I", value)[0]})
    elif code == 6 and length == 0:
        row["name"] = "ATOMIC_AGGREGATE"
    elif code == 8 and length % 4 == 0:
        row.update({"name": "COMMUNITIES", "communities": [f"{high}:{low}" for high, low in struct.iter_unpack("!HH", value)][:256]})
    elif code == 14:
        row["name"] = "MP_REACH_NLRI"
        if length >= 5:
            afi, safi, nh_len = struct.unpack_from("!HBB", value, 0)
            if 4 + nh_len + 1 > len(value):
                raise ValueError("truncated BGP MP_REACH next hop")
            next_hop_raw, nlri_raw = value[4:4 + nh_len], value[5 + nh_len:]
            row.update({"afi": afi, "safi": safi, "next_hop_bytes": nh_len, "next_hops": _mp_next_hops(afi, next_hop_raw),
                        "reserved": value[4 + nh_len], "nlri": _mp_nlri(afi, safi, nlri_raw), "nlri_payload_bytes": len(nlri_raw)})
    elif code == 15:
        row["name"] = "MP_UNREACH_NLRI"
        if length >= 3:
            afi, safi = struct.unpack_from("!HB", value, 0); withdrawn_raw = value[3:]
            row.update({"afi": afi, "safi": safi, "withdrawn_nlri": _mp_nlri(afi, safi, withdrawn_raw), "withdrawn_payload_bytes": len(withdrawn_raw)})
    elif code == 16:
        communities, malformed = _bgp_extended_communities(value)
        row.update({"name": "EXTENDED_COMMUNITIES", "communities": communities, "malformed": malformed})
    elif code == 22:
        row["name"] = "PMSI_TUNNEL"; row.update(decode_pmsi_tunnel_attribute(value))
    elif code == 23:
        row["name"] = "TUNNEL_ENCAPSULATION"; row.update(decode_bgp_tunnel_encapsulation_attribute(value))
    else:
        row.update({"name": f"ATTRIBUTE_{code}", "value_sha256": _hash_text(value, b"arenyxa-bgp-attribute-v1")})


def _bgp_path_attributes(data: bytes) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    cursor = 0
    while cursor + 3 <= len(data) and len(rows) < 512:
        flags, code = data[cursor], data[cursor + 1]
        cursor += 2
        extended = bool(flags & 0x10)
        length_width = 2 if extended else 1
        _need(data, cursor, length_width, "BGP attribute length")
        length = struct.unpack_from("!H", data, cursor)[0] if extended else data[cursor]
        cursor += length_width
        _need(data, cursor, length, "BGP path attribute")
        value = data[cursor:cursor + length]
        cursor += length
        row: dict[str, Any] = {"code": code, "length": length, "optional": bool(flags & 0x80), "transitive": bool(flags & 0x40), "partial": bool(flags & 0x20)}
        _decode_bgp_attribute(code, value, row)
        rows.append(row)
    if cursor != len(data):
        raise ValueError("truncated BGP path attribute header")
    return rows

def decode_bgp_message(data: bytes) -> dict[str, Any]:
    _need(data, 0, 19, "BGP message")
    if data[:16] != b"\xff" * 16:
        raise ValueError("invalid BGP marker")
    length, message_type = struct.unpack_from("!HB", data, 16)
    if length < 19 or length > 4096 or length > len(data):
        raise ValueError("invalid BGP message length")
    body = data[19:length]
    fields: dict[str, Any] = {
        "message_type": message_type,
        "message_name": _BGP_MESSAGE_NAMES.get(message_type, "unknown"),
        "length": length,
    }
    if message_type == 1:
        _need(body, 0, 10, "BGP OPEN")
        version, asn16, hold_time, identifier, optional_length = struct.unpack_from("!BHHIB", body, 0)
        _need(body, 10, optional_length, "BGP OPEN optional parameters")
        fields.update({
            "version": version,
            "asn": asn16,
            "hold_time": hold_time,
            "bgp_identifier": str(ipaddress.IPv4Address(identifier)),
            "capabilities": _bgp_capabilities(body[10:10 + optional_length]),
        })
    elif message_type == 2:
        _need(body, 0, 4, "BGP UPDATE")
        withdrawn_length = struct.unpack_from("!H", body, 0)[0]
        _need(body, 2, withdrawn_length + 2, "BGP withdrawn routes")
        withdrawn = body[2:2 + withdrawn_length]
        attr_len_offset = 2 + withdrawn_length
        attributes_length = struct.unpack_from("!H", body, attr_len_offset)[0]
        attrs_start = attr_len_offset + 2
        _need(body, attrs_start, attributes_length, "BGP path attributes")
        nlri = body[attrs_start + attributes_length:]
        fields.update({
            "withdrawn_routes": _prefixes_v4(withdrawn),
            "path_attributes": _bgp_path_attributes(body[attrs_start:attrs_start + attributes_length]),
            "nlri": _prefixes_v4(nlri),
        })
    elif message_type == 3:
        _need(body, 0, 2, "BGP NOTIFICATION")
        fields.update({"error_code": body[0], "error_subcode": body[1], "data_sha256": _hash_text(body[2:], b"arenyxa-bgp-notification-v1")})
    elif message_type == 5:
        _need(body, 0, 4, "BGP ROUTE-REFRESH")
        afi, _reserved, safi = struct.unpack_from("!HBB", body, 0)
        fields.update({"afi": afi, "safi": safi})
    return fields


def _mqtt_varint(data: bytes, cursor: int) -> tuple[int, int]:
    value = 0
    multiplier = 1
    for _ in range(4):
        _need(data, cursor, 1, "MQTT variable byte integer")
        byte = data[cursor]
        cursor += 1
        value += (byte & 0x7F) * multiplier
        if not byte & 0x80:
            return value, cursor
        multiplier *= 128
    raise ValueError("invalid MQTT variable byte integer")


def _mqtt_utf8(data: bytes, cursor: int) -> tuple[bytes, int]:
    _need(data, cursor, 2, "MQTT UTF-8 length")
    length = struct.unpack_from("!H", data, cursor)[0]
    cursor += 2
    _need(data, cursor, length, "MQTT UTF-8 value")
    return data[cursor:cursor + length], cursor + length


def _mqtt_properties(data: bytes, cursor: int, *, version: int) -> tuple[int, int]:
    if version != 5:
        return 0, cursor
    length, after = _mqtt_varint(data, cursor)
    _need(data, after, length, "MQTT v5 properties")
    return length, after + length


def decode_mqtt_packet(data: bytes) -> dict[str, Any]:
    _need(data, 0, 2, "MQTT packet")
    packet_type = data[0] >> 4
    flags = data[0] & 0x0F
    remaining, cursor = _mqtt_varint(data, 1)
    end = cursor + remaining
    _need(data, cursor, remaining, "MQTT packet body")
    fields: dict[str, Any] = {
        "packet_type": packet_type,
        "packet_name": _MQTT_PACKET_NAMES.get(packet_type, "UNKNOWN"),
        "flags": flags,
        "remaining_length": remaining,
        "packet_bytes": end,
    }
    if packet_type == 1:  # CONNECT
        protocol, cursor = _mqtt_utf8(data, cursor)
        _need(data, cursor, 4, "MQTT CONNECT flags")
        version = data[cursor]
        connect_flags = data[cursor + 1]
        keep_alive = struct.unpack_from("!H", data, cursor + 2)[0]
        cursor += 4
        property_length, cursor = _mqtt_properties(data, cursor, version=version)
        client_id, cursor = _mqtt_utf8(data, cursor)
        fields.update({
            "protocol_name": protocol.decode("utf-8", errors="replace")[:32],
            "protocol_level": version,
            "clean_start": bool(connect_flags & 0x02),
            "will_flag": bool(connect_flags & 0x04),
            "will_qos": (connect_flags >> 3) & 0x03,
            "username_flag": bool(connect_flags & 0x80),
            "password_flag": bool(connect_flags & 0x40),
            "keep_alive": keep_alive,
            "property_bytes": property_length,
            "client_id_bytes": len(client_id),
            "client_id_sha256": _hash_text(client_id, b"arenyxa-mqtt-client-v1") if client_id else "",
        })
    elif packet_type == 3:  # PUBLISH
        topic, cursor = _mqtt_utf8(data, cursor)
        qos = (flags >> 1) & 0x03
        packet_identifier = None
        if qos:
            _need(data, cursor, 2, "MQTT packet identifier")
            packet_identifier = struct.unpack_from("!H", data, cursor)[0]
            cursor += 2
        # Version cannot always be inferred from an isolated PUBLISH. Do not consume
        # an ambiguous byte as v5 properties without a session-level version context.
        payload = data[cursor:end]
        fields.update({
            "dup": bool(flags & 0x08),
            "qos": qos,
            "retain": bool(flags & 0x01),
            "packet_identifier": packet_identifier,
            "topic_bytes": len(topic),
            "topic_sha256": _hash_text(topic, b"arenyxa-mqtt-topic-v1"),
            "payload_bytes": len(payload),
            "payload_sha256": _hash_text(payload, b"arenyxa-mqtt-payload-v1"),
        })
    elif packet_type in {4, 5, 6, 7, 9, 11} and remaining >= 2:
        fields["packet_identifier"] = struct.unpack_from("!H", data, cursor)[0]
    return fields


def _protobuf_varint(data: bytes, cursor: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _index in range(10):
        _need(data, cursor, 1, "Protobuf varint")
        byte = data[cursor]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, cursor
        shift += 7
    raise ValueError("invalid Protobuf varint")


def decode_protobuf_message(data: bytes, *, max_fields: int = 256) -> dict[str, Any]:
    """Decode bounded Protobuf wire metadata without retaining length-delimited values."""
    if len(data) > 16 * 1024 * 1024:
        raise ValueError("Protobuf message exceeds analysis budget")
    cursor = 0
    rows: list[dict[str, Any]] = []
    limit = max(1, min(4096, int(max_fields)))
    while cursor < len(data) and len(rows) < limit:
        key, cursor = _protobuf_varint(data, cursor)
        field_number = key >> 3
        wire_type = key & 0x07
        if field_number < 1 or wire_type not in {0, 1, 2, 5}:
            raise ValueError("invalid Protobuf field key")
        row: dict[str, Any] = {"field_number": field_number, "wire_type": wire_type}
        if wire_type == 0:
            value, cursor = _protobuf_varint(data, cursor)
            row.update({"kind": "varint", "value": value})
        elif wire_type == 1:
            _need(data, cursor, 8, "Protobuf fixed64")
            row.update({"kind": "fixed64", "value": int.from_bytes(data[cursor:cursor + 8], "little")})
            cursor += 8
        elif wire_type == 5:
            _need(data, cursor, 4, "Protobuf fixed32")
            row.update({"kind": "fixed32", "value": int.from_bytes(data[cursor:cursor + 4], "little")})
            cursor += 4
        else:
            size, cursor = _protobuf_varint(data, cursor)
            _need(data, cursor, size, "Protobuf length-delimited field")
            value = data[cursor:cursor + size]
            cursor += size
            row.update({
                "kind": "length-delimited",
                "length": size,
                "sha256": hashlib.sha256(value).hexdigest(),
            })
        rows.append(row)
    if cursor != len(data):
        raise ValueError("Protobuf field-count budget exceeded")
    return {"message_bytes": len(data), "field_count": len(rows), "fields": rows}


def decode_amqp_frame(data: bytes) -> dict[str, Any]:
    """Decode an AMQP protocol header or one bounded AMQP 0-9-1 frame."""
    if data.startswith(b"AMQP"):
        _need(data, 0, 8, "AMQP protocol header")
        return {
            "kind": "protocol-header",
            "protocol_id": data[4],
            "version": f"{data[5]}.{data[6]}.{data[7]}",
            "frame_bytes": 8,
        }
    _need(data, 0, 8, "AMQP frame")
    frame_type = data[0]
    channel = struct.unpack_from("!H", data, 1)[0]
    size = struct.unpack_from("!I", data, 3)[0]
    if size > 16 * 1024 * 1024:
        raise ValueError("AMQP frame exceeds analysis budget")
    _need(data, 7, size + 1, "AMQP frame payload")
    frame_end = data[7 + size]
    if frame_end != 0xCE:
        raise ValueError("invalid AMQP frame end marker")
    payload = data[7:7 + size]
    return {
        "kind": "frame",
        "frame_type": frame_type,
        "channel": channel,
        "payload_bytes": size,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "frame_end": frame_end,
        "frame_bytes": 8 + size,
    }


def decode_kafka_message(data: bytes) -> dict[str, Any]:
    """Decode a Kafka request header while retaining no record payload bytes."""
    _need(data, 0, 12, "Kafka request")
    frame_length = struct.unpack_from("!i", data, 0)[0]
    if frame_length < 8 or frame_length > 100 * 1024 * 1024:
        raise ValueError("invalid Kafka request length")
    _need(data, 4, frame_length, "Kafka request body")
    api_key, api_version, correlation_id, client_length = struct.unpack_from("!hhih", data, 4)
    cursor = 14
    if client_length < -1 or client_length > 4096:
        raise ValueError("invalid Kafka client ID length")
    client_id = b""
    if client_length >= 0:
        _need(data, cursor, client_length, "Kafka client ID")
        client_id = data[cursor:cursor + client_length]
        cursor += client_length
    return {
        "frame_length": frame_length,
        "frame_bytes": frame_length + 4,
        "api_key": api_key,
        "api_version": api_version,
        "correlation_id": correlation_id,
        "client_id": client_id.decode("utf-8", errors="replace")[:256],
        "request_payload_bytes": frame_length + 4 - cursor,
        "request_payload_sha256": hashlib.sha256(data[cursor:4 + frame_length]).hexdigest(),
    }


def decode_modbus_tcp(data: bytes) -> dict[str, Any]:
    _need(data, 0, 8, "Modbus/TCP ADU")
    transaction, protocol_id, length, unit = struct.unpack_from("!HHHB", data, 0)
    if protocol_id != 0:
        raise ValueError("invalid Modbus/TCP protocol id")
    if length < 2 or 6 + length > len(data):
        raise ValueError("invalid Modbus/TCP length")
    function = data[7]
    base_function = function & 0x7F
    fields: dict[str, Any] = {
        "transaction_id": transaction,
        "protocol_id": protocol_id,
        "length": length,
        "unit_id": unit,
        "function_code": function,
        "function_name": _MODBUS_FUNCTIONS.get(base_function, f"function-{base_function}"),
        "exception": bool(function & 0x80),
    }
    pdu = data[8:6 + length]
    if fields["exception"] and pdu:
        fields["exception_code"] = pdu[0]
    elif base_function in {1, 2, 3, 4, 5, 6} and len(pdu) >= 4:
        address, value = struct.unpack_from("!HH", pdu, 0)
        fields.update({"address": address, "quantity_or_value": value})
    elif base_function in {15, 16} and len(pdu) >= 5:
        address, quantity, byte_count = struct.unpack_from("!HHB", pdu, 0)
        fields.update({"address": address, "quantity": quantity, "byte_count": byte_count})
    elif base_function == 22 and len(pdu) >= 6:
        address, and_mask, or_mask = struct.unpack_from("!HHH", pdu, 0)
        fields.update({"address": address, "and_mask": and_mask, "or_mask": or_mask})
    elif base_function == 43 and len(pdu) >= 2:
        fields.update({"mei_type": pdu[0], "mei_read_device_id_code": pdu[1]})
    return fields


def decode_iec104_apdu(data: bytes) -> dict[str, Any]:
    _need(data, 0, 6, "IEC 60870-5-104 APDU")
    if data[0] != 0x68:
        raise ValueError("invalid IEC 60870-5-104 start byte")
    apdu_length = data[1]
    if apdu_length < 4 or 2 + apdu_length > len(data):
        raise ValueError("invalid IEC 60870-5-104 APDU length")
    control = data[2:6]
    if not control[0] & 0x01:
        frame_kind = "i"
        send_seq = ((control[1] << 8) | control[0]) >> 1
        recv_seq = ((control[3] << 8) | control[2]) >> 1
        fields: dict[str, Any] = {"apdu_length": apdu_length, "frame_kind": frame_kind, "send_sequence": send_seq, "receive_sequence": recv_seq}
        asdu = data[6:2 + apdu_length]
        if len(asdu) >= 6:
            type_id = asdu[0]
            vsq = asdu[1]
            cause_raw = struct.unpack_from("<H", asdu, 2)[0]
            common_address = struct.unpack_from("<H", asdu, 4)[0]
            fields.update({
                "asdu_type_id": type_id,
                "asdu_type": _IEC104_TYPE_NAMES.get(type_id, f"TYPE_{type_id}"),
                "object_count": vsq & 0x7F,
                "sequence_of_elements": bool(vsq & 0x80),
                "cause_of_transmission": cause_raw & 0x3F,
                "test": bool(cause_raw & 0x80),
                "negative_confirm": bool(cause_raw & 0x40),
                "originator_address": (cause_raw >> 8) & 0xFF,
                "common_address": common_address,
            })
        return fields
    if control[0] & 0x03 == 1:
        recv_seq = ((control[3] << 8) | control[2]) >> 1
        return {"apdu_length": apdu_length, "frame_kind": "s", "receive_sequence": recv_seq}
    u_names = {0x07: "STARTDT_ACT", 0x0B: "STARTDT_CON", 0x13: "STOPDT_ACT", 0x23: "STOPDT_CON", 0x43: "TESTFR_ACT", 0x83: "TESTFR_CON"}
    return {"apdu_length": apdu_length, "frame_kind": "u", "u_function": u_names.get(control[0], f"0x{control[0]:02x}")}


def decode_dnp3_link(data: bytes) -> dict[str, Any]:
    _need(data, 0, 10, "DNP3 link frame")
    if data[:2] != b"\x05\x64":
        raise ValueError("invalid DNP3 start bytes")
    length = data[2]
    control = data[3]
    destination = struct.unpack_from("<H", data, 4)[0]
    source = struct.unpack_from("<H", data, 6)[0]
    function = control & 0x0F
    prm = bool(control & 0x40)
    primary_names = {0: "reset-link-states", 2: "test-link-states", 3: "confirmed-user-data", 4: "unconfirmed-user-data", 9: "request-link-status"}
    secondary_names = {0: "ack", 1: "nack", 11: "link-status", 15: "not-supported"}
    fields: dict[str, Any] = {
        "length": length,
        "destination": destination,
        "source": source,
        "direction": "from-master" if control & 0x80 else "from-outstation",
        "primary_message": prm,
        "frame_count_bit": bool(control & 0x20),
        "frame_count_valid": bool(control & 0x10),
        "link_function": function,
        "link_function_name": (primary_names if prm else secondary_names).get(function, f"function-{function}"),
    }
    # DNP3 inserts a CRC every 16 data bytes. Only expose transport/application
    # metadata when the first user-data block is available; do not pretend CRC
    # verification has occurred here.
    user_offset = 10
    if len(data) > user_offset:
        transport = data[user_offset]
        fields.update({
            "transport_final": bool(transport & 0x80),
            "transport_first": bool(transport & 0x40),
            "transport_sequence": transport & 0x3F,
            "crc_verified": False,
        })
        if len(data) > user_offset + 1:
            app_control = data[user_offset + 1]
            fields.update({
                "application_final": bool(app_control & 0x80),
                "application_first": bool(app_control & 0x40),
                "application_confirm": bool(app_control & 0x20),
                "application_unsolicited": bool(app_control & 0x10),
                "application_sequence": app_control & 0x0F,
            })
        if len(data) > user_offset + 2:
            app_function = data[user_offset + 2]
            fields["application_function"] = app_function
    return fields


def decode_sctp_chunks(raw: bytes, cursor: int, *, limit: int = 64) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    while cursor + 4 <= len(raw) and len(rows) < limit:
        chunk_type, flags, length = struct.unpack_from("!BBH", raw, cursor)
        if length < 4 or cursor + length > len(raw):
            raise ValueError("invalid SCTP chunk length")
        body = raw[cursor + 4:cursor + length]
        row: dict[str, Any] = {"type": chunk_type, "name": _SCTP_CHUNK_NAMES.get(chunk_type, f"CHUNK_{chunk_type}"), "flags": flags, "length": length}
        if chunk_type in {1, 2} and len(body) >= 16:
            initiate_tag, a_rwnd, out_streams, in_streams, initial_tsn = struct.unpack_from("!IIHHI", body, 0)
            row.update({"initiate_tag": initiate_tag, "a_rwnd": a_rwnd, "outbound_streams": out_streams, "inbound_streams": in_streams, "initial_tsn": initial_tsn})
        elif chunk_type == 0 and len(body) >= 12:
            tsn, stream_id, stream_seq, ppid = struct.unpack_from("!IHHI", body, 0)
            row.update({"tsn": tsn, "stream_id": stream_id, "stream_sequence": stream_seq, "ppid": ppid, "unordered": bool(flags & 0x04), "beginning": bool(flags & 0x02), "ending": bool(flags & 0x01), "user_data_bytes": len(body) - 12})
        elif chunk_type == 3 and len(body) >= 12:
            cumulative_tsn_ack, a_rwnd, gaps, duplicates = struct.unpack_from("!IIHH", body, 0)
            row.update({"cumulative_tsn_ack": cumulative_tsn_ack, "a_rwnd": a_rwnd, "gap_ack_blocks": gaps, "duplicate_tsns": duplicates})
        elif chunk_type == 7 and len(body) >= 4:
            row["cumulative_tsn_ack"] = struct.unpack_from("!I", body, 0)[0]
        elif chunk_type in {4, 5, 9}:
            row["parameter_bytes"] = len(body)
            row["parameter_sha256"] = _hash_text(body, b"arenyxa-sctp-parameter-v1") if body else ""
        rows.append(row)
        cursor += (length + 3) & ~3
    return rows

_SSH_KEX_LIST_NAMES = (
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_client_to_server",
    "encryption_server_to_client",
    "mac_client_to_server",
    "mac_server_to_client",
    "compression_client_to_server",
    "compression_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
)


def decode_ssh_kexinit(data: bytes) -> dict[str, Any]:
    """Decode one cleartext SSH_MSG_KEXINIT transport packet.

    SSH transport algorithm negotiation is visible before encryption starts. This
    decoder retains algorithm names but never key material or subsequent payloads.
    """
    _need(data, 0, 6, "SSH binary packet")
    packet_length = struct.unpack_from("!I", data, 0)[0]
    padding_length = data[4]
    if packet_length < 18 or packet_length > 256 * 1024 or 4 + packet_length > len(data):
        raise ValueError("invalid SSH binary packet length")
    payload_end = 4 + packet_length - padding_length
    if payload_end <= 5 or payload_end > len(data):
        raise ValueError("invalid SSH padding length")
    payload = data[5:payload_end]
    _need(payload, 0, 17, "SSH KEXINIT payload")
    if payload[0] != 20:
        raise ValueError("SSH packet is not KEXINIT")
    cursor = 17  # message id + 16-byte cookie
    fields: dict[str, Any] = {
        "message": "KEXINIT",
        "packet_length": packet_length,
        "padding_length": padding_length,
    }
    fingerprint_parts: list[str] = []
    for name in _SSH_KEX_LIST_NAMES:
        _need(payload, cursor, 4, "SSH name-list length")
        size = struct.unpack_from("!I", payload, cursor)[0]
        cursor += 4
        if size > 64 * 1024:
            raise ValueError("SSH name-list exceeds native decoder budget")
        _need(payload, cursor, size, "SSH name-list")
        raw_list = payload[cursor:cursor + size]
        cursor += size
        text = raw_list.decode("ascii", errors="replace")
        values = [item for item in text.split(",") if item][:256]
        fields[name] = values
        fingerprint_parts.append(",".join(values))
    _need(payload, cursor, 5, "SSH KEXINIT trailer")
    fields["first_kex_packet_follows"] = bool(payload[cursor])
    fields["reserved"] = struct.unpack_from("!I", payload, cursor + 1)[0]
    canonical = ";".join(fingerprint_parts).encode("utf-8")
    fields["ssh_algorithm_fingerprint_sha256"] = hashlib.sha256(
        b"arenyxa-ssh-kex-v1\x00" + canonical
    ).hexdigest()
    return fields
