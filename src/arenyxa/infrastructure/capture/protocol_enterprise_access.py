from __future__ import annotations

import hashlib
import ipaddress
import struct
from typing import Any


_MAX_OPTIONS = 512
_MAX_RADIUS_ATTRIBUTES = 512
_MAX_SNMP_VARBINDS = 512
_MAX_RELAY_DEPTH = 4

_DHCP_MESSAGE_NAMES = {
    1: "discover", 2: "offer", 3: "request", 4: "decline", 5: "ack", 6: "nak", 7: "release", 8: "inform",
}
_DHCPV6_MESSAGE_NAMES = {
    1: "solicit", 2: "advertise", 3: "request", 4: "confirm", 5: "renew", 6: "rebind", 7: "reply",
    8: "release", 9: "decline", 10: "reconfigure", 11: "information-request", 12: "relay-forward",
    13: "relay-reply", 14: "leasequery", 15: "leasequery-reply", 16: "leasequery-done", 17: "leasequery-data",
    18: "reconfigure-request", 19: "reconfigure-reply", 20: "dhcpv4-query", 21: "dhcpv4-response",
}
_RADIUS_CODE_NAMES = {
    1: "access-request", 2: "access-accept", 3: "access-reject", 4: "accounting-request", 5: "accounting-response",
    11: "access-challenge", 12: "status-server", 13: "status-client", 40: "disconnect-request", 41: "disconnect-ack",
    42: "disconnect-nak", 43: "coa-request", 44: "coa-ack", 45: "coa-nak",
}
_RADIUS_ATTRIBUTE_NAMES = {
    1: "user-name", 2: "user-password", 3: "chap-password", 4: "nas-ip-address", 5: "nas-port",
    6: "service-type", 7: "framed-protocol", 8: "framed-ip-address", 9: "framed-ip-netmask", 11: "filter-id",
    18: "reply-message", 24: "state", 25: "class", 26: "vendor-specific", 30: "called-station-id",
    31: "calling-station-id", 32: "nas-identifier", 40: "acct-status-type", 44: "acct-session-id",
    61: "nas-port-type", 79: "eap-message", 80: "message-authenticator",
}
_SNMP_PDU_NAMES = {
    0xA0: "get-request", 0xA1: "get-next-request", 0xA2: "response", 0xA3: "set-request", 0xA4: "trap-v1",
    0xA5: "get-bulk-request", 0xA6: "inform-request", 0xA7: "trap-v2", 0xA8: "report",
}


def _digest(value: bytes, *, domain: bytes) -> str:
    return hashlib.sha256(domain + b"\x00" + value).hexdigest()


def _text(value: bytes, limit: int = 255) -> str:
    return value[:limit].decode("utf-8", errors="replace")


def _ipv4_list(value: bytes) -> list[str]:
    if len(value) % 4:
        return []

    return [
        str(ipaddress.IPv4Address(value[pos:pos + 4]))
        for pos in range(0, len(value), 4)
    ][:64]

def _dhcp_classless_routes(value: bytes) -> tuple[list[dict[str, str]], bool]:
    cursor = 0
    routes: list[dict[str, str]] = []
    malformed = False
    while cursor < len(value) and len(routes) < 128:
        prefix_length = value[cursor]
        cursor += 1
        if prefix_length > 32:
            malformed = True
            break
        prefix_bytes = (prefix_length + 7) // 8
        if cursor + prefix_bytes + 4 > len(value):
            malformed = True
            break
        raw_prefix = value[cursor:cursor + prefix_bytes]
        cursor += prefix_bytes
        router = str(ipaddress.IPv4Address(value[cursor:cursor + 4]))
        cursor += 4
        network_address = ipaddress.IPv4Address(
            raw_prefix + b"\x00" * (4 - prefix_bytes)
        )

        network = ipaddress.ip_network(
            f"{network_address}/{prefix_length}",
            strict=False,
        )
        routes.append({"prefix": str(network), "router": router})
    if cursor != len(value):
        malformed = True
    return routes, malformed


def _dhcp_options(data: bytes, start: int) -> tuple[list[dict[str, Any]], bool]:
    rows: list[dict[str, Any]] = []
    cursor = start
    malformed = False
    while cursor < len(data) and len(rows) < _MAX_OPTIONS:
        code = data[cursor]
        cursor += 1
        if code == 0:
            continue
        if code == 255:
            break
        if cursor >= len(data):
            malformed = True
            break
        length = data[cursor]
        cursor += 1
        if cursor + length > len(data):
            malformed = True
            break
        value = data[cursor:cursor + length]
        cursor += length
        row: dict[str, Any] = {"code": code, "length": length}
        if code == 1 and length == 4:
            row.update({"name": "subnet-mask", "address": str(ipaddress.IPv4Address(value))})
        elif code == 3:
            row.update({"name": "routers", "addresses": _ipv4_list(value)})
        elif code == 6:
            row.update({"name": "dns-servers", "addresses": _ipv4_list(value)})
        elif code == 12:
            row.update({"name": "host-name", "text": _text(value)})
        elif code == 15:
            row.update({"name": "domain-name", "text": _text(value)})
        elif code == 28 and length == 4:
            row.update({"name": "broadcast-address", "address": str(ipaddress.IPv4Address(value))})
        elif code == 50 and length == 4:
            row.update({"name": "requested-address", "address": str(ipaddress.IPv4Address(value))})
        elif code in {51, 58, 59} and length == 4:
            name = {51: "lease-time", 58: "renewal-time", 59: "rebinding-time"}[code]
            row.update({"name": name, "seconds": struct.unpack("!I", value)[0]})
        elif code == 53 and length == 1:
            row.update({"name": "message-type", "message_type": value[0], "message_type_name": _DHCP_MESSAGE_NAMES.get(value[0], "unknown")})
        elif code == 54 and length == 4:
            row.update({"name": "server-identifier", "address": str(ipaddress.IPv4Address(value))})
        elif code == 55:
            row.update({"name": "parameter-request-list", "option_codes": list(value[:128])})
        elif code == 57 and length == 2:
            row.update({"name": "maximum-message-size", "bytes": struct.unpack("!H", value)[0]})
        elif code == 60:
            row.update({"name": "vendor-class-identifier", "text": _text(value)})
        elif code == 61:
            row.update({"name": "client-identifier", "bytes": length, "sha256": _digest(value, domain=b"dhcp-client-id"), "retained": False})
        elif code == 66:
            row.update({"name": "tftp-server-name", "text": _text(value)})
        elif code == 67:
            row.update({"name": "bootfile-name", "text": _text(value)})
        elif code in {121, 249}:
            routes, route_malformed = _dhcp_classless_routes(value)
            row.update({"name": "classless-static-routes", "routes": routes, "malformed": route_malformed})
        elif code == 82:
            row.update({"name": "relay-agent-information", "bytes": length, "sha256": _digest(value, domain=b"dhcp-relay-agent"), "retained": False})
        else:
            row.update({"name": "unknown", "sha256": _digest(value, domain=b"dhcp-option"), "retained": False})
        rows.append(row)
    return rows, malformed


def decode_dhcpv4(data: bytes) -> dict[str, Any]:
    if len(data) < 240:
        raise ValueError("truncated DHCPv4 message")
    op, hardware_type, hardware_len, hops, xid, seconds, flags = struct.unpack_from("!BBBBIHH", data, 0)
    result: dict[str, Any] = {
        "operation": op,
        "operation_name": {1: "bootrequest", 2: "bootreply"}.get(op, "unknown"),
        "hardware_type": hardware_type,
        "hardware_length": hardware_len,
        "hops": hops,
        "transaction_id": xid,
        "seconds": seconds,
        "broadcast": bool(flags & 0x8000),
        "client_ip": str(ipaddress.IPv4Address(data[12:16])),
        "your_ip": str(ipaddress.IPv4Address(data[16:20])),
        "server_ip": str(ipaddress.IPv4Address(data[20:24])),
        "gateway_ip": str(ipaddress.IPv4Address(data[24:28])),
    }
    if hardware_len == 6:
        result["client_mac"] = ":".join(f"{byte:02x}" for byte in data[28:34])
    if data[236:240] != b"\x63\x82\x53\x63":
        result.update({"dhcp_magic_cookie": False, "options": [], "option_count": 0})
        return result
    options, malformed = _dhcp_options(data, 240)
    result.update({"dhcp_magic_cookie": True, "options": options, "option_count": len(options), "options_malformed": malformed})
    for row in options:
        name = str(row.get("name") or "")
        if name == "message-type":
            result.update({"message_type": row.get("message_type"), "message_type_name": row.get("message_type_name")})
        elif name == "requested-address":
            result["requested_ip"] = row.get("address")
        elif name == "server-identifier":
            result["server_identifier"] = row.get("address")
        elif name == "lease-time":
            result["lease_time_seconds"] = row.get("seconds")
        elif name == "host-name":
            result["hostname"] = row.get("text")
    return result


def _dhcpv6_options(data: bytes, *, depth: int) -> tuple[list[dict[str, Any]], bool]:
    rows: list[dict[str, Any]] = []
    cursor = 0
    malformed = False
    while cursor + 4 <= len(data) and len(rows) < _MAX_OPTIONS:
        code, length = struct.unpack_from("!HH", data, cursor)
        cursor += 4
        if cursor + length > len(data):
            malformed = True
            break
        value = data[cursor:cursor + length]
        cursor += length
        row: dict[str, Any] = {"code": code, "length": length}
        if code in {1, 2}:
            row.update({
                "name": "client-id" if code == 1 else "server-id",
                "duid_bytes": length,
                "duid_sha256": _digest(value, domain=b"dhcpv6-duid"),
                "duid_retained": False,
            })
        elif code in {3, 25} and length >= 12:
            nested, nested_bad = _dhcpv6_options(value[12:], depth=depth + 1)
            row.update({
                "name": "ia-na" if code == 3 else "ia-pd",
                "iaid": struct.unpack_from("!I", value, 0)[0],
                "t1_seconds": struct.unpack_from("!I", value, 4)[0],
                "t2_seconds": struct.unpack_from("!I", value, 8)[0],
                "options": nested,
                "options_malformed": nested_bad,
            })
        elif code == 4 and length >= 4:
            nested, nested_bad = _dhcpv6_options(value[4:], depth=depth + 1)
            row.update({"name": "ia-ta", "iaid": struct.unpack_from("!I", value, 0)[0], "options": nested, "options_malformed": nested_bad})
        elif code == 5 and length >= 24:
            nested, nested_bad = _dhcpv6_options(value[24:], depth=depth + 1)
            row.update({
                "name": "ia-address", "address": str(ipaddress.IPv6Address(value[:16])),
                "preferred_lifetime_seconds": struct.unpack_from("!I", value, 16)[0],
                "valid_lifetime_seconds": struct.unpack_from("!I", value, 20)[0],
                "options": nested, "options_malformed": nested_bad,
            })
        elif code == 6 and length % 2 == 0:
            row.update({"name": "option-request", "option_codes": list(struct.unpack(f"!{length // 2}H", value))[:256]})
        elif code == 7 and length == 1:
            row.update({"name": "preference", "preference": value[0]})
        elif code == 8 and length == 2:
            row.update({"name": "elapsed-time", "centiseconds": struct.unpack("!H", value)[0]})
        elif code == 9 and depth < _MAX_RELAY_DEPTH:
            row.update({"name": "relay-message", "message": decode_dhcpv6(value, depth=depth + 1)})
        elif code == 12 and length == 16:
            row.update({"name": "server-unicast", "address": str(ipaddress.IPv6Address(value))})
        elif code == 13 and length >= 2:
            message = value[2:]
            row.update({
                "name": "status-code", "status_code": struct.unpack_from("!H", value, 0)[0],
                "status_message_bytes": len(message), "status_message_sha256": _digest(message, domain=b"dhcpv6-status"),
                "status_message_retained": False,
            })
        elif code == 14 and length == 0:
            row.update({"name": "rapid-commit"})
        elif code == 18:
            row.update({"name": "interface-id", "bytes": length, "sha256": _digest(value, domain=b"dhcpv6-interface-id"), "retained": False})
        elif code == 23 and length % 16 == 0:
            row.update({"name": "dns-recursive-name-server", "addresses": [str(ipaddress.IPv6Address(value[pos:pos + 16])) for pos in range(0, length, 16)][:64]})
        elif code == 26 and length >= 25:
            nested, nested_bad = _dhcpv6_options(value[25:], depth=depth + 1)
            row.update({
                "name": "ia-prefix", "preferred_lifetime_seconds": struct.unpack_from("!I", value, 0)[0],
                "valid_lifetime_seconds": struct.unpack_from("!I", value, 4)[0], "prefix_length": value[8],
                "prefix": str(ipaddress.ip_network(f"{ipaddress.IPv6Address(value[9:25])}/{value[8]}", strict=False)),
                "options": nested, "options_malformed": nested_bad,
            })
        elif code == 37 and length >= 4:
            opaque = value[4:]
            row.update({"name": "remote-id", "enterprise_number": struct.unpack_from("!I", value, 0)[0], "bytes": len(opaque), "sha256": _digest(opaque, domain=b"dhcpv6-remote-id"), "retained": False})
        else:
            row.update({"name": "unknown", "sha256": _digest(value, domain=b"dhcpv6-option"), "retained": False})
        rows.append(row)
    if cursor != len(data):
        malformed = True
    return rows, malformed


def decode_dhcpv6(data: bytes, *, depth: int = 0) -> dict[str, Any]:
    if not data or depth > _MAX_RELAY_DEPTH:
        raise ValueError("invalid DHCPv6 message")
    message_type = data[0]
    result: dict[str, Any] = {"message_type": message_type, "message_type_name": _DHCPV6_MESSAGE_NAMES.get(message_type, "unknown")}
    if message_type in {12, 13}:
        if len(data) < 34:
            raise ValueError("truncated DHCPv6 relay message")
        result.update({
            "hop_count": data[1], "link_address": str(ipaddress.IPv6Address(data[2:18])),
            "peer_address": str(ipaddress.IPv6Address(data[18:34])),
        })
        options, malformed = _dhcpv6_options(data[34:], depth=depth)
    else:
        if len(data) < 4:
            raise ValueError("truncated DHCPv6 message")
        result["transaction_id"] = data[1:4].hex()
        options, malformed = _dhcpv6_options(data[4:], depth=depth)
    result.update({"options": options, "option_count": len(options), "options_malformed": malformed})
    return result


def decode_radius(data: bytes) -> dict[str, Any]:
    if len(data) < 20:
        raise ValueError("truncated RADIUS packet")
    code, identifier, length = struct.unpack_from("!BBH", data, 0)
    if length < 20 or length > len(data) or length > 4096:
        raise ValueError("invalid RADIUS length")
    authenticator = data[4:20]
    rows: list[dict[str, Any]] = []
    cursor = 20
    malformed = False
    while cursor + 2 <= length and len(rows) < _MAX_RADIUS_ATTRIBUTES:
        attr_type, attr_length = data[cursor], data[cursor + 1]
        if attr_length < 2 or cursor + attr_length > length:
            malformed = True
            break
        value = data[cursor + 2:cursor + attr_length]
        cursor += attr_length
        name = _RADIUS_ATTRIBUTE_NAMES.get(attr_type, "unknown")
        row: dict[str, Any] = {"type": attr_type, "name": name, "length": attr_length}
        if attr_type in {1, 11, 18, 24, 25, 30, 31, 32, 44}:
            row.update({"value_bytes": len(value), "value_sha256": _digest(value, domain=b"radius-identity"), "value_retained": False})
        elif attr_type in {2, 3, 79, 80}:
            row.update({"sensitive_bytes": len(value), "sensitive_sha256": _digest(value, domain=b"radius-sensitive"), "sensitive_material_retained": False})
        elif attr_type in {4, 8, 9} and len(value) == 4:
            row["address"] = str(ipaddress.IPv4Address(value))
        elif attr_type in {5, 6, 7, 40, 61} and len(value) == 4:
            row["value"] = struct.unpack("!I", value)[0]
        elif attr_type == 26 and len(value) >= 4:
            opaque = value[4:]
            row.update({"vendor_id": struct.unpack_from("!I", value, 0)[0], "vendor_data_bytes": len(opaque), "vendor_data_sha256": _digest(opaque, domain=b"radius-vsa"), "vendor_data_retained": False})
        else:
            row.update({"value_bytes": len(value), "value_sha256": _digest(value, domain=b"radius-attribute"), "value_retained": False})
        rows.append(row)
    if cursor != length:
        malformed = True
    return {
        "code": code,
        "code_name": _RADIUS_CODE_NAMES.get(code, "unknown"),
        "identifier": identifier,
        "length": length,
        "authenticator_sha256": _digest(authenticator, domain=b"radius-authenticator"),
        "authenticator_retained": False,
        "attributes": rows,
        "attribute_count": len(rows),
        "attributes_malformed": malformed,
    }


def _ber_tlv(data: bytes, offset: int) -> tuple[int, int, int, int]:
    if offset + 2 > len(data):
        raise ValueError("truncated BER TLV")
    tag = data[offset]
    first = data[offset + 1]
    cursor = offset + 2
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4 or cursor + count > len(data):
            raise ValueError("invalid BER length")
        length = int.from_bytes(data[cursor:cursor + count], "big")
        cursor += count
    else:
        length = first
    end = cursor + length
    if end > len(data):
        raise ValueError("BER value exceeds message")
    return tag, length, cursor, end


def _ber_int(data: bytes, offset: int) -> tuple[int, int]:
    tag, _length, start, end = _ber_tlv(data, offset)
    if tag != 0x02:
        raise ValueError("BER integer expected")
    return int.from_bytes(data[start:end], "big", signed=True) if end > start else 0, end


def _decode_oid(value: bytes) -> str:
    if not value:
        return ""
    first = value[0]
    parts = [min(2, first // 40), first - min(2, first // 40) * 40]
    current = 0
    for byte in value[1:]:
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(current)
            current = 0
    if current:
        parts.append(current)
    return ".".join(str(part) for part in parts)


def _snmp_value(tag: int, value: bytes) -> dict[str, Any]:
    if tag == 0x02:
        return {"type": "integer", "value": int.from_bytes(value, "big", signed=True) if value else 0}
    if tag == 0x05:
        return {"type": "null"}
    if tag == 0x06:
        return {"type": "object-identifier", "value": _decode_oid(value)}
    if tag == 0x40 and len(value) == 4:
        return {"type": "ip-address", "value": str(ipaddress.IPv4Address(value))}
    if tag in {0x41, 0x42, 0x43, 0x46}:
        names = {0x41: "counter32", 0x42: "gauge32", 0x43: "timeticks", 0x46: "counter64"}
        return {"type": names[tag], "value": int.from_bytes(value, "big", signed=False)}
    if tag in {0x80, 0x81, 0x82}:
        return {"type": {0x80: "no-such-object", 0x81: "no-such-instance", 0x82: "end-of-mib-view"}[tag]}
    return {"type": f"ber-0x{tag:02x}", "bytes": len(value), "sha256": _digest(value, domain=b"snmp-value"), "retained": False}


def _decode_snmp_pdu(data: bytes, offset: int) -> dict[str, Any]:
    pdu_tag, _length, start, end = _ber_tlv(data, offset)
    result: dict[str, Any] = {"pdu_type": _SNMP_PDU_NAMES.get(pdu_tag, f"0x{pdu_tag:02x}")}
    if pdu_tag == 0xA4:
        result["pdu_bytes"] = end - start
        return result
    if start == end:
        result.update({"pdu_malformed": True, "pdu_error": "missing-request-id", "pdu_bytes": 0})
        return result
    request_id, cursor = _ber_int(data, start)
    error_status, cursor = _ber_int(data, cursor)
    error_index, cursor = _ber_int(data, cursor)
    result.update({"request_id": request_id, "error_status": error_status, "error_index": error_index})
    var_tag, _var_len, var_start, var_end = _ber_tlv(data, cursor)
    if var_tag != 0x30:
        raise ValueError("invalid SNMP variable binding list")
    cursor = var_start
    rows: list[dict[str, Any]] = []
    while cursor < var_end and len(rows) < _MAX_SNMP_VARBINDS:
        bind_tag, _bind_len, bind_start, bind_end = _ber_tlv(data, cursor)
        if bind_tag != 0x30:
            raise ValueError("invalid SNMP variable binding")
        oid_tag, _oid_len, oid_start, oid_end = _ber_tlv(data, bind_start)
        if oid_tag != 0x06:
            raise ValueError("SNMP variable binding OID missing")
        value_tag, _value_len, value_start, value_end = _ber_tlv(data, oid_end)
        rows.append({"oid": _decode_oid(data[oid_start:oid_end]), **_snmp_value(value_tag, data[value_start:value_end])})
        cursor = bind_end
    result.update({"varbind_count": len(rows), "varbinds": rows, "varbind_budget_reached": cursor < var_end})
    return result


def _decode_usm_security_parameters(raw: bytes) -> dict[str, Any]:
    try:
        tag, _length, start, end = _ber_tlv(raw, 0)
        if tag != 0x30:
            raise ValueError("USM sequence missing")
        engine_tag, _engine_len, engine_start, engine_end = _ber_tlv(raw, start)
        if engine_tag != 0x04:
            raise ValueError("USM engine ID missing")
        boots, cursor = _ber_int(raw, engine_end)
        engine_time, cursor = _ber_int(raw, cursor)
        user_tag, _user_len, user_start, user_end = _ber_tlv(raw, cursor)
        if user_tag != 0x04:
            raise ValueError("USM user name missing")
        return {
            "engine_id_bytes": engine_end - engine_start,
            "engine_id_sha256": _digest(raw[engine_start:engine_end], domain=b"snmp-engine-id"),
            "engine_boots": boots,
            "engine_time_seconds": engine_time,
            "user_name_bytes": user_end - user_start,
            "user_name_sha256": _digest(raw[user_start:user_end], domain=b"snmp-user-name"),
            "identity_material_retained": False,
            "parsed": True,
            "trailing_bytes": max(0, end - user_end),
        }
    except (ValueError, IndexError, struct.error):
        return {"parsed": False, "bytes": len(raw), "sha256": _digest(raw, domain=b"snmp-security-params"), "retained": False}


def decode_snmp(data: bytes) -> dict[str, Any]:
    outer_tag, _outer_len, start, end = _ber_tlv(data, 0)
    if outer_tag != 0x30:
        raise ValueError("invalid SNMP message")
    version, cursor = _ber_int(data, start)
    result: dict[str, Any] = {"version": version, "message_bytes": end}
    if version in {0, 1}:
        community_tag, _community_len, community_start, community_end = _ber_tlv(data, cursor)
        if community_tag != 0x04:
            raise ValueError("invalid SNMP community")
        community = data[community_start:community_end]
        result.update({
            "version_name": "v1" if version == 0 else "v2c",
            "community_present": bool(community),
            "community_length": len(community),
            "community_sha256": _digest(community, domain=b"snmp-community"),
            "community_retained": False,
        })
        result.update(_decode_snmp_pdu(data, community_end))
        return result
    if version != 3:
        result["version_name"] = "unknown"
        return result
    result["version_name"] = "v3"
    header_tag, _header_len, header_start, header_end = _ber_tlv(data, cursor)
    if header_tag != 0x30:
        raise ValueError("invalid SNMPv3 header")
    msg_id, hcursor = _ber_int(data, header_start)
    max_size, hcursor = _ber_int(data, hcursor)
    flags_tag, _flags_len, flags_start, flags_end = _ber_tlv(data, hcursor)
    if flags_tag != 0x04 or flags_end - flags_start != 1:
        raise ValueError("invalid SNMPv3 flags")
    flags = data[flags_start]
    security_model, _ = _ber_int(data, flags_end)
    sec_tag, _sec_len, sec_start, sec_end = _ber_tlv(data, header_end)
    if sec_tag != 0x04:
        raise ValueError("invalid SNMPv3 security parameters")
    result.update({
        "message_id": msg_id,
        "maximum_message_size": max_size,
        "auth_flag": bool(flags & 0x01),
        "privacy_flag": bool(flags & 0x02),
        "reportable_flag": bool(flags & 0x04),
        "security_model": security_model,
        "security_parameters": _decode_usm_security_parameters(data[sec_start:sec_end]),
    })
    data_tag, _data_len, data_start, data_end = _ber_tlv(data, sec_end)
    if data_tag == 0x04:
        encrypted = data[data_start:data_end]
        result.update({"scoped_pdu_encrypted": True, "encrypted_pdu_bytes": len(encrypted), "encrypted_pdu_sha256": _digest(encrypted, domain=b"snmpv3-encrypted-pdu"), "encrypted_pdu_retained": False})
        return result
    if data_tag != 0x30:
        raise ValueError("invalid SNMPv3 scoped PDU")
    context_engine_tag, _context_engine_len, context_engine_start, context_engine_end = _ber_tlv(data, data_start)
    context_name_tag, _context_name_len, context_name_start, context_name_end = _ber_tlv(data, context_engine_end)
    if context_engine_tag != 0x04 or context_name_tag != 0x04:
        raise ValueError("invalid SNMPv3 scoped PDU context")
    result.update({
        "scoped_pdu_encrypted": False,
        "context_engine_id_sha256": _digest(data[context_engine_start:context_engine_end], domain=b"snmp-context-engine"),
        "context_name_sha256": _digest(data[context_name_start:context_name_end], domain=b"snmp-context-name"),
        "context_identity_retained": False,
    })
    result.update(_decode_snmp_pdu(data, context_name_end))
    return result
