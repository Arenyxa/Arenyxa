from __future__ import annotations

import hashlib
import ipaddress
import struct
from typing import Any


_MAX_CDP_TLVS = 128
_MAX_CDP_TEXT = 2048


def _mac(raw: bytes) -> str:
    if len(raw) != 6:
        raise ValueError("MAC address must be six bytes")
    return ":".join(f"{item:02x}" for item in raw)


def _bridge_id(raw: bytes) -> dict[str, Any]:
    if len(raw) != 8:
        raise ValueError("bridge identifier must be eight bytes")
    priority_sysid = struct.unpack_from("!H", raw, 0)[0]
    return {
        "priority": priority_sysid & 0xF000,
        "system_id_extension": priority_sysid & 0x0FFF,
        "mac_address": _mac(raw[2:8]),
        "raw": raw.hex(),
    }


def _stp_seconds(raw: int) -> float:
    return round(int(raw) / 256.0, 4)


def decode_stp_bpdu(payload: bytes) -> dict[str, Any]:
    """Decode classic STP/RSTP/MSTP common BPDU structure after LLC."""
    if len(payload) < 4:
        raise ValueError("truncated spanning-tree BPDU")
    protocol_id, version, bpdu_type = struct.unpack_from("!HBB", payload, 0)
    if protocol_id != 0:
        raise ValueError("unsupported spanning-tree protocol identifier")
    protocol_name = "stp"
    if version == 2:
        protocol_name = "rstp"
    elif version >= 3:
        protocol_name = "mstp"
    result: dict[str, Any] = {
        "protocol_id": protocol_id,
        "version": version,
        "protocol_name": protocol_name,
        "bpdu_type": bpdu_type,
        "bpdu_type_name": {0x00: "configuration", 0x02: "rapid-spanning-tree", 0x80: "topology-change-notification"}.get(bpdu_type, "unknown"),
    }
    if bpdu_type == 0x80:
        return result
    if len(payload) < 35:
        raise ValueError("truncated spanning-tree configuration BPDU")
    flags = payload[4]
    result.update({
        "flags": f"0x{flags:02x}",
        "topology_change": bool(flags & 0x01),
        "proposal": bool(flags & 0x02) if version >= 2 else False,
        "port_role": ((flags >> 2) & 0x03) if version >= 2 else None,
        "learning": bool(flags & 0x10) if version >= 2 else False,
        "forwarding": bool(flags & 0x20) if version >= 2 else False,
        "agreement": bool(flags & 0x40) if version >= 2 else False,
        "topology_change_ack": bool(flags & 0x80),
        "root_id": _bridge_id(payload[5:13]),
        "root_path_cost": struct.unpack_from("!I", payload, 13)[0],
        "bridge_id": _bridge_id(payload[17:25]),
        "port_id": f"0x{struct.unpack_from('!H', payload, 25)[0]:04x}",
        "message_age_seconds": _stp_seconds(struct.unpack_from("!H", payload, 27)[0]),
        "max_age_seconds": _stp_seconds(struct.unpack_from("!H", payload, 29)[0]),
        "hello_time_seconds": _stp_seconds(struct.unpack_from("!H", payload, 31)[0]),
        "forward_delay_seconds": _stp_seconds(struct.unpack_from("!H", payload, 33)[0]),
    })
    if version >= 2 and len(payload) >= 36:
        result["version1_length"] = payload[35]
    if version >= 3 and len(payload) > 36:
        mst = payload[36:]
        result["mst_extension_bytes"] = len(mst)
        result["mst_extension_sha256"] = hashlib.sha256(mst).hexdigest()
    return result


def _lacp_state(value: int) -> dict[str, bool]:
    return {
        "activity": bool(value & 0x01),
        "timeout_short": bool(value & 0x02),
        "aggregation": bool(value & 0x04),
        "synchronization": bool(value & 0x08),
        "collecting": bool(value & 0x10),
        "distributing": bool(value & 0x20),
        "defaulted": bool(value & 0x40),
        "expired": bool(value & 0x80),
    }


def _lacp_system_tlv(value: bytes) -> dict[str, Any]:
    if len(value) < 18:
        raise ValueError("truncated LACP actor/partner TLV")
    system_priority = struct.unpack_from("!H", value, 0)[0]
    system_id = _mac(value[2:8])
    key, port_priority, port = struct.unpack_from("!HHH", value, 8)
    state = value[14]
    return {
        "system_priority": system_priority,
        "system_id": system_id,
        "key": key,
        "port_priority": port_priority,
        "port": port,
        "state_raw": f"0x{state:02x}",
        "state": _lacp_state(state),
    }


def decode_slow_protocol(payload: bytes) -> dict[str, Any]:
    """Decode IEEE 802.3 Slow Protocol subtype metadata, including LACP."""
    if len(payload) < 2:
        raise ValueError("truncated slow-protocol header")
    subtype, version = payload[0], payload[1]
    result: dict[str, Any] = {
        "subtype": subtype,
        "subtype_name": {1: "lacp", 2: "marker"}.get(subtype, "unknown"),
        "version": version,
    }
    if subtype != 1:
        result["payload_bytes"] = max(0, len(payload) - 2)
        return result
    cursor = 2
    tlvs: list[dict[str, Any]] = []
    for _ in range(16):
        if cursor + 2 > len(payload):
            break
        tlv_type, length = payload[cursor], payload[cursor + 1]
        if tlv_type == 0:
            tlvs.append({"type": 0, "name": "terminator", "length": length})
            break
        if length < 2 or cursor + length > len(payload):
            result["malformed_tlv"] = True
            break
        value = payload[cursor + 2:cursor + length]
        row: dict[str, Any] = {"type": tlv_type, "length": length}
        if tlv_type == 1:
            row.update({"name": "actor", **_lacp_system_tlv(value)})
            result["actor"] = dict(row)
        elif tlv_type == 2:
            row.update({"name": "partner", **_lacp_system_tlv(value)})
            result["partner"] = dict(row)
        elif tlv_type == 3 and len(value) >= 2:
            row.update({"name": "collector", "max_delay_tens_of_microseconds": struct.unpack_from("!H", value, 0)[0]})
            result["collector"] = dict(row)
        else:
            row.update({"name": "unknown", "value_sha256": hashlib.sha256(value).hexdigest()})
        tlvs.append(row)
        cursor += length
    result["tlvs"] = tlvs
    result["tlv_count"] = len(tlvs)
    return result


def _cdp_text(value: bytes) -> str:
    return value[:_MAX_CDP_TEXT].decode("utf-8", errors="replace")


def _cdp_addresses(value: bytes) -> list[str]:
    if len(value) < 4:
        return []
    count = struct.unpack_from("!I", value, 0)[0]
    cursor = 4
    addresses: list[str] = []
    for _ in range(min(count, 128)):
        if cursor + 2 > len(value):
            break
        _protocol_type = value[cursor]
        protocol_length = value[cursor + 1]
        cursor += 2
        if cursor + protocol_length + 2 > len(value):
            break
        cursor += protocol_length
        address_length = struct.unpack_from("!H", value, cursor)[0]
        cursor += 2
        if cursor + address_length > len(value):
            break
        raw = value[cursor:cursor + address_length]
        cursor += address_length
        try:
            if len(raw) == 4:
                addresses.append(str(ipaddress.IPv4Address(raw)))
            elif len(raw) == 16:
                addresses.append(str(ipaddress.IPv6Address(raw)))
        except ipaddress.AddressValueError:
            continue
    return addresses


def decode_cdp(payload: bytes) -> dict[str, Any]:
    """Decode bounded Cisco Discovery Protocol metadata after SNAP."""
    if len(payload) < 4:
        raise ValueError("truncated CDP header")
    version, ttl, checksum = struct.unpack_from("!BBH", payload, 0)
    cursor = 4
    result: dict[str, Any] = {
        "version": version,
        "ttl_seconds": ttl,
        "checksum": f"0x{checksum:04x}",
        "tlvs": [],
    }
    capabilities_map = {
        0x01: "router",
        0x02: "transparent-bridge",
        0x04: "source-route-bridge",
        0x08: "switch",
        0x10: "host",
        0x20: "igmp",
        0x40: "repeater",
        0x80: "voip-phone",
    }
    tlvs: list[dict[str, Any]] = result["tlvs"]
    while cursor + 4 <= len(payload) and len(tlvs) < _MAX_CDP_TLVS:
        kind, length = struct.unpack_from("!HH", payload, cursor)
        if length < 4 or cursor + length > len(payload):
            result["malformed_tlv"] = True
            break
        value = payload[cursor + 4:cursor + length]
        row: dict[str, Any] = {"type": kind, "length": length}
        if kind == 0x0001:
            row.update({"name": "device-id", "text": _cdp_text(value)})
            result["device_id"] = row["text"]
        elif kind == 0x0002:
            addresses = _cdp_addresses(value)
            row.update({"name": "addresses", "addresses": addresses})
            result["addresses"] = addresses
        elif kind == 0x0003:
            row.update({"name": "port-id", "text": _cdp_text(value)})
            result["port_id"] = row["text"]
        elif kind == 0x0004 and len(value) >= 4:
            bits = struct.unpack_from("!I", value, 0)[0]
            names = [name for mask, name in capabilities_map.items() if bits & mask]
            row.update({"name": "capabilities", "bits": f"0x{bits:08x}", "enabled": names})
            result["capabilities"] = names
        elif kind == 0x0005:
            row.update({"name": "software-version", "text": _cdp_text(value)})
            result["software_version"] = row["text"]
        elif kind == 0x0006:
            row.update({"name": "platform", "text": _cdp_text(value)})
            result["platform"] = row["text"]
        elif kind == 0x0009:
            row.update({"name": "vtp-management-domain", "text": _cdp_text(value)})
            result["vtp_management_domain"] = row["text"]
        elif kind == 0x000A and len(value) >= 2:
            vlan = struct.unpack_from("!H", value, 0)[0]
            row.update({"name": "native-vlan", "vlan_id": vlan})
            result["native_vlan"] = vlan
        elif kind == 0x000B and value:
            duplex = "full" if value[0] else "half"
            row.update({"name": "duplex", "mode": duplex})
            result["duplex"] = duplex
        else:
            row.update({"name": "unknown", "value_sha256": hashlib.sha256(value).hexdigest()})
        tlvs.append(row)
        cursor += length
    result["tlv_count"] = len(tlvs)
    result["trailing_bytes"] = max(0, len(payload) - cursor)
    return result
