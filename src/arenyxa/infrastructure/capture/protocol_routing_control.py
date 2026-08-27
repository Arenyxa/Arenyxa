from __future__ import annotations

import hashlib
import ipaddress
import struct
from typing import Any


_MAX_MULTICAST_SOURCES = 512
_MAX_GROUP_RECORDS = 256
_MAX_PIM_OPTIONS = 128


def decode_vrrp(payload: bytes, *, ipv6: bool) -> dict[str, Any]:
    if len(payload) < 8:
        raise ValueError("truncated VRRP advertisement")
    first, vrid, priority, address_count = struct.unpack_from("!BBBB", payload, 0)
    version = first >> 4
    packet_type = first & 0x0F
    result: dict[str, Any] = {
        "version": version,
        "type": packet_type,
        "type_name": "advertisement" if packet_type == 1 else "unknown",
        "virtual_router_id": vrid,
        "priority": priority,
        "address_count": address_count,
    }
    if version == 2:
        auth_type, advert_interval, checksum = struct.unpack_from("!BBH", payload, 4)
        address_size = 4
        result.update({
            "authentication_type": auth_type,
            "advertisement_interval_seconds": advert_interval,
            "checksum": f"0x{checksum:04x}",
        })
    elif version == 3:
        interval_field, checksum = struct.unpack_from("!HH", payload, 4)
        address_size = 16 if ipv6 else 4
        result.update({
            "reserved": (interval_field >> 12) & 0xF,
            "max_advertisement_interval_centiseconds": interval_field & 0x0FFF,
            "max_advertisement_interval_seconds": round((interval_field & 0x0FFF) / 100.0, 2),
            "checksum": f"0x{checksum:04x}",
        })
    else:
        raise ValueError(f"unsupported VRRP version: {version}")
    cursor = 8
    addresses: list[str] = []
    for _ in range(min(address_count, 255)):
        if cursor + address_size > len(payload):
            result["addresses_truncated"] = True
            break
        raw = payload[cursor:cursor + address_size]
        addresses.append(str(ipaddress.ip_address(raw)))
        cursor += address_size
    result["addresses"] = addresses
    result["decoded_address_count"] = len(addresses)
    if version == 2 and cursor < len(payload):
        # VRRPv2 authentication data can contain credentials. Never retain it.
        auth = payload[cursor:]
        result["authentication_data_bytes"] = len(auth)
        result["authentication_data_sha256"] = hashlib.sha256(auth).hexdigest()
        result["authentication_data_retained"] = False
    return result


def decode_igmp(payload: bytes) -> dict[str, Any]:
    if len(payload) < 8:
        raise ValueError("truncated IGMP message")
    message_type, max_response, checksum = struct.unpack_from("!BBH", payload, 0)
    group = str(ipaddress.IPv4Address(payload[4:8]))
    names = {
        0x11: "membership-query",
        0x12: "v1-membership-report",
        0x16: "v2-membership-report",
        0x17: "leave-group",
        0x22: "v3-membership-report",
    }
    result: dict[str, Any] = {
        "type": f"0x{message_type:02x}",
        "type_name": names.get(message_type, "unknown"),
        "max_response_code": max_response,
        "checksum": f"0x{checksum:04x}",
        "group": group,
    }
    if message_type == 0x11 and len(payload) >= 12:
        resv_s_qrv = payload[8]
        source_count = struct.unpack_from("!H", payload, 10)[0]
        cursor = 12
        sources: list[str] = []
        for _ in range(min(source_count, _MAX_MULTICAST_SOURCES)):
            if cursor + 4 > len(payload):
                result["sources_truncated"] = True
                break
            sources.append(str(ipaddress.IPv4Address(payload[cursor:cursor + 4])))
            cursor += 4
        result.update({
            "version": 3,
            "suppress_router_processing": bool(resv_s_qrv & 0x08),
            "qrv": resv_s_qrv & 0x07,
            "qqic": payload[9],
            "source_count": source_count,
            "sources": sources,
        })
    elif message_type == 0x22:
        if len(payload) < 8:
            raise ValueError("truncated IGMPv3 report")
        record_count = struct.unpack_from("!H", payload, 6)[0]
        cursor = 8
        records: list[dict[str, Any]] = []
        record_names = {
            1: "mode-is-include", 2: "mode-is-exclude", 3: "change-to-include", 4: "change-to-exclude",
            5: "allow-new-sources", 6: "block-old-sources",
        }
        for _ in range(min(record_count, _MAX_GROUP_RECORDS)):
            if cursor + 8 > len(payload):
                result["records_truncated"] = True
                break
            record_type, aux_words, source_count = struct.unpack_from("!BBH", payload, cursor)
            multicast = str(ipaddress.IPv4Address(payload[cursor + 4:cursor + 8]))
            cursor += 8
            sources: list[str] = []
            for _source in range(min(source_count, _MAX_MULTICAST_SOURCES)):
                if cursor + 4 > len(payload):
                    result["records_truncated"] = True
                    break
                sources.append(str(ipaddress.IPv4Address(payload[cursor:cursor + 4])))
                cursor += 4
            aux_bytes = aux_words * 4
            if cursor + aux_bytes > len(payload):
                result["records_truncated"] = True
                break
            if aux_bytes:
                cursor += aux_bytes
            records.append({
                "record_type": record_type,
                "record_type_name": record_names.get(record_type, "unknown"),
                "multicast_address": multicast,
                "source_count": source_count,
                "sources": sources,
                "auxiliary_data_bytes": aux_bytes,
            })
        result.update({"version": 3, "group_record_count": record_count, "group_records": records})
    else:
        result["version"] = 1 if message_type == 0x12 else 2
    return result


def decode_pim(payload: bytes) -> dict[str, Any]:
    if len(payload) < 4:
        raise ValueError("truncated PIM header")
    first, reserved, checksum = struct.unpack_from("!BBH", payload, 0)
    version, message_type = first >> 4, first & 0x0F
    type_names = {
        0: "hello", 1: "register", 2: "register-stop", 3: "join-prune", 4: "bootstrap",
        5: "assert", 6: "graft", 7: "graft-ack", 8: "candidate-rp-advertisement",
        9: "state-refresh", 10: "df-election",
    }
    result: dict[str, Any] = {
        "version": version,
        "type": message_type,
        "type_name": type_names.get(message_type, "unknown"),
        "reserved": reserved,
        "checksum": f"0x{checksum:04x}",
    }
    if version != 2:
        return result
    body = payload[4:]
    if message_type == 0:
        cursor = 0
        options: list[dict[str, Any]] = []
        while cursor + 4 <= len(body) and len(options) < _MAX_PIM_OPTIONS:
            option_type, length = struct.unpack_from("!HH", body, cursor)
            cursor += 4
            if cursor + length > len(body):
                result["options_truncated"] = True
                break
            value = body[cursor:cursor + length]
            cursor += length
            row: dict[str, Any] = {"type": option_type, "length": length}
            if option_type == 1 and length == 2:
                row.update({"name": "holdtime", "holdtime_seconds": struct.unpack("!H", value)[0]})
                result["holdtime_seconds"] = row["holdtime_seconds"]
            elif option_type == 2 and length == 4:
                propagation_delay, override_interval = struct.unpack("!HH", value)
                row.update({
                    "name": "lan-prune-delay",
                    "t_bit": bool(propagation_delay & 0x8000),
                    "propagation_delay_ms": propagation_delay & 0x7FFF,
                    "override_interval_ms": override_interval,
                })
            elif option_type == 19 and length == 4:
                row.update({"name": "dr-priority", "dr_priority": struct.unpack("!I", value)[0]})
                result["dr_priority"] = row["dr_priority"]
            elif option_type == 20 and length == 4:
                row.update({"name": "generation-id", "generation_id": f"0x{struct.unpack('!I', value)[0]:08x}"})
                result["generation_id"] = row["generation_id"]
            else:
                row.update({"name": "unknown", "value_sha256": hashlib.sha256(value).hexdigest()})
            options.append(row)
        result["hello_options"] = options
        result["hello_option_count"] = len(options)
    elif message_type == 1 and len(body) >= 4:
        flags = struct.unpack_from("!I", body, 0)[0]
        result.update({
            "border": bool(flags & 0x80000000),
            "null_register": bool(flags & 0x40000000),
            "register_payload_bytes": max(0, len(body) - 4),
        })
    return result


def decode_bfd_control(payload: bytes) -> dict[str, Any]:
    if len(payload) < 24:
        raise ValueError("truncated BFD control packet")
    version_diag, state_flags, detect_mult, length = struct.unpack_from("!BBBB", payload, 0)
    version = version_diag >> 5
    diagnostic = version_diag & 0x1F
    state = (state_flags >> 6) & 0x03
    if length < 24 or length > len(payload):
        raise ValueError("invalid BFD control packet length")
    my_disc, your_disc, min_tx, min_rx, min_echo = struct.unpack_from("!IIIII", payload, 4)
    return {
        "version": version,
        "diagnostic": diagnostic,
        "state": state,
        "state_name": {0: "admin-down", 1: "down", 2: "init", 3: "up"}.get(state, "unknown"),
        "poll": bool(state_flags & 0x20),
        "final": bool(state_flags & 0x10),
        "control_plane_independent": bool(state_flags & 0x08),
        "authentication_present": bool(state_flags & 0x04),
        "demand": bool(state_flags & 0x02),
        "multipoint": bool(state_flags & 0x01),
        "detect_multiplier": detect_mult,
        "length": length,
        "my_discriminator": my_disc,
        "your_discriminator": your_disc,
        "desired_min_tx_interval_us": min_tx,
        "required_min_rx_interval_us": min_rx,
        "required_min_echo_rx_interval_us": min_echo,
        "detection_time_floor_us": detect_mult * min_rx,
        "authentication_bytes": max(0, length - 24) if bool(state_flags & 0x04) else 0,
        "authentication_material_retained": False,
    }
