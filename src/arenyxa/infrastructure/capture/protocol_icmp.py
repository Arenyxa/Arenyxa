from __future__ import annotations

import ipaddress
import struct
from typing import Any

MAX_ND_OPTIONS = 128
MAX_DNSSL_NAMES = 64


def _need(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError(f"truncated {label}")


def _dnssl_names(data: bytes) -> list[str]:
    names: list[str] = []
    cursor = 0
    labels: list[str] = []
    while cursor < len(data) and len(names) < MAX_DNSSL_NAMES:
        size = data[cursor]
        cursor += 1
        if size == 0:
            if labels:
                names.append(".".join(labels))
                labels = []
            # remaining bytes may be padding
            if all(value == 0 for value in data[cursor:]):
                break
            continue
        if size > 63 or cursor + size > len(data):
            raise ValueError("invalid ICMPv6 DNSSL label")
        labels.append(data[cursor:cursor + size].decode("ascii", errors="replace")[:63])
        cursor += size
    if labels and len(names) < MAX_DNSSL_NAMES:
        names.append(".".join(labels))
    return names


def _nd_options(data: bytes, cursor: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for _ in range(MAX_ND_OPTIONS):
        if cursor >= len(data):
            break
        _need(data, cursor, 2, "ICMPv6 ND option")
        option_type = data[cursor]
        units = data[cursor + 1]
        if units == 0:
            raise ValueError("ICMPv6 ND option has zero length")
        length = units * 8
        _need(data, cursor, length, "ICMPv6 ND option")
        raw = data[cursor:cursor + length]
        row: dict[str, Any] = {"type": option_type, "length": length}
        if option_type in {1, 2}:
            row["name"] = "source-link-layer" if option_type == 1 else "target-link-layer"
            address = raw[2:]
            row["link_layer_address"] = ":".join(f"{value:02x}" for value in address) if len(address) == 6 else address.hex()
        elif option_type == 3 and length >= 32:
            prefix_length = raw[2]
            flags = raw[3]
            row.update({
                "name": "prefix-information",
                "prefix_length": prefix_length,
                "on_link": bool(flags & 0x80),
                "autonomous": bool(flags & 0x40),
                "valid_lifetime": struct.unpack_from("!I", raw, 4)[0],
                "preferred_lifetime": struct.unpack_from("!I", raw, 8)[0],
                "prefix": str(ipaddress.IPv6Address(raw[16:32])) + f"/{prefix_length}",
            })
        elif option_type == 5 and length >= 8:
            row.update({"name": "mtu", "mtu": struct.unpack_from("!I", raw, 4)[0]})
        elif option_type == 25 and length >= 24 and (length - 8) % 16 == 0:
            row.update({
                "name": "rdnss",
                "lifetime": struct.unpack_from("!I", raw, 4)[0],
                "servers": [str(ipaddress.IPv6Address(raw[pos:pos + 16])) for pos in range(8, length, 16)],
            })
        elif option_type == 31 and length >= 16:
            row.update({
                "name": "dnssl",
                "lifetime": struct.unpack_from("!I", raw, 4)[0],
                "domains": _dnssl_names(raw[8:]),
            })
        else:
            row["name"] = f"option-{option_type}"
            row["value_bytes"] = max(0, length - 2)
        rows.append(row)
        cursor += length
    if cursor != len(data):
        raise ValueError("ICMPv6 ND option count exceeds native decoder bound")
    return rows


def decode_icmp_message(data: bytes, *, ipv6: bool) -> dict[str, Any]:
    _need(data, 0, 4, "ICMP header")
    icmp_type, code, checksum = struct.unpack_from("!BBH", data, 0)
    fields: dict[str, Any] = {"type": icmp_type, "code": code, "checksum": f"0x{checksum:04x}"}
    if (not ipv6 and icmp_type in {0, 8}) or (ipv6 and icmp_type in {128, 129}):
        _need(data, 0, 8, "ICMP echo")
        identifier, sequence = struct.unpack_from("!HH", data, 4)
        fields.update({"message": "echo-reply" if icmp_type in {0, 129} else "echo-request", "identifier": identifier, "sequence": sequence})
        return fields
    if not ipv6:
        names = {3: "destination-unreachable", 5: "redirect", 11: "time-exceeded", 12: "parameter-problem"}
        if icmp_type in names:
            fields["message"] = names[icmp_type]
        if icmp_type == 3 and code == 4 and len(data) >= 8:
            fields["next_hop_mtu"] = struct.unpack_from("!H", data, 6)[0]
        return fields

    names6 = {
        1: "destination-unreachable", 2: "packet-too-big", 3: "time-exceeded", 4: "parameter-problem",
        133: "router-solicitation", 134: "router-advertisement", 135: "neighbor-solicitation",
        136: "neighbor-advertisement", 137: "redirect",
    }
    if icmp_type in names6:
        fields["message"] = names6[icmp_type]
    if icmp_type == 2:
        _need(data, 0, 8, "ICMPv6 Packet Too Big")
        fields["mtu"] = struct.unpack_from("!I", data, 4)[0]
    elif icmp_type == 133:
        _need(data, 0, 8, "ICMPv6 Router Solicitation")
        fields["options"] = _nd_options(data, 8)
    elif icmp_type == 134:
        _need(data, 0, 16, "ICMPv6 Router Advertisement")
        flags = data[5]
        fields.update({
            "current_hop_limit": data[4],
            "managed": bool(flags & 0x80),
            "other_configuration": bool(flags & 0x40),
            "router_preference": (flags >> 3) & 0x03,
            "router_lifetime": struct.unpack_from("!H", data, 6)[0],
            "reachable_time_ms": struct.unpack_from("!I", data, 8)[0],
            "retrans_timer_ms": struct.unpack_from("!I", data, 12)[0],
            "options": _nd_options(data, 16),
        })
    elif icmp_type in {135, 136}:
        _need(data, 0, 24, "ICMPv6 Neighbor Discovery")
        word = struct.unpack_from("!I", data, 4)[0]
        fields["target_address"] = str(ipaddress.IPv6Address(data[8:24]))
        if icmp_type == 136:
            fields.update({"router": bool(word & 0x80000000), "solicited": bool(word & 0x40000000), "override": bool(word & 0x20000000)})
        fields["options"] = _nd_options(data, 24)
    elif icmp_type == 137:
        _need(data, 0, 40, "ICMPv6 Redirect")
        fields.update({
            "target_address": str(ipaddress.IPv6Address(data[8:24])),
            "destination_address": str(ipaddress.IPv6Address(data[24:40])),
            "options": _nd_options(data, 40),
        })
    return fields
