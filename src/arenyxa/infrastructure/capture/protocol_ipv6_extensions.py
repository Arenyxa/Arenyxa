from __future__ import annotations

import hashlib
import ipaddress
import struct
from typing import Any

MAX_SRH_SEGMENTS = 64
MAX_SRH_TLVS = 64


def decode_ipv6_routing_header(data: bytes) -> dict[str, Any]:
    if len(data) < 4:
        raise ValueError("truncated IPv6 routing header")
    fields: dict[str, Any] = {
        "next_header": data[0],
        "routing_type": data[2],
        "segments_left": data[3],
    }
    if data[2] != 4:
        return fields
    if len(data) < 8:
        raise ValueError("truncated IPv6 Segment Routing Header")
    last_entry = data[4]
    flags = data[5]
    tag = struct.unpack_from("!H", data, 6)[0]
    segment_count = last_entry + 1
    if segment_count > MAX_SRH_SEGMENTS:
        raise ValueError("SRv6 segment list exceeds native decoder bound")
    segment_bytes = segment_count * 16
    if 8 + segment_bytes > len(data):
        raise ValueError("truncated SRv6 segment list")
    segments = [
        str(ipaddress.IPv6Address(data[8 + index * 16:24 + index * 16]))
        for index in range(segment_count)
    ]
    fields.update({
        "segment_routing_header": True,
        "last_entry": last_entry,
        "flags": f"0x{flags:02x}",
        "tag": tag,
        "segment_list": segments,
        "active_segment": segments[fields["segments_left"]] if fields["segments_left"] < len(segments) else "",
    })
    cursor = 8 + segment_bytes
    tlvs: list[dict[str, Any]] = []
    for _ in range(MAX_SRH_TLVS):
        if cursor >= len(data):
            break
        tlv_type = data[cursor]
        if tlv_type == 0:  # Pad1
            tlvs.append({"type": 0, "name": "Pad1", "length": 0})
            cursor += 1
            continue
        if cursor + 2 > len(data):
            raise ValueError("truncated SRv6 TLV header")
        length = data[cursor + 1]
        if cursor + 2 + length > len(data):
            raise ValueError("truncated SRv6 TLV")
        value = data[cursor + 2:cursor + 2 + length]
        row: dict[str, Any] = {
            "type": tlv_type,
            "length": length,
            "mutable": bool(tlv_type & 0x80),
            "value_sha256": hashlib.sha256(b"arenyxa-srv6-tlv-v1\x00" + value).hexdigest() if value else "",
        }
        if tlv_type == 5:
            row["name"] = "HMAC"
            if length >= 6:
                row["hmac_key_id"] = struct.unpack_from("!I", value, 2)[0]
                row["hmac_digest_bytes"] = max(0, length - 6)
        else:
            row["name"] = f"TLV_{tlv_type}"
        tlvs.append(row)
        cursor += 2 + length
    if cursor != len(data):
        raise ValueError("SRv6 TLV count exceeds native decoder bound")
    fields["tlvs"] = tlvs
    return fields
