from __future__ import annotations

import hashlib
import ipaddress
import re
import struct
from typing import Any


_MAX_SIP_HEADER_BYTES = 64 * 1024
_MAX_SIP_HEADERS = 512
_MAX_SDP_LINES = 1024
_MAX_RTCP_PACKETS = 64
_MAX_RTCP_REPORTS = 64


def _hash(domain: bytes, value: str | bytes) -> str:
    raw = value.encode("utf-8", "replace") if isinstance(value, str) else value
    return hashlib.sha256(domain + b"\x00" + raw).hexdigest()


def _uri_metadata(value: str) -> dict[str, Any]:
    text = str(value or "").strip()
    match = re.search(r"(?P<scheme>sips?|tel):(?P<body>[^>;\s]+)", text, re.IGNORECASE)
    row: dict[str, Any] = {
        "value_sha256": _hash(b"arenyxa-sip-uri/v1", text),
        "value_retained": False,
    }
    if not match:
        return row
    scheme = match.group("scheme").casefold()
    body = match.group("body")
    row["scheme"] = scheme
    if scheme in {"sip", "sips"}:
        authority = body.split("?", 1)[0].split(";", 1)[0]
        host_port = authority.rsplit("@", 1)[-1]
        if host_port.startswith("[") and "]" in host_port:
            host = host_port[1:host_port.index("]")]
        else:
            host = host_port.rsplit(":", 1)[0] if host_port.count(":") == 1 else host_port
        row["host"] = host.casefold()
        row["user_present"] = "@" in authority
    return row


def _sip_headers(header_lines: list[str]) -> dict[str, list[str]]:
    unfolded: list[str] = []
    for line in header_lines[:_MAX_SIP_HEADERS * 2]:
        if line[:1] in {" ", "\t"} and unfolded:
            unfolded[-1] += " " + line.strip()
        else:
            unfolded.append(line)
    compact = {"v": "via", "f": "from", "t": "to", "i": "call-id", "m": "contact", "l": "content-length", "c": "content-type"}
    result: dict[str, list[str]] = {}
    for line in unfolded[:_MAX_SIP_HEADERS]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = compact.get(name.strip().casefold(), name.strip().casefold())
        result.setdefault(key, []).append(value.strip())
    return result


def _single(headers: dict[str, list[str]], name: str) -> str:
    values = headers.get(name, [])
    return values[0] if values else ""


def _sdp_address(value: str) -> str:
    parts = value.strip().split()
    if len(parts) < 3:
        return ""
    address = parts[2].split("/", 1)[0]
    try:
        return str(ipaddress.ip_address(address))
    except ValueError:
        return address.casefold()


def _new_sdp_media(value: str, connection: str) -> dict[str, Any] | None:
    parts = value.split()
    if len(parts) < 4:
        return None
    try:
        port = int(parts[1].split("/", 1)[0])
    except ValueError:
        return None
    return {
        "media": parts[0].casefold(), "port": port, "protocol": parts[2], "formats": parts[3:67],
        "connection_address": connection, "rtpmap": [], "fmtp": [], "direction": "",
        "rtcp_mux": False, "rtcp_port": None, "mid": "",
    }


def _append_security_attribute(target: dict[str, Any] | None, session: list[dict[str, Any]], row: dict[str, Any]) -> None:
    (target.setdefault("security_attributes", []) if target is not None else session).append(row)


def _apply_sdp_attribute(value: str, target: dict[str, Any] | None, session: list[dict[str, Any]]) -> bool:
    name, sep, attr_value = value.partition(":")
    attr_name = name.casefold()
    if target is not None and attr_name == "rtpmap" and sep:
        token, _, encoding = attr_value.partition(" ")
        pieces = encoding.split("/")
        target["rtpmap"].append({
            "payload_type": token, "encoding": pieces[0].casefold() if pieces else "",
            "clock_rate": int(pieces[1]) if len(pieces) > 1 and pieces[1].isdigit() else None,
            "channels": int(pieces[2]) if len(pieces) > 2 and pieces[2].isdigit() else None,
        })
    elif target is not None and attr_name == "fmtp" and sep:
        token, _, params = attr_value.partition(" ")
        target["fmtp"].append({
            "payload_type": token, "parameters_bytes": len(params.encode("utf-8", "replace")),
            "parameters_sha256": _hash(b"arenyxa-sdp-fmtp/v1", params), "parameters_retained": False,
        })
    elif target is not None and attr_name in {"sendrecv", "sendonly", "recvonly", "inactive"}:
        target["direction"] = attr_name
    elif target is not None and attr_name == "rtcp-mux":
        target["rtcp_mux"] = True
    elif target is not None and attr_name == "rtcp" and sep:
        try:
            target["rtcp_port"] = int(attr_value.split()[0])
        except (ValueError, IndexError):
            return False
    elif target is not None and attr_name == "mid" and sep:
        target["mid"] = attr_value[:128]
    elif attr_name in {"ice-ufrag", "ice-pwd"} and sep:
        _append_security_attribute(target, session, {
            "name": attr_name, "value_bytes": len(attr_value.encode("utf-8", "replace")),
            "value_sha256": _hash(f"arenyxa-sdp-{attr_name}/v1".encode(), attr_value), "value_retained": False,
        })
    elif attr_name == "fingerprint" and sep:
        algorithm, _, fingerprint = attr_value.partition(" ")
        _append_security_attribute(target, session, {
            "name": "fingerprint", "algorithm": algorithm.casefold(), "fingerprint": fingerprint.casefold()[:256],
        })
    elif attr_name == "setup" and sep:
        _append_security_attribute(target, session, {"name": "setup", "role": attr_value.casefold()[:32]})
    elif attr_name == "group" and sep and target is None:
        parts = attr_value.split()
        session.append({"name": "group", "semantics": parts[0] if parts else "", "mids": parts[1:65]})
    return True


def decode_sdp(body: bytes) -> dict[str, Any]:
    text = body.decode("utf-8", errors="replace")
    lines = [line.rstrip("\r") for line in text.split("\n") if line.rstrip("\r")][:_MAX_SDP_LINES]
    session_connection = ""
    media_rows: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    session_attributes: list[dict[str, Any]] = []
    malformed = False
    for line in lines:
        if len(line) < 2 or line[1] != "=":
            malformed = True
            continue
        kind, value = line[0], line[2:]
        if kind == "c":
            address = _sdp_address(value)
            if current is None:
                session_connection = address
            else:
                current["connection_address"] = address
        elif kind == "m":
            current = _new_sdp_media(value, session_connection)
            if current is None:
                malformed = True
            else:
                media_rows.append(current)
        elif kind == "a" and not _apply_sdp_attribute(value, current, session_attributes):
            malformed = True
    return {
        "line_count": len(lines), "session_connection_address": session_connection, "media": media_rows[:64],
        "media_count": len(media_rows), "session_attributes": session_attributes[:128],
        "malformed": malformed, "body_retained": False,
    }
def decode_sip_message(data: bytes) -> dict[str, Any]:
    raw = bytes(data)
    header_end = raw.find(b"\r\n\r\n", 0, _MAX_SIP_HEADER_BYTES)
    delimiter = 4
    if header_end < 0:
        header_end = raw.find(b"\n\n", 0, _MAX_SIP_HEADER_BYTES)
        delimiter = 2
    if header_end < 0:
        raise ValueError("SIP header terminator not found within bounded header window")
    header_text = raw[:header_end].decode("utf-8", errors="replace")
    lines = header_text.replace("\r\n", "\n").split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("empty SIP start line")
    start = lines[0].strip()
    headers = _sip_headers(lines[1:])
    response = start.upper().startswith("SIP/2.0 ")
    fields: dict[str, Any] = {
        "response": response,
        "start_line_bytes": len(lines[0].encode("utf-8", "replace")),
        "header_count": sum(len(values) for values in headers.values()),
        "headers_truncated": sum(len(values) for values in headers.values()) >= _MAX_SIP_HEADERS,
    }
    if response:
        parts = start.split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            raise ValueError("invalid SIP status line")
        fields.update({"version": parts[0], "status_code": int(parts[1]), "reason": parts[2][:128] if len(parts) > 2 else ""})
    else:
        parts = start.split(" ", 2)
        if len(parts) != 3 or parts[2].upper() != "SIP/2.0":
            raise ValueError("invalid SIP request line")
        fields.update({"method": parts[0], "version": parts[2], "request_uri": _uri_metadata(parts[1])})
    call_id = _single(headers, "call-id")
    cseq = _single(headers, "cseq")
    cseq_parts = cseq.split(None, 1)
    fields["call_id_sha256"] = _hash(b"arenyxa-sip-call-id/v1", call_id) if call_id else ""
    fields["call_id_retained"] = False
    fields["cseq_number"] = int(cseq_parts[0]) if cseq_parts and cseq_parts[0].isdigit() else None
    fields["cseq_method"] = cseq_parts[1] if len(cseq_parts) > 1 else ""
    fields["from"] = _uri_metadata(_single(headers, "from")) if _single(headers, "from") else {}
    fields["to"] = _uri_metadata(_single(headers, "to")) if _single(headers, "to") else {}
    contacts = headers.get("contact", [])
    fields["contacts"] = [_uri_metadata(value) for value in contacts[:32]]
    vias: list[dict[str, Any]] = []
    for value in headers.get("via", [])[:32]:
        branch_match = re.search(r"(?:^|;)\s*branch=([^;\s]+)", value, re.IGNORECASE)
        transport_match = re.match(r"SIP/2\.0/(?P<transport>[^\s]+)\s+(?P<sentby>[^;\s]+)", value, re.IGNORECASE)
        row: dict[str, Any] = {}
        if transport_match:
            row["transport"] = transport_match.group("transport").upper()
            row["sent_by"] = transport_match.group("sentby")[:256]
        if branch_match:
            branch = branch_match.group(1)
            row["branch_sha256"] = _hash(b"arenyxa-sip-via-branch/v1", branch)
            row["branch_retained"] = False
        vias.append(row)
    fields["vias"] = vias
    try:
        fields["max_forwards"] = int(_single(headers, "max-forwards")) if _single(headers, "max-forwards") else None
    except ValueError:
        fields["max_forwards"] = None
        fields["max_forwards_malformed"] = True
    content_type = _single(headers, "content-type").split(";", 1)[0].strip().casefold()
    body = raw[header_end + delimiter:]
    declared = _single(headers, "content-length")
    if declared:
        try:
            body = body[:max(0, int(declared))]
        except ValueError:
            fields["content_length_malformed"] = True
    fields.update({
        "content_type": content_type,
        "body_bytes": len(body),
        "body_sha256": _hash(b"arenyxa-sip-body/v1", body) if body else "",
        "body_retained": False,
    })
    if content_type == "application/sdp" and body:
        fields["sdp"] = decode_sdp(body)
    return fields


def _signed24(raw: bytes) -> int:
    value = int.from_bytes(raw, "big")
    return value - (1 << 24) if value & 0x800000 else value


def _rtcp_report_blocks(data: bytes, offset: int, count: int) -> tuple[list[dict[str, Any]], int, bool]:
    rows: list[dict[str, Any]] = []
    cursor = offset
    malformed = False
    for _ in range(min(count, _MAX_RTCP_REPORTS)):
        if cursor + 24 > len(data):
            malformed = True
            break
        ssrc = struct.unpack_from("!I", data, cursor)[0]
        fraction = data[cursor + 4]
        cumulative = _signed24(data[cursor + 5:cursor + 8])
        ext_seq, jitter, lsr, dlsr = struct.unpack_from("!IIII", data, cursor + 8)
        rows.append({
            "source_ssrc": ssrc,
            "fraction_lost": fraction,
            "fraction_lost_ratio": round(fraction / 256.0, 6),
            "cumulative_packets_lost": cumulative,
            "extended_highest_sequence": ext_seq,
            "interarrival_jitter": jitter,
            "last_sender_report": lsr,
            "delay_since_last_sender_report": dlsr,
        })
        cursor += 24
    return rows, cursor, malformed


def decode_rtp_or_rtcp(data: bytes) -> tuple[str, dict[str, Any]]:
    raw = bytes(data)
    if len(raw) < 4 or raw[0] >> 6 != 2:
        raise ValueError("invalid RTP/RTCP version")
    packet_type = raw[1]
    if 192 <= packet_type <= 223:
        packets: list[dict[str, Any]] = []
        cursor = 0
        malformed = False
        while cursor + 4 <= len(raw) and len(packets) < _MAX_RTCP_PACKETS:
            first, pt, length_words = struct.unpack_from("!BBH", raw, cursor)
            if first >> 6 != 2:
                malformed = True
                break
            packet_bytes = (length_words + 1) * 4
            if packet_bytes < 4 or cursor + packet_bytes > len(raw):
                malformed = True
                break
            count = first & 0x1F
            body = raw[cursor:cursor + packet_bytes]
            row: dict[str, Any] = {"packet_type": pt, "report_count": count, "length_bytes": packet_bytes, "padding": bool(first & 0x20)}
            if pt == 200 and packet_bytes >= 28:
                ssrc, ntp_sec, ntp_frac, rtp_ts, sent_packets, sent_octets = struct.unpack_from("!IIIIII", body, 4)
                reports, _, report_malformed = _rtcp_report_blocks(body, 28, count)
                row.update({"name": "sender-report", "ssrc": ssrc, "ntp_seconds": ntp_sec, "ntp_fraction": ntp_frac, "rtp_timestamp": rtp_ts, "sender_packet_count": sent_packets, "sender_octet_count": sent_octets, "reports": reports, "reports_malformed": report_malformed})
            elif pt == 201 and packet_bytes >= 8:
                ssrc = struct.unpack_from("!I", body, 4)[0]
                reports, _, report_malformed = _rtcp_report_blocks(body, 8, count)
                row.update({"name": "receiver-report", "ssrc": ssrc, "reports": reports, "reports_malformed": report_malformed})
            elif pt == 202 and packet_bytes >= 4:
                row["name"] = "source-description"
                row["chunk_count"] = count
                row["sdes_payload_sha256"] = _hash(b"arenyxa-rtcp-sdes/v1", body[4:])
                row["sdes_payload_retained"] = False
            elif pt == 203:
                sources = [struct.unpack_from("!I", body, 4 + index * 4)[0] for index in range(min(count, (len(body) - 4) // 4))]
                row.update({"name": "bye", "sources": sources})
            else:
                row.update({"name": {204: "app"}.get(pt, f"rtcp-{pt}"), "body_sha256": _hash(b"arenyxa-rtcp-body/v1", body[4:]), "body_retained": False})
            packets.append(row)
            cursor += packet_bytes
        if cursor != len(raw):
            malformed = True
        return "rtcp", {"compound_packets": packets, "packet_count": len(packets), "malformed": malformed, "payload_retained": False}

    if len(raw) < 12:
        raise ValueError("truncated RTP header")
    first, second, sequence, timestamp, ssrc = struct.unpack_from("!BBHII", raw, 0)
    csrc_count = first & 0x0F
    cursor = 12
    if cursor + csrc_count * 4 > len(raw):
        raise ValueError("truncated RTP CSRC vector")
    csrcs = list(struct.unpack_from(f"!{csrc_count}I", raw, cursor)) if csrc_count else []
    cursor += csrc_count * 4
    extension: dict[str, Any] | None = None
    if first & 0x10:
        if cursor + 4 > len(raw):
            raise ValueError("truncated RTP header extension")
        profile, words = struct.unpack_from("!HH", raw, cursor)
        extension_bytes = words * 4
        if cursor + 4 + extension_bytes > len(raw):
            raise ValueError("truncated RTP extension payload")
        value = raw[cursor + 4:cursor + 4 + extension_bytes]
        extension = {
            "profile": f"0x{profile:04x}",
            "bytes": len(value),
            "sha256": _hash(b"arenyxa-rtp-extension/v1", value),
            "retained": False,
        }
        cursor += 4 + extension_bytes
    padding_bytes = raw[-1] if first & 0x20 and raw else 0
    if padding_bytes > len(raw) - cursor:
        raise ValueError("invalid RTP padding length")
    payload_end = len(raw) - padding_bytes if padding_bytes else len(raw)
    payload = raw[cursor:payload_end]
    return "rtp", {
        "marker": bool(second & 0x80),
        "payload_type": second & 0x7F,
        "sequence": sequence,
        "timestamp": timestamp,
        "ssrc": ssrc,
        "csrcs": csrcs,
        "csrc_count": csrc_count,
        "extension": extension,
        "padding": bool(first & 0x20),
        "padding_bytes": padding_bytes,
        "payload_bytes": len(payload),
        "payload_retained": False,
    }
