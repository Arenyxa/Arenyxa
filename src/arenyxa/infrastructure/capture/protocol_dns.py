from __future__ import annotations

import hashlib
import ipaddress
import struct
from typing import Any

_DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC",
    48: "DNSKEY", 52: "TLSA", 64: "SVCB", 65: "HTTPS", 257: "CAA",
}
_DNS_CLASSES = {1: "IN", 3: "CH", 4: "HS", 255: "ANY"}

_SVCB_KEYS = {
    0: "mandatory", 1: "alpn", 2: "no-default-alpn", 3: "port", 4: "ipv4hint",
    5: "ech", 6: "ipv6hint", 7: "dohpath", 8: "ohttp", 9: "tls-supported-groups",
    10: "docpath", 11: "pvd", 12: "oots",
}


class DNSMessageDecoder:
    MAX_QUESTIONS = 64
    MAX_RECORDS = 256
    MAX_NAME_DEPTH = 128
    MAX_NAME_CHARS = 255
    MAX_TXT_PARTS = 32

    def __init__(self, data: bytes) -> None:
        self.data = data

    def name(self, cursor: int) -> tuple[str, int]:
        labels: list[str] = []
        position = cursor
        resume = cursor
        jumped = False
        seen: set[int] = set()
        for _depth in range(self.MAX_NAME_DEPTH):
            if position >= len(self.data):
                raise ValueError("truncated DNS name")
            length = self.data[position]
            if length == 0:
                if not jumped:
                    resume = position + 1
                return ".".join(labels)[:self.MAX_NAME_CHARS], resume
            if length & 0xC0 == 0xC0:
                if position + 1 >= len(self.data):
                    raise ValueError("truncated DNS compression pointer")
                pointer = ((length & 0x3F) << 8) | self.data[position + 1]
                if pointer >= len(self.data) or pointer in seen:
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
            if length > 63 or position + length > len(self.data):
                raise ValueError("invalid DNS label")
            raw = self.data[position:position + length]
            try:
                label = raw.decode("ascii")
            except UnicodeDecodeError:
                label = raw.decode("utf-8", errors="replace")
            labels.append(label)
            if sum(len(item) + 1 for item in labels) > self.MAX_NAME_CHARS:
                raise ValueError("DNS name exceeds budget")
            position += length
            if not jumped:
                resume = position
        raise ValueError("DNS name depth budget exceeded")

    def decode(self) -> dict[str, Any]:
        if len(self.data) < 12:
            raise ValueError("truncated DNS header")
        transaction_id, flags, questions, answers, authorities, additionals = struct.unpack_from("!HHHHHH", self.data, 0)
        if questions > self.MAX_QUESTIONS:
            raise ValueError("DNS question count exceeds safety bound")
        if answers + authorities + additionals > self.MAX_RECORDS:
            raise ValueError("DNS resource record count exceeds safety bound")
        fields: dict[str, Any] = {
            "transaction_id": transaction_id,
            "response": bool(flags & 0x8000),
            "opcode": (flags >> 11) & 0x0F,
            "authoritative": bool(flags & 0x0400),
            "truncated": bool(flags & 0x0200),
            "recursion_desired": bool(flags & 0x0100),
            "recursion_available": bool(flags & 0x0080),
            "authenticated_data": bool(flags & 0x0020),
            "checking_disabled": bool(flags & 0x0010),
            "rcode": flags & 0x0F,
            "questions": questions,
            "answers": answers,
            "authorities": authorities,
            "additionals": additionals,
        }
        cursor = 12
        question_rows: list[dict[str, Any]] = []
        for _index in range(questions):
            question_name, cursor = self.name(cursor)
            if cursor + 4 > len(self.data):
                raise ValueError("truncated DNS question")
            qtype, qclass = struct.unpack_from("!HH", self.data, cursor)
            cursor += 4
            question_rows.append({
                "name": question_name,
                "type": qtype,
                "type_name": _DNS_TYPES.get(qtype, str(qtype)),
                "class": qclass,
                "class_name": _DNS_CLASSES.get(qclass, str(qclass)),
            })
        fields["question_records"] = question_rows
        total_budget = answers + authorities + additionals
        answer_rows, cursor, used = self._records(cursor, min(answers, total_budget))
        total_budget -= used
        authority_rows, cursor, used = self._records(cursor, min(authorities, total_budget))
        total_budget -= used
        additional_rows, _cursor, _used = self._records(cursor, min(additionals, total_budget))
        if answer_rows:
            fields["answer_records"] = answer_rows
        if authority_rows:
            fields["authority_records"] = authority_rows
        if additional_rows:
            fields["additional_records"] = additional_rows
        return fields

    def _records(self, cursor: int, count: int) -> tuple[list[dict[str, Any]], int, int]:
        rows: list[dict[str, Any]] = []
        for _index in range(max(0, int(count))):
            owner, cursor = self.name(cursor)
            if cursor + 10 > len(self.data):
                raise ValueError("truncated DNS resource record")
            rr_type, rr_class, ttl, rdlength = struct.unpack_from("!HHIH", self.data, cursor)
            cursor += 10
            rstart = cursor
            rend = cursor + rdlength
            if rend > len(self.data):
                raise ValueError("truncated DNS rdata")
            row: dict[str, Any] = {
                "name": owner,
                "type": rr_type,
                "type_name": _DNS_TYPES.get(rr_type, str(rr_type)),
                "class": rr_class,
                "class_name": _DNS_CLASSES.get(rr_class, str(rr_class)),
                "ttl": ttl,
                "rdlength": rdlength,
            }
            row.update(self._rdata(rr_type, rr_class, ttl, rstart, rend))
            rows.append(row)
            cursor = rend
        return rows, cursor, len(rows)

    def _rdata(self, rr_type: int, rr_class: int, ttl: int, start: int, end: int) -> dict[str, Any]:
        raw = self.data[start:end]
        if rr_type == 1 and len(raw) == 4:
            return {"address": str(ipaddress.IPv4Address(raw))}
        if rr_type == 28 and len(raw) == 16:
            return {"address": str(ipaddress.IPv6Address(raw))}
        if rr_type in {2, 5, 12}:
            target, _unused = self._rdata_name(start, end)
            return {"target": target}
        if rr_type == 15 and len(raw) >= 3:
            preference = int.from_bytes(raw[:2], "big")
            exchange, _unused = self._rdata_name(start + 2, end)
            return {"preference": preference, "exchange": exchange}
        if rr_type == 33 and len(raw) >= 7:
            priority, weight, port = struct.unpack_from("!HHH", raw, 0)
            target, _unused = self._rdata_name(start + 6, end)
            return {"priority": priority, "weight": weight, "port": port, "target": target}
        if rr_type == 6 and len(raw) >= 22:
            mname, pos = self._rdata_name(start, end)
            rname, pos = self._rdata_name(pos, end)
            if pos + 20 <= end:
                serial, refresh, retry, expire, minimum = struct.unpack_from("!IIIII", self.data, pos)
                return {"mname": mname, "rname": rname, "serial": serial, "refresh": refresh, "retry": retry, "expire": expire, "minimum": minimum}
        if rr_type == 16:
            values: list[str] = []
            pos = 0
            while pos < len(raw) and len(values) < self.MAX_TXT_PARTS:
                size = raw[pos]
                pos += 1
                if pos + size > len(raw):
                    break
                values.append(raw[pos:pos + size].decode("utf-8", errors="replace")[:1024])
                pos += size
            return {"text": values}
        if rr_type == 41:  # EDNS OPT: class is UDP payload size, TTL contains ext rcode/version/flags
            return {
                "udp_payload_size": rr_class,
                "extended_rcode": (ttl >> 24) & 0xFF,
                "edns_version": (ttl >> 16) & 0xFF,
                "dnssec_ok": bool(ttl & 0x8000),
                "option_bytes": len(raw),
            }
        if rr_type == 43 and len(raw) >= 4:
            return {"key_tag": int.from_bytes(raw[:2], "big"), "algorithm": raw[2], "digest_type": raw[3], "digest": raw[4:].hex()[:2048]}
        if rr_type == 48 and len(raw) >= 4:
            return {"flags": int.from_bytes(raw[:2], "big"), "protocol": raw[2], "algorithm": raw[3], "public_key_bytes": len(raw) - 4}
        if rr_type == 52 and len(raw) >= 3:
            return {"certificate_usage": raw[0], "selector": raw[1], "matching_type": raw[2], "association_data": raw[3:].hex()[:2048]}
        if rr_type in {64, 65} and len(raw) >= 3:
            priority = int.from_bytes(raw[:2], "big")
            target, pos = self._rdata_name(start + 2, end)
            params = self._svcb_params(pos, end)
            return {
                "priority": priority, "target": target,
                "service_parameter_bytes": max(0, end - pos), "service_parameters": params,
            }
        if rr_type == 257 and len(raw) >= 2:
            tag_len = raw[1]
            if 2 + tag_len <= len(raw):
                return {"flags": raw[0], "tag": raw[2:2 + tag_len].decode("ascii", errors="replace"), "value": raw[2 + tag_len:].decode("utf-8", errors="replace")[:2048]}
        return {"rdata_hex": raw.hex()[:2048]}

    def _rdata_name(self, cursor: int, end: int) -> tuple[str, int]:
        """Decode a possibly-compressed name without consuming the next record.

        Compression pointers may reference any earlier message offset, but the bytes
        that encode the name at the current location must remain inside this RDATA.
        """
        name, resume = self.name(cursor)
        if resume > end:
            raise ValueError("DNS name exceeds resource record boundary")
        return name, resume

    def _svcb_params(self, cursor: int, end: int) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        while cursor + 4 <= end and len(rows) < 64:
            key, length = struct.unpack_from("!HH", self.data, cursor)
            cursor += 4
            if cursor + length > end:
                raise ValueError("truncated SVCB service parameter")
            value = self.data[cursor:cursor + length]
            cursor += length
            row: dict[str, Any] = {"key": key, "name": _SVCB_KEYS.get(key, f"key{key}"), "length": length}
            if key == 0 and length % 2 == 0:
                row["mandatory_keys"] = [int.from_bytes(value[pos:pos + 2], "big") for pos in range(0, length, 2)][:64]
            elif key == 1:
                alpns: list[str] = []
                pos = 0
                while pos < len(value) and len(alpns) < 32:
                    size = value[pos]
                    pos += 1
                    if size == 0 or pos + size > len(value):
                        row["malformed"] = True
                        break
                    alpns.append(value[pos:pos + size].decode("ascii", errors="replace")[:255])
                    pos += size
                row["alpn"] = alpns
            elif key == 2:
                row["enabled"] = length == 0
                if length:
                    row["malformed"] = True
            elif key == 3 and length == 2:
                row["port"] = int.from_bytes(value, "big")
            elif key == 4 and length and length % 4 == 0:
                row["ipv4_hints"] = [str(ipaddress.IPv4Address(value[pos:pos + 4])) for pos in range(0, length, 4)][:64]
            elif key == 5:
                row["ech_config_bytes"] = length
                row["ech_config_sha256"] = hashlib.sha256(value).hexdigest() if value else ""
            elif key == 6 and length and length % 16 == 0:
                row["ipv6_hints"] = [str(ipaddress.IPv6Address(value[pos:pos + 16])) for pos in range(0, length, 16)][:64]
            elif key in {7, 10, 11}:
                row["text"] = value.decode("utf-8", errors="replace")[:2048]
            elif key == 8:
                row["enabled"] = length == 0
            elif key == 9 and length % 2 == 0:
                row["groups"] = [f"0x{int.from_bytes(value[pos:pos + 2], 'big'):04x}" for pos in range(0, length, 2)][:64]
            elif key == 12:
                row["value_hex"] = value.hex()[:512]
            else:
                row["value_hex"] = value.hex()[:2048]
            rows.append(row)
        if cursor != end:
            raise ValueError("invalid SVCB service parameter tail")
        return rows


def decode_dns_message(data: bytes) -> dict[str, Any]:
    return DNSMessageDecoder(data).decode()
