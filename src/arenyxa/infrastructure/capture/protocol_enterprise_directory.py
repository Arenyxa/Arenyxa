from __future__ import annotations

import hashlib
import struct
from typing import Any

_MAX_BER_LENGTH = 16 * 1024 * 1024
_MAX_SMB_DIALECTS = 64

_SMB2_COMMANDS = {
    0x0000: "negotiate",
    0x0001: "session-setup",
    0x0002: "logoff",
    0x0003: "tree-connect",
    0x0004: "tree-disconnect",
    0x0005: "create",
    0x0006: "close",
    0x0007: "flush",
    0x0008: "read",
    0x0009: "write",
    0x000A: "lock",
    0x000B: "ioctl",
    0x000C: "cancel",
    0x000D: "echo",
    0x000E: "query-directory",
    0x000F: "change-notify",
    0x0010: "query-info",
    0x0011: "set-info",
    0x0012: "oplock-break",
}

_LDAP_OPS = {
    0x60: "bind-request",
    0x61: "bind-response",
    0x42: "unbind-request",
    0x63: "search-request",
    0x64: "search-entry",
    0x65: "search-done",
    0x66: "modify-request",
    0x67: "modify-response",
    0x68: "add-request",
    0x69: "add-response",
    0x4A: "delete-request",
    0x6B: "delete-response",
    0x6C: "modify-dn-request",
    0x6D: "modify-dn-response",
    0x6E: "compare-request",
    0x6F: "compare-response",
    0x50: "abandon-request",
    0x77: "extended-request",
    0x78: "extended-response",
    0x79: "intermediate-response",
}

_KERBEROS_MESSAGES = {
    10: "as-req",
    11: "as-rep",
    12: "tgs-req",
    13: "tgs-rep",
    14: "ap-req",
    15: "ap-rep",
    20: "safe",
    21: "priv",
    22: "cred",
    30: "error",
}

_KERBEROS_ERRORS = {
    6: "principal-unknown",
    7: "service-principal-unknown",
    12: "policy",
    18: "client-revoked",
    23: "key-expired",
    24: "preauth-failed",
    25: "preauth-required",
    31: "integrity-check-failed",
    32: "ticket-expired",
    37: "clock-skew",
    52: "response-too-big",
    60: "generic",
    68: "wrong-realm",
}


def _hash(data: bytes) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def _secbuf(data: bytes, offset: int) -> tuple[int, int]:
    if offset < 0 or offset + 8 > len(data):
        raise ValueError("truncated NTLM security buffer")
    length, maximum, location = struct.unpack_from("<HHI", data, offset)
    if maximum < length or location > len(data) or length > len(data) - location:
        raise ValueError("invalid NTLM security buffer")
    return location, length


def _hashed_field(data: bytes, offset: int, label: str) -> dict[str, Any]:
    location, length = _secbuf(data, offset)
    raw = data[location : location + length]
    return {f"{label}_bytes": length, f"{label}_sha256": _hash(raw) if raw else ""}


def decode_ntlmssp(data: bytes) -> dict[str, Any] | None:
    marker = data.find(b"NTLMSSP\x00")
    if marker < 0 or marker + 12 > len(data):
        return None
    payload = data[marker:]
    message_type = struct.unpack_from("<I", payload, 8)[0]
    result: dict[str, Any] = {
        "message_type": message_type,
        "message_name": {1: "negotiate", 2: "challenge", 3: "authenticate"}.get(message_type, "unknown"),
        "offset": marker,
        "credentials_retained": False,
    }
    if message_type == 1 and len(payload) >= 16:
        result["negotiate_flags"] = struct.unpack_from("<I", payload, 12)[0]
        if len(payload) >= 32:
            result.update(_hashed_field(payload, 16, "domain"))
            result.update(_hashed_field(payload, 24, "workstation"))
    elif message_type == 2 and len(payload) >= 32:
        result.update(_hashed_field(payload, 12, "target_name"))
        result["negotiate_flags"] = struct.unpack_from("<I", payload, 20)[0]
        result["server_challenge_sha256"] = _hash(payload[24:32])
    elif message_type == 3 and len(payload) >= 64:
        result.update(_hashed_field(payload, 28, "domain"))
        result.update(_hashed_field(payload, 36, "user"))
        result.update(_hashed_field(payload, 44, "workstation"))
        lm_location, lm_length = _secbuf(payload, 12)
        nt_location, nt_length = _secbuf(payload, 20)
        result.update(
            {
                "lm_response_bytes": lm_length,
                "nt_response_bytes": nt_length,
                "lm_response_sha256": _hash(payload[lm_location : lm_location + lm_length]) if lm_length else "",
                "nt_response_sha256": _hash(payload[nt_location : nt_location + nt_length]) if nt_length else "",
                "negotiate_flags": struct.unpack_from("<I", payload, 60)[0],
            }
        )
    return result


def _utf16_hash(data: bytes, offset: int, length: int, label: str) -> dict[str, Any]:
    if offset < 0 or length < 0 or offset > len(data) or length > len(data) - offset:
        return {f"{label}_malformed": True}
    raw = data[offset : offset + length]
    return {f"{label}_bytes": len(raw), f"{label}_sha256": _hash(raw) if raw else ""}


def _smb2_negotiate(data: bytes, body: int, response: bool, remaining: int, fields: dict[str, Any]) -> None:
    if not response and remaining >= 36:
        dialect_count = struct.unpack_from("<H", data, body + 2)[0]
        fields.update({"dialect_count": dialect_count, "security_mode": struct.unpack_from("<H", data, body + 4)[0],
                       "capabilities": struct.unpack_from("<I", data, body + 8)[0], "client_guid_sha256": _hash(data[body + 12:body + 28])})
        dialects, pos = [], body + 36
        for _ in range(min(dialect_count, _MAX_SMB_DIALECTS)):
            if pos + 2 > len(data):
                fields["dialects_truncated"] = True
                break
            dialects.append(f"0x{struct.unpack_from('<H', data, pos)[0]:04x}")
            pos += 2
        fields["dialects"] = dialects
    elif response and remaining >= 64:
        fields.update({
            "security_mode": struct.unpack_from("<H", data, body + 2)[0], "selected_dialect": f"0x{struct.unpack_from('<H', data, body + 4)[0]:04x}",
            "negotiate_context_count": struct.unpack_from("<H", data, body + 6)[0], "server_guid_sha256": _hash(data[body + 8:body + 24]),
            "capabilities": struct.unpack_from("<I", data, body + 24)[0], "max_transact_size": struct.unpack_from("<I", data, body + 28)[0],
            "max_read_size": struct.unpack_from("<I", data, body + 32)[0], "max_write_size": struct.unpack_from("<I", data, body + 36)[0],
        })


def _smb2_security_buffer(data: bytes, fields: dict[str, Any], offset: int, length: int) -> None:
    fields["security_buffer_bytes"] = length
    if offset <= len(data) and length <= len(data) - offset:
        security = data[offset:offset + length]
        fields["security_buffer_sha256"] = _hash(security) if security else ""
        ntlm = decode_ntlmssp(security)
        if ntlm is not None:
            fields["ntlmssp"] = ntlm
    else:
        fields["security_buffer_malformed"] = True


def _smb2_session_setup(data: bytes, body: int, response: bool, remaining: int, fields: dict[str, Any]) -> None:
    if not response and remaining >= 24:
        security_offset, security_length = struct.unpack_from("<HH", data, body + 12)
        fields.update({"flags": data[body + 2], "security_mode": data[body + 3], "capabilities": struct.unpack_from("<I", data, body + 4)[0],
                       "channel": struct.unpack_from("<I", data, body + 8)[0], "previous_session_id": struct.unpack_from("<Q", data, body + 16)[0]})
        _smb2_security_buffer(data, fields, security_offset, security_length)
    elif response and remaining >= 8:
        security_offset, security_length = struct.unpack_from("<HH", data, body + 4)
        fields["session_flags"] = struct.unpack_from("<H", data, body + 2)[0]
        _smb2_security_buffer(data, fields, security_offset, security_length)


def _smb2_file_operation(data: bytes, body: int, command: int, response: bool, remaining: int, fields: dict[str, Any]) -> None:
    if command == 0x0003:
        if not response and remaining >= 8:
            path_offset, path_length = struct.unpack_from("<HH", data, body + 4)
            fields.update(_utf16_hash(data, path_offset, path_length, "share_path"))
        elif response and remaining >= 16:
            fields.update({"share_type": data[body + 2], "share_flags": struct.unpack_from("<I", data, body + 4)[0],
                           "share_capabilities": struct.unpack_from("<I", data, body + 8)[0], "maximal_access": struct.unpack_from("<I", data, body + 12)[0]})
    elif command == 0x0005 and not response and remaining >= 56:
        name_offset, name_length = struct.unpack_from("<HH", data, body + 44)
        fields.update({"requested_oplock_level": data[body + 3], "impersonation_level": struct.unpack_from("<I", data, body + 4)[0],
                       "desired_access": struct.unpack_from("<I", data, body + 24)[0], "file_attributes": struct.unpack_from("<I", data, body + 28)[0],
                       "share_access": struct.unpack_from("<I", data, body + 32)[0], "create_disposition": struct.unpack_from("<I", data, body + 36)[0],
                       "create_options": struct.unpack_from("<I", data, body + 40)[0]})
        fields.update(_utf16_hash(data, name_offset, name_length, "file_name"))
    elif command in {0x0008, 0x0009} and not response and remaining >= 48:
        fields.update({"io_length": struct.unpack_from("<I", data, body + 4)[0], "file_offset": struct.unpack_from("<Q", data, body + 8)[0],
                       "file_id_sha256": _hash(data[body + 16:body + 32])})
    elif command == 0x000B and not response and remaining >= 56:
        fields.update({"control_code": f"0x{struct.unpack_from('<I', data, body + 4)[0]:08x}", "file_id_sha256": _hash(data[body + 8:body + 24])})


def _decode_smb2_body(data: bytes, command: int, response: bool, cursor: int) -> dict[str, Any]:
    body = cursor + 64
    if body + 2 > len(data):
        return {"body_truncated": True}
    fields: dict[str, Any] = {"structure_size": struct.unpack_from("<H", data, body)[0]}
    remaining = len(data) - body
    if command == 0x0000:
        _smb2_negotiate(data, body, response, remaining, fields)
    elif command == 0x0001:
        _smb2_session_setup(data, body, response, remaining, fields)
    else:
        _smb2_file_operation(data, body, command, response, remaining, fields)
    return fields

def decode_smb_message(data: bytes) -> dict[str, Any]:
    cursor = 4 if len(data) >= 8 and data[0] == 0 and data[4:8] in {b"\xfeSMB", b"\xffSMB"} else 0
    if cursor + 5 > len(data):
        raise ValueError("truncated SMB message")
    signature = data[cursor : cursor + 4]
    if signature == b"\xffSMB":
        return {"dialect": "smb1", "command": data[cursor + 4], "header_bytes": min(32, len(data) - cursor)}
    if signature != b"\xfeSMB" or cursor + 64 > len(data):
        raise ValueError("invalid SMB signature or SMB2 header")
    if struct.unpack_from("<H", data, cursor + 4)[0] != 64:
        raise ValueError("invalid SMB2 structure size")
    command = struct.unpack_from("<H", data, cursor + 12)[0]
    flags = struct.unpack_from("<I", data, cursor + 16)[0]
    response = bool(flags & 0x00000001)
    async_command = bool(flags & 0x00000002)
    fields: dict[str, Any] = {
        "dialect": "smb2+",
        "command": command,
        "command_name": _SMB2_COMMANDS.get(command, "unknown"),
        "response": response,
        "credit_charge": struct.unpack_from("<H", data, cursor + 6)[0],
        "credits": struct.unpack_from("<H", data, cursor + 14)[0],
        "flags": flags,
        "async_command": async_command,
        "related_operations": bool(flags & 0x00000004),
        "signed": bool(flags & 0x00000008),
        "dfs_operation": bool(flags & 0x10000000),
        "replay_operation": bool(flags & 0x20000000),
        "next_command": struct.unpack_from("<I", data, cursor + 20)[0],
        "message_id": struct.unpack_from("<Q", data, cursor + 24)[0],
        "session_id": struct.unpack_from("<Q", data, cursor + 40)[0],
    }
    if response:
        fields["status"] = struct.unpack_from("<I", data, cursor + 8)[0]
    else:
        fields["channel_sequence"] = struct.unpack_from("<H", data, cursor + 8)[0]
    if async_command:
        fields["async_id"] = struct.unpack_from("<Q", data, cursor + 32)[0]
    else:
        fields["process_id"] = struct.unpack_from("<I", data, cursor + 32)[0]
        fields["tree_id"] = struct.unpack_from("<I", data, cursor + 36)[0]
    fields["body"] = _decode_smb2_body(data, command, response, cursor)
    return fields


def _ber_length(data: bytes, cursor: int) -> tuple[int, int]:
    if cursor >= len(data):
        raise ValueError("truncated BER length")
    first = data[cursor]
    cursor += 1
    if first < 0x80:
        return first, cursor
    count = first & 0x7F
    if count == 0 or count > 4 or cursor + count > len(data):
        raise ValueError("invalid BER length")
    length = int.from_bytes(data[cursor : cursor + count], "big")
    if length > _MAX_BER_LENGTH:
        raise ValueError("BER value exceeds decoder budget")
    return length, cursor + count


def _ber_tlv(data: bytes, cursor: int) -> tuple[int, int, int, int]:
    if cursor >= len(data):
        raise ValueError("truncated BER tag")
    tag = data[cursor]
    length, start = _ber_length(data, cursor + 1)
    end = start + length
    if end > len(data):
        raise ValueError("truncated BER value")
    return tag, length, start, end


def _ber_int(data: bytes, start: int, end: int) -> int:
    raw = data[start:end]
    if not raw or len(raw) > 8:
        raise ValueError("invalid BER integer")
    return int.from_bytes(raw, "big", signed=bool(raw[0] & 0x80))


def _ldap_result(data: bytes, start: int, end: int) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    cursor = start
    try:
        tag, _length, value_start, value_end = _ber_tlv(data, cursor)
        if tag != 0x0A:
            return fields
        fields["result_code"] = _ber_int(data, value_start, value_end)
        cursor = value_end
        for label in ("matched_dn", "diagnostic"):
            tag, _length, value_start, value_end = _ber_tlv(data, cursor)
            if tag != 0x04:
                return fields
            raw = data[value_start:value_end]
            fields[f"{label}_bytes"] = len(raw)
            fields[f"{label}_sha256"] = _hash(raw) if raw else ""
            cursor = value_end
    except ValueError:
        fields["result_body_malformed"] = True
    return fields


def decode_ldap_message(data: bytes) -> dict[str, Any]:
    tag, _length, start, end = _ber_tlv(data, 0)
    if tag != 0x30:
        raise ValueError("invalid LDAP message")
    message_tag, _message_length, message_start, message_end = _ber_tlv(data, start)
    if message_tag != 0x02:
        raise ValueError("invalid LDAP message id")
    message_id = _ber_int(data, message_start, message_end)
    if message_id < 0:
        raise ValueError("negative LDAP message id")
    if message_end >= end:
        raise ValueError("LDAP protocol operation is missing")
    op_tag, _op_length, op_start, op_end = _ber_tlv(data, message_end)
    result: dict[str, Any] = {
        "message_id": message_id,
        "operation": _LDAP_OPS.get(op_tag, f"0x{op_tag:02x}"),
        "operation_tag": op_tag,
        "message_bytes": end,
        "sensitive_strings_retained": False,
    }
    if op_tag == 0x60:  # BindRequest
        try:
            version_tag, _vlen, vstart, vend = _ber_tlv(data, op_start)
            if version_tag == 0x02:
                result["ldap_version"] = _ber_int(data, vstart, vend)
            name_tag, _nlen, nstart, nend = _ber_tlv(data, vend)
            if name_tag == 0x04:
                raw = data[nstart:nend]
                result.update({"bind_name_bytes": len(raw), "bind_name_sha256": _hash(raw) if raw else ""})
                if nend < op_end:
                    result["authentication_tag"] = data[nend]
        except ValueError:
            result["bind_body_malformed"] = True
    elif op_tag == 0x63:  # SearchRequest
        try:
            base_tag, _blen, bstart, bend = _ber_tlv(data, op_start)
            if base_tag == 0x04:
                base = data[bstart:bend]
                result.update({"base_dn_bytes": len(base), "base_dn_sha256": _hash(base) if base else ""})
            cursor = bend
            scalar_names = ("scope", "deref_aliases", "size_limit", "time_limit")
            for name in scalar_names:
                scalar_tag, _slen, sstart, send = _ber_tlv(data, cursor)
                if scalar_tag not in {0x02, 0x0A}:
                    raise ValueError("invalid LDAP search scalar")
                result[name] = _ber_int(data, sstart, send)
                cursor = send
            bool_tag, _bool_len, bool_start, bool_end = _ber_tlv(data, cursor)
            if bool_tag == 0x01 and bool_end > bool_start:
                result["types_only"] = data[bool_start] != 0
                cursor = bool_end
            if cursor < op_end:
                result["filter_tag"] = data[cursor]
        except ValueError:
            result["search_body_malformed"] = True
    elif op_tag in {0x61, 0x65, 0x67, 0x69, 0x6B, 0x6D, 0x6F, 0x78}:
        result.update(_ldap_result(data, op_start, op_end))
    elif op_tag in {0x66, 0x68, 0x6C, 0x6E}:
        try:
            dn_tag, _dlen, dstart, dend = _ber_tlv(data, op_start)
            if dn_tag == 0x04:
                dn = data[dstart:dend]
                result.update({"target_dn_bytes": len(dn), "target_dn_sha256": _hash(dn) if dn else ""})
        except ValueError:
            result["request_body_malformed"] = True
    return result


def _context_integer(data: bytes, start: int, end: int, wanted_tag: int) -> int | None:
    cursor = start
    visits = 0
    while cursor < end and visits < 128:
        visits += 1
        try:
            tag, _length, value_start, value_end = _ber_tlv(data, cursor)
        except ValueError:
            return None
        if tag == 0xA0 + wanted_tag:
            try:
                inner_tag, _inner_len, inner_start, inner_end = _ber_tlv(data, value_start)
                if inner_tag in {0x02, 0x0A}:
                    return _ber_int(data, inner_start, inner_end)
            except ValueError:
                return None
        cursor = value_end
    return None


def decode_kerberos_message(data: bytes, *, tcp: bool) -> dict[str, Any]:
    cursor = 0
    declared = None
    if tcp:
        if len(data) < 5:
            raise ValueError("truncated Kerberos TCP message")
        declared = struct.unpack_from("!I", data, 0)[0]
        if declared <= 0 or declared > len(data) - 4:
            raise ValueError("invalid Kerberos TCP length")
        cursor = 4
    tag, _length, start, end = _ber_tlv(data, cursor)
    if tag & 0x60 != 0x60:
        raise ValueError("invalid Kerberos application tag")
    message_type = tag & 0x1F
    result: dict[str, Any] = {
        "message_type": message_type,
        "message_name": _KERBEROS_MESSAGES.get(message_type, "unknown"),
        "transport": "tcp" if tcp else "udp",
        "message_bytes": end - cursor,
        "encrypted_material_retained": False,
    }
    if declared is not None:
        result["tcp_declared_bytes"] = declared
    pvno = _context_integer(data, start, end, 0)
    explicit_type = _context_integer(data, start, end, 1)
    if pvno is not None:
        result["protocol_version"] = pvno
    if explicit_type is not None:
        result["declared_message_type"] = explicit_type
        result["message_type_consistent"] = explicit_type == message_type
    if message_type == 30:
        error_code = _context_integer(data, start, end, 6)
        if error_code is not None:
            result["error_code"] = error_code
            result["error_name"] = _KERBEROS_ERRORS.get(error_code, "unknown")
    return result
