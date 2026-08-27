from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import hashlib
import struct
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from arenyxa.infrastructure.capture.protocol_intelligence import ProtocolDecodeResult

_QUIC_V1 = 0x00000001
_QUIC_V2 = 0x6B3343CF
_HTTP2_TYPES = {
    0x0: "DATA", 0x1: "HEADERS", 0x2: "PRIORITY", 0x3: "RST_STREAM",
    0x4: "SETTINGS", 0x5: "PUSH_PROMISE", 0x6: "PING", 0x7: "GOAWAY",
    0x8: "WINDOW_UPDATE", 0x9: "CONTINUATION",
}
_HTTP3_TYPES = {
    0x0: "DATA", 0x1: "HEADERS", 0x3: "CANCEL_PUSH", 0x4: "SETTINGS",
    0x5: "PUSH_PROMISE", 0x7: "GOAWAY", 0xD: "MAX_PUSH_ID",
}
_HTTP3_SETTINGS = {
    0x1: "QPACK_MAX_TABLE_CAPACITY",
    0x6: "MAX_FIELD_SECTION_SIZE",
    0x7: "QPACK_BLOCKED_STREAMS",
    0x8: "ENABLE_CONNECT_PROTOCOL",
    0x33: "H3_DATAGRAM",
}
_QUIC_TRANSPORT_PARAMETERS = {
    0x00: "original_destination_connection_id",
    0x01: "max_idle_timeout",
    0x02: "stateless_reset_token",
    0x03: "max_udp_payload_size",
    0x04: "initial_max_data",
    0x05: "initial_max_stream_data_bidi_local",
    0x06: "initial_max_stream_data_bidi_remote",
    0x07: "initial_max_stream_data_uni",
    0x08: "initial_max_streams_bidi",
    0x09: "initial_max_streams_uni",
    0x0A: "ack_delay_exponent",
    0x0B: "max_ack_delay",
    0x0C: "disable_active_migration",
    0x0D: "preferred_address",
    0x0E: "active_connection_id_limit",
    0x0F: "initial_source_connection_id",
    0x10: "retry_source_connection_id",
    0x20: "max_datagram_frame_size",
}


def _is_grease(value: int) -> bool:
    return 0 <= value <= 0xFFFF and (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def _md5_protocol_fingerprint(text: str) -> str:
    payload = text.encode("ascii", errors="strict")
    try:
        return hashlib.md5(payload, usedforsecurity=False).hexdigest()
    except TypeError:  # pragma: no cover - compatibility with older hashlib providers
        return hashlib.md5(payload).hexdigest()  # noqa: S324 - JA3 compatibility hash, not a security primitive


def _safe_hostname(raw: bytes) -> str:
    try:
        ascii_name = raw.decode("ascii")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")[:253]
    try:
        return ascii_name.encode("ascii").decode("idna")[:253]
    except UnicodeError:
        return ascii_name[:253]


def _ja4_tls_client(
    legacy_version: int,
    ciphers: list[int],
    extensions: dict[str, Any],
) -> tuple[str, str]:
    """Return a deterministic JA4 TLS client fingerprint with GREASE normalized."""
    clean_ciphers = [value for value in ciphers if not _is_grease(value)]
    clean_extensions = [value for value in extensions["extensions"] if not _is_grease(value)]
    versions = [value for value in extensions["supported_versions"] if not _is_grease(value)]
    selected_version = max(versions, default=legacy_version)
    version_code = {
        0x0304: "13",
        0x0303: "12",
        0x0302: "11",
        0x0301: "10",
    }.get(selected_version, "00")
    sni_code = "d" if extensions.get("sni") else "i"
    alpn_values = [str(item).casefold() for item in extensions.get("alpn", ()) if str(item)]
    alpn = alpn_values[0] if alpn_values else ""
    alpn_code = (alpn[:1] + alpn[-1:]) if alpn else "00"
    prefix = (
        f"t{version_code}{sni_code}"
        f"{min(99, len(clean_ciphers)):02d}{min(99, len(clean_extensions)):02d}{alpn_code}"
    )
    cipher_raw = ",".join(f"{value:04x}" for value in sorted(clean_ciphers))
    extension_ids = [value for value in clean_extensions if value not in {0, 16}]
    signature_ids = [
        value for value in extensions.get("signature_algorithms", ()) if not _is_grease(value)
    ]
    extension_raw = (
        ",".join(f"{value:04x}" for value in sorted(extension_ids))
        + "_"
        + ",".join(f"{value:04x}" for value in sorted(signature_ids))
    )
    ja4 = (
        f"{prefix}_{hashlib.sha256(cipher_raw.encode('ascii')).hexdigest()[:12]}_"
        f"{hashlib.sha256(extension_raw.encode('ascii')).hexdigest()[:12]}"
    )
    return ja4, f"{prefix}_{cipher_raw}_{extension_raw}"


def quic_varint(data: bytes, cursor: int = 0) -> tuple[int, int]:
    if cursor < 0 or cursor >= len(data):
        raise ValueError("truncated QUIC variable-length integer")
    first = data[cursor]
    length = 1 << (first >> 6)
    if cursor + length > len(data):
        raise ValueError("truncated QUIC variable-length integer")
    value = first & 0x3F
    for byte in data[cursor + 1:cursor + length]:
        value = (value << 8) | byte
    return value, cursor + length


class ModernProtocolMixin:
    """Bounded modern TLS/HTTP2/QUIC/HTTP3 metadata decoders.

    QUIC payloads remain encrypted unless the caller supplies already-decrypted stream
    bytes. The native decoder never claims to decrypt TLS or QUIC traffic by itself.
    """

    MAX_MODERN_FRAMES = 128

    def _modern_tls_extensions(self, body: bytes, cursor: int, extension_end: int) -> dict[str, Any]:
        result: dict[str, Any] = {"extensions": [], "groups": [], "point_formats": [], "signature_algorithms": [],
                                  "supported_versions": [], "key_share_groups": [], "psk_modes": [], "alpn": [],
                                  "quic_transport_parameters": [], "sni": "", "malformed": False}
        while cursor + 4 <= extension_end and len(result["extensions"]) < 256:
            ext_type, ext_len = struct.unpack_from("!HH", body, cursor); cursor += 4
            if cursor + ext_len > extension_end:
                result["malformed"] = True; break
            value = body[cursor:cursor + ext_len]; cursor += ext_len; result["extensions"].append(ext_type)
            if ext_type == 0 and len(value) >= 5:
                name_list_len = int.from_bytes(value[:2], "big")
                if name_list_len + 2 <= len(value) and value[2] == 0:
                    name_len = int.from_bytes(value[3:5], "big")
                    if 5 + name_len <= len(value): result["sni"] = _safe_hostname(value[5:5 + name_len])
            elif ext_type in {10, 13} and len(value) >= 2:
                total = min(int.from_bytes(value[:2], "big"), len(value) - 2)
                values = [int.from_bytes(value[pos:pos + 2], "big") for pos in range(2, 2 + total - (total % 2), 2)]
                result["groups" if ext_type == 10 else "signature_algorithms"] = values[:128]
            elif ext_type == 11 and value:
                result["point_formats"] = list(value[1:1 + min(value[0], len(value) - 1)])[:32]
            elif ext_type == 16 and len(value) >= 2:
                total, pos = min(int.from_bytes(value[:2], "big"), len(value) - 2), 2
                end = 2 + total
                while pos < end and len(result["alpn"]) < 32:
                    size = value[pos]; pos += 1
                    if pos + size > end: result["malformed"] = True; break
                    result["alpn"].append(value[pos:pos + size].decode("ascii", errors="replace")[:64]); pos += size
            elif ext_type == 43 and len(value) >= 3:
                total = min(value[0], len(value) - 1)
                result["supported_versions"] = [int.from_bytes(value[pos:pos + 2], "big") for pos in range(1, 1 + total - (total % 2), 2)][:32]
            elif ext_type == 45 and value:
                result["psk_modes"] = list(value[1:1 + min(value[0], len(value) - 1)])[:16]
            elif ext_type == 51 and len(value) >= 2:
                total, pos = min(int.from_bytes(value[:2], "big"), len(value) - 2), 2
                end = 2 + total
                while pos + 4 <= end and len(result["key_share_groups"]) < 64:
                    group, share_len = int.from_bytes(value[pos:pos + 2], "big"), int.from_bytes(value[pos + 2:pos + 4], "big"); pos += 4
                    if pos + share_len > end: result["malformed"] = True; break
                    result["key_share_groups"].append(group); pos += share_len
            elif ext_type == 57:
                result["quic_transport_parameters"] = self._quic_transport_parameter_rows(value)
        return result

    @staticmethod
    def _tls_fingerprints(legacy_version: int, ciphers: list[int], ext: dict[str, Any]) -> tuple[str, str]:
        ja3_ciphers = [value for value in ciphers if not _is_grease(value)]
        ja3_extensions = [value for value in ext["extensions"] if not _is_grease(value)]
        ja3_groups = [value for value in ext["groups"] if not _is_grease(value)]
        ja3 = ",".join((str(legacy_version), "-".join(map(str, ja3_ciphers)), "-".join(map(str, ja3_extensions)),
                         "-".join(map(str, ja3_groups)), "-".join(map(str, ext["point_formats"]))))
        semantic = "|".join(("-".join(f"{value:04x}" for value in sorted(ja3_ciphers)),
                             "-".join(f"{value:04x}" for value in sorted(ja3_extensions)),
                             "-".join(f"{value:04x}" for value in sorted(ext["signature_algorithms"]) if not _is_grease(value)),
                             "-".join(ext["alpn"])))
        return ja3, semantic

    def _modern_tls_client_hello(self, body: bytes) -> dict[str, Any]:
        if len(body) < 35: return {}
        legacy_version, cursor = int.from_bytes(body[:2], "big"), 34
        session_len = body[cursor]; cursor += 1
        if cursor + session_len + 2 > len(body): return {}
        cursor += session_len; cipher_length = int.from_bytes(body[cursor:cursor + 2], "big"); cursor += 2
        if cipher_length % 2 or cursor + cipher_length > len(body): return {}
        ciphers = [int.from_bytes(body[pos:pos + 2], "big") for pos in range(cursor, cursor + cipher_length, 2)]
        cursor += cipher_length
        if cursor >= len(body): return {}
        compression_length = body[cursor]; cursor += 1
        if cursor + compression_length + 2 > len(body): return {}
        cursor += compression_length; extension_total = int.from_bytes(body[cursor:cursor + 2], "big"); cursor += 2
        ext = self._modern_tls_extensions(body, cursor, min(len(body), cursor + extension_total))
        ja3, semantic = self._tls_fingerprints(legacy_version, ciphers, ext)
        ja4, ja4_raw = _ja4_tls_client(legacy_version, ciphers, ext)
        return {
            "cipher_suites": [f"0x{value:04x}" for value in ciphers[:256]], "extension_types": ext["extensions"],
            "supported_groups": [f"0x{value:04x}" for value in ext["groups"]], "ec_point_formats": ext["point_formats"],
            "signature_algorithms": [f"0x{value:04x}" for value in ext["signature_algorithms"]],
            "supported_versions": [f"0x{value:04x}" for value in ext["supported_versions"]],
            "key_share_groups": [f"0x{value:04x}" for value in ext["key_share_groups"]], "psk_key_exchange_modes": ext["psk_modes"],
            "server_name": ext["sni"], "alpn": ext["alpn"], "ja3": ja3, "ja3_md5": _md5_protocol_fingerprint(ja3),
            "ja4": ja4, "ja4_raw": ja4_raw,
            "tls_semantic_sha256": hashlib.sha256(semantic.encode("utf-8")).hexdigest(),
            "grease_cipher_count": sum(1 for value in ciphers if _is_grease(value)),
            "grease_extension_count": sum(1 for value in ext["extensions"] if _is_grease(value)),
            "quic_transport_parameters": ext["quic_transport_parameters"], "malformed_extensions": ext["malformed"],
        }

    def _modern_tls_server_hello(self, body: bytes) -> dict[str, Any]:
        if len(body) < 38:
            return {}
        cursor = 34
        session_len = body[cursor]
        cursor += 1
        if cursor + session_len + 3 > len(body):
            return {"server_legacy_version": body[:2].hex()}
        cursor += session_len
        cipher = int.from_bytes(body[cursor:cursor + 2], "big")
        cursor += 3  # cipher + compression
        fields: dict[str, Any] = {
            "server_legacy_version": body[:2].hex(),
            "selected_cipher_suite": f"0x{cipher:04x}",
        }
        if cursor + 2 > len(body):
            return fields
        total = int.from_bytes(body[cursor:cursor + 2], "big")
        cursor += 2
        end = min(len(body), cursor + total)
        extensions: list[int] = []
        selected_version = 0
        selected_alpn = ""
        malformed = False
        while cursor + 4 <= end and len(extensions) < 128:
            ext_type, ext_len = struct.unpack_from("!HH", body, cursor)
            cursor += 4
            if cursor + ext_len > end:
                malformed = True
                break
            value = body[cursor:cursor + ext_len]
            cursor += ext_len
            extensions.append(ext_type)
            if ext_type == 43 and len(value) == 2:
                selected_version = int.from_bytes(value, "big")
            elif ext_type == 16 and len(value) >= 3:
                total_alpn = min(int.from_bytes(value[:2], "big"), len(value) - 2)
                if total_alpn >= 1:
                    name_len = value[2]
                    if 3 + name_len <= len(value):
                        selected_alpn = value[3:3 + name_len].decode("ascii", errors="replace")[:64]
            if ext_type == 43 and len(value) == 2:
                fields["selected_version"] = f"0x{int.from_bytes(value, 'big'):04x}"
            elif ext_type == 51 and len(value) >= 2:
                fields["selected_key_share_group"] = f"0x{int.from_bytes(value[:2], 'big'):04x}"
        fields["extension_types"] = extensions
        if selected_version:
            fields["selected_version"] = f"0x{selected_version:04x}"
        if selected_alpn:
            fields["selected_alpn"] = selected_alpn
        ja3s_extensions = [value for value in extensions if not _is_grease(value)]
        ja3s = ",".join((
            str(int.from_bytes(body[:2], "big")),
            str(cipher),
            "-".join(str(value) for value in ja3s_extensions),
        ))
        fields["ja3s"] = ja3s
        fields["ja3s_md5"] = _md5_protocol_fingerprint(ja3s)
        fields["malformed_extensions"] = malformed
        return fields

    def _quic_transport_parameter_rows(self, data: bytes) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        cursor = 0
        while cursor < len(data) and len(rows) < 64:
            try:
                parameter_id, cursor = quic_varint(data, cursor)
                length, cursor = quic_varint(data, cursor)
            except ValueError:
                break
            if length > len(data) - cursor:
                break
            raw = data[cursor:cursor + length]
            cursor += length
            row: dict[str, Any] = {
                "id": parameter_id,
                "name": _QUIC_TRANSPORT_PARAMETERS.get(parameter_id, f"0x{parameter_id:x}"),
                "length": length,
            }
            if parameter_id in {1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14, 32} and raw:
                try:
                    numeric, end = quic_varint(raw, 0)
                    if end == len(raw):
                        row["value"] = numeric
                except ValueError:
                    record_current_exception(__name__, 'ModernProtocolMixin._quic_transport_parameter_rows:306')
            rows.append(row)
        return rows

    def _modern_quic_header(self, data: bytes) -> dict[str, Any]:
        if not data:
            raise ValueError("empty QUIC packet")
        first = data[0]
        fields: dict[str, Any] = {
            "header_form": "long" if first & 0x80 else "short",
            "fixed_bit": bool(first & 0x40),
            "spin_bit": bool(first & 0x20) if not (first & 0x80) else None,
        }
        if not (first & 0x80):
            return fields
        if len(data) < 7:
            raise ValueError("truncated QUIC long header")
        version = int.from_bytes(data[1:5], "big")
        fields["version"] = f"0x{version:08x}"
        fields["version_name"] = "version-negotiation" if version == 0 else "v1" if version == _QUIC_V1 else "v2" if version == _QUIC_V2 else "other"
        cursor = 5
        dcid_len = data[cursor]
        cursor += 1
        if dcid_len > 20 or cursor + dcid_len >= len(data):
            raise ValueError("invalid QUIC destination connection id")
        fields["destination_connection_id"] = data[cursor:cursor + dcid_len].hex()
        fields["dcid_length"] = dcid_len
        cursor += dcid_len
        scid_len = data[cursor]
        cursor += 1
        if scid_len > 20 or cursor + scid_len > len(data):
            raise ValueError("invalid QUIC source connection id")
        fields["source_connection_id"] = data[cursor:cursor + scid_len].hex()
        fields["scid_length"] = scid_len
        cursor += scid_len
        if version == 0:
            versions: list[str] = []
            while cursor + 4 <= len(data) and len(versions) < 64:
                versions.append(f"0x{int.from_bytes(data[cursor:cursor + 4], 'big'):08x}")
                cursor += 4
            fields["offered_versions"] = versions
            fields["packet_type"] = "Version Negotiation"
            return fields
        type_bits = (first >> 4) & 0x03
        if version == _QUIC_V2:
            packet_type = {0: "Retry", 1: "Initial", 2: "0-RTT", 3: "Handshake"}[type_bits]
        else:
            packet_type = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}[type_bits]
        fields["packet_type"] = packet_type
        if packet_type == "Initial":
            token_length, cursor = quic_varint(data, cursor)
            if token_length > len(data) - cursor:
                raise ValueError("invalid QUIC Initial token length")
            fields["token_length"] = token_length
            cursor += token_length
        if packet_type != "Retry" and cursor < len(data):
            protected_length, cursor = quic_varint(data, cursor)
            fields["protected_payload_length"] = protected_length
            fields["packet_number_length"] = (first & 0x03) + 1
            fields["protected_payload_offset"] = cursor
        return fields

    def _http2_frame_rows(self, data: bytes, *, start: int = 0) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        cursor = max(0, int(start))
        for _index in range(self.MAX_MODERN_FRAMES):
            if cursor + 9 > len(data):
                break
            length = int.from_bytes(data[cursor:cursor + 3], "big")
            frame_type = data[cursor + 3]
            flags = data[cursor + 4]
            stream_id = int.from_bytes(data[cursor + 5:cursor + 9], "big") & 0x7FFFFFFF
            cursor += 9
            if length > 16 * 1024 * 1024 or cursor + length > len(data):
                break
            payload = data[cursor:cursor + length]
            cursor += length
            row: dict[str, Any] = {
                "type": _HTTP2_TYPES.get(frame_type, f"0x{frame_type:02x}"),
                "type_id": frame_type, "flags": f"0x{flags:02x}", "stream_id": stream_id, "length": length,
            }
            if frame_type == 0x4 and stream_id == 0 and length % 6 == 0:
                row["settings"] = [
                    {"id": int.from_bytes(payload[pos:pos + 2], "big"), "value": int.from_bytes(payload[pos + 2:pos + 6], "big")}
                    for pos in range(0, min(length, 6 * 64), 6)
                ]
            elif frame_type == 0x6 and length == 8:
                row["opaque_data"] = payload.hex()
            elif frame_type == 0x7 and length >= 8:
                row["last_stream_id"] = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
                row["error_code"] = int.from_bytes(payload[4:8], "big")
            elif frame_type == 0x8 and length == 4:
                row["window_increment"] = int.from_bytes(payload, "big") & 0x7FFFFFFF
            rows.append(row)
        return rows

    def _http3_frame_rows(self, data: bytes) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        cursor = 0
        for _index in range(self.MAX_MODERN_FRAMES):
            if cursor >= len(data):
                break
            try:
                frame_type, cursor = quic_varint(data, cursor)
                length, cursor = quic_varint(data, cursor)
            except ValueError:
                break
            if length > 16 * 1024 * 1024 or cursor + length > len(data):
                break
            payload = data[cursor:cursor + length]
            cursor += length
            row: dict[str, Any] = {"type": _HTTP3_TYPES.get(frame_type, f"0x{frame_type:x}"), "type_id": frame_type, "length": length}
            if frame_type == 0x4:
                settings: list[dict[str, Any]] = []
                position = 0
                while position < len(payload) and len(settings) < 64:
                    try:
                        setting_id, position = quic_varint(payload, position)
                        setting_value, position = quic_varint(payload, position)
                    except ValueError:
                        break
                    settings.append({"id": setting_id, "name": _HTTP3_SETTINGS.get(setting_id, f"0x{setting_id:x}"), "value": setting_value})
                row["settings"] = settings
            elif frame_type in {0x7, 0xD} and payload:
                try:
                    row["identifier"], _unused = quic_varint(payload, 0)
                except ValueError:
                    record_current_exception(__name__, 'ModernProtocolMixin._http3_frame_rows:433')
            rows.append(row)
        return rows

    def _add_http3_stream(self, data: bytes, offset: int, result: "ProtocolDecodeResult") -> None:
        frames = self._http3_frame_rows(data)
        self._add(result, "http3", offset, len(data), {"frames": frames, "frame_count": len(frames), "decrypted_stream": True})
        result.application_protocol = "http3"
