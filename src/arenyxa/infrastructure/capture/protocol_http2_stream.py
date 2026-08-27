from __future__ import annotations

import hashlib
import struct
from typing import Any

from arenyxa.infrastructure.capture.protocol_dns import decode_dns_message

MAX_HTTP2_FRAME_BYTES = 16 * 1024 * 1024
MAX_HTTP2_FRAMES = 4096
MAX_HTTP2_HEADER_BLOCK = 512 * 1024
MAX_HTTP2_HEADER_LIST = 128 * 1024
MAX_HTTP2_HEADERS = 256
MAX_GRPC_MESSAGES = 512
MAX_GRPC_MESSAGE_BYTES = 64 * 1024 * 1024
MAX_HTTP2_REASSEMBLY_BYTES = 64 * 1024 * 1024

_HTTP2_FRAME_NAMES = {
    0x0: "DATA",
    0x1: "HEADERS",
    0x2: "PRIORITY",
    0x3: "RST_STREAM",
    0x4: "SETTINGS",
    0x5: "PUSH_PROMISE",
    0x6: "PING",
    0x7: "GOAWAY",
    0x8: "WINDOW_UPDATE",
    0x9: "CONTINUATION",
}


def _header_block_fragment(frame_type: int, flags: int, payload: bytes) -> tuple[bytes, dict[str, Any]]:
    """Return the HPACK fragment and bounded HEADERS/PUSH metadata.

    RFC 9113 frame-specific padding/priority fields are stripped before the
    HPACK block is handed to the decoder.  The function deliberately rejects
    malformed lengths instead of trying to recover through payload bytes.
    """
    cursor = 0
    pad_length = 0
    metadata: dict[str, Any] = {}
    if flags & 0x08:  # PADDED
        if not payload:
            raise ValueError("HTTP/2 padded frame is missing pad length")
        pad_length = payload[0]
        cursor = 1
    if frame_type == 0x1 and flags & 0x20:  # HEADERS + PRIORITY
        if cursor + 5 > len(payload):
            raise ValueError("HTTP/2 HEADERS priority section is truncated")
        dependency = int.from_bytes(payload[cursor:cursor + 4], "big")
        metadata["exclusive"] = bool(dependency & 0x80000000)
        metadata["stream_dependency"] = dependency & 0x7FFFFFFF
        metadata["weight"] = int(payload[cursor + 4]) + 1
        cursor += 5
    elif frame_type == 0x5:  # PUSH_PROMISE
        if cursor + 4 > len(payload):
            raise ValueError("HTTP/2 PUSH_PROMISE is truncated")
        metadata["promised_stream_id"] = int.from_bytes(payload[cursor:cursor + 4], "big") & 0x7FFFFFFF
        cursor += 4
    end = len(payload) - pad_length
    if pad_length > len(payload) - cursor or end < cursor:
        raise ValueError("HTTP/2 padding exceeds frame payload")
    fragment = payload[cursor:end]
    if len(fragment) > MAX_HTTP2_HEADER_BLOCK:
        raise ValueError("HTTP/2 header block fragment exceeds safety bound")
    metadata["padding_length"] = pad_length
    return fragment, metadata


def _decode_hpack(decoder: Any, block: bytes) -> tuple[list[dict[str, str]], dict[str, Any]]:
    if len(block) > MAX_HTTP2_HEADER_BLOCK:
        raise ValueError("HTTP/2 HPACK block exceeds safety bound")
    headers_raw = decoder.decode(block, raw=True)
    if len(headers_raw) > MAX_HTTP2_HEADERS:
        raise ValueError("HTTP/2 header count exceeds safety bound")
    rows: list[dict[str, str]] = []
    total = 0
    pseudo: dict[str, str] = {}
    for raw_name, raw_value in headers_raw:
        name = bytes(raw_name).decode("utf-8", errors="replace")[:512]
        value = bytes(raw_value).decode("utf-8", errors="replace")[:8192]
        total += len(name.encode("utf-8")) + len(value.encode("utf-8"))
        if total > MAX_HTTP2_HEADER_LIST:
            raise ValueError("HTTP/2 decoded header list exceeds safety bound")
        rows.append({"name": name, "value": value})
        if name.startswith(":"):
            pseudo[name] = value
    semantic = {
        "method": pseudo.get(":method", ""),
        "scheme": pseudo.get(":scheme", ""),
        "authority": pseudo.get(":authority", ""),
        "path": pseudo.get(":path", ""),
        "status": pseudo.get(":status", ""),
    }
    return rows, semantic


def _data_fragment(flags: int, payload: bytes) -> bytes:
    if not (flags & 0x08):
        return payload
    if not payload:
        raise ValueError("HTTP/2 padded DATA frame is missing pad length")
    pad_length = payload[0]
    if pad_length > len(payload) - 1:
        raise ValueError("HTTP/2 DATA padding exceeds payload")
    end = len(payload) - pad_length
    return payload[1:end]


def _consume_grpc_buffer(buffer: bytearray) -> list[dict[str, Any]]:
    """Consume complete gRPC envelopes while retaining only an incomplete suffix."""
    rows: list[dict[str, Any]] = []
    while len(buffer) >= 5 and len(rows) < MAX_GRPC_MESSAGES:
        compressed = buffer[0]
        length = int.from_bytes(buffer[1:5], "big")
        if compressed not in {0, 1} or length > MAX_GRPC_MESSAGE_BYTES:
            raise ValueError("invalid or oversized gRPC message envelope")
        if len(buffer) < 5 + length:
            break
        message = bytes(buffer[5:5 + length])
        del buffer[:5 + length]
        rows.append({
            "compressed": bool(compressed),
            "length": length,
            "sha256": hashlib.sha256(message).hexdigest(),
        })
    return rows


def decode_http2_stream(data: bytes) -> dict[str, Any]:
    """Decode a sequential cleartext/decrypted HTTP/2 direction.

    HPACK is connection-stateful, so this entry point intentionally accepts an
    ordered byte stream rather than unrelated packet payloads.  It is suitable
    for h2c traffic or TLS streams that have already been decrypted/reassembled.
    """
    try:
        from hpack import Decoder
    except ImportError as exc:  # pragma: no cover - exercised by dependency gate
        raise RuntimeError("HTTP/2 HPACK decoding requires the capture extra dependency 'hpack'") from exc

    raw = bytes(data)
    cursor = 0
    client_preface = raw.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    if client_preface:
        cursor = 24
    decoder = Decoder(max_header_list_size=MAX_HTTP2_HEADER_LIST)
    decoder.max_allowed_table_size = 65536
    frames: list[dict[str, Any]] = []
    stream_headers: dict[int, dict[str, str]] = {}
    stream_summaries: dict[int, dict[str, Any]] = {}
    grpc_buffers: dict[int, bytearray] = {}
    doh_buffers: dict[int, bytearray] = {}
    reassembly_bytes = 0
    pending_stream = 0
    pending_block = bytearray()
    pending_frame_index = -1

    for _ in range(MAX_HTTP2_FRAMES):
        if cursor >= len(raw):
            break
        if cursor + 9 > len(raw):
            frames.append({"type": "TRUNCATED", "offset": cursor, "remaining": len(raw) - cursor})
            break
        frame_offset = cursor
        length = int.from_bytes(raw[cursor:cursor + 3], "big")
        frame_type = raw[cursor + 3]
        flags = raw[cursor + 4]
        stream_id = int.from_bytes(raw[cursor + 5:cursor + 9], "big") & 0x7FFFFFFF
        cursor += 9
        if length > MAX_HTTP2_FRAME_BYTES or cursor + length > len(raw):
            frames.append({
                "type": "MALFORMED", "type_id": frame_type, "offset": frame_offset,
                "declared_length": length, "remaining": len(raw) - cursor,
            })
            break
        payload = raw[cursor:cursor + length]
        cursor += length
        row: dict[str, Any] = {
            "type": _HTTP2_FRAME_NAMES.get(frame_type, f"0x{frame_type:02x}"),
            "type_id": frame_type,
            "flags": f"0x{flags:02x}",
            "stream_id": stream_id,
            "length": length,
            "offset": frame_offset,
        }

        if frame_type in {0x1, 0x5}:  # HEADERS/PUSH_PROMISE
            if stream_id == 0:
                row["protocol_error"] = "header-frame-on-stream-zero"
            elif pending_stream:
                row["protocol_error"] = "header-block-interleaving"
            else:
                try:
                    fragment, metadata = _header_block_fragment(frame_type, flags, payload)
                    row.update(metadata)
                    pending_stream = stream_id
                    pending_block.extend(fragment)
                    pending_frame_index = len(frames)
                    if flags & 0x04:  # END_HEADERS
                        headers, semantic = _decode_hpack(decoder, bytes(pending_block))
                        row["headers"] = headers
                        row.update({key: value for key, value in semantic.items() if value})
                        normalized = {item["name"].casefold(): item["value"] for item in headers}
                        stream_headers[stream_id] = normalized
                        summary = stream_summaries.setdefault(stream_id, {"stream_id": stream_id})
                        summary.update({key: value for key, value in semantic.items() if value})
                        content_type = normalized.get("content-type", "")
                        if content_type.casefold().startswith("application/grpc"):
                            summary["grpc"] = True
                            summary["content_type"] = content_type
                        elif content_type.casefold().split(";", 1)[0].strip() == "application/dns-message":
                            summary["doh"] = True
                            summary["content_type"] = content_type
                        pending_stream = 0
                        pending_block.clear()
                        pending_frame_index = -1
                except (ValueError, TypeError) as exc:
                    row["decode_error"] = str(exc)[:256]
                    pending_stream = 0
                    pending_block.clear()
                    pending_frame_index = -1
        elif frame_type == 0x9:  # CONTINUATION
            if not pending_stream or pending_stream != stream_id:
                row["protocol_error"] = "unexpected-continuation"
            else:
                if len(pending_block) + len(payload) > MAX_HTTP2_HEADER_BLOCK:
                    row["decode_error"] = "HTTP/2 continued header block exceeds safety bound"
                    pending_stream = 0
                    pending_block.clear()
                    pending_frame_index = -1
                else:
                    pending_block.extend(payload)
                    if flags & 0x04:
                        try:
                            headers, semantic = _decode_hpack(decoder, bytes(pending_block))
                            row["continued_headers"] = headers
                            row.update({key: value for key, value in semantic.items() if value})
                            normalized = {item["name"].casefold(): item["value"] for item in headers}
                            stream_headers[stream_id] = normalized
                            summary = stream_summaries.setdefault(stream_id, {"stream_id": stream_id})
                            summary.update({key: value for key, value in semantic.items() if value})
                            content_type = normalized.get("content-type", "")
                            if content_type.casefold().startswith("application/grpc"):
                                summary["grpc"] = True
                                summary["content_type"] = content_type
                            elif content_type.casefold().split(";", 1)[0].strip() == "application/dns-message":
                                summary["doh"] = True
                                summary["content_type"] = content_type
                            if 0 <= pending_frame_index < len(frames):
                                frames[pending_frame_index]["header_block_completed_by_continuation"] = True
                        except (ValueError, TypeError) as exc:
                            row["decode_error"] = str(exc)[:256]
                        finally:
                            pending_stream = 0
                            pending_block.clear()
                            pending_frame_index = -1
        elif frame_type == 0x0:  # DATA
            headers = stream_headers.get(stream_id, {})
            try:
                body = _data_fragment(flags, payload)
            except ValueError as exc:
                row["decode_error"] = str(exc)[:256]
                body = b""
            content_type = str(headers.get("content-type", "")).casefold().split(";", 1)[0].strip()
            if content_type.startswith("application/grpc"):
                buffer = grpc_buffers.setdefault(stream_id, bytearray())
                if (
                    len(buffer) + len(body) > MAX_GRPC_MESSAGE_BYTES + 5
                    or reassembly_bytes + len(body) > MAX_HTTP2_REASSEMBLY_BYTES
                ):
                    row["decode_error"] = "gRPC reassembly buffer exceeds safety bound"
                    reassembly_bytes -= len(buffer)
                    buffer.clear()
                else:
                    before = len(buffer)
                    buffer.extend(body)
                    try:
                        messages = _consume_grpc_buffer(buffer)
                    except ValueError as exc:
                        row["decode_error"] = str(exc)[:256]
                        buffer.clear()
                        messages = []
                    reassembly_bytes += len(buffer) - before
                    row["grpc"] = True
                    row["grpc_messages"] = messages
                    row["grpc_pending_bytes"] = len(buffer)
                    summary = stream_summaries.setdefault(stream_id, {"stream_id": stream_id, "grpc": True})
                    summary["grpc_message_count"] = int(summary.get("grpc_message_count", 0)) + len(messages)
                    summary["grpc_payload_bytes"] = int(summary.get("grpc_payload_bytes", 0)) + sum(int(item["length"]) for item in messages)
                    summary["grpc_pending_bytes"] = len(buffer)
            elif content_type == "application/dns-message":
                buffer = doh_buffers.setdefault(stream_id, bytearray())
                if len(buffer) + len(body) > 65535 or reassembly_bytes + len(body) > MAX_HTTP2_REASSEMBLY_BYTES:
                    row["decode_error"] = "DoH DNS body exceeds 65535-byte wire-format limit"
                    reassembly_bytes -= len(buffer)
                    buffer.clear()
                else:
                    buffer.extend(body)
                    reassembly_bytes += len(body)
                    row["doh"] = True
                    row["doh_body_bytes"] = len(buffer)
                    summary = stream_summaries.setdefault(stream_id, {"stream_id": stream_id, "doh": True})
                    summary["doh_body_bytes"] = len(buffer)
                    if flags & 0x01 and buffer:
                        try:
                            summary["doh_dns"] = decode_dns_message(bytes(buffer))
                        except (IndexError, ValueError, struct.error) as exc:
                            summary["doh_decode_error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
                        finally:
                            reassembly_bytes -= len(buffer)
                            buffer.clear()
        elif frame_type == 0x4 and stream_id == 0 and length % 6 == 0:
            row["settings"] = [
                {"id": int.from_bytes(payload[pos:pos + 2], "big"), "value": int.from_bytes(payload[pos + 2:pos + 6], "big")}
                for pos in range(0, min(length, 6 * 64), 6)
            ]
        elif frame_type == 0x3 and length == 4:
            row["error_code"] = int.from_bytes(payload, "big")
        elif frame_type == 0x6 and length == 8:
            row["opaque_data_sha256"] = hashlib.sha256(payload).hexdigest()
        elif frame_type == 0x7 and length >= 8:
            row["last_stream_id"] = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
            row["error_code"] = int.from_bytes(payload[4:8], "big")
            if len(payload) > 8:
                row["debug_data_length"] = len(payload) - 8
                row["debug_data_sha256"] = hashlib.sha256(payload[8:]).hexdigest()
        elif frame_type == 0x8 and length == 4:
            row["window_increment"] = int.from_bytes(payload, "big") & 0x7FFFFFFF
        frames.append(row)

    return {
        "schema": "arenyxa.http2-stream/v1",
        "client_preface": client_preface,
        "bytes_consumed": cursor,
        "bytes_total": len(raw),
        "frame_count": len(frames),
        "frames": frames,
        "streams": sorted(stream_summaries.values(), key=lambda item: int(item["stream_id"])),
        "pending_header_stream": pending_stream,
        "pending_grpc_streams": {str(key): len(value) for key, value in grpc_buffers.items() if value},
        "pending_doh_streams": {str(key): len(value) for key, value in doh_buffers.items() if value},
        "pending_reassembly_bytes": reassembly_bytes,
        "hpack_stateful": True,
        "decrypted_or_cleartext_stream_required": True,
    }
