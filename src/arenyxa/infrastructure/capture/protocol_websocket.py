from __future__ import annotations

import hashlib
import struct
from typing import Any

MAX_WEBSOCKET_FRAMES = 4096
MAX_WEBSOCKET_PAYLOAD_BYTES = 64 * 1024 * 1024

_OPCODES = {
    0x0: "continuation",
    0x1: "text",
    0x2: "binary",
    0x8: "close",
    0x9: "ping",
    0xA: "pong",
}


def _payload_length(raw: bytes, cursor: int, second: int) -> tuple[int, int, str | None]:
    length = second & 0x7F
    if length == 126:
        if cursor + 2 > len(raw):
            return 0, cursor, "extended-length-16"
        return struct.unpack_from("!H", raw, cursor)[0], cursor + 2, None
    if length == 127:
        if cursor + 8 > len(raw):
            return 0, cursor, "extended-length-64"
        length = struct.unpack_from("!Q", raw, cursor)[0]
        if length & (1 << 63):
            return length, cursor + 8, "invalid-64-bit-length"
        return length, cursor + 8, None
    return length, cursor, None


def _frame_payload(raw: bytes, cursor: int, length: int, masked: bool, *, unmask_payload: bool) -> tuple[bytes, int, str | None]:
    mask = b""
    if masked:
        if cursor + 4 > len(raw):
            return b"", cursor, "mask-key"
        mask = raw[cursor:cursor + 4]
        cursor += 4
    if cursor + length > len(raw):
        return b"", cursor, "payload"
    payload = raw[cursor:cursor + length]
    cursor += length
    if masked and unmask_payload:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return payload, cursor, None


def _fragment_state(row: dict[str, Any], opcode: int, fin: bool, length: int, active: int | None, total: int) -> tuple[int | None, int]:
    if opcode in {0x1, 0x2}:
        if active is not None:
            row["protocol_error"] = "new-data-frame-during-fragmentation"
        elif not fin:
            return opcode, length
    elif opcode == 0x0:
        if active is None:
            row["protocol_error"] = "continuation-without-start"
        else:
            total += length
            row.update({"message_opcode": active, "message_accumulated_bytes": total})
            if total > MAX_WEBSOCKET_PAYLOAD_BYTES:
                row["protocol_error"] = "fragmented-message-budget"
                return None, 0
            if fin:
                return None, 0
    elif opcode not in _OPCODES:
        row["protocol_error"] = "reserved-opcode"
    return active, total


def _decode_frame(raw: bytes, cursor: int, active: int | None, total: int, *, unmask_payload: bool) -> tuple[dict[str, Any], int, int | None, int, bool]:
    start = cursor
    if cursor + 2 > len(raw):
        return {"offset": start, "type": "truncated", "remaining": len(raw) - cursor}, cursor, active, total, True
    first, second = raw[cursor], raw[cursor + 1]
    cursor += 2
    fin, rsv, opcode, masked = bool(first & 0x80), (first >> 4) & 0x07, first & 0x0F, bool(second & 0x80)
    length, cursor, error = _payload_length(raw, cursor, second)
    if error:
        kind = "malformed" if error == "invalid-64-bit-length" else "truncated"
        return {"offset": start, "type": kind, "reason": error}, cursor, active, total, True
    if length > MAX_WEBSOCKET_PAYLOAD_BYTES:
        return {"offset": start, "type": "malformed", "reason": "payload-budget", "payload_length": length}, cursor, active, total, True
    logical, cursor, error = _frame_payload(raw, cursor, length, masked, unmask_payload=unmask_payload)
    if error:
        return {"offset": start, "type": "truncated", "reason": error, "payload_length": length}, cursor, active, total, True
    row: dict[str, Any] = {
        "offset": start, "fin": fin, "rsv_bits": rsv, "opcode": opcode,
        "type": _OPCODES.get(opcode, f"reserved-0x{opcode:x}"), "masked": masked,
        "payload_length": length, "payload_sha256": hashlib.sha256(logical).hexdigest(),
    }
    if rsv:
        row["protocol_error"] = "reserved-bits-without-negotiated-extension"
    if opcode >= 0x8 and (not fin or length > 125):
        row["protocol_error"] = "invalid-control-frame"
    if opcode == 0x8 and length == 1:
        row["protocol_error"] = "invalid-close-payload"
    if opcode == 0x8 and len(logical) >= 2:
        row.update({"close_code": int.from_bytes(logical[:2], "big"), "close_reason_bytes": len(logical) - 2})
    active, total = _fragment_state(row, opcode, fin, length, active, total)
    return row, cursor, active, total, False


def decode_websocket_stream(data: bytes, *, unmask_payload: bool = True) -> dict[str, Any]:
    """Decode an already-identified RFC 6455 frame stream without retaining payload bytes."""
    raw, cursor, frames = bytes(data), 0, []
    fragmented_opcode: int | None = None
    fragmented_bytes = 0
    for _ in range(MAX_WEBSOCKET_FRAMES):
        if cursor >= len(raw):
            break
        row, cursor, fragmented_opcode, fragmented_bytes, stop = _decode_frame(
            raw, cursor, fragmented_opcode, fragmented_bytes, unmask_payload=unmask_payload,
        )
        frames.append(row)
        if stop:
            break
    return {
        "schema": "arenyxa.websocket-stream/v1", "frame_count": len(frames), "frames": frames,
        "bytes_consumed": cursor, "bytes_total": len(raw), "fragmentation_open": fragmented_opcode is not None,
        "identified_stream_required": True, "payload_retained": False,
    }
