from __future__ import annotations

import hashlib
import hmac
from typing import Any

from arenyxa.infrastructure.capture.protocol_modern import quic_varint

_QUIC_V1 = 0x00000001
_QUIC_V2 = 0x6B3343CF
_INITIAL_SALTS = {
    _QUIC_V1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    _QUIC_V2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
}
_LABELS = {
    _QUIC_V1: ("quic key", "quic iv", "quic hp"),
    _QUIC_V2: ("quicv2 key", "quicv2 iv", "quicv2 hp"),
}
MAX_INITIAL_PACKET_BYTES = 64 * 1024
MAX_INITIAL_FRAMES = 256
MAX_INITIAL_CRYPTO_BYTES = 64 * 1024


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length <= 0 or length > 255 * hashlib.sha256().digest_size:
        raise ValueError("invalid HKDF output length")
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info + bytes((counter,)), hashlib.sha256).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def _hkdf_expand_label(secret: bytes, label: str, length: int) -> bytes:
    full = b"tls13 " + label.encode("ascii", errors="strict")
    if len(full) > 255:
        raise ValueError("HKDF label exceeds one-byte TLS length")
    info = length.to_bytes(2, "big") + bytes((len(full),)) + full + b"\x00"
    return _hkdf_expand(secret, info, length)


def derive_quic_initial_keys(version: int, destination_connection_id: bytes, *, role: str) -> dict[str, bytes]:
    """Derive standardized QUIC v1/v2 Initial packet keys.

    Initial keys provide passive protocol visibility, not endpoint authentication. They
    are intentionally derivable by on-path observers from the client's first DCID.
    """

    version_id = int(version)
    if version_id not in _INITIAL_SALTS:
        raise ValueError("QUIC Initial key derivation supports standardized v1/v2 only")
    dcid = bytes(destination_connection_id)
    if not (1 <= len(dcid) <= 20):
        raise ValueError("QUIC Initial destination connection id must be 1..20 bytes")
    direction = str(role).casefold()
    if direction not in {"client", "server"}:
        raise ValueError("QUIC Initial role must be client or server")
    initial_secret = _hkdf_extract(_INITIAL_SALTS[version_id], dcid)
    traffic_secret = _hkdf_expand_label(initial_secret, f"{direction} in", 32)
    key_label, iv_label, hp_label = _LABELS[version_id]
    return {
        "secret": traffic_secret,
        "key": _hkdf_expand_label(traffic_secret, key_label, 16),
        "iv": _hkdf_expand_label(traffic_secret, iv_label, 12),
        "hp": _hkdf_expand_label(traffic_secret, hp_label, 16),
    }


def _initial_header_offsets(packet: bytes) -> tuple[int, int, bytes, int]:
    if len(packet) < 8 or not (packet[0] & 0x80):
        raise ValueError("not a QUIC long-header packet")
    version = int.from_bytes(packet[1:5], "big")
    if version not in _INITIAL_SALTS:
        raise ValueError("unsupported QUIC Initial version")
    type_bits = (packet[0] >> 4) & 0x03
    expected_initial = 1 if version == _QUIC_V2 else 0
    if type_bits != expected_initial:
        raise ValueError("packet is not a QUIC Initial")
    cursor = 5
    dcid_len = packet[cursor]
    cursor += 1
    if not (1 <= dcid_len <= 20) or cursor + dcid_len >= len(packet):
        raise ValueError("invalid QUIC Initial DCID")
    dcid = packet[cursor:cursor + dcid_len]
    cursor += dcid_len
    scid_len = packet[cursor]
    cursor += 1
    if scid_len > 20 or cursor + scid_len > len(packet):
        raise ValueError("invalid QUIC Initial SCID")
    cursor += scid_len
    token_length, cursor = quic_varint(packet, cursor)
    if token_length > len(packet) - cursor:
        raise ValueError("invalid QUIC Initial token length")
    cursor += token_length
    protected_length, pn_offset = quic_varint(packet, cursor)
    packet_end = pn_offset + protected_length
    if protected_length < 17 or packet_end > len(packet):
        raise ValueError("invalid QUIC Initial protected length")
    return version, pn_offset, dcid, packet_end


def _packet_number(truncated: int, pn_length: int, largest_packet_number: int) -> int:
    expected = max(0, int(largest_packet_number) + 1)
    window = 1 << (pn_length * 8)
    half = window // 2
    mask = window - 1
    candidate = (expected & ~mask) | truncated
    if candidate <= expected - half and candidate < (1 << 62) - window:
        candidate += window
    elif candidate > expected + half and candidate >= window:
        candidate -= window
    return candidate


def _nonce(iv: bytes, packet_number: int) -> bytes:
    pn = int(packet_number).to_bytes(len(iv), "big")
    return bytes(left ^ right for left, right in zip(iv, pn))


def _parse_initial_frames(plaintext: bytes) -> tuple[list[dict[str, Any]], bytes]:
    frames: list[dict[str, Any]] = []
    crypto_chunks: dict[int, bytes] = {}
    cursor = 0
    while cursor < len(plaintext) and len(frames) < MAX_INITIAL_FRAMES:
        frame_type, cursor = quic_varint(plaintext, cursor)
        if frame_type == 0x00:  # PADDING can be very long; collapse contiguous bytes.
            start = cursor - 1
            while cursor < len(plaintext) and plaintext[cursor] == 0:
                cursor += 1
            frames.append({"type": "PADDING", "length": cursor - start})
            continue
        if frame_type == 0x01:
            frames.append({"type": "PING"})
            continue
        if frame_type in {0x02, 0x03}:
            largest, cursor = quic_varint(plaintext, cursor)
            delay, cursor = quic_varint(plaintext, cursor)
            range_count, cursor = quic_varint(plaintext, cursor)
            first_range, cursor = quic_varint(plaintext, cursor)
            if range_count > 64:
                raise ValueError("QUIC Initial ACK range budget exceeded")
            ranges: list[dict[str, int]] = []
            for _index in range(range_count):
                gap, cursor = quic_varint(plaintext, cursor)
                ack_range, cursor = quic_varint(plaintext, cursor)
                ranges.append({"gap": gap, "ack_range": ack_range})
            ecn = None
            if frame_type == 0x03:
                ect0, cursor = quic_varint(plaintext, cursor)
                ect1, cursor = quic_varint(plaintext, cursor)
                ce, cursor = quic_varint(plaintext, cursor)
                ecn = {"ect0": ect0, "ect1": ect1, "ce": ce}
            frames.append({
                "type": "ACK_ECN" if frame_type == 0x03 else "ACK", "largest_acknowledged": largest,
                "ack_delay": delay, "first_ack_range": first_range, "ranges": ranges, "ecn": ecn,
            })
            continue
        if frame_type == 0x06:
            crypto_offset, cursor = quic_varint(plaintext, cursor)
            crypto_length, cursor = quic_varint(plaintext, cursor)
            if crypto_length > MAX_INITIAL_CRYPTO_BYTES or cursor + crypto_length > len(plaintext):
                raise ValueError("invalid QUIC Initial CRYPTO frame")
            chunk = plaintext[cursor:cursor + crypto_length]
            cursor += crypto_length
            crypto_chunks[crypto_offset] = chunk
            frames.append({"type": "CRYPTO", "offset": crypto_offset, "length": crypto_length})
            continue
        if frame_type in {0x1C, 0x1D}:
            error_code, cursor = quic_varint(plaintext, cursor)
            trigger = None
            if frame_type == 0x1C:
                trigger, cursor = quic_varint(plaintext, cursor)
            reason_length, cursor = quic_varint(plaintext, cursor)
            if reason_length > 4096 or cursor + reason_length > len(plaintext):
                raise ValueError("invalid QUIC CONNECTION_CLOSE reason")
            reason = plaintext[cursor:cursor + reason_length].decode("utf-8", errors="replace")[:4096]
            cursor += reason_length
            frames.append({"type": "CONNECTION_CLOSE", "error_code": error_code, "trigger_frame_type": trigger, "reason": reason})
            continue
        # Unknown frame types cannot be skipped without knowing their schema. Keep the
        # remaining bytes bounded and stop rather than guessing a length.
        frames.append({"type": f"0x{frame_type:x}", "unparsed_tail_bytes": len(plaintext) - cursor})
        break

    assembled = bytearray()
    expected = 0
    for offset in sorted(crypto_chunks):
        chunk = crypto_chunks[offset]
        if offset != expected or len(assembled) + len(chunk) > MAX_INITIAL_CRYPTO_BYTES:
            break
        assembled.extend(chunk)
        expected += len(chunk)
    return frames, bytes(assembled)


def decrypt_quic_initial(
    packet: bytes,
    *,
    role: str = "client",
    initial_destination_connection_id: bytes | None = None,
    largest_packet_number: int = -1,
) -> dict[str, Any]:
    """Remove v1/v2 Initial protection and parse bounded plaintext frames.

    For a client Initial, the packet's DCID is sufficient. For a server Initial, the
    caller must provide the client's original Initial DCID because the server's visible
    packet can carry a different destination connection ID.
    """

    raw = bytes(packet)
    if len(raw) > MAX_INITIAL_PACKET_BYTES:
        raise ValueError("QUIC Initial packet exceeds native analysis budget")
    if not (-1 <= int(largest_packet_number) < (1 << 62)):
        raise ValueError("largest QUIC packet number must be -1 or a 62-bit value")
    version, pn_offset, visible_dcid, packet_end = _initial_header_offsets(raw)
    direction = str(role).casefold()
    if direction == "server" and initial_destination_connection_id is None:
        raise ValueError("server Initial decryption requires the client Initial destination connection id")
    seed_dcid = visible_dcid if initial_destination_connection_id is None else bytes(initial_destination_connection_id)
    keys = derive_quic_initial_keys(version, seed_dcid, role=direction)

    sample_offset = pn_offset + 4
    if sample_offset + 16 > packet_end:
        raise ValueError("QUIC Initial packet is too short for header-protection sample")
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover - cryptography is a core Arenyxa dependency
        raise RuntimeError("cryptography is required for QUIC Initial analysis") from exc

    encryptor = Cipher(algorithms.AES(keys["hp"]), modes.ECB()).encryptor()
    mask = encryptor.update(raw[sample_offset:sample_offset + 16]) + encryptor.finalize()
    first = raw[0] ^ (mask[0] & 0x0F)
    pn_length = (first & 0x03) + 1
    if pn_offset + pn_length > packet_end:
        raise ValueError("invalid QUIC Initial packet-number length")
    pn_bytes = bytes(raw[pn_offset + index] ^ mask[index + 1] for index in range(pn_length))
    truncated = int.from_bytes(pn_bytes, "big")
    packet_number = _packet_number(truncated, pn_length, largest_packet_number)
    header = bytes((first,)) + raw[1:pn_offset] + pn_bytes
    ciphertext = raw[pn_offset + pn_length:packet_end]
    if len(ciphertext) < 16:
        raise ValueError("QUIC Initial ciphertext is shorter than the authentication tag")
    plaintext = AESGCM(keys["key"]).decrypt(_nonce(keys["iv"], packet_number), ciphertext, header)
    frames, crypto = _parse_initial_frames(plaintext)
    return {
        "version": f"0x{version:08x}",
        "version_name": "v1" if version == _QUIC_V1 else "v2",
        "role": direction,
        "packet_number": packet_number,
        "packet_number_length": pn_length,
        "initial_dcid": seed_dcid.hex(),
        "plaintext_bytes": len(plaintext),
        "frames": frames,
        "crypto_stream_bytes": crypto,
        "crypto_stream_sha256": hashlib.sha256(crypto).hexdigest() if crypto else "",
    }
