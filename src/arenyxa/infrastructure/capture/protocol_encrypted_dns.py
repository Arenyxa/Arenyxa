from __future__ import annotations

from typing import Any

from arenyxa.infrastructure.capture.protocol_dns import decode_dns_message

MAX_DNS_MESSAGE_BYTES = 65535
MAX_DNS_MESSAGES_PER_STREAM = 256


def decode_doh_body(data: bytes) -> dict[str, Any]:
    raw = bytes(data)
    if not raw or len(raw) > MAX_DNS_MESSAGE_BYTES:
        raise ValueError("DoH application/dns-message body must contain 1..65535 bytes")
    return {
        "schema": "arenyxa.doh-body/v1",
        "media_type": "application/dns-message",
        "body_bytes": len(raw),
        "dns": decode_dns_message(raw),
        "decrypted_http_body_required": True,
    }


def decode_doq_stream(data: bytes) -> dict[str, Any]:
    """Decode one already-decrypted DNS-over-QUIC stream direction.

    DoQ carries each DNS message with the same two-octet length prefix used by
    DNS-over-TCP.  This entry point deliberately accepts plaintext QUIC stream
    bytes only; it does not imply arbitrary QUIC payload decryption.
    """
    raw = bytes(data)
    cursor = 0
    messages: list[dict[str, Any]] = []
    for _ in range(MAX_DNS_MESSAGES_PER_STREAM):
        if cursor >= len(raw):
            break
        if cursor + 2 > len(raw):
            raise ValueError("truncated DoQ DNS length prefix")
        length = int.from_bytes(raw[cursor:cursor + 2], "big")
        cursor += 2
        if length <= 0 or length > MAX_DNS_MESSAGE_BYTES:
            raise ValueError("invalid DoQ DNS message length")
        if cursor + length > len(raw):
            raise ValueError("truncated DoQ DNS message")
        message = raw[cursor:cursor + length]
        cursor += length
        messages.append({"length": length, "dns": decode_dns_message(message)})
    if cursor != len(raw):
        raise ValueError("DoQ stream exceeds native message-count budget")
    return {
        "schema": "arenyxa.doq-stream/v1",
        "message_count": len(messages),
        "messages": messages,
        "bytes_consumed": cursor,
        "decrypted_quic_stream_required": True,
    }
