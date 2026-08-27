from __future__ import annotations

import hashlib
import ipaddress
import struct
from typing import Any


_BVLC_FUNCTIONS = {
    0x00: "result",
    0x01: "write-broadcast-distribution-table",
    0x02: "read-broadcast-distribution-table",
    0x03: "read-broadcast-distribution-table-ack",
    0x04: "forwarded-npdu",
    0x05: "register-foreign-device",
    0x06: "read-foreign-device-table",
    0x07: "read-foreign-device-table-ack",
    0x08: "delete-foreign-device-table-entry",
    0x09: "distribute-broadcast-to-network",
    0x0A: "original-unicast-npdu",
    0x0B: "original-broadcast-npdu",
}
_NETWORK_MESSAGES = {
    0x00: "who-is-router-to-network",
    0x01: "i-am-router-to-network",
    0x02: "i-could-be-router-to-network",
    0x03: "reject-message-to-network",
    0x04: "router-busy-to-network",
    0x05: "router-available-to-network",
    0x06: "initialize-routing-table",
    0x07: "initialize-routing-table-ack",
    0x08: "establish-connection-to-network",
    0x09: "disconnect-connection-to-network",
    0x12: "what-is-network-number",
    0x13: "network-number-is",
}
_CONFIRMED_SERVICES = {
    0: "acknowledge-alarm", 1: "confirmed-cov-notification", 2: "confirmed-event-notification",
    3: "get-alarm-summary", 4: "get-enrollment-summary", 5: "subscribe-cov", 6: "atomic-read-file",
    7: "atomic-write-file", 8: "add-list-element", 9: "remove-list-element", 10: "create-object",
    11: "delete-object", 12: "read-property", 13: "read-property-conditional", 14: "read-property-multiple",
    15: "write-property", 16: "write-property-multiple", 17: "device-communication-control",
    18: "confirmed-private-transfer", 19: "confirmed-text-message", 20: "reinitialize-device",
    21: "vt-open", 22: "vt-close", 23: "vt-data", 24: "authenticate", 25: "request-key",
    26: "read-range", 27: "life-safety-operation", 28: "subscribe-cov-property",
    29: "get-event-information", 30: "subscribe-cov-property-multiple", 31: "confirmed-cov-notification-multiple",
}
_UNCONFIRMED_SERVICES = {
    0: "i-am", 1: "i-have", 2: "unconfirmed-cov-notification", 3: "unconfirmed-event-notification",
    4: "unconfirmed-private-transfer", 5: "unconfirmed-text-message", 6: "time-synchronization",
    7: "who-has", 8: "who-is", 9: "utc-time-synchronization", 10: "write-group",
    11: "unconfirmed-cov-notification-multiple",
}
_PDU_TYPES = {
    0: "confirmed-request", 1: "unconfirmed-request", 2: "simple-ack", 3: "complex-ack",
    4: "segment-ack", 5: "error", 6: "reject", 7: "abort",
}


def _sha256(namespace: str, value: bytes) -> str:
    return hashlib.sha256(namespace.encode("ascii") + b"\x00" + value).hexdigest()


def _opaque_payload(namespace: str, value: bytes) -> dict[str, Any]:
    return {
        "payload_bytes": len(value),
        "payload_sha256": _sha256(namespace, value) if value else "",
        "payload_retained": False,
    }


def _address(value: bytes) -> str:
    if len(value) == 6:
        return f"{ipaddress.IPv4Address(value[:4])}:{struct.unpack_from('!H', value, 4)[0]}"
    return value.hex()


def _decode_apdu(data: bytes) -> dict[str, Any]:
    if not data:
        raise ValueError("empty BACnet APDU")
    pdu_type = data[0] >> 4
    flags = data[0] & 0x0F
    row: dict[str, Any] = {"pdu_type": pdu_type, "pdu_type_name": _PDU_TYPES.get(pdu_type, f"pdu-{pdu_type}"), "flags": flags}
    cursor = 1
    service: int | None = None
    if pdu_type == 0:
        if len(data) < 4:
            raise ValueError("truncated BACnet Confirmed-Request APDU")
        row.update({
            "segmented_message": bool(flags & 0x08),
            "more_follows": bool(flags & 0x04),
            "segmented_response_accepted": bool(flags & 0x02),
            "max_segments_max_apdu": data[1],
            "invoke_id": data[2],
        })
        cursor = 3
        if row["segmented_message"]:
            if len(data) < 6:
                raise ValueError("truncated segmented BACnet Confirmed-Request APDU")
            row.update({"sequence_number": data[3], "proposed_window_size": data[4]})
            cursor = 5
        service = data[cursor]
        cursor += 1
        row["service_name"] = _CONFIRMED_SERVICES.get(service, f"confirmed-service-{service}")
    elif pdu_type == 1:
        if len(data) < 2:
            raise ValueError("truncated BACnet Unconfirmed-Request APDU")
        service = data[1]
        cursor = 2
        row["service_name"] = _UNCONFIRMED_SERVICES.get(service, f"unconfirmed-service-{service}")
    elif pdu_type == 2:
        if len(data) < 3:
            raise ValueError("truncated BACnet Simple-ACK APDU")
        row.update({"invoke_id": data[1]})
        service = data[2]
        cursor = 3
        row["service_name"] = _CONFIRMED_SERVICES.get(service, f"confirmed-service-{service}")
    elif pdu_type == 3:
        if len(data) < 3:
            raise ValueError("truncated BACnet Complex-ACK APDU")
        row.update({"segmented_message": bool(flags & 0x08), "more_follows": bool(flags & 0x04), "invoke_id": data[1]})
        cursor = 2
        if row["segmented_message"]:
            if len(data) < 5:
                raise ValueError("truncated segmented BACnet Complex-ACK APDU")
            row.update({"sequence_number": data[2], "proposed_window_size": data[3]})
            cursor = 4
        service = data[cursor]
        cursor += 1
        row["service_name"] = _CONFIRMED_SERVICES.get(service, f"confirmed-service-{service}")
    elif pdu_type == 4:
        if len(data) < 4:
            raise ValueError("truncated BACnet Segment-ACK APDU")
        row.update({"negative_ack": bool(flags & 0x02), "server": bool(flags & 0x01), "invoke_id": data[1], "sequence_number": data[2], "actual_window_size": data[3]})
        cursor = 4
    elif pdu_type in {5, 6, 7}:
        if len(data) < 3:
            raise ValueError("truncated BACnet terminal APDU")
        row["invoke_id"] = data[1]
        if pdu_type == 5:
            service = data[2]
            row["service_name"] = _CONFIRMED_SERVICES.get(service, f"confirmed-service-{service}")
        elif pdu_type == 6:
            row["reject_reason"] = data[2]
        else:
            row.update({"server": bool(flags & 0x01), "abort_reason": data[2]})
        cursor = 3
    else:
        cursor = 1
    if service is not None:
        row["service_choice"] = service
    row.update(_opaque_payload("arenyxa-bacnet-apdu-body/v1", data[cursor:]))
    return row


def _decode_npdu(data: bytes) -> dict[str, Any]:
    if len(data) < 2:
        raise ValueError("truncated BACnet NPDU")
    version, control = data[0], data[1]
    cursor = 2
    row: dict[str, Any] = {
        "version": version,
        "control": control,
        "network_layer_message": bool(control & 0x80),
        "destination_specified": bool(control & 0x20),
        "source_specified": bool(control & 0x08),
        "expecting_reply": bool(control & 0x04),
        "priority": control & 0x03,
    }
    if row["destination_specified"]:
        if cursor + 3 > len(data):
            raise ValueError("truncated BACnet destination address")
        dnet = struct.unpack_from("!H", data, cursor)[0]
        dlen = data[cursor + 2]
        cursor += 3
        if cursor + dlen + 1 > len(data):
            raise ValueError("truncated BACnet destination address value")
        row.update({"destination_network": dnet, "destination_address": data[cursor:cursor + dlen].hex(), "hop_count": data[cursor + dlen]})
        cursor += dlen + 1
    if row["source_specified"]:
        if cursor + 3 > len(data):
            raise ValueError("truncated BACnet source address")
        snet = struct.unpack_from("!H", data, cursor)[0]
        slen = data[cursor + 2]
        cursor += 3
        if cursor + slen > len(data):
            raise ValueError("truncated BACnet source address value")
        row.update({"source_network": snet, "source_address": data[cursor:cursor + slen].hex()})
        cursor += slen
    if row["network_layer_message"]:
        if cursor >= len(data):
            raise ValueError("truncated BACnet network-layer message")
        message_type = data[cursor]
        cursor += 1
        row.update({"network_message_type": message_type, "network_message_name": _NETWORK_MESSAGES.get(message_type, f"network-message-{message_type}")})
        if message_type >= 0x80:
            if cursor + 2 > len(data):
                raise ValueError("truncated BACnet vendor network message")
            row["vendor_id"] = struct.unpack_from("!H", data, cursor)[0]
            cursor += 2
        row.update(_opaque_payload("arenyxa-bacnet-network-message/v1", data[cursor:]))
    else:
        row["apdu"] = _decode_apdu(data[cursor:])
    row["decoded_length"] = len(data)
    return row


def decode_bacnet_ip(data: bytes) -> dict[str, Any]:
    raw = bytes(data)
    if len(raw) < 4:
        raise ValueError("truncated BACnet/IP BVLC header")
    bvlc_type, function, declared_length = struct.unpack_from("!BBH", raw, 0)
    if declared_length < 4 or declared_length > len(raw):
        raise ValueError("invalid BACnet/IP BVLC length")
    body = raw[4:declared_length]
    row: dict[str, Any] = {
        "bvlc_type": bvlc_type,
        "bvlc_function": function,
        "bvlc_function_name": _BVLC_FUNCTIONS.get(function, f"function-0x{function:02x}"),
        "bvlc_length": declared_length,
        "decoded_length": declared_length,
        "trailing_bytes": len(raw) - declared_length,
    }
    if function == 0x00 and len(body) >= 2:
        row["result_code"] = struct.unpack_from("!H", body, 0)[0]
    elif function == 0x04:
        if len(body) < 6:
            raise ValueError("truncated BACnet/IP Forwarded-NPDU source")
        row["original_source"] = _address(body[:6])
        row["npdu"] = _decode_npdu(body[6:])
    elif function in {0x09, 0x0A, 0x0B}:
        row["npdu"] = _decode_npdu(body)
    elif function == 0x05 and len(body) >= 2:
        row["foreign_device_ttl_seconds"] = struct.unpack_from("!H", body, 0)[0]
    elif function == 0x08 and len(body) >= 6:
        row["foreign_device_address"] = _address(body[:6])
    elif body:
        row.update(_opaque_payload("arenyxa-bacnet-bvlc-body/v1", body))
    return row
