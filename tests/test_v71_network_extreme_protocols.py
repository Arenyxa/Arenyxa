from __future__ import annotations

import ipaddress
import struct

from arenyxa.infrastructure.capture.protocol_intelligence import ProtocolIntelligenceEngine


def _extension(kind: int, value: bytes) -> bytes:
    return struct.pack("!HH", kind, len(value)) + value


def _client_hello_record() -> bytes:
    random = bytes(range(32))
    ciphers = struct.pack("!HHH", 0x1301, 0x1302, 0xC02F)
    sni_name = b"example.com"
    sni = struct.pack("!H", 3 + len(sni_name)) + b"\x00" + struct.pack("!H", len(sni_name)) + sni_name
    alpn_value = b"\x00\x0c\x02h2\x08http/1.1"
    groups = b"\x00\x04\x00\x1d\x00\x17"
    points = b"\x01\x00"
    sigalgs = b"\x00\x04\x08\x04\x04\x03"
    versions = b"\x04\x03\x04\x03\x03"
    key_share = b"\x00\x08\x00\x1d\x00\x04abcd"
    extensions = b"".join((
        _extension(0, sni),
        _extension(10, groups),
        _extension(11, points),
        _extension(13, sigalgs),
        _extension(16, alpn_value),
        _extension(43, versions),
        _extension(51, key_share),
    ))
    hello = b"\x03\x03" + random + b"\x00" + struct.pack("!H", len(ciphers)) + ciphers + b"\x01\x00" + struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def _dns_response() -> bytes:
    # example.com A + AAAA, both using a compression pointer to the question name.
    header = struct.pack("!HHHHHH", 0xBEEF, 0x8180, 1, 2, 0, 0)
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    a = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ipaddress.IPv4Address("203.0.113.7").packed
    aaaa_raw = ipaddress.IPv6Address("2001:db8::7").packed
    aaaa = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 60, len(aaaa_raw)) + aaaa_raw
    return header + question + a + aaaa


def test_tls_client_hello_exposes_deep_fingerprint_and_negotiation_metadata() -> None:
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        _client_hello_record(), source_port=50000, destination_port=443, transport="tcp"
    )
    assert decoded.application_protocol == "tls"
    fields = decoded.layers[-1].fields
    assert fields["server_name"] == "example.com"
    assert fields["alpn"] == ["h2", "http/1.1"]
    assert "0x0304" in fields["supported_versions"]
    assert fields["key_share_groups"] == ["0x001d"]
    assert len(fields["ja3_md5"]) == 32
    assert len(fields["tls_semantic_sha256"]) == 64


def test_dns_decoder_exposes_bounded_resource_records() -> None:
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        _dns_response(), source_port=53, destination_port=53000, transport="udp"
    )
    fields = decoded.layers[-1].fields
    assert fields["question_records"][0]["name"] == "example.com"
    assert fields["answer_records"][0]["address"] == "203.0.113.7"
    assert fields["answer_records"][1]["address"] == "2001:db8::7"
    assert fields["answer_records"][1]["type_name"] == "AAAA"


def test_http2_preface_decodes_settings_frames() -> None:
    settings_payload = struct.pack("!HI", 0x3, 100)
    frame = len(settings_payload).to_bytes(3, "big") + b"\x04\x00" + b"\x00\x00\x00\x00" + settings_payload
    payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        payload, source_port=51000, destination_port=80, transport="tcp"
    )
    fields = decoded.layers[-1].fields
    assert decoded.application_protocol == "http2"
    assert fields["frame_count"] == 1
    assert fields["frames"][0]["type"] == "SETTINGS"
    assert fields["frames"][0]["settings"][0] == {"id": 3, "value": 100}


def test_quic_v1_initial_header_decodes_connection_ids_and_length() -> None:
    payload = (
        b"\xc0" + b"\x00\x00\x00\x01" + b"\x08" + b"12345678" + b"\x04" + b"abcd" +
        b"\x00" + b"\x01" + b"\x00"
    )
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        payload, source_port=51000, destination_port=443, transport="udp"
    )
    fields = decoded.layers[-1].fields
    assert decoded.application_protocol == "quic"
    assert decoded.encrypted is True
    assert fields["version_name"] == "v1"
    assert fields["packet_type"] == "Initial"
    assert fields["destination_connection_id"] == b"12345678".hex()
    assert fields["source_connection_id"] == b"abcd".hex()


def test_decrypted_http3_stream_decodes_settings_without_claiming_quic_decryption() -> None:
    decoded = ProtocolIntelligenceEngine().decode_http3_stream(b"\x04\x02\x01\x20")
    assert decoded.application_protocol == "http3"
    assert decoded.encrypted is False
    fields = decoded.layers[-1].fields
    assert fields["decrypted_stream"] is True
    assert fields["frames"][0]["type"] == "SETTINGS"
    assert fields["frames"][0]["settings"][0]["name"] == "QPACK_MAX_TABLE_CAPACITY"


def test_protocol_expert_reports_dns_error_and_tls_legacy_offer_without_false_negotiation_claim() -> None:
    dns = bytearray(_dns_response())
    # Set SERVFAIL (rcode 2) while keeping this a response.
    flags = int.from_bytes(dns[2:4], "big")
    dns[2:4] = ((flags & 0xFFF0) | 2).to_bytes(2, "big")
    decoded_dns = ProtocolIntelligenceEngine().decode_application_payload(
        bytes(dns), source_port=53, destination_port=53000, transport="udp"
    )
    dns_findings = ProtocolIntelligenceEngine.expert_findings(decoded_dns)
    assert any(row["code"] == "DNS_NONZERO_RCODE" and row["severity"] == "warning" for row in dns_findings)

    decoded_tls = ProtocolIntelligenceEngine().decode_application_payload(
        _client_hello_record(), source_port=50000, destination_port=443, transport="tcp"
    )
    tls_findings = ProtocolIntelligenceEngine.expert_findings(decoded_tls)
    weak = [row for row in tls_findings if row["code"] == "TLS_WEAK_CIPHER_OFFERED"]
    assert weak == []  # the fixture offers only modern suites


def test_packet_protocol_coverage_is_graded_and_native_deep_is_explicit() -> None:
    from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine

    coverage = PacketAnalysisEngine("").protocol_coverage()
    assert coverage["external_available"] is False
    assert coverage["native_protocol_count"] >= 80
    assert coverage["native_deep_count"] >= 10
    assert coverage["native_deep_count"] + coverage["native_metadata_count"] == coverage["native_protocol_count"]
    assert set(coverage["native_deep_protocols"]) <= set(coverage["native_protocols"])
    assert {"dns", "tls", "http2", "http3", "quic"}.issubset(set(coverage["native_deep_protocols"]))
    assert set(coverage["coverage_model"]) == {"native-deep", "structured-metadata", "external-deep"}


def test_linux_sll2_link_layer_is_not_double_decoded() -> None:
    # SLL2 header + minimal IPv4/UDP header. The test targets the link dispatch contract,
    # not checksum validation.
    sll2 = struct.pack("!HHIHB", 0x0800, 0, 1, 1, 0) + b"\x00" + b"\x00" * 8
    ipv4 = b"\x45\x00\x00\x1c\x00\x01\x00\x00\x40\x11\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
    udp = struct.pack("!HHHH", 50000, 50001, 8, 0)
    decoded = ProtocolIntelligenceEngine().decode_frame(sll2 + ipv4 + udp, link_type="linux-sll2")
    assert [layer.name for layer in decoded.layers].count("linux-sll2") == 1


def _dns_https_response() -> bytes:
    header = struct.pack("!HHHHHH", 0xCAFE, 0x8180, 1, 1, 0, 0)
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 65, 1)
    target = b"\x03svc\x07example\x03com\x00"
    alpn = b"\x02h2\x02h3"
    params = (
        struct.pack("!HH", 1, len(alpn)) + alpn
        + struct.pack("!HHH", 3, 2, 8443)
        + struct.pack("!HH", 4, 4) + ipaddress.IPv4Address("192.0.2.50").packed
        + struct.pack("!HH", 6, 16) + ipaddress.IPv6Address("2001:db8::50").packed
        + struct.pack("!HH", 7, len(b"/dns-query{?dns}")) + b"/dns-query{?dns}"
    )
    rdata = struct.pack("!H", 1) + target + params
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 65, 1, 60, len(rdata)) + rdata
    return header + question + answer


def test_dns_https_svcb_parameters_expose_modern_service_binding_metadata() -> None:
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        _dns_https_response(), source_port=53, destination_port=54000, transport="udp"
    )
    https = decoded.layers[-1].fields["answer_records"][0]
    assert https["type_name"] == "HTTPS"
    assert https["priority"] == 1
    assert https["target"] == "svc.example.com"
    params = {row["name"]: row for row in https["service_parameters"]}
    assert params["alpn"]["alpn"] == ["h2", "h3"]
    assert params["port"]["port"] == 8443
    assert params["ipv4hint"]["ipv4_hints"] == ["192.0.2.50"]
    assert params["ipv6hint"]["ipv6_hints"] == ["2001:db8::50"]
    assert params["dohpath"]["text"] == "/dns-query{?dns}"


def test_tls12_certificate_handshake_exposes_x509_fingerprints_and_san() -> None:
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    private = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(private.public_key())
        .serial_number(42).not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.test")]), critical=False)
        .sign(private, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    body = (3 + len(der)).to_bytes(3, "big") + len(der).to_bytes(3, "big") + der
    handshake = b"\x0b" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        record, source_port=443, destination_port=55000, transport="tcp"
    )
    fields = decoded.layers[-1].fields
    assert fields["certificate_count"] == 1
    first = fields["certificate_chain"][0]
    assert first["san_dns"] == ["example.test"]
    assert len(first["sha256"]) == 64
    assert len(first["spki_sha256"]) == 64


def _qvar(value: int) -> bytes:
    if 0 <= value < 64:
        return bytes((value,))
    if value < 16384:
        return (0x4000 | value).to_bytes(2, "big")
    raise ValueError("test varint too large")


def _synthetic_protected_quic_v1_initial() -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    dcid = bytes.fromhex("8394c8f03e515708")
    key = bytes.fromhex("1f369613dd76d5467730efcbe3b1a22d")
    iv = bytes.fromhex("fa044b2f42a3fd3b46fb255c")
    hp = bytes.fromhex("9f50449e04a0e810283a1e9933adedd2")
    packet_number = 2
    pn = packet_number.to_bytes(2, "big")
    crypto = b"\x01\x00\x00\x04test"
    plaintext = b"\x06\x00" + _qvar(len(crypto)) + crypto + b"\x00" * 8
    protected_length = len(pn) + len(plaintext) + 16
    first = 0xC1  # v1 Initial, 2-byte packet number
    prefix = bytes((first,)) + b"\x00\x00\x00\x01" + b"\x08" + dcid + b"\x00" + b"\x00" + _qvar(protected_length)
    header = prefix + pn
    nonce = bytes(left ^ right for left, right in zip(iv, packet_number.to_bytes(12, "big")))
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, header)
    packet = bytearray(header + ciphertext)
    pn_offset = len(prefix)
    sample = bytes(packet[pn_offset + 4:pn_offset + 20])
    encryptor = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()
    packet[0] ^= mask[0] & 0x0F
    for index in range(len(pn)):
        packet[pn_offset + index] ^= mask[index + 1]
    return bytes(packet)


def test_quic_initial_key_derivation_matches_standard_v1_and_v2_vectors() -> None:
    from arenyxa.infrastructure.capture.protocol_quic_initial import derive_quic_initial_keys

    dcid = bytes.fromhex("8394c8f03e515708")
    v1 = derive_quic_initial_keys(0x00000001, dcid, role="client")
    assert v1["key"].hex() == "1f369613dd76d5467730efcbe3b1a22d"
    assert v1["iv"].hex() == "fa044b2f42a3fd3b46fb255c"
    assert v1["hp"].hex() == "9f50449e04a0e810283a1e9933adedd2"
    v2 = derive_quic_initial_keys(0x6B3343CF, dcid, role="client")
    assert v2["key"].hex() == "8b1a0bc121284290a29e0971b5cd045d"
    assert v2["iv"].hex() == "91f73e2351d8fa91660e909f"
    assert v2["hp"].hex() == "45b95e15235d6f45a6b19cbcb0294ba9"


def test_native_quic_v1_initial_can_remove_public_initial_protection_and_parse_crypto_frame() -> None:
    from arenyxa.infrastructure.capture.protocol_quic_initial import decrypt_quic_initial

    packet = _synthetic_protected_quic_v1_initial()
    opened = decrypt_quic_initial(packet, role="client")
    assert opened["packet_number"] == 2
    assert opened["version_name"] == "v1"
    assert opened["frames"][0] == {"type": "CRYPTO", "offset": 0, "length": 8}
    assert opened["crypto_stream_bytes"] == b"\x01\x00\x00\x04test"

    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        packet, source_port=55000, destination_port=443, transport="udp"
    )
    fields = decoded.layers[-1].fields
    assert fields["packet_type"] == "Initial"
    assert fields["initial_decryption"]["packet_number"] == 2
    assert fields["initial_decryption"]["crypto_stream_sha256"]


def _h2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    return len(payload).to_bytes(3, "big") + bytes((frame_type, flags)) + (stream_id & 0x7FFFFFFF).to_bytes(4, "big") + payload


def test_http2_stream_hpack_headers_and_grpc_envelope() -> None:
    from hpack import Encoder
    from arenyxa.infrastructure.capture.protocol_intelligence import ProtocolIntelligenceEngine

    encoder = Encoder()
    request_headers = encoder.encode([
        (b":method", b"POST"),
        (b":scheme", b"https"),
        (b":authority", b"api.example.test"),
        (b":path", b"/telemetry.Trace/Push"),
        (b"content-type", b"application/grpc"),
        (b"te", b"trailers"),
    ])
    # Split a single HPACK block over HEADERS + CONTINUATION to exercise reconstruction.
    pivot = max(1, len(request_headers) // 2)
    message = b"bounded-grpc-payload"
    grpc_data = b"\x00" + len(message).to_bytes(4, "big") + message
    raw = (
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        + _h2_frame(0x1, 0x00, 1, request_headers[:pivot])
        + _h2_frame(0x9, 0x04, 1, request_headers[pivot:])
        + _h2_frame(0x0, 0x01, 1, grpc_data)
    )
    decoded = ProtocolIntelligenceEngine().decode_http2_stream(raw)
    assert decoded["client_preface"] is True
    assert decoded["hpack_stateful"] is True
    stream = decoded["streams"][0]
    assert stream["method"] == "POST"
    assert stream["authority"] == "api.example.test"
    assert stream["grpc"] is True
    assert stream["grpc_message_count"] == 1
    data = decoded["frames"][-1]
    assert data["grpc_messages"][0]["length"] == len(message)
    assert data["grpc_messages"][0]["sha256"] == __import__("hashlib").sha256(message).hexdigest()
    assert message.decode() not in str(decoded)


def test_http2_stream_rejects_interleaved_header_blocks() -> None:
    from hpack import Encoder
    from arenyxa.infrastructure.capture.protocol_intelligence import ProtocolIntelligenceEngine

    block = Encoder().encode([(b":method", b"GET"), (b":path", b"/")])
    raw = _h2_frame(0x1, 0x00, 1, block[:1]) + _h2_frame(0x1, 0x04, 3, block)
    decoded = ProtocolIntelligenceEngine().decode_http2_stream(raw)
    assert decoded["frames"][1]["protocol_error"] == "header-block-interleaving"


def test_websocket_identified_stream_decodes_masked_frame_without_retaining_payload() -> None:
    import hashlib
    from arenyxa.infrastructure.capture.protocol_intelligence import ProtocolIntelligenceEngine

    payload = b"sensitive-websocket-message"
    mask = b"\x11\x22\x33\x44"
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    raw = bytes((0x81, 0x80 | len(payload))) + mask + masked
    decoded = ProtocolIntelligenceEngine().decode_websocket_stream(raw)
    frame = decoded["frames"][0]
    assert frame["type"] == "text"
    assert frame["masked"] is True
    assert frame["payload_sha256"] == hashlib.sha256(payload).hexdigest()
    assert payload.decode() not in str(decoded)
    assert decoded["payload_retained"] is False


def test_packet_forensics_correlates_dns_latency_and_tls_fingerprints() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets
    from arenyxa.infrastructure.capture.packet_models import PacketRecord

    def packet(number, timestamp, source, destination, protocol, layers):
        return PacketRecord(
            frame_number=number, timestamp=timestamp, length=100, captured_length=100,
            protocols=protocol, protocol=protocol.split(":")[-1], info="", source=source,
            destination=destination, source_port=53000 if source == "10.0.0.1" else 53,
            destination_port=53 if destination == "8.8.8.8" else 53000,
            tcp_stream=None, udp_stream=None, http2_stream=None, quic_stream=None,
            host="example.test", method="", uri="", status=None, metadata={"native_layers": layers},
        )

    query = packet(1, "2026-08-20T00:00:00+00:00", "10.0.0.1", "8.8.8.8", "udp:dns", [{
        "name": "dns", "fields": {"transaction_id": 7, "response": False, "rcode": 0,
        "question_records": [{"name": "example.test", "type_name": "A"}]},
    }])
    response = packet(2, "2026-08-20T00:00:00.025000+00:00", "8.8.8.8", "10.0.0.1", "udp:dns", [{
        "name": "dns", "fields": {"transaction_id": 7, "response": True, "rcode": 0,
        "question_records": [{"name": "example.test", "type_name": "A"}]},
    }])
    tls = packet(3, "2026-08-20T00:00:01+00:00", "10.0.0.1", "1.1.1.1", "tcp:tls", [{
        "name": "tls", "fields": {"ja3_md5": "abc", "server_name": "service.test", "alpn_protocols": ["h2"]},
    }])
    summary = forensic_summary_from_packets([query, response, tls])
    assert summary["dns"]["completed_transactions"] == 1
    assert summary["dns"]["latency_ms"]["p50"] == 25.0
    assert summary["tls"]["client_fingerprints"]["abc"] == 1
    assert summary["tls"]["alpn"]["h2"] == 1


def test_packet_forensics_tcp_syn_fingerprint_and_arp_conflict_are_evidence_based() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets
    from arenyxa.infrastructure.capture.packet_models import PacketRecord

    def row(number, mac, syn=False):
        layers = [
            {"name": "arp", "fields": {"sender_ip": "10.0.0.5", "sender_mac": mac}},
            {"name": "ipv4", "fields": {"ttl": 64}},
        ]
        protocols = "ethernet:arp"
        if syn:
            layers.append({"name": "tcp", "fields": {
                "flags": ["syn"], "window": 64240,
                "options": [
                    {"kind": 2, "name": "mss", "value": 1460},
                    {"kind": 4, "name": "sack-permitted"},
                    {"kind": 3, "name": "window-scale", "value": 7},
                ],
            }})
            protocols = "ethernet:ipv4:tcp"
        return PacketRecord(
            frame_number=number, timestamp="2026-08-20T00:00:00+00:00", length=64, captured_length=64,
            protocols=protocols, protocol=protocols.split(":")[-1], info="", source="10.0.0.5", destination="10.0.0.1",
            source_port=1234 if syn else None, destination_port=443 if syn else None,
            tcp_stream=None, udp_stream=None, http2_stream=None, quic_stream=None, host="", method="", uri="", status=None,
            metadata={"native_layers": layers},
        )

    summary = forensic_summary_from_packets([row(1, "00:11:22:33:44:55", True), row(2, "66:77:88:99:aa:bb")])
    assert len(summary["tcp_syn_fingerprints"]) == 1
    fp = summary["tcp_syn_fingerprints"][0]
    assert fp["mss"] == 1460 and fp["window_scale"] == 7 and fp["sack_permitted"] is True
    assert len(fp["fingerprint_sha256"]) == 64
    assert summary["layer2"]["arp_binding_conflicts"][0]["ip"] == "10.0.0.5"


def test_bgp_open_and_update_expose_capabilities_path_attributes_and_nlri() -> None:
    engine = ProtocolIntelligenceEngine()
    asn4 = 4200000000
    capabilities = b"\x02\x06" + b"\x41\x04" + struct.pack("!I", asn4)
    open_body = struct.pack("!BHHIB", 4, 64512, 90, int(ipaddress.IPv4Address("192.0.2.1")), len(capabilities)) + capabilities
    open_packet = b"\xff" * 16 + struct.pack("!HB", 19 + len(open_body), 1) + open_body
    opened = engine.decode_application_payload(open_packet, source_port=50000, destination_port=179, transport="tcp")
    open_fields = opened.layers[-1].fields
    assert open_fields["message_name"] == "open"
    assert open_fields["bgp_identifier"] == "192.0.2.1"
    assert open_fields["capabilities"][0]["name"] == "four-octet-asn"
    assert open_fields["capabilities"][0]["asn4"] == asn4

    origin = b"\x40\x01\x01\x00"
    next_hop = b"\x40\x03\x04" + ipaddress.IPv4Address("198.51.100.1").packed
    local_pref = b"\x40\x05\x04" + struct.pack("!I", 200)
    attrs = origin + next_hop + local_pref
    nlri = b"\x18" + ipaddress.IPv4Address("203.0.113.0").packed[:3]
    update_body = b"\x00\x00" + struct.pack("!H", len(attrs)) + attrs + nlri
    update_packet = b"\xff" * 16 + struct.pack("!HB", 19 + len(update_body), 2) + update_body
    updated = engine.decode_application_payload(update_packet, source_port=179, destination_port=50000, transport="tcp")
    update_fields = updated.layers[-1].fields
    attrs_by_name = {row["name"]: row for row in update_fields["path_attributes"]}
    assert update_fields["nlri"] == ["203.0.113.0/24"]
    assert attrs_by_name["ORIGIN"]["origin"] == "igp"
    assert attrs_by_name["NEXT_HOP"]["next_hop"] == "198.51.100.1"
    assert attrs_by_name["LOCAL_PREF"]["value"] == 200


def test_mqtt_v5_connect_and_publish_decode_without_retaining_business_payload() -> None:
    engine = ProtocolIntelligenceEngine()
    body = b"\x00\x04MQTT" + b"\x05\x02" + struct.pack("!H", 60) + b"\x00" + b"\x00\x03abc"
    connect = bytes((0x10, len(body))) + body
    decoded = engine.decode_application_payload(connect, source_port=50000, destination_port=1883, transport="tcp")
    fields = decoded.layers[-1].fields
    assert fields["packet_name"] == "CONNECT"
    assert fields["protocol_level"] == 5
    assert fields["clean_start"] is True
    assert fields["client_id_bytes"] == 3
    assert len(fields["client_id_sha256"]) == 64
    assert "client_id" not in fields

    topic = b"plant/line1/temperature"
    payload = b"42.5"
    publish_body = struct.pack("!H", len(topic)) + topic + payload
    publish = bytes((0x30, len(publish_body))) + publish_body
    published = engine.decode_application_payload(publish, source_port=50000, destination_port=1883, transport="tcp")
    pub_fields = published.layers[-1].fields
    assert pub_fields["packet_name"] == "PUBLISH"
    assert pub_fields["payload_bytes"] == len(payload)
    assert len(pub_fields["payload_sha256"]) == 64
    assert "payload" not in pub_fields
    assert "topic" not in pub_fields


def test_modbus_iec104_and_dnp3_expose_bounded_control_metadata() -> None:
    engine = ProtocolIntelligenceEngine()
    modbus = struct.pack("!HHHB", 7, 0, 6, 1) + b"\x03" + struct.pack("!HH", 100, 10)
    modbus_decoded = engine.decode_application_payload(modbus, source_port=50000, destination_port=502, transport="tcp")
    modbus_fields = modbus_decoded.layers[-1].fields
    assert modbus_fields["function_name"] == "read-holding-registers"
    assert modbus_fields["address"] == 100
    assert modbus_fields["quantity_or_value"] == 10

    # I-format frame: send sequence 1, receive sequence 2, General Interrogation ASDU.
    iec = b"\x68\x0a\x02\x00\x04\x00" + bytes((100, 1)) + struct.pack("<HH", 6, 1)
    iec_decoded = engine.decode_application_payload(iec, source_port=50000, destination_port=2404, transport="tcp")
    iec_fields = iec_decoded.layers[-1].fields
    assert iec_fields["frame_kind"] == "i"
    assert iec_fields["send_sequence"] == 1
    assert iec_fields["receive_sequence"] == 2
    assert iec_fields["asdu_type"] == "C_IC_NA_1"
    assert iec_fields["cause_of_transmission"] == 6

    # Link CRC bytes are present but deliberately not claimed as verified by the native fast path.
    dnp = b"\x05\x64\x05\xc4\x01\x00\x02\x00\x00\x00\xc1\xc2\x01"
    dnp_decoded = engine.decode_application_payload(dnp, source_port=50000, destination_port=20000, transport="tcp")
    dnp_fields = dnp_decoded.layers[-1].fields
    assert dnp_fields["direction"] == "from-master"
    assert dnp_fields["transport_first"] is True
    assert dnp_fields["transport_final"] is True
    assert dnp_fields["crc_verified"] is False
    findings = engine.expert_findings(dnp_decoded)
    assert any(row["code"] == "DNP3_CRC_NOT_VERIFIED_NATIVE" for row in findings)


def test_sctp_chunks_decode_init_data_and_sack_semantics() -> None:
    from arenyxa.infrastructure.capture.protocol_deep_application import decode_sctp_chunks

    common = struct.pack("!HHII", 5000, 5001, 0x11223344, 0)
    init_body = struct.pack("!IIHHI", 0xAABBCCDD, 65535, 10, 10, 1234)
    init = struct.pack("!BBH", 1, 0, 20) + init_body
    data_body = struct.pack("!IHHI", 1234, 3, 4, 51) + b"hello"
    data_chunk = struct.pack("!BBH", 0, 3, 4 + len(data_body)) + data_body
    data_chunk += b"\x00" * ((-len(data_chunk)) % 4)
    sack_body = struct.pack("!IIHH", 1234, 32768, 0, 0)
    sack = struct.pack("!BBH", 3, 0, 16) + sack_body
    chunks = decode_sctp_chunks(common + init + data_chunk + sack, 12)
    assert [row["name"] for row in chunks] == ["INIT", "DATA", "SACK"]
    assert chunks[0]["outbound_streams"] == 10
    assert chunks[1]["stream_id"] == 3
    assert chunks[1]["beginning"] is True and chunks[1]["ending"] is True
    assert chunks[2]["cumulative_tsn_ack"] == 1234


def test_coverage_promotes_routing_messaging_transport_and_ot_protocols_to_native_deep() -> None:
    from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine

    deep = set(PacketAnalysisEngine("").protocol_coverage()["native_deep_protocols"])
    assert {"bgp", "sctp", "mqtt", "modbus-tcp", "iec104", "dnp3"}.issubset(deep)


def test_forensic_tls_correlates_client_sni_with_visible_certificate_san() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets
    from arenyxa.infrastructure.capture.packet_models import PacketRecord

    def packet(number: int, source: str, destination: str, source_port: int, destination_port: int, fields: dict) -> PacketRecord:
        return PacketRecord(
            frame_number=number,
            timestamp=f"2026-08-20T00:00:0{number}+00:00",
            length=100,
            captured_length=100,
            protocols="eth:ip:tcp:tls",
            protocol="TLS",
            info="",
            source=source,
            destination=destination,
            source_port=source_port,
            destination_port=destination_port,
            tcp_stream=1,
            udp_stream=None,
            http2_stream=None,
            quic_stream=None,
            host="",
            method="",
            uri="",
            status=None,
            metadata={"native_layers": [{"name": "tls", "fields": fields}]},
        )

    client = packet(1, "10.0.0.10", "203.0.113.5", 55000, 443, {
        "handshake_type": 1,
        "server_name": "api.example.test",
        "ja3_md5": "a" * 32,
        "alpn_protocols": ["h2"],
    })
    server = packet(2, "203.0.113.5", "10.0.0.10", 443, 55000, {
        "handshake_type": 11,
        "certificate_chain": [{
            "san_dns": ["*.example.test"],
            "sha256": "b" * 64,
            "spki_sha256": "c" * 64,
            "not_valid_after": "2027-01-01T00:00:00+00:00",
        }],
    })
    summary = forensic_summary_from_packets([client, server])
    session = summary["tls"]["certificate_sessions"][0]
    assert session["server_name"] == "api.example.test"
    assert session["name_match"] is True
    assert summary["tls"]["certificate_name_mismatches"] == 0

    mismatch_server = packet(3, "203.0.113.5", "10.0.0.10", 443, 55000, {
        "handshake_type": 11,
        "certificate_chain": [{"san_dns": ["other.example.net"], "sha256": "d" * 64}],
    })
    mismatch = forensic_summary_from_packets([client, mismatch_server])
    assert mismatch["tls"]["certificate_name_mismatches"] == 1
    assert mismatch["tls"]["certificate_sessions"][0]["name_match"] is False


def test_ssh_kexinit_exposes_algorithm_negotiation_and_semantic_fingerprint() -> None:
    engine = ProtocolIntelligenceEngine()
    lists = [
        "curve25519-sha256,diffie-hellman-group1-sha1",
        "ssh-ed25519,ssh-dss",
        "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
        "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-256",
        "none",
        "none",
        "",
        "",
    ]
    payload = bytearray(b"\x14" + bytes(range(16)))
    for value in lists:
        raw = value.encode("ascii")
        payload += struct.pack("!I", len(raw)) + raw
    payload += b"\x00" + b"\x00\x00\x00\x00"
    padding = b"\x00" * 8
    packet_length = 1 + len(payload) + len(padding)
    packet = struct.pack("!I", packet_length) + bytes((len(padding),)) + bytes(payload) + padding
    decoded = engine.decode_application_payload(packet, source_port=50000, destination_port=22, transport="tcp")
    fields = decoded.layers[-1].fields
    assert decoded.application_protocol == "ssh"
    assert fields["message"] == "KEXINIT"
    assert fields["kex_algorithms"][0] == "curve25519-sha256"
    assert len(fields["ssh_algorithm_fingerprint_sha256"]) == 64
    findings = engine.expert_findings(decoded)
    codes = {row["code"] for row in findings}
    assert "SSH_LEGACY_KEX_OFFERED" in codes
    assert "SSH_LEGACY_HOSTKEY_OFFERED" in codes


def _h2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    return len(payload).to_bytes(3, "big") + bytes((frame_type, flags)) + (stream_id & 0x7FFFFFFF).to_bytes(4, "big") + payload


def test_http2_grpc_reassembly_spans_data_frames_and_strips_padding() -> None:
    from hpack import Encoder

    block = Encoder().encode([
        (b":method", b"POST"),
        (b":scheme", b"https"),
        (b":authority", b"svc.example"),
        (b":path", b"/demo.Service/Call"),
        (b"content-type", b"application/grpc"),
    ])
    headers = _h2_frame(1, 0x04, 1, block)
    envelope = b"\x00" + (11).to_bytes(4, "big") + b"hello world"
    first = _h2_frame(0, 0, 1, envelope[:7])
    # PADDED DATA: one pad-length octet, body suffix, then two padding octets.
    second = _h2_frame(0, 0x09, 1, b"\x02" + envelope[7:] + b"\x00\x00")
    decoded = ProtocolIntelligenceEngine().decode_http2_stream(headers + first + second)
    summary = decoded["streams"][0]
    assert summary["grpc"] is True
    assert summary["grpc_message_count"] == 1
    assert summary["grpc_payload_bytes"] == 11
    assert summary["grpc_pending_bytes"] == 0
    assert decoded["frames"][-1]["grpc_messages"][0]["length"] == 11


def test_http2_doh_decrypted_body_is_decoded_only_after_end_stream() -> None:
    from hpack import Encoder

    block = Encoder().encode([
        (b":method", b"POST"),
        (b":scheme", b"https"),
        (b":authority", b"resolver.example"),
        (b":path", b"/dns-query"),
        (b"content-type", b"application/dns-message"),
    ])
    headers = _h2_frame(1, 0x04, 3, block)
    dns = _dns_response()
    first = _h2_frame(0, 0, 3, dns[:15])
    second = _h2_frame(0, 0x01, 3, dns[15:])
    decoded = ProtocolIntelligenceEngine().decode_http2_stream(headers + first + second)
    summary = decoded["streams"][0]
    assert summary["doh"] is True
    assert summary["doh_dns"]["transaction_id"] == 0xBEEF
    assert summary["doh_dns"]["answer_records"][0]["address"] == "203.0.113.7"
    assert decoded["pending_doh_streams"] == {}


def test_doh_body_and_doq_plaintext_stream_reuse_bounded_dns_wire_decoder() -> None:
    engine = ProtocolIntelligenceEngine()
    dns = _dns_response()
    doh = engine.decode_doh_body(dns)
    assert doh["media_type"] == "application/dns-message"
    assert doh["dns"]["transaction_id"] == 0xBEEF
    assert doh["decrypted_http_body_required"] is True

    doq = engine.decode_doq_stream(len(dns).to_bytes(2, "big") + dns)
    assert doq["message_count"] == 1
    assert doq["messages"][0]["dns"]["answer_records"][1]["type_name"] == "AAAA"
    assert doq["decrypted_quic_stream_required"] is True


def test_protocol_coverage_includes_encrypted_dns_transports_without_claiming_dot_decryption() -> None:
    from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine

    coverage = PacketAnalysisEngine("").protocol_coverage()
    native = set(coverage["native_protocols"])
    deep = set(coverage["native_deep_protocols"])
    assert {"doh", "dot", "doq"}.issubset(native)
    assert {"doh", "doq"}.issubset(deep)
    assert "dot" not in deep  # TLS metadata is native; DNS plaintext is not visible without decryption.
    assert "doq-decrypted-stream" in coverage["stream_deep_decoders"]


def _ipv6_srh_frame(*, segments_left: int = 0) -> bytes:
    source = ipaddress.IPv6Address("2001:db8::1").packed
    destination = ipaddress.IPv6Address("2001:db8::100").packed
    sid = ipaddress.IPv6Address("2001:db8:1::dead").packed
    # Next Header=UDP, Hdr Ext Len=2 => 24 octets total, Routing Type=4.
    srh = bytes((17, 2, 4, segments_left, 0, 0)) + struct.pack("!H", 123) + sid
    udp = struct.pack("!HHHH", 12345, 54321, 8, 0)
    ipv6 = struct.pack("!IHBB", 6 << 28, len(srh) + len(udp), 43, 64) + source + destination
    ethernet = bytes.fromhex("00112233445566778899aabb86dd")
    return ethernet + ipv6 + srh + udp


def test_srv6_segment_routing_header_exposes_sids_active_segment_and_bounds() -> None:
    engine = ProtocolIntelligenceEngine()
    decoded = engine.decode_frame(_ipv6_srh_frame(), link_type="ethernet")
    routing = next(layer.fields for layer in decoded.layers if layer.name == "ipv6-routing")
    assert routing["routing_type"] == 4
    assert routing["segment_routing_header"] is True
    assert routing["segment_list"] == ["2001:db8:1::dead"]
    assert routing["active_segment"] == "2001:db8:1::dead"
    assert routing["tag"] == 123
    assert "udp" in decoded.protocols

    invalid = engine.decode_frame(_ipv6_srh_frame(segments_left=1), link_type="ethernet")
    findings = engine.expert_findings(invalid)
    assert any(row["code"] == "SRV6_SEGMENTS_LEFT_INVALID" for row in findings)


def _ipv6_icmp_frame(payload: bytes, *, source: str = "fe80::1", destination: str = "ff02::1") -> bytes:
    ipv6 = struct.pack("!IHBB", 6 << 28, len(payload), 58, 255) + ipaddress.IPv6Address(source).packed + ipaddress.IPv6Address(destination).packed
    return bytes.fromhex("33330000000166778899aabb86dd") + ipv6 + payload


def test_icmpv6_router_advertisement_decodes_prefix_mtu_rdnss_and_dnssl_options() -> None:
    prefix = (
        bytes((3, 4, 64, 0xC0))
        + struct.pack("!II", 7200, 3600)
        + b"\x00\x00\x00\x00"
        + ipaddress.IPv6Address("2001:db8:100::").packed
    )
    mtu = bytes((5, 1, 0, 0)) + struct.pack("!I", 1500)
    rdnss = bytes((25, 3, 0, 0)) + struct.pack("!I", 1200) + ipaddress.IPv6Address("2001:4860:4860::8888").packed
    domain = b"\x07example\x03com\x00"
    dnssl_value = b"\x00\x00" + struct.pack("!I", 1200) + domain
    dnssl_value += b"\x00" * ((-(2 + len(dnssl_value))) % 8)
    dnssl = bytes((31, (2 + len(dnssl_value)) // 8)) + dnssl_value
    ra = b"\x86\x00\x00\x00" + bytes((64, 0xC0)) + struct.pack("!HII", 1800, 0, 0) + prefix + mtu + rdnss + dnssl
    decoded = ProtocolIntelligenceEngine().decode_frame(_ipv6_icmp_frame(ra), link_type="ethernet")
    fields = next(layer.fields for layer in decoded.layers if layer.name == "icmpv6")
    assert fields["message"] == "router-advertisement"
    assert fields["managed"] is True and fields["other_configuration"] is True
    options = {row["name"]: row for row in fields["options"]}
    assert options["prefix-information"]["prefix"] == "2001:db8:100::/64"
    assert options["prefix-information"]["autonomous"] is True
    assert options["mtu"]["mtu"] == 1500
    assert options["rdnss"]["servers"] == ["2001:4860:4860::8888"]
    assert options["dnssl"]["domains"] == ["example.com"]


def test_icmpv6_packet_too_big_exposes_path_mtu() -> None:
    packet = b"\x02\x00\x00\x00" + struct.pack("!I", 1280)
    decoded = ProtocolIntelligenceEngine().decode_frame(_ipv6_icmp_frame(packet), link_type="ethernet")
    fields = next(layer.fields for layer in decoded.layers if layer.name == "icmpv6")
    assert fields["message"] == "packet-too-big"
    assert fields["mtu"] == 1280


def _ipv4_ospf_frame(payload: bytes, *, source: str = "192.0.2.1", destination: str = "224.0.0.5") -> bytes:
    ipv4 = (
        b"\x45\x00" + struct.pack("!H", 20 + len(payload)) + b"\x00\x01\x00\x00" + b"\x01\x59\x00\x00"
        + ipaddress.IPv4Address(source).packed + ipaddress.IPv4Address(destination).packed
    )
    return bytes.fromhex("01005e0000050011223344550800") + ipv4 + payload


def _ipv6_ospf_frame(payload: bytes, *, source: str = "fe80::1", destination: str = "ff02::5") -> bytes:
    ipv6 = (
        struct.pack("!IHBB", 6 << 28, len(payload), 89, 1)
        + ipaddress.IPv6Address(source).packed + ipaddress.IPv6Address(destination).packed
    )
    return bytes.fromhex("33330000000500112233445586dd") + ipv6 + payload


def test_ospfv2_hello_decodes_neighbor_election_and_timers() -> None:
    body = (
        ipaddress.IPv4Address("255.255.255.0").packed
        + struct.pack("!HBBI", 10, 0x02, 1, 40)
        + ipaddress.IPv4Address("192.0.2.254").packed
        + ipaddress.IPv4Address("192.0.2.253").packed
        + ipaddress.IPv4Address("10.0.0.2").packed
        + ipaddress.IPv4Address("10.0.0.3").packed
    )
    header = (
        struct.pack("!BBH", 2, 1, 24 + len(body))
        + ipaddress.IPv4Address("10.0.0.1").packed
        + ipaddress.IPv4Address("0.0.0.0").packed
        + struct.pack("!HH", 0x1234, 0)
        + b"\x00" * 8
    )
    decoded = ProtocolIntelligenceEngine().decode_frame(_ipv4_ospf_frame(header + body), link_type="ethernet")
    fields = next(layer.fields for layer in decoded.layers if layer.name == "ospf")
    assert fields["version"] == 2
    assert fields["packet_type_name"] == "hello"
    assert fields["network_mask"] == "255.255.255.0"
    assert fields["hello_interval_seconds"] == 10
    assert fields["router_dead_interval_seconds"] == 40
    assert fields["designated_router"] == "192.0.2.254"
    assert fields["neighbors"] == ["10.0.0.2", "10.0.0.3"]


def test_ospfv3_hello_decodes_interface_options_neighbors_and_instance() -> None:
    body = (
        struct.pack("!I", 7)
        + bytes((5, 0x00, 0x00, 0x13))
        + struct.pack("!HH", 10, 40)
        + ipaddress.IPv4Address("10.1.0.254").packed
        + ipaddress.IPv4Address("10.1.0.253").packed
        + ipaddress.IPv4Address("10.1.0.2").packed
    )
    header = (
        struct.pack("!BBH", 3, 1, 16 + len(body))
        + ipaddress.IPv4Address("10.1.0.1").packed
        + ipaddress.IPv4Address("0.0.0.1").packed
        + struct.pack("!HBB", 0x4321, 9, 0)
    )
    decoded = ProtocolIntelligenceEngine().decode_frame(_ipv6_ospf_frame(header + body), link_type="ethernet")
    fields = next(layer.fields for layer in decoded.layers if layer.name == "ospf")
    assert fields["version"] == 3
    assert fields["instance_id"] == 9
    assert fields["interface_id"] == 7
    assert fields["router_priority"] == 5
    assert fields["options"] == "0x000013"
    assert fields["designated_router_id"] == "10.1.0.254"
    assert fields["neighbors"] == ["10.1.0.2"]


def test_ospfv3_database_description_decodes_flags_and_lsa_headers() -> None:
    lsa = (
        struct.pack("!HH", 12, 0x2001)
        + ipaddress.IPv4Address("1.2.3.4").packed
        + ipaddress.IPv4Address("10.1.0.1").packed
        + struct.pack("!IHH", 0x80000001, 0xABCD, 24)
    )
    body = b"\x00\x00\x00\x13" + struct.pack("!H", 1500) + bytes((0, 0x07)) + struct.pack("!I", 99) + lsa
    header = (
        struct.pack("!BBH", 3, 2, 16 + len(body))
        + ipaddress.IPv4Address("10.1.0.1").packed
        + ipaddress.IPv4Address("0.0.0.1").packed
        + struct.pack("!HBB", 0, 0, 0)
    )
    decoded = ProtocolIntelligenceEngine().decode_frame(_ipv6_ospf_frame(header + body), link_type="ethernet")
    fields = next(layer.fields for layer in decoded.layers if layer.name == "ospf")
    assert fields["packet_type_name"] == "database-description"
    assert fields["interface_mtu"] == 1500
    assert fields["init"] is True and fields["more"] is True and fields["master"] is True
    assert fields["dd_sequence_number"] == 99
    assert fields["lsa_headers"][0]["ls_type_name"] == "router-lsa"
    assert fields["lsa_headers"][0]["advertising_router"] == "10.1.0.1"


def test_ospfv2_link_state_update_decodes_bounded_lsa_inventory() -> None:
    lsa = (
        struct.pack("!HBB", 5, 0x02, 1)
        + ipaddress.IPv4Address("10.10.0.0").packed
        + ipaddress.IPv4Address("10.0.0.1").packed
        + struct.pack("!IHH", 0x80000002, 0x1111, 20)
    )
    body = struct.pack("!I", 1) + lsa
    header = (
        struct.pack("!BBH", 2, 4, 24 + len(body))
        + ipaddress.IPv4Address("10.0.0.1").packed
        + ipaddress.IPv4Address("0.0.0.0").packed
        + struct.pack("!HH", 0, 0)
        + b"\x00" * 8
    )
    decoded = ProtocolIntelligenceEngine().decode_frame(_ipv4_ospf_frame(header + body), link_type="ethernet")
    fields = next(layer.fields for layer in decoded.layers if layer.name == "ospf")
    assert fields["packet_type_name"] == "link-state-update"
    assert fields["advertised_lsa_count"] == 1
    assert fields["decoded_lsa_count"] == 1
    assert fields["lsas"][0]["ls_type_name"] == "router-lsa"
    assert fields["invalid_lsa_length"] is False


def test_ospf_expert_reports_invalid_lsa_length_without_overclaiming_compromise() -> None:
    malformed_lsa = (
        struct.pack("!HBB", 5, 0x02, 1)
        + ipaddress.IPv4Address("10.10.0.0").packed
        + ipaddress.IPv4Address("10.0.0.1").packed
        + struct.pack("!IHH", 0x80000002, 0x1111, 19)
    )
    body = struct.pack("!I", 1) + malformed_lsa
    header = (
        struct.pack("!BBH", 2, 4, 24 + len(body))
        + ipaddress.IPv4Address("10.0.0.1").packed
        + ipaddress.IPv4Address("0.0.0.0").packed
        + struct.pack("!HH", 0, 0)
        + b"\x00" * 8
    )
    decoded = ProtocolIntelligenceEngine().decode_frame(_ipv4_ospf_frame(header + body), link_type="ethernet")
    findings = ProtocolIntelligenceEngine.expert_findings(decoded)
    finding = next(row for row in findings if row["code"] == "OSPF_LSA_LENGTH_INVALID")
    assert finding["severity"] == "warning"
    assert "compromise" not in finding["title"].casefold()


def _lldp_tlv(kind: int, value: bytes) -> bytes:
    return struct.pack("!H", (kind << 9) | len(value)) + value


def test_lldp_deep_decoder_exposes_topology_identity_capabilities_and_management_address() -> None:
    chassis = _lldp_tlv(1, b"\x04" + bytes.fromhex("001122334455"))
    port = _lldp_tlv(2, b"\x05Gi1/0/1")
    ttl = _lldp_tlv(3, struct.pack("!H", 120))
    name = _lldp_tlv(5, b"core-sw-01")
    caps = _lldp_tlv(7, struct.pack("!HH", 0x0014, 0x0014))
    mgmt = _lldp_tlv(8, b"\x05\x01" + ipaddress.IPv4Address("192.0.2.10").packed + b"\x02" + struct.pack("!I", 7) + b"\x00")
    end = _lldp_tlv(0, b"")
    frame = bytes.fromhex("0180c200000e00112233445588cc") + chassis + port + ttl + name + caps + mgmt + end
    decoded = ProtocolIntelligenceEngine().decode_frame(frame, link_type="ethernet")
    fields = next(layer.fields for layer in decoded.layers if layer.name == "lldp")
    assert fields["chassis_id"]["mac_address"] == "00:11:22:33:44:55"
    assert fields["port_id"]["text"] == "Gi1/0/1"
    assert fields["ttl_seconds"] == 120
    assert fields["system_name"] == "core-sw-01"
    assert fields["system_capabilities"]["enabled"] == ["bridge", "router"]
    assert fields["management_addresses"][0]["address"] == "192.0.2.10"
    assert fields["end_seen"] is True


def test_eapol_identity_hashes_identity_instead_of_retaining_username() -> None:
    identity = b"alice@example.org"
    eap = struct.pack("!BBH", 2, 9, 5 + len(identity)) + b"\x01" + identity
    packet = struct.pack("!BBH", 2, 0, len(eap)) + eap
    frame = bytes.fromhex("0180c2000003001122334455888e") + packet
    decoded = ProtocolIntelligenceEngine().decode_frame(frame, link_type="ethernet")
    fields = next(layer.fields for layer in decoded.layers if layer.name == "eapol")
    assert fields["packet_type_name"] == "eap-packet"
    assert fields["eap_code_name"] == "response"
    assert fields["eap_type_name"] == "identity"
    assert len(fields["identity_sha256"]) == 64
    assert "alice@example.org" not in repr(fields)


def test_eapol_key_exposes_replay_and_key_info_without_retaining_key_material() -> None:
    key_info = 0x0002 | 0x0008 | 0x0080 | 0x0100
    descriptor = (
        b"\x02" + struct.pack("!HHQ", key_info, 16, 42) + b"N" * 32 + b"I" * 16
        + b"\x00" * 8 + b"\x00" * 8 + b"M" * 16 + struct.pack("!H", 4) + b"DATA"
    )
    packet = struct.pack("!BBH", 2, 3, len(descriptor)) + descriptor
    frame = bytes.fromhex("0180c2000003001122334455888e") + packet
    decoded = ProtocolIntelligenceEngine().decode_frame(frame, link_type="ethernet")
    fields = next(layer.fields for layer in decoded.layers if layer.name == "eapol")
    assert fields["packet_type_name"] == "key"
    assert fields["replay_counter"] == 42
    assert fields["pairwise_key"] is True
    assert fields["key_ack"] is True and fields["key_mic"] is True
    assert fields["key_data_length"] == 4
    assert fields["sensitive_key_material_retained"] is False
    assert "DATA" not in repr(fields)


def _ospfv2_lsu(lsas: list[bytes], *, router_id: str = "10.0.0.1") -> bytes:
    body = struct.pack("!I", len(lsas)) + b"".join(lsas)
    header = (
        struct.pack("!BBH", 2, 4, 24 + len(body))
        + ipaddress.IPv4Address(router_id).packed
        + ipaddress.IPv4Address("0.0.0.0").packed
        + struct.pack("!HH", 0, 0)
        + b"\x00" * 8
    )
    return _ipv4_ospf_frame(header + body)


def _ospfv3_lsu(lsas: list[bytes], *, router_id: str = "10.1.0.1") -> bytes:
    body = struct.pack("!I", len(lsas)) + b"".join(lsas)
    header = (
        struct.pack("!BBH", 3, 4, 16 + len(body))
        + ipaddress.IPv4Address(router_id).packed
        + ipaddress.IPv4Address("0.0.0.1").packed
        + struct.pack("!HBB", 0, 0, 0)
    )
    return _ipv6_ospf_frame(header + body)


def _ospfv2_lsa(ls_type: int, link_state_id: str, body: bytes, *, advertising_router: str = "10.0.0.1") -> bytes:
    length = 20 + len(body)
    return (
        struct.pack("!HBB", 10, 0x02, ls_type)
        + ipaddress.IPv4Address(link_state_id).packed
        + ipaddress.IPv4Address(advertising_router).packed
        + struct.pack("!IHH", 0x80000001, 0x2222, length)
        + body
    )


def _ospfv3_lsa(ls_type: int, link_state_id: str, body: bytes, *, advertising_router: str = "10.1.0.1") -> bytes:
    length = 20 + len(body)
    return (
        struct.pack("!HH", 10, ls_type)
        + ipaddress.IPv4Address(link_state_id).packed
        + ipaddress.IPv4Address(advertising_router).packed
        + struct.pack("!IHH", 0x80000001, 0x3333, length)
        + body
    )


def test_ospfv2_router_lsa_decodes_topology_links_and_metrics() -> None:
    link1 = (
        ipaddress.IPv4Address("10.0.0.2").packed
        + ipaddress.IPv4Address("192.0.2.1").packed
        + bytes((1, 0))
        + struct.pack("!H", 10)
    )
    link2 = (
        ipaddress.IPv4Address("192.0.2.0").packed
        + ipaddress.IPv4Address("255.255.255.0").packed
        + bytes((3, 0))
        + struct.pack("!H", 20)
    )
    lsa = _ospfv2_lsa(1, "10.0.0.1", bytes((0x03, 0)) + struct.pack("!H", 2) + link1 + link2)
    decoded = ProtocolIntelligenceEngine().decode_frame(_ospfv2_lsu([lsa]), link_type="ethernet")
    fields = next(layer.fields for layer in decoded.layers if layer.name == "ospf")
    body = fields["lsas"][0]["body"]
    assert body["area_border_router"] is True
    assert body["as_boundary_router"] is True
    assert body["advertised_link_count"] == 2
    assert body["links"][0]["link_type_name"] == "point-to-point"
    assert body["links"][0]["metric"] == 10
    assert body["links"][1]["link_type_name"] == "stub-network"


def test_ospfv2_network_and_external_lsas_expose_route_semantics() -> None:
    network_body = (
        ipaddress.IPv4Address("255.255.255.0").packed
        + ipaddress.IPv4Address("10.0.0.1").packed
        + ipaddress.IPv4Address("10.0.0.2").packed
    )
    external_body = (
        ipaddress.IPv4Address("255.255.255.0").packed
        + bytes((0x80,)) + (100).to_bytes(3, "big")
        + ipaddress.IPv4Address("192.0.2.254").packed
        + struct.pack("!I", 0xAABBCCDD)
    )
    decoded = ProtocolIntelligenceEngine().decode_frame(
        _ospfv2_lsu([
            _ospfv2_lsa(2, "192.0.2.1", network_body),
            _ospfv2_lsa(5, "203.0.113.0", external_body),
        ]),
        link_type="ethernet",
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "ospf")
    network = fields["lsas"][0]["body"]
    external = fields["lsas"][1]["body"]
    assert network["network_mask"] == "255.255.255.0"
    assert network["attached_routers"] == ["10.0.0.1", "10.0.0.2"]
    assert external["external_metric_type_2"] is True
    assert external["metric"] == 100
    assert external["forwarding_address"] == "192.0.2.254"
    assert external["external_route_tag"] == "0xaabbccdd"


def test_ospfv3_router_link_and_intra_area_prefix_lsas_decode_ipv6_topology() -> None:
    router_body = (
        bytes((0x01, 0x00, 0x00, 0x13))
        + bytes((1, 0)) + struct.pack("!HIII", 10, 7, 8, int(ipaddress.IPv4Address("10.1.0.2")))
    )
    prefix_bytes = ipaddress.IPv6Address("2001:db8:100::").packed[:8]
    link_body = (
        bytes((5, 0x00, 0x00, 0x13))
        + ipaddress.IPv6Address("fe80::1").packed
        + struct.pack("!I", 1)
        + bytes((64, 0x02, 0, 0))
        + prefix_bytes
    )
    intra_body = (
        struct.pack("!HH", 1, 0x2001)
        + ipaddress.IPv4Address("0.0.0.0").packed
        + ipaddress.IPv4Address("10.1.0.1").packed
        + bytes((64, 0x00)) + struct.pack("!H", 20)
        + prefix_bytes
    )
    decoded = ProtocolIntelligenceEngine().decode_frame(
        _ospfv3_lsu([
            _ospfv3_lsa(0x2001, "0.0.0.0", router_body),
            _ospfv3_lsa(0x0008, "0.0.0.7", link_body),
            _ospfv3_lsa(0x2009, "0.0.0.0", intra_body),
        ]),
        link_type="ethernet",
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "ospf")
    router = fields["lsas"][0]["body"]
    link = fields["lsas"][1]["body"]
    intra = fields["lsas"][2]["body"]
    assert router["area_border_router"] is True
    assert router["links"][0]["neighbor_router_id"] == "10.1.0.2"
    assert link["link_local_address"] == "fe80::1"
    assert link["prefixes"][0]["prefix"] == "2001:db8:100::/64"
    assert link["prefixes"][0]["prefix_options"]["local_address"] is True
    assert intra["referenced_ls_type"] == 0x2001
    assert intra["prefixes"][0]["metric"] == 20
    assert intra["prefixes"][0]["prefix"] == "2001:db8:100::/64"


def test_ospf_expert_preserves_header_and_reports_recognized_lsa_body_malformed() -> None:
    # Router-LSA claims two links but contains only one link descriptor.
    link = (
        ipaddress.IPv4Address("10.0.0.2").packed
        + ipaddress.IPv4Address("192.0.2.1").packed
        + bytes((1, 0))
        + struct.pack("!H", 10)
    )
    lsa = _ospfv2_lsa(1, "10.0.0.1", bytes((0, 0)) + struct.pack("!H", 2) + link)
    decoded = ProtocolIntelligenceEngine().decode_frame(_ospfv2_lsu([lsa]), link_type="ethernet")
    fields = next(layer.fields for layer in decoded.layers if layer.name == "ospf")
    assert fields["lsas"][0]["body_malformed"] is True
    findings = ProtocolIntelligenceEngine.expert_findings(decoded)
    assert any(row["code"] == "OSPF_LSA_BODY_MALFORMED" for row in findings)


def _packet_record(frame: int, source: str, destination: str, layers: list[dict[str, object]]) -> object:
    from arenyxa.infrastructure.capture.packet_models import PacketRecord

    return PacketRecord(
        frame_number=frame,
        timestamp=f"2026-08-20T00:00:{frame:02d}+00:00",
        length=100,
        captured_length=100,
        protocols=":".join(str(row.get("name") or "") for row in layers),
        protocol=str(layers[-1].get("name") or "unknown") if layers else "unknown",
        info="",
        source=source,
        destination=destination,
        source_port=None,
        destination_port=None,
        tcp_stream=None,
        udp_stream=None,
        http2_stream=None,
        quic_stream=None,
        host="",
        method="",
        uri="",
        status=None,
        metadata={"native_layers": layers},
    )


def test_network_evidence_graph_correlates_dns_tls_lldp_and_ospf_without_payload() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    packets = [
        _packet_record(1, "192.0.2.10", "192.0.2.53", [{
            "name": "dns",
            "fields": {
                "question_records": [{"name": "api.example.test", "type_name": "A"}],
                "answer_records": [{"name": "api.example.test", "type_name": "A", "address": "203.0.113.20"}],
            },
        }]),
        _packet_record(2, "192.0.2.10", "203.0.113.20", [{
            "name": "tls",
            "fields": {
                "server_name": "api.example.test",
                "certificate_chain": [{"sha256": "ab" * 32, "san_dns": ["api.example.test", "*.example.test"]}],
            },
        }]),
        _packet_record(3, "192.0.2.2", "224.0.0.5", [{
            "name": "ospf",
            "fields": {"router_id": "10.0.0.1", "packet_type_name": "hello", "neighbors": ["10.0.0.2"]},
        }]),
        _packet_record(4, "0.0.0.0", "0.0.0.0", [{
            "name": "lldp",
            "fields": {
                "system_name": "core-sw-01",
                "chassis_id": {"mac_address": "00:11:22:33:44:55"},
                "management_addresses": [{"address": "192.0.2.2"}],
            },
        }]),
    ]
    summary = forensic_summary_from_packets(packets)
    graph = summary["evidence_graph"]
    relations = {row["relation"] for row in graph["edges"]}
    assert "dns-resolves-to" in relations
    assert "tls-served-by" in relations
    assert "certificate-asserts-name" in relations
    assert "ospf-hello-neighbor" in relations
    assert "lldp-management-address" in relations
    assert graph["node_limit_reached"] is False
    assert "payload" not in repr(graph).casefold()


def _tcp_packet_record(
    frame: int,
    timestamp: str,
    source: str,
    source_port: int,
    destination: str,
    destination_port: int,
    flags: list[str],
    *,
    length: int = 60,
    window: int = 65535,
    analysis: list[str] | None = None,
    protocol: str = "tcp",
) -> object:
    from arenyxa.infrastructure.capture.packet_models import PacketRecord

    return PacketRecord(
        frame_number=frame,
        timestamp=timestamp,
        length=length,
        captured_length=length,
        protocols=f"ipv4:tcp:{protocol}" if protocol != "tcp" else "ipv4:tcp",
        protocol=protocol,
        info="",
        source=source,
        destination=destination,
        source_port=source_port,
        destination_port=destination_port,
        tcp_stream=None,
        udp_stream=None,
        http2_stream=None,
        quic_stream=None,
        host="",
        method="",
        uri="",
        status=None,
        tcp_analysis=list(analysis or []),
        metadata={"native_layers": [{"name": "tcp", "fields": {"flags": flags, "window": window}}]},
    )


def test_tcp_session_analyzer_correlates_bidirectional_handshake_and_transport_health() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    packets = [
        _tcp_packet_record(1, "2026-08-20T00:00:00.000+00:00", "10.0.0.10", 50000, "10.0.0.20", 443, ["syn"]),
        _tcp_packet_record(2, "2026-08-20T00:00:00.025+00:00", "10.0.0.20", 443, "10.0.0.10", 50000, ["syn", "ack"]),
        _tcp_packet_record(3, "2026-08-20T00:00:00.050+00:00", "10.0.0.10", 50000, "10.0.0.20", 443, ["ack"], protocol="tls"),
        _tcp_packet_record(4, "2026-08-20T00:00:00.060+00:00", "10.0.0.10", 50000, "10.0.0.20", 443, ["ack"], analysis=["retransmission"]),
        _tcp_packet_record(5, "2026-08-20T00:00:00.070+00:00", "10.0.0.20", 443, "10.0.0.10", 50000, ["ack"], window=0, analysis=["zero_window"]),
        _tcp_packet_record(6, "2026-08-20T00:00:00.080+00:00", "10.0.0.20", 443, "10.0.0.10", 50000, ["rst", "ack"]),
    ]
    summary = forensic_summary_from_packets(packets)["tcp_sessions"]
    assert summary["session_count"] == 1
    assert summary["established_sessions"] == 1
    assert summary["reset_sessions"] == 1
    assert summary["sessions_with_retransmission"] == 1
    assert summary["sessions_with_zero_window"] == 1
    assert summary["handshake_ms"]["p50"] == 50.0
    assert summary["syn_ack_ms"]["p50"] == 25.0
    row = summary["top_sessions"][0]
    assert row["initiator"] == {"address": "10.0.0.10", "port": 50000}
    assert row["client"] == {"address": "10.0.0.10", "port": 50000}
    assert row["server"] == {"address": "10.0.0.20", "port": 443}
    assert row["state"] == "reset"
    assert row["syn_count"] == 1
    assert row["syn_ack_count"] == 1
    assert row["applications"] == ["tls"]


def test_routing_control_plane_analyzer_tracks_bgp_churn_and_ospf_adjacencies() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    def packet(frame: int, source: str, destination: str, name: str, fields: dict[str, object]) -> object:
        return _packet_record(frame, source, destination, [{"name": name, "fields": fields}])

    packets = [
        packet(1, "192.0.2.1", "192.0.2.2", "bgp", {
            "message_name": "open", "asn": 64512,
            "capabilities": [{"name": "four-octet-asn", "asn4": 4200000001}],
        }),
        packet(2, "192.0.2.1", "192.0.2.2", "bgp", {
            "message_name": "update", "nlri": ["203.0.113.0/24"], "withdrawn_routes": [],
            "path_attributes": [{"name": "AS_PATH", "segments": [{"type": "sequence", "asns": [64512, 64496]}]}],
        }),
        packet(3, "192.0.2.1", "192.0.2.2", "bgp", {
            "message_name": "update", "nlri": ["203.0.113.0/24"], "withdrawn_routes": [],
            "path_attributes": [{"name": "AS_PATH", "segments": [{"type": "sequence", "asns": [64512, 64497]}]}],
        }),
        packet(4, "192.0.2.1", "192.0.2.2", "bgp", {
            "message_name": "update", "nlri": [], "withdrawn_routes": ["203.0.113.0/24"], "path_attributes": [],
        }),
        packet(5, "10.0.0.1", "224.0.0.5", "ospf", {
            "router_id": "10.0.0.1", "packet_type_name": "hello", "neighbors": ["10.0.0.2", "10.0.0.3"],
        }),
        packet(6, "10.0.0.1", "224.0.0.5", "ospf", {
            "router_id": "10.0.0.1", "packet_type_name": "link-state-update",
            "lsas": [{"ls_type_name": "router-lsa", "advertising_router": "10.0.0.1", "body_malformed": False}],
        }),
    ]
    routing = forensic_summary_from_packets(packets)["routing_control_plane"]
    assert routing["bgp"]["peer_as"]["192.0.2.1"] == 4200000001
    assert routing["bgp"]["announcements"] == 2
    assert routing["bgp"]["withdrawals"] == 1
    assert routing["bgp"]["path_changes"] == 1
    assert routing["bgp"]["active_route_count"] == 0
    assert routing["bgp"]["top_prefix_churn"][0] == {"prefix": "203.0.113.0/24", "events": 3}
    assert routing["ospf"]["adjacency_count"] == 2
    assert routing["ospf"]["lsa_types"]["router-lsa"] == 1


def _ethernet_8023(destination: bytes, source: bytes, payload: bytes) -> bytes:
    if len(payload) > 1500:
        raise ValueError("802.3 test payload too large")
    return destination + source + struct.pack("!H", len(payload)) + payload


def test_rstp_bpdu_decodes_root_bridge_role_and_timers() -> None:
    root_id = struct.pack("!H", 0x8001) + bytes.fromhex("001122334455")
    bridge_id = struct.pack("!H", 0x9001) + bytes.fromhex("66778899aabb")
    bpdu = (
        struct.pack("!HBB", 0, 2, 0x02)
        + bytes((0x3D,))
        + root_id
        + struct.pack("!I", 20000)
        + bridge_id
        + struct.pack("!H", 0x8001)
        + struct.pack("!HHHH", 256, 5120, 512, 3840)
        + b"\x00"
    )
    frame = _ethernet_8023(
        bytes.fromhex("0180c2000000"), bytes.fromhex("66778899aabb"), b"\x42\x42\x03" + bpdu
    )
    decoded = ProtocolIntelligenceEngine().decode_frame(frame, link_type="ethernet")
    fields = next(layer.fields for layer in decoded.layers if layer.name == "rstp")
    assert fields["protocol_name"] == "rstp"
    assert fields["root_id"]["mac_address"] == "00:11:22:33:44:55"
    assert fields["bridge_id"]["mac_address"] == "66:77:88:99:aa:bb"
    assert fields["root_path_cost"] == 20000
    assert fields["message_age_seconds"] == 1.0
    assert fields["hello_time_seconds"] == 2.0
    assert decoded.application_protocol == "rstp"


def _lacp_system_tlv(tlv_type: int, system: str, *, key: int, port: int, state: int) -> bytes:
    value = (
        struct.pack("!H", 32768)
        + bytes.fromhex(system.replace(":", ""))
        + struct.pack("!HHH", key, 32768, port)
        + bytes((state,))
        + b"\x00\x00\x00"
    )
    return bytes((tlv_type, 20)) + value


def test_lacp_slow_protocol_decodes_actor_partner_and_state_machine_bits() -> None:
    payload = (
        b"\x01\x01"
        + _lacp_system_tlv(1, "00:11:22:33:44:55", key=10, port=7, state=0x3D)
        + _lacp_system_tlv(2, "66:77:88:99:aa:bb", key=10, port=8, state=0x3D)
        + bytes((3, 16)) + struct.pack("!H", 5) + b"\x00" * 12
        + b"\x00\x00"
    )
    frame = bytes.fromhex("0180c20000020011223344558809") + payload
    decoded = ProtocolIntelligenceEngine().decode_frame(frame, link_type="ethernet")
    fields = next(layer.fields for layer in decoded.layers if layer.name == "lacp")
    assert fields["actor"]["system_id"] == "00:11:22:33:44:55"
    assert fields["partner"]["system_id"] == "66:77:88:99:aa:bb"
    assert fields["actor"]["state"]["aggregation"] is True
    assert fields["actor"]["state"]["synchronization"] is True
    assert fields["collector"]["max_delay_tens_of_microseconds"] == 5


def _cdp_tlv(kind: int, value: bytes) -> bytes:
    return struct.pack("!HH", kind, 4 + len(value)) + value


def test_cdp_snap_decoder_exposes_neighbor_identity_platform_vlan_and_management_address() -> None:
    addresses = struct.pack("!I", 1) + b"\x01\x01\xcc" + struct.pack("!H", 4) + ipaddress.IPv4Address("192.0.2.5").packed
    cdp = (
        bytes((2, 180)) + b"\x00\x00"
        + _cdp_tlv(0x0001, b"dist-sw-01")
        + _cdp_tlv(0x0002, addresses)
        + _cdp_tlv(0x0003, b"GigabitEthernet1/0/48")
        + _cdp_tlv(0x0004, struct.pack("!I", 0x09))
        + _cdp_tlv(0x0006, b"C9300")
        + _cdp_tlv(0x000A, struct.pack("!H", 120))
        + _cdp_tlv(0x000B, b"\x01")
    )
    llc_snap = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + cdp
    frame = _ethernet_8023(bytes.fromhex("01000ccccccc"), bytes.fromhex("001122334455"), llc_snap)
    decoded = ProtocolIntelligenceEngine().decode_frame(frame, link_type="ethernet")
    fields = next(layer.fields for layer in decoded.layers if layer.name == "cdp")
    assert fields["device_id"] == "dist-sw-01"
    assert fields["port_id"] == "GigabitEthernet1/0/48"
    assert fields["addresses"] == ["192.0.2.5"]
    assert set(fields["capabilities"]) == {"router", "switch"}
    assert fields["platform"] == "C9300"
    assert fields["native_vlan"] == 120
    assert fields["duplex"] == "full"


def test_protocol_catalog_marks_enterprise_l2_and_ospf_as_native_deep() -> None:
    rows = {row["protocol"]: row for row in ProtocolIntelligenceEngine().protocol_catalog()}
    for protocol in ("ospf", "stp", "rstp", "mstp", "lacp", "cdp"):
        assert rows[protocol]["mode"] == "native-deep"


def test_network_evidence_graph_adds_cdp_lacp_and_spanning_tree_relationships() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    packets = [
        _packet_record(1, "0.0.0.0", "0.0.0.0", [{
            "name": "cdp",
            "fields": {"device_id": "dist-sw-01", "platform": "C9300", "addresses": ["192.0.2.5"], "native_vlan": 120},
        }]),
        _packet_record(2, "0.0.0.0", "0.0.0.0", [{
            "name": "lacp",
            "fields": {"actor": {"system_id": "00:11:22:33:44:55"}, "partner": {"system_id": "66:77:88:99:aa:bb"}},
        }]),
        _packet_record(3, "0.0.0.0", "0.0.0.0", [{
            "name": "rstp",
            "fields": {"bridge_id": {"mac_address": "66:77:88:99:aa:bb"}, "root_id": {"mac_address": "00:11:22:33:44:55"}},
        }]),
    ]
    graph = forensic_summary_from_packets(packets)["evidence_graph"]
    relations = {row["relation"] for row in graph["edges"]}
    assert {"cdp-platform", "cdp-management-address", "cdp-native-vlan", "lacp-partner", "spanning-tree-root"}.issubset(relations)


def _ipv4_proto_frame(payload: bytes, protocol: int, *, source: str = "192.0.2.1", destination: str = "224.0.0.18") -> bytes:
    ipv4 = (
        b"\x45\x00" + struct.pack("!H", 20 + len(payload)) + b"\x00\x01\x00\x00" + bytes((255, protocol)) + b"\x00\x00"
        + ipaddress.IPv4Address(source).packed + ipaddress.IPv4Address(destination).packed
    )
    return bytes.fromhex("01005e0000120011223344550800") + ipv4 + payload


def test_vrrpv3_decodes_virtual_addresses_priority_and_centisecond_interval() -> None:
    payload = (
        bytes((0x31, 42, 150, 2))
        + struct.pack("!HH", 0x0064, 0x1234)
        + ipaddress.IPv4Address("192.0.2.254").packed
        + ipaddress.IPv4Address("192.0.2.253").packed
    )
    decoded = ProtocolIntelligenceEngine().decode_frame(_ipv4_proto_frame(payload, 112), link_type="ethernet")
    fields = next(layer.fields for layer in decoded.layers if layer.name == "vrrp")
    assert fields["version"] == 3
    assert fields["type_name"] == "advertisement"
    assert fields["virtual_router_id"] == 42
    assert fields["priority"] == 150
    assert fields["max_advertisement_interval_centiseconds"] == 100
    assert fields["max_advertisement_interval_seconds"] == 1.0
    assert fields["addresses"] == ["192.0.2.254", "192.0.2.253"]


def test_igmpv3_query_and_report_decode_source_filters_and_group_records() -> None:
    query = (
        bytes((0x11, 100)) + b"\x00\x00" + ipaddress.IPv4Address("239.1.1.1").packed
        + bytes((0x0A, 125)) + struct.pack("!H", 2)
        + ipaddress.IPv4Address("198.51.100.1").packed + ipaddress.IPv4Address("198.51.100.2").packed
    )
    decoded_query = ProtocolIntelligenceEngine().decode_frame(_ipv4_proto_frame(query, 2, destination="224.0.0.1"), link_type="ethernet")
    qfields = next(layer.fields for layer in decoded_query.layers if layer.name == "igmp")
    assert qfields["version"] == 3
    assert qfields["type_name"] == "membership-query"
    assert qfields["suppress_router_processing"] is True
    assert qfields["qrv"] == 2
    assert qfields["sources"] == ["198.51.100.1", "198.51.100.2"]

    record = (
        bytes((1, 0)) + struct.pack("!H", 2) + ipaddress.IPv4Address("239.1.1.1").packed
        + ipaddress.IPv4Address("198.51.100.1").packed + ipaddress.IPv4Address("198.51.100.2").packed
    )
    report = bytes((0x22, 0)) + b"\x00\x00\x00\x00" + struct.pack("!H", 1) + record
    decoded_report = ProtocolIntelligenceEngine().decode_frame(_ipv4_proto_frame(report, 2, destination="224.0.0.22"), link_type="ethernet")
    rfields = next(layer.fields for layer in decoded_report.layers if layer.name == "igmp")
    assert rfields["group_record_count"] == 1
    assert rfields["group_records"][0]["record_type_name"] == "mode-is-include"
    assert rfields["group_records"][0]["source_count"] == 2


def test_pimv2_hello_decodes_holdtime_dr_priority_and_generation_id() -> None:
    options = (
        struct.pack("!HHH", 1, 2, 105)
        + struct.pack("!HHI", 19, 4, 1000)
        + struct.pack("!HHI", 20, 4, 0xAABBCCDD)
    )
    payload = bytes((0x20, 0)) + b"\x00\x00" + options
    decoded = ProtocolIntelligenceEngine().decode_frame(_ipv4_proto_frame(payload, 103, destination="224.0.0.13"), link_type="ethernet")
    fields = next(layer.fields for layer in decoded.layers if layer.name == "pim")
    assert fields["version"] == 2
    assert fields["type_name"] == "hello"
    assert fields["holdtime_seconds"] == 105
    assert fields["dr_priority"] == 1000
    assert fields["generation_id"] == "0xaabbccdd"


def test_bfd_control_decodes_session_state_discriminators_and_detection_floor_without_auth_material() -> None:
    payload = (
        bytes(((1 << 5) | 0, (3 << 6) | 0x04, 3, 24))
        + struct.pack("!IIIII", 0x11111111, 0x22222222, 100000, 50000, 0)
    )
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        payload, source_port=3784, destination_port=3784, transport="udp"
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "bfd")
    assert fields["version"] == 1
    assert fields["state_name"] == "up"
    assert fields["my_discriminator"] == 0x11111111
    assert fields["your_discriminator"] == 0x22222222
    assert fields["detect_multiplier"] == 3
    assert fields["detection_time_floor_us"] == 150000
    assert fields["authentication_present"] is True
    assert fields["authentication_material_retained"] is False


def test_protocol_catalog_marks_routing_ha_control_protocols_as_native_deep() -> None:
    rows = {row["protocol"]: row for row in ProtocolIntelligenceEngine().protocol_catalog()}
    for protocol in ("igmp", "pim", "vrrp", "bfd"):
        assert rows[protocol]["mode"] == "native-deep"


def test_routing_ha_expert_findings_report_bfd_and_vrrp_state_without_attack_claims() -> None:
    bfd_payload = bytes(((1 << 5), (1 << 6), 3, 24)) + struct.pack("!IIIII", 1, 0, 100000, 50000, 0)
    bfd = ProtocolIntelligenceEngine().decode_application_payload(bfd_payload, source_port=3784, destination_port=3784, transport="udp")
    bfd_findings = ProtocolIntelligenceEngine.expert_findings(bfd)
    assert any(row["code"] == "BFD_SESSION_NOT_UP" for row in bfd_findings)

    vrrp_payload = bytes((0x31, 42, 0, 1)) + struct.pack("!HH", 100, 0) + ipaddress.IPv4Address("192.0.2.254").packed
    vrrp = ProtocolIntelligenceEngine().decode_frame(_ipv4_proto_frame(vrrp_payload, 112), link_type="ethernet")
    vrrp_findings = ProtocolIntelligenceEngine.expert_findings(vrrp)
    finding = next(row for row in vrrp_findings if row["code"] == "VRRP_MASTER_RELINQUISH")
    assert finding["severity"] == "note"
    assert "attack" not in finding["title"].casefold()


def test_isis_lan_hello_decodes_system_identity_hostname_protocols_and_interface_address() -> None:
    common = bytes((0x83, 27, 1, 0, 15, 1, 0, 3))
    source_id = bytes.fromhex("490001000001")
    designated = bytes.fromhex("49000100000101")
    tlvs = (
        bytes((137, len(b"spine-01"))) + b"spine-01"
        + bytes((129, 2, 0xCC, 0x8E))
        + bytes((132, 4)) + ipaddress.IPv4Address("192.0.2.10").packed
    )
    additional = (
        bytes((2,)) + source_id + struct.pack("!HH", 30, 27 + len(tlvs)) + bytes((100,)) + designated
    )
    payload = common + additional + tlvs
    frame = _ethernet_8023(
        bytes.fromhex("0180c2000014"), bytes.fromhex("001122334455"), b"\xfe\xfe\x03" + payload
    )
    decoded = ProtocolIntelligenceEngine().decode_frame(frame, link_type="ethernet")
    fields = next(layer.fields for layer in decoded.layers if layer.name == "isis")
    assert fields["pdu_type_name"] == "l1-lan-hello"
    assert fields["source_id"] == "4900.0100.0001"
    assert fields["holding_timer_seconds"] == 30
    tlv_by_name = {row["name"]: row for row in fields["tlvs"]}
    assert tlv_by_name["dynamic-hostname"]["hostname"] == "spine-01"
    assert tlv_by_name["ipv4-interface-addresses"]["addresses"] == ["192.0.2.10"]
    assert tlv_by_name["protocols-supported"]["nlpids"] == ["0xcc", "0x8e"]
    assert decoded.application_protocol == "isis"


def _ldp_message(message_type: int, message_id: int, tlvs: bytes) -> bytes:
    message_length = 4 + len(tlvs)
    return struct.pack("!HHI", message_type, message_length, message_id) + tlvs


def test_ldp_pdu_decodes_hello_and_label_mapping_control_plane_metadata() -> None:
    hello_tlv = struct.pack("!HHHH", 0x0400, 4, 15, 0x8000)
    label_tlv = struct.pack("!HHI", 0x0200, 4, 16000)
    messages = _ldp_message(0x0100, 1, hello_tlv) + _ldp_message(0x0400, 2, label_tlv)
    pdu_length = 6 + len(messages)
    payload = struct.pack("!HH", 1, pdu_length) + ipaddress.IPv4Address("192.0.2.1").packed + struct.pack("!H", 0) + messages
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        payload, source_port=646, destination_port=646, transport="tcp"
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "ldp")
    assert fields["lsr_id"] == "192.0.2.1"
    assert fields["label_space_id"] == 0
    assert [row["type_name"] for row in fields["messages"]] == ["hello", "label-mapping"]
    assert fields["messages"][0]["tlvs"][0]["hold_time_seconds"] == 15
    assert fields["messages"][0]["tlvs"][0]["targeted_hello"] is True
    assert fields["messages"][1]["tlvs"][0]["label"] == 16000


def test_protocol_catalog_marks_isis_and_ldp_as_native_deep() -> None:
    rows = {row["protocol"]: row for row in ProtocolIntelligenceEngine().protocol_catalog()}
    assert rows["isis"]["mode"] == "native-deep"
    assert rows["ldp"]["mode"] == "native-deep"


def test_network_evidence_graph_correlates_isis_and_ldp_control_plane_identities() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    packets = [
        _packet_record(1, "192.0.2.10", "224.0.0.5", [{
            "name": "isis",
            "fields": {
                "source_id": "4900.0100.0001",
                "tlvs": [
                    {"name": "dynamic-hostname", "hostname": "spine-01"},
                    {"name": "ipv4-interface-addresses", "addresses": ["192.0.2.10"]},
                    {"name": "extended-ipv4-reachability", "prefixes": [{"prefix": "203.0.113.0/24"}]},
                    {"name": "extended-is-reachability", "neighbors": [{"neighbor_id": "4900.0100.0002.00"}]},
                ],
            },
        }]),
        _packet_record(2, "192.0.2.10", "192.0.2.11", [{
            "name": "ldp",
            "fields": {"lsr_id": "192.0.2.10", "messages": [{"type_name": "keepalive"}]},
        }]),
    ]
    graph = forensic_summary_from_packets(packets)["evidence_graph"]
    relations = {row["relation"] for row in graph["edges"]}
    assert {"isis-hostname", "isis-interface-address", "ldp-speaker-id", "ldp-session-peer"}.issubset(relations)


def _bgp_update_with_attributes(attributes: bytes) -> bytes:
    body = struct.pack("!H", 0) + struct.pack("!H", len(attributes)) + attributes
    return b"\xff" * 16 + struct.pack("!HB", 19 + len(body), 2) + body


def test_bgp_mp_reach_and_unreach_decode_ipv6_next_hop_and_nlri() -> None:
    prefix = bytes((64,)) + ipaddress.IPv6Address("2001:db8:100::").packed[:8]
    next_hop = ipaddress.IPv6Address("2001:db8::1").packed
    mp_reach_value = struct.pack("!HB", 2, 1) + bytes((len(next_hop),)) + next_hop + b"\x00" + prefix
    mp_reach = bytes((0x80, 14, len(mp_reach_value))) + mp_reach_value
    withdrawn_prefix = bytes((48,)) + ipaddress.IPv6Address("2001:db8:200::").packed[:6]
    mp_unreach_value = struct.pack("!HB", 2, 1) + withdrawn_prefix
    mp_unreach = bytes((0x80, 15, len(mp_unreach_value))) + mp_unreach_value
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        _bgp_update_with_attributes(mp_reach + mp_unreach), source_port=179, destination_port=50000, transport="tcp"
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "bgp")
    attrs = {row["name"]: row for row in fields["path_attributes"]}
    assert attrs["MP_REACH_NLRI"]["afi"] == 2
    assert attrs["MP_REACH_NLRI"]["safi"] == 1
    assert attrs["MP_REACH_NLRI"]["next_hops"] == ["2001:db8::1"]
    assert attrs["MP_REACH_NLRI"]["nlri"] == ["2001:db8:100::/64"]
    assert attrs["MP_UNREACH_NLRI"]["withdrawn_nlri"] == ["2001:db8:200::/48"]


def test_routing_control_plane_v2_tracks_mp_bgp_isis_ldp_bfd_and_vrrp_state() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    packets = [
        _packet_record(1, "2001:db8::1", "2001:db8::2", [{
            "name": "bgp",
            "fields": {
                "message_name": "update",
                "nlri": [],
                "withdrawn_routes": [],
                "path_attributes": [
                    {"name": "AS_PATH", "segments": [{"type": "sequence", "asns": [23456]}]},
                    {"name": "AS4_PATH", "segments": [{"type": "sequence", "asns": [4200000001, 64496]}]},
                    {"name": "MP_REACH_NLRI", "afi": 2, "safi": 1, "nlri": ["2001:db8:100::/64"]},
                ],
            },
        }]),
        _packet_record(2, "2001:db8::1", "2001:db8::2", [{
            "name": "bgp",
            "fields": {
                "message_name": "update",
                "nlri": [],
                "withdrawn_routes": [],
                "path_attributes": [
                    {"name": "MP_UNREACH_NLRI", "afi": 2, "safi": 1, "withdrawn_nlri": ["2001:db8:100::/64"]},
                ],
            },
        }]),
        _packet_record(3, "192.0.2.10", "01:80:c2:00:00:14", [{
            "name": "isis",
            "fields": {
                "pdu_type_name": "l1-lan-hello",
                "source_id": "4900.0100.0001",
                "tlvs": [
                    {"name": "dynamic-hostname", "hostname": "spine-01"},
                    {"name": "ipv4-interface-addresses", "addresses": ["192.0.2.10"]},
                    {"name": "extended-ipv4-reachability", "prefixes": [{"prefix": "203.0.113.0/24"}]},
                    {"name": "extended-is-reachability", "neighbors": [{"neighbor_id": "4900.0100.0002.00"}]},
                ],
                "tlvs_truncated": False,
            },
        }]),
        _packet_record(4, "192.0.2.10", "192.0.2.11", [{
            "name": "ldp",
            "fields": {
                "lsr_id": "192.0.2.10",
                "messages_truncated": False,
                "messages": [
                    {"type_name": "keepalive", "tlvs": []},
                    {"type_name": "label-mapping", "tlvs": [
                        {"name": "fec", "elements": [{"type_name": "prefix", "prefix": "203.0.113.0/24"}]},
                        {"name": "generic-label", "label": 16000},
                    ]},
                    {"type_name": "address", "tlvs": [
                        {"name": "address-list", "addresses": ["192.0.2.10", "192.0.2.12"]}
                    ]},
                ],
            },
        }]),
        _packet_record(5, "10.0.0.1", "10.0.0.2", [{
            "name": "bfd",
            "fields": {
                "state_name": "down", "my_discriminator": 100, "your_discriminator": 200,
                "detection_time_floor_us": 150000,
            },
        }]),
        _packet_record(6, "10.0.0.2", "10.0.0.1", [{
            "name": "bfd",
            "fields": {
                "state_name": "up", "my_discriminator": 200, "your_discriminator": 100,
                "detection_time_floor_us": 120000,
            },
        }]),
        _packet_record(7, "10.0.0.254", "224.0.0.18", [{
            "name": "vrrp",
            "fields": {
                "version": 3, "virtual_router_id": 42, "priority": 0,
                "addresses": ["192.0.2.254"], "max_advertisement_interval_seconds": 1.0,
            },
        }]),
    ]
    routing = forensic_summary_from_packets(packets)["routing_control_plane"]
    assert routing["schema"] == "arenyxa.routing-control-plane/v2"
    assert routing["bgp"]["announcements"] == 1
    assert routing["bgp"]["withdrawals"] == 1
    assert routing["bgp"]["active_route_count"] == 0
    assert routing["bgp"]["top_prefix_churn"][0] == {"prefix": "2001:db8:100::/64", "events": 2}
    assert routing["isis"]["hostnames"]["4900.0100.0001"] == "spine-01"
    assert routing["isis"]["interface_addresses"]["4900.0100.0001"] == ["192.0.2.10"]
    assert routing["isis"]["reachable_prefixes"]["4900.0100.0001"] == ["203.0.113.0/24"]
    assert routing["isis"]["adjacency_count"] == 1
    assert routing["ldp"]["messages"]["label-mapping"] == 1
    assert routing["ldp"]["observed_label_count"] == 1
    assert routing["ldp"]["active_binding_count"] == 1
    assert routing["ldp"]["bindings"][0] == {
        "lsr_id": "192.0.2.10", "fec_prefix": "203.0.113.0/24", "label": 16000
    }
    assert routing["ldp"]["addresses"]["192.0.2.10"] == ["192.0.2.10", "192.0.2.12"]
    assert routing["bfd"]["session_count"] == 1
    assert routing["bfd"]["state_transitions"] == 1
    assert routing["bfd"]["minimum_detection_floor_us"] == 120000
    assert routing["vrrp"]["master_relinquishments"] == 1


def test_routing_control_plane_prefers_as4_path_when_as_path_is_transition_placeholder() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    packet = _packet_record(1, "192.0.2.1", "192.0.2.2", [{
        "name": "bgp",
        "fields": {
            "message_name": "update",
            "nlri": ["203.0.113.0/24"],
            "withdrawn_routes": [],
            "path_attributes": [
                {"name": "AS_PATH", "segments": [{"type": "sequence", "asns": [23456]}]},
                {"name": "AS4_PATH", "segments": [{"type": "sequence", "asns": [4200000001, 64496]}]},
            ],
        },
    }])
    route = forensic_summary_from_packets([packet])["routing_control_plane"]["bgp"]["routes"][0]
    assert route["as_path"] == [4200000001, 64496]


def test_isis_extended_reachability_decodes_te_neighbor_ipv4_and_ipv6_prefixes() -> None:
    common = bytes((0x83, 27, 1, 0, 15, 1, 0, 3))
    source_id = bytes.fromhex("490001000001")
    designated = bytes.fromhex("49000100000101")
    sub = bytes((6, 4)) + ipaddress.IPv4Address("192.0.2.1").packed
    ext_is_value = bytes.fromhex("49000100000201") + (25).to_bytes(3, "big") + bytes((len(sub),)) + sub
    ext_ipv4_value = struct.pack("!I", 100) + bytes((24,)) + ipaddress.IPv4Address("203.0.113.0").packed[:3]
    ext_ipv6_value = struct.pack("!I", 200) + bytes((0x40, 64)) + ipaddress.IPv6Address("2001:db8:100::").packed[:8]
    tlvs = (
        bytes((22, len(ext_is_value))) + ext_is_value
        + bytes((135, len(ext_ipv4_value))) + ext_ipv4_value
        + bytes((236, len(ext_ipv6_value))) + ext_ipv6_value
    )
    additional = bytes((2,)) + source_id + struct.pack("!HH", 30, 27 + len(tlvs)) + bytes((100,)) + designated
    frame = _ethernet_8023(
        bytes.fromhex("0180c2000014"), bytes.fromhex("001122334455"), b"\xfe\xfe\x03" + common + additional + tlvs
    )
    decoded = ProtocolIntelligenceEngine().decode_frame(frame, link_type="ethernet")
    fields = next(layer.fields for layer in decoded.layers if layer.name == "isis")
    by_name = {row["name"]: row for row in fields["tlvs"]}
    neighbor = by_name["extended-is-reachability"]["neighbors"][0]
    assert neighbor["neighbor_id"] == "4900.0100.0002.01"
    assert neighbor["metric"] == 25
    assert neighbor["sub_tlvs"][0]["address"] == "192.0.2.1"
    assert by_name["extended-ipv4-reachability"]["prefixes"][0]["prefix"] == "203.0.113.0/24"
    ipv6 = by_name["ipv6-reachability"]["prefixes"][0]
    assert ipv6["prefix"] == "2001:db8:100::/64"
    assert ipv6["external"] is True


def test_ldp_fec_and_address_list_decode_ipv4_ipv6_without_opaque_payload() -> None:
    fec_value = b"\x02" + struct.pack("!HB", 2, 64) + ipaddress.IPv6Address("2001:db8:feed::").packed[:8]
    fec_tlv = struct.pack("!HH", 0x0100, len(fec_value)) + fec_value
    address_value = struct.pack("!H", 1) + ipaddress.IPv4Address("192.0.2.10").packed + ipaddress.IPv4Address("192.0.2.11").packed
    address_tlv = struct.pack("!HH", 0x0101, len(address_value)) + address_value
    label_tlv = struct.pack("!HHI", 0x0200, 4, 16000)
    messages = _ldp_message(0x0400, 1, fec_tlv + label_tlv) + _ldp_message(0x0300, 2, address_tlv)
    payload = struct.pack("!HH", 1, 6 + len(messages)) + ipaddress.IPv4Address("192.0.2.1").packed + b"\x00\x00" + messages
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        payload, source_port=646, destination_port=646, transport="tcp"
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "ldp")
    mapping = fields["messages"][0]["tlvs"]
    fec = next(row for row in mapping if row["name"] == "fec")
    assert fec["elements"][0]["address_family_name"] == "ipv6"
    assert fec["elements"][0]["prefix"] == "2001:db8:feed::/64"
    assert "value_sha256" not in fec
    addresses = fields["messages"][1]["tlvs"][0]
    assert addresses["addresses"] == ["192.0.2.10", "192.0.2.11"]


def test_isis_and_ldp_expert_report_nested_reachability_and_fec_structure_errors() -> None:
    common = bytes((0x83, 27, 1, 0, 15, 1, 0, 3))
    source_id = bytes.fromhex("490001000001")
    designated = bytes.fromhex("49000100000101")
    malformed_reach = struct.pack("!I", 10) + bytes((24,))  # /24 prefix bytes intentionally absent.
    tlvs = bytes((135, len(malformed_reach))) + malformed_reach
    additional = bytes((2,)) + source_id + struct.pack("!HH", 30, 27 + len(tlvs)) + bytes((100,)) + designated
    isis_frame = _ethernet_8023(
        bytes.fromhex("0180c2000014"), bytes.fromhex("001122334455"), b"\xfe\xfe\x03" + common + additional + tlvs
    )
    isis = ProtocolIntelligenceEngine().decode_frame(isis_frame, link_type="ethernet")
    assert any(row["code"] == "ISIS_REACHABILITY_MALFORMED" for row in ProtocolIntelligenceEngine.expert_findings(isis))

    malformed_fec_value = b"\x02" + struct.pack("!HB", 2, 64)  # IPv6 /64 bytes intentionally absent.
    malformed_fec_tlv = struct.pack("!HH", 0x0100, len(malformed_fec_value)) + malformed_fec_value
    messages = _ldp_message(0x0400, 1, malformed_fec_tlv)
    ldp_payload = struct.pack("!HH", 1, 6 + len(messages)) + ipaddress.IPv4Address("192.0.2.1").packed + b"\x00\x00" + messages
    ldp = ProtocolIntelligenceEngine().decode_application_payload(
        ldp_payload, source_port=646, destination_port=646, transport="tcp"
    )
    assert any(row["code"] == "LDP_FEC_MALFORMED" for row in ProtocolIntelligenceEngine.expert_findings(ldp))


def test_dhcpv4_deep_decoder_exposes_lease_network_and_routes_but_hashes_client_identifier() -> None:
    fixed = bytearray(240)
    fixed[0:4] = bytes((1, 1, 6, 0))
    struct.pack_into("!I", fixed, 4, 0x12345678)
    fixed[28:34] = bytes.fromhex("001122334455")
    fixed[236:240] = b"\x63\x82\x53\x63"
    route_value = bytes((24, 203, 0, 113)) + ipaddress.IPv4Address("192.0.2.1").packed
    options = (
        bytes((53, 1, 3))
        + bytes((50, 4)) + ipaddress.IPv4Address("192.0.2.100").packed
        + bytes((54, 4)) + ipaddress.IPv4Address("192.0.2.1").packed
        + bytes((51, 4)) + struct.pack("!I", 3600)
        + bytes((6, 8)) + ipaddress.IPv4Address("192.0.2.53").packed + ipaddress.IPv4Address("192.0.2.54").packed
        + bytes((61, 7, 1)) + bytes.fromhex("001122334455")
        + bytes((121, len(route_value))) + route_value
        + b"\xff"
    )
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        bytes(fixed) + options, source_port=68, destination_port=67, transport="udp"
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "dhcp")
    assert fields["message_type_name"] == "request"
    assert fields["requested_ip"] == "192.0.2.100"
    assert fields["server_identifier"] == "192.0.2.1"
    assert fields["lease_time_seconds"] == 3600
    by_name = {row["name"]: row for row in fields["options"]}
    assert by_name["dns-servers"]["addresses"] == ["192.0.2.53", "192.0.2.54"]
    assert by_name["classless-static-routes"]["routes"] == [{"prefix": "203.0.113.0/24", "router": "192.0.2.1"}]
    client_id = by_name["client-identifier"]
    assert client_id["retained"] is False and len(client_id["sha256"]) == 64


def test_dhcpv6_deep_decoder_handles_ia_na_iaaddr_dns_and_hashes_duid() -> None:
    duid = b"\x00\x03\x00\x01" + bytes.fromhex("001122334455")
    client_id = struct.pack("!HH", 1, len(duid)) + duid
    iaaddr_value = ipaddress.IPv6Address("2001:db8::100").packed + struct.pack("!II", 1800, 3600)
    iaaddr = struct.pack("!HH", 5, len(iaaddr_value)) + iaaddr_value
    ia_na_value = struct.pack("!III", 7, 900, 1440) + iaaddr
    ia_na = struct.pack("!HH", 3, len(ia_na_value)) + ia_na_value
    dns_value = ipaddress.IPv6Address("2001:db8::53").packed
    dns = struct.pack("!HH", 23, len(dns_value)) + dns_value
    payload = b"\x01\x01\x02\x03" + client_id + ia_na + dns
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        payload, source_port=546, destination_port=547, transport="udp"
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "dhcpv6")
    assert fields["message_type_name"] == "solicit"
    by_name = {row["name"]: row for row in fields["options"]}
    assert by_name["client-id"]["duid_retained"] is False
    ia = by_name["ia-na"]
    assert ia["iaid"] == 7
    assert ia["options"][0]["address"] == "2001:db8::100"
    assert ia["options"][0]["valid_lifetime_seconds"] == 3600
    assert by_name["dns-recursive-name-server"]["addresses"] == ["2001:db8::53"]


def test_radius_deep_decoder_redacts_credentials_and_user_identity_but_keeps_nas_metadata() -> None:
    username = b"alice@example.test"
    user_attr = bytes((1, len(username) + 2)) + username
    password = bytes(range(16))
    password_attr = bytes((2, 18)) + password
    nas_attr = bytes((4, 6)) + ipaddress.IPv4Address("192.0.2.10").packed
    eap = b"\x02\x01\x00\x05\x01"
    eap_attr = bytes((79, len(eap) + 2)) + eap
    attributes = user_attr + password_attr + nas_attr + eap_attr
    length = 20 + len(attributes)
    payload = struct.pack("!BBH", 1, 7, length) + b"A" * 16 + attributes
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        payload, source_port=55000, destination_port=1812, transport="udp"
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "radius")
    assert fields["code_name"] == "access-request"
    by_name = {row["name"]: row for row in fields["attributes"]}
    assert by_name["nas-ip-address"]["address"] == "192.0.2.10"
    assert by_name["user-name"]["value_retained"] is False
    assert by_name["user-password"]["sensitive_material_retained"] is False
    assert by_name["eap-message"]["sensitive_material_retained"] is False
    assert "alice@example.test" not in repr(fields)


def _ber_test(tag: int, value: bytes) -> bytes:
    assert len(value) < 128
    return bytes((tag, len(value))) + value


def test_snmp_v2c_and_v3_deep_decoder_hashes_community_and_security_identity() -> None:
    oid = _ber_test(0x06, bytes.fromhex("2b06010201010300"))
    timeticks = _ber_test(0x43, (12345).to_bytes(2, "big"))
    varbind = _ber_test(0x30, oid + timeticks)
    varlist = _ber_test(0x30, varbind)
    pdu = _ber_test(0xA0, _ber_test(0x02, b"\x01") + _ber_test(0x02, b"\x00") + _ber_test(0x02, b"\x00") + varlist)
    v2c = _ber_test(0x30, _ber_test(0x02, b"\x01") + _ber_test(0x04, b"public") + pdu)
    decoded = ProtocolIntelligenceEngine().decode_application_payload(v2c, source_port=50000, destination_port=161, transport="udp")
    fields = next(layer.fields for layer in decoded.layers if layer.name == "snmp")
    assert fields["version_name"] == "v2c"
    assert fields["community_retained"] is False
    assert "public" not in repr(fields)
    assert fields["varbinds"][0]["oid"] == "1.3.6.1.2.1.1.3.0"
    assert fields["varbinds"][0]["type"] == "timeticks"
    assert fields["varbinds"][0]["value"] == 12345

    usm = _ber_test(0x30,
        _ber_test(0x04, b"\x80\x00\x01")
        + _ber_test(0x02, b"\x01")
        + _ber_test(0x02, b"\x02")
        + _ber_test(0x04, b"admin")
        + _ber_test(0x04, b"\x00" * 12)
        + _ber_test(0x04, b"\x00" * 8)
    )
    header = _ber_test(0x30,
        _ber_test(0x02, b"\x07")
        + _ber_test(0x02, b"\x00\xff\xe3")
        + _ber_test(0x04, b"\x03")
        + _ber_test(0x02, b"\x03")
    )
    v3 = _ber_test(0x30,
        _ber_test(0x02, b"\x03") + header + _ber_test(0x04, usm) + _ber_test(0x04, b"ciphertext")
    )
    decoded3 = ProtocolIntelligenceEngine().decode_application_payload(v3, source_port=50000, destination_port=161, transport="udp")
    fields3 = next(layer.fields for layer in decoded3.layers if layer.name == "snmp")
    assert fields3["version_name"] == "v3"
    assert fields3["auth_flag"] is True and fields3["privacy_flag"] is True
    assert fields3["scoped_pdu_encrypted"] is True
    assert fields3["security_parameters"]["identity_material_retained"] is False
    assert "admin" not in repr(fields3)


def test_protocol_catalog_marks_enterprise_access_protocols_as_native_deep() -> None:
    rows = {row["protocol"]: row for row in ProtocolIntelligenceEngine().protocol_catalog()}
    for protocol in ("dhcp", "dhcpv6", "radius", "snmp"):
        assert rows[protocol]["mode"] == "native-deep"


def test_enterprise_access_evidence_graph_correlates_dhcp_radius_and_snmp_without_plaintext_identity() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    principal_hash = "a" * 64
    client_hash = "b" * 64
    packets = [
        _packet_record(1, "0.0.0.0", "255.255.255.255", [{
            "name": "dhcp",
            "fields": {
                "client_mac": "00:11:22:33:44:55", "hostname": "edge-client", "your_ip": "192.0.2.100",
                "server_identifier": "192.0.2.1", "options": [
                    {"name": "client-identifier", "sha256": client_hash},
                    {"name": "dns-servers", "addresses": ["192.0.2.53"]},
                ],
            },
        }]),
        _packet_record(2, "192.0.2.10", "192.0.2.20", [{
            "name": "radius",
            "fields": {"attributes": [
                {"name": "user-name", "value_sha256": principal_hash},
                {"name": "nas-ip-address", "address": "192.0.2.10"},
                {"name": "framed-ip-address", "address": "192.0.2.100"},
            ]},
        }]),
        _packet_record(3, "192.0.2.30", "192.0.2.40", [{
            "name": "snmp",
            "fields": {"pdu_type": "get-request", "varbinds": [{"oid": "1.3.6.1.2.1.1.3.0"}]},
        }]),
    ]
    graph = forensic_summary_from_packets(packets)["evidence_graph"]
    relations = {row["relation"] for row in graph["edges"]}
    assert {"dhcp-address", "dhcp-server", "dhcp-dns-server", "radius-framed-address", "radius-auth-server", "snmp-observes-oid"}.issubset(relations)
    values = {row["value"] for row in graph["nodes"]}
    assert principal_hash in values and client_hash in values
    assert "alice@example.test" not in values


def test_enterprise_access_expert_reports_negative_outcomes_and_invalid_snmpv3_flags() -> None:
    fixed = bytearray(240)
    fixed[0:4] = bytes((2, 1, 6, 0))
    struct.pack_into("!I", fixed, 4, 0x01020304)
    fixed[236:240] = b"\x63\x82\x53\x63"
    dhcp = ProtocolIntelligenceEngine().decode_application_payload(
        bytes(fixed) + bytes((53, 1, 6, 255)), source_port=67, destination_port=68, transport="udp"
    )
    assert any(row["code"] == "DHCP_NAK_OBSERVED" for row in ProtocolIntelligenceEngine.expert_findings(dhcp))

    radius_payload = struct.pack("!BBH", 3, 9, 20) + b"R" * 16
    radius = ProtocolIntelligenceEngine().decode_application_payload(
        radius_payload, source_port=1812, destination_port=55000, transport="udp"
    )
    assert any(row["code"] == "RADIUS_AUTH_OUTCOME" for row in ProtocolIntelligenceEngine.expert_findings(radius))

    header = _ber_test(0x30,
        _ber_test(0x02, b"\x07")
        + _ber_test(0x02, b"\x00\xff\xe3")
        + _ber_test(0x04, b"\x02")  # privacy without authentication: invalid by SNMPv3 architecture.
        + _ber_test(0x02, b"\x03")
    )
    snmpv3 = _ber_test(0x30,
        _ber_test(0x02, b"\x03") + header + _ber_test(0x04, b"") + _ber_test(0x04, b"ciphertext")
    )
    snmp = ProtocolIntelligenceEngine().decode_application_payload(
        snmpv3, source_port=50000, destination_port=161, transport="udp"
    )
    assert any(row["code"] == "SNMPV3_PRIV_WITHOUT_AUTH" for row in ProtocolIntelligenceEngine.expert_findings(snmp))


def _mpls_entry(label: int, *, bottom: bool, traffic_class: int = 0, ttl: int = 64) -> bytes:
    value = ((label & 0xFFFFF) << 12) | ((traffic_class & 0x7) << 9) | ((1 if bottom else 0) << 8) | (ttl & 0xFF)
    return struct.pack("!I", value)


def test_mpls_deep_decoder_marks_special_purpose_entropy_and_stack_semantics() -> None:
    frame = (
        bytes.fromhex("00112233445566778899aabb")
        + struct.pack("!H", 0x8847)
        + _mpls_entry(7, bottom=False, ttl=63)
        + _mpls_entry(100000, bottom=True, traffic_class=5, ttl=62)
    )
    decoded = ProtocolIntelligenceEngine().decode_frame(frame, link_type="ethernet")
    fields = next(layer.fields for layer in decoded.layers if layer.name == "mpls")
    assert fields["label_count"] == 2
    assert fields["bottom_of_stack_seen"] is True
    assert fields["labels"][0]["special_purpose_name"] == "entropy-label-indicator"
    assert fields["labels"][0]["entropy_label_value"] == 100000
    assert fields["labels"][1]["entropy_label"] is True
    assert fields["labels"][1]["traffic_class"] == 5
    rows = {row["protocol"]: row for row in ProtocolIntelligenceEngine().protocol_catalog()}
    assert rows["mpls"]["mode"] == "native-deep"


def test_mpls_expert_reports_implicit_null_and_reserved_entropy_label_on_wire() -> None:
    implicit = bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", 0x8847) + _mpls_entry(3, bottom=True)
    decoded = ProtocolIntelligenceEngine().decode_frame(implicit, link_type="ethernet")
    assert any(row["code"] == "MPLS_IMPLICIT_NULL_ON_WIRE" for row in ProtocolIntelligenceEngine.expert_findings(decoded))

    invalid_entropy = (
        bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", 0x8847)
        + _mpls_entry(7, bottom=False) + _mpls_entry(2, bottom=True)
    )
    decoded_entropy = ProtocolIntelligenceEngine().decode_frame(invalid_entropy, link_type="ethernet")
    assert any(row["code"] == "MPLS_ENTROPY_LABEL_RESERVED" for row in ProtocolIntelligenceEngine.expert_findings(decoded_entropy))


def test_network_evidence_graph_links_ldp_fec_label_binding_to_observed_mpls_label() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    packets = [
        _packet_record(1, "192.0.2.1", "192.0.2.2", [{
            "name": "ldp", "fields": {
                "lsr_id": "192.0.2.1",
                "messages": [{"type_name": "label-mapping", "tlvs": [
                    {"name": "fec", "elements": [{"prefix": "203.0.113.0/24"}]},
                    {"name": "generic-label", "label": 16000},
                ]}],
            },
        }]),
        _packet_record(2, "198.51.100.1", "198.51.100.2", [{
            "name": "mpls", "fields": {"labels": [{"label": 16000, "bottom_of_stack": True, "ttl": 63}]},
        }]),
    ]
    graph = forensic_summary_from_packets(packets)["evidence_graph"]
    relations = {row["relation"] for row in graph["edges"]}
    assert "ldp-fec-label-binding" in relations
    assert "mpls-top-label" in relations
    label_nodes = [row for row in graph["nodes"] if row["kind"] == "mpls-label" and row["value"] == "16000"]
    assert len(label_nodes) == 1


def test_vxlan_deep_decoder_exposes_vni_and_reserved_semantics() -> None:
    payload = bytes((0x08, 0, 0, 0, 0x12, 0x34, 0x56, 0))
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        payload, source_port=55000, destination_port=4789, transport="udp"
    )
    assert decoded.application_protocol == "vxlan"
    fields = decoded.layers[-1].fields
    assert fields["vni"] == 0x123456
    assert fields["instance_valid"] is True
    assert fields["reserved_flag_bits"] == 0
    assert fields["reserved_bytes_nonzero"] is False
    rows = {row["protocol"]: row for row in ProtocolIntelligenceEngine().protocol_catalog()}
    assert rows["vxlan"]["mode"] == "native-deep"


def test_vxlan_expert_reports_missing_i_flag_and_reserved_fields() -> None:
    payload = bytes((0x01, 1, 0, 0, 0, 0, 1, 1))
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        payload, source_port=55000, destination_port=4789, transport="udp"
    )
    codes = {row["code"] for row in ProtocolIntelligenceEngine.expert_findings(decoded)}
    assert "VXLAN_VNI_FLAG_MISSING" in codes
    assert "VXLAN_RESERVED_NONZERO" in codes


def test_geneve_deep_decoder_bounds_and_hashes_options_without_retaining_payload() -> None:
    option = struct.pack("!HBB", 0x0102, 0x81, 0x01) + b"abcd"
    payload = bytes((0x02, 0x40)) + struct.pack("!H", 0x6558) + bytes.fromhex("12345600") + option
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        payload, source_port=55000, destination_port=6081, transport="udp"
    )
    assert decoded.application_protocol == "geneve"
    fields = decoded.layers[-1].fields
    assert fields["version"] == 0
    assert fields["option_length"] == 8
    assert fields["protocol_type"] == "0x6558"
    assert fields["vni"] == 0x123456
    assert fields["critical"] is True
    assert fields["options_malformed"] is False
    assert fields["critical_option_count"] == 1
    row = fields["options"][0]
    assert row["class"] == "0x0102"
    assert row["type"] == 1
    assert row["critical"] is True
    assert row["data_bytes"] == 4
    assert len(row["data_sha256"]) == 64
    assert row["data_retained"] is False
    rows = {item["protocol"]: item for item in ProtocolIntelligenceEngine().protocol_catalog()}
    assert rows["geneve"]["mode"] == "native-deep"


def test_geneve_expert_reports_option_length_boundary_violation() -> None:
    # Opt Len advertises one 4-byte option area, while this option header itself
    # declares four additional data bytes. The decoder must retain the base
    # Geneve evidence and mark the option vector malformed rather than over-read.
    option_header_only = struct.pack("!HBB", 0x0102, 0x01, 0x01)
    payload = bytes((0x01, 0x00)) + struct.pack("!H", 0x6558) + bytes.fromhex("00000100") + option_header_only
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        payload, source_port=55000, destination_port=6081, transport="udp"
    )
    fields = decoded.layers[-1].fields
    assert fields["options_malformed"] is True
    assert any(
        row["code"] == "GENEVE_OPTIONS_MALFORMED"
        for row in ProtocolIntelligenceEngine.expert_findings(decoded)
    )


def _evpn_rd_asn(asn: int, assigned: int) -> bytes:
    return struct.pack("!HHI", 0, asn, assigned)


def _evpn_nlri(route_type: int, value: bytes) -> bytes:
    assert len(value) <= 255
    return bytes((route_type, len(value))) + value


def _evpn_service_id(value: int) -> bytes:
    return int(value).to_bytes(3, "big")


def test_bgp_evpn_mp_reach_decodes_rt2_rt3_and_rt5_with_vni_semantics() -> None:
    rd = _evpn_rd_asn(65000, 100)
    esi = b"\x00" * 10
    tag = struct.pack("!I", 0)
    vni = 5000
    rt2 = _evpn_nlri(
        2,
        rd + esi + tag + b"\x30" + bytes.fromhex("001122334455")
        + b"\x20" + ipaddress.IPv4Address("192.0.2.10").packed + _evpn_service_id(vni),
    )
    rt3 = _evpn_nlri(
        3,
        rd + tag + b"\x20" + ipaddress.IPv4Address("198.51.100.10").packed,
    )
    rt5 = _evpn_nlri(
        5,
        rd + esi + tag + b"\x18" + ipaddress.IPv4Address("203.0.113.0").packed
        + ipaddress.IPv4Address("192.0.2.10").packed + _evpn_service_id(vni),
    )
    nlri = rt2 + rt3 + rt5
    next_hop = ipaddress.IPv4Address("198.51.100.10").packed
    mp_value = struct.pack("!HB", 25, 70) + bytes((len(next_hop),)) + next_hop + b"\x00" + nlri
    mp_reach = bytes((0x80, 14, len(mp_value))) + mp_value
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        _bgp_update_with_attributes(mp_reach), source_port=179, destination_port=50000, transport="tcp"
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "bgp")
    attr = next(row for row in fields["path_attributes"] if row["name"] == "MP_REACH_NLRI")
    assert attr["afi"] == 25 and attr["safi"] == 70
    assert attr["next_hops"] == ["198.51.100.10"]
    routes = attr["nlri"]
    assert [route["route_type"] for route in routes] == [2, 3, 5]
    assert routes[0]["mac_address"] == "00:11:22:33:44:55"
    assert routes[0]["ip_address"] == "192.0.2.10"
    assert routes[0]["service"]["service_id_24"] == vni
    assert routes[1]["originating_router_ip"] == "198.51.100.10"
    assert routes[2]["ip_prefix"] == "203.0.113.0/24"
    assert routes[2]["gateway_ip"] == "192.0.2.10"
    assert routes[2]["overlay_index_kind"] == "gateway-ip"


def test_bgp_evpn_unknown_and_malformed_routes_keep_digest_not_opaque_payload() -> None:
    from arenyxa.infrastructure.capture.protocol_evpn import decode_evpn_nlri

    unknown = _evpn_nlri(99, b"opaque-route-data")
    malformed_rt2 = _evpn_nlri(2, b"short")
    rows = decode_evpn_nlri(unknown + malformed_rt2)
    assert rows[0]["route_type"] == 99
    assert rows[0]["payload_retained"] is False
    assert len(rows[0]["payload_sha256"]) == 64
    assert "opaque-route-data" not in repr(rows[0])
    assert rows[1]["route_type"] == 2
    assert rows[1]["malformed"] is True
    assert rows[1]["payload_retained"] is False


def test_evpn_overlay_forensics_correlates_control_plane_service_id_mac_and_vxlan_data_plane() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    vni = 5000
    evpn_route = {
        "route_type": 2,
        "route_type_name": "mac-ip-advertisement",
        "ethernet_tag_id": 0,
        "ethernet_segment_identifier": {"value_hex": "00" * 10, "zero": True},
        "mac_address": "00:11:22:33:44:55",
        "ip_address": "192.0.2.10",
        "service": {"label20": vni >> 4, "service_id_24": vni},
    }
    bgp = _packet_record(1, "198.51.100.10", "198.51.100.20", [{
        "name": "bgp",
        "fields": {
            "message_name": "update",
            "path_attributes": [{
                "name": "MP_REACH_NLRI", "afi": 25, "safi": 70,
                "next_hops": ["198.51.100.10"], "nlri": [evpn_route],
            }],
        },
    }])
    vxlan = _packet_record(2, "198.51.100.10", "198.51.100.20", [
        {"name": "vxlan", "fields": {"vni": vni, "instance_valid": True}},
        {"name": "ethernet", "fields": {"source": "00:11:22:33:44:55", "destination": "66:77:88:99:aa:bb"}},
    ])
    summary = forensic_summary_from_packets([bgp, vxlan])
    overlay = summary["evpn_overlay"]
    assert overlay["evpn"]["route_type_counts"]["mac-ip-advertisement"] == 1
    assert overlay["correlation"]["service_id_matches_vxlan_vni"] == [vni]
    match = overlay["correlation"]["mac_control_data_matches"][0]
    assert match["matched_mac_count"] == 1
    graph_relations = {row["relation"] for row in summary["evidence_graph"]["edges"]}
    assert {"evpn-advertises-mac", "evpn-service-mac", "evpn-mac-ip-binding", "vxlan-source-vtep-vni"}.issubset(graph_relations)


def test_evpn_overlay_forensics_does_not_claim_unobserved_service_id_is_vxlan() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    route = {
        "route_type": 5,
        "route_type_name": "ip-prefix",
        "ethernet_tag_id": 0,
        "ip_prefix": "203.0.113.0/24",
        "gateway_ip": "192.0.2.10",
        "service": {"label20": 100, "service_id_24": 1600},
    }
    packet = _packet_record(1, "198.51.100.10", "198.51.100.20", [{
        "name": "bgp", "fields": {
            "message_name": "update",
            "path_attributes": [{"name": "MP_REACH_NLRI", "afi": 25, "safi": 70, "nlri": [route]}],
        },
    }])
    overlay = forensic_summary_from_packets([packet])["evpn_overlay"]
    assert overlay["correlation"]["service_id_matches_vxlan_vni"] == []
    assert overlay["correlation"]["evpn_service_without_observed_vxlan"] == [1600]
    assert "does not infer encapsulation" in overlay["correlation"]["interpretation"]


def test_routing_control_plane_does_not_stringify_evpn_routes_as_ip_prefixes() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    route = {
        "route_type": 2,
        "route_type_name": "mac-ip-advertisement",
        "ethernet_tag_id": 0,
        "mac_address": "00:11:22:33:44:55",
        "service": {"service_id_24": 5000},
    }
    packet = _packet_record(1, "198.51.100.10", "198.51.100.20", [{
        "name": "bgp", "fields": {
            "message_name": "update",
            "path_attributes": [{"name": "MP_REACH_NLRI", "afi": 25, "safi": 70, "nlri": [route]}],
        },
    }])
    routing = forensic_summary_from_packets([packet])["routing_control_plane"]
    assert routing["bgp"]["active_route_count"] == 0
    assert routing["bgp"]["routes"] == []


def test_bgp_evpn_expert_reports_malformed_route_and_rt5_multiple_overlay_indexes() -> None:
    malformed = {"route_type": 2, "route_type_name": "mac-ip-advertisement", "malformed": True, "parse_error": "short"}
    rt5 = {
        "route_type": 5, "route_type_name": "ip-prefix", "ip_prefix": "203.0.113.0/24",
        "gateway_ip": "192.0.2.10", "ethernet_segment_identifier": {"zero": False, "value_hex": "01" + "00" * 9},
    }
    packet = _packet_record(1, "198.51.100.10", "198.51.100.20", [{
        "name": "bgp", "fields": {
            "message_name": "update",
            "path_attributes": [{"name": "MP_REACH_NLRI", "afi": 25, "safi": 70, "nlri": [malformed, rt5]}],
        },
    }])
    # Expert works on ProtocolDecodeResult, so construct one through a real BGP
    # message for malformed NLRI and validate RT-5 logic through the helper-level
    # fields path used by native results.
    from arenyxa.infrastructure.capture.protocol_intelligence import ProtocolDecodeResult, ProtocolLayer
    decoded = ProtocolDecodeResult(
        frame_length=0, link_type="synthetic", protocols=("bgp",),
        layers=[ProtocolLayer(name="bgp", offset=0, length=0, fields=packet.metadata["native_layers"][0]["fields"])],
        application_protocol="bgp", encrypted=False, truncated=False, warnings=[],
    )
    codes = {row["code"] for row in ProtocolIntelligenceEngine.expert_findings(decoded)}
    assert "BGP_EVPN_NLRI_MALFORMED" in codes
    assert "BGP_EVPN_RT5_MULTIPLE_OVERLAY_INDEXES" in codes


def _bgp_ext_community_mac_mobility(sequence: int, *, sticky: bool = False) -> bytes:
    return bytes((0x06, 0x00, 0x01 if sticky else 0x00, 0x00)) + struct.pack("!I", sequence)


def _bgp_ext_community_encapsulation(tunnel_type: int) -> bytes:
    return bytes((0x03, 0x0C, 0, 0, 0, 0)) + struct.pack("!H", tunnel_type)


def test_bgp_extended_communities_decode_evpn_mobility_esi_and_encapsulation() -> None:
    mobility = _bgp_ext_community_mac_mobility(42, sticky=True)
    esi_label = bytes((0x06, 0x01, 0x01, 0, 0)) + _evpn_service_id(16000)
    es_import = bytes((0x06, 0x02)) + bytes.fromhex("001122334455")
    default_gateway = bytes((0x03, 0x0D)) + b"\x00" * 6
    encapsulation = _bgp_ext_community_encapsulation(8)
    value = mobility + esi_label + es_import + default_gateway + encapsulation
    attribute = bytes((0xC0, 16, len(value))) + value
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        _bgp_update_with_attributes(attribute), source_port=179, destination_port=50000, transport="tcp"
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "bgp")
    ext = next(row for row in fields["path_attributes"] if row["name"] == "EXTENDED_COMMUNITIES")
    communities = {row["name"]: row for row in ext["communities"]}
    assert communities["mac-mobility"]["sequence"] == 42
    assert communities["mac-mobility"]["sticky"] is True
    assert communities["esi-label"]["single_active"] is True
    assert communities["es-import"]["value"] == "00:11:22:33:44:55"
    assert communities["default-gateway"]["reserved_nonzero"] is False
    assert communities["encapsulation"]["tunnel_type"] == 8
    assert communities["encapsulation"]["tunnel_type_name"] == "vxlan"


def test_evpn_overlay_uses_explicit_encapsulation_to_promote_proven_vxlan_vni_and_tracks_mobility() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    vni = 7000
    route = {
        "route_type": 2, "route_type_name": "mac-ip-advertisement", "ethernet_tag_id": 0,
        "ethernet_segment_identifier": {"value_hex": "00" * 10, "zero": True},
        "mac_address": "00:aa:bb:cc:dd:ee", "ip_address": "192.0.2.70",
        "service": {"service_id_24": vni},
    }
    first = _packet_record(1, "198.51.100.1", "198.51.100.254", [{
        "name": "bgp", "fields": {"message_name": "update", "path_attributes": [
            {"name": "EXTENDED_COMMUNITIES", "communities": [
                {"name": "encapsulation", "tunnel_type_name": "vxlan"},
                {"name": "mac-mobility", "sequence": 1, "sticky": False},
            ]},
            {"name": "MP_REACH_NLRI", "afi": 25, "safi": 70, "nlri": [route]},
        ]},
    }])
    moved = _packet_record(2, "198.51.100.2", "198.51.100.254", [{
        "name": "bgp", "fields": {"message_name": "update", "path_attributes": [
            {"name": "EXTENDED_COMMUNITIES", "communities": [
                {"name": "encapsulation", "tunnel_type_name": "vxlan"},
                {"name": "mac-mobility", "sequence": 2, "sticky": False},
            ]},
            {"name": "MP_REACH_NLRI", "afi": 25, "safi": 70, "nlri": [route]},
        ]},
    }])
    data = _packet_record(3, "198.51.100.2", "198.51.100.3", [
        {"name": "vxlan", "fields": {"vni": vni}},
        {"name": "ethernet", "fields": {"source": "00:aa:bb:cc:dd:ee", "destination": "00:00:5e:00:01:01"}},
    ])
    overlay = forensic_summary_from_packets([first, moved, data])["evpn_overlay"]
    assert overlay["evpn"]["encapsulation_counts"]["vxlan"] == 2
    assert overlay["evpn"]["mac_mobility_events"] == 1
    assert overlay["evpn"]["mac_location_variants"] == 1
    assert overlay["correlation"]["control_plane_proven_vxlan_vni_matches"] == [vni]
    assert overlay["correlation"]["mac_control_data_matches"][0]["matched_mac_count"] == 1


def test_bgp_evpn_expert_reports_incompatible_vxlan_mpls_encapsulation_set() -> None:
    from arenyxa.infrastructure.capture.protocol_intelligence import ProtocolDecodeResult, ProtocolLayer

    fields = {
        "message_name": "update",
        "path_attributes": [{"name": "EXTENDED_COMMUNITIES", "communities": [
            {"name": "encapsulation", "tunnel_type_name": "vxlan"},
            {"name": "encapsulation", "tunnel_type_name": "mpls"},
        ]}],
    }
    decoded = ProtocolDecodeResult(
        frame_length=0, link_type="synthetic", protocols=("bgp",),
        layers=[ProtocolLayer(name="bgp", offset=0, length=0, fields=fields)],
        application_protocol="bgp", encrypted=False, truncated=False, warnings=[],
    )
    codes = {row["code"] for row in ProtocolIntelligenceEngine.expert_findings(decoded)}
    assert "BGP_EVPN_INCOMPATIBLE_ENCAPSULATIONS" in codes


def test_evpn_decodes_rt1_rt4_and_ipv6_rt5_without_collapsing_address_family() -> None:
    from arenyxa.infrastructure.capture.protocol_evpn import decode_evpn_nlri

    rd = _evpn_rd_asn(65000, 200)
    esi = bytes.fromhex("01001122334455667788")
    tag = struct.pack("!I", 77)
    rt1 = _evpn_nlri(1, rd + esi + tag + _evpn_service_id(9000))
    rt4 = _evpn_nlri(4, rd + esi + b"\x80" + ipaddress.IPv6Address("2001:db8::44").packed)
    rt5 = _evpn_nlri(
        5,
        rd + b"\x00" * 10 + tag + b"\x40"
        + ipaddress.IPv6Address("2001:db8:500::").packed
        + ipaddress.IPv6Address("2001:db8::1").packed
        + _evpn_service_id(9000),
    )
    rows = decode_evpn_nlri(rt1 + rt4 + rt5)
    assert rows[0]["route_type_name"] == "ethernet-auto-discovery"
    assert rows[0]["ethernet_segment_identifier"]["value_hex"] == esi.hex()
    assert rows[0]["service"]["service_id_24"] == 9000
    assert rows[1]["route_type_name"] == "ethernet-segment"
    assert rows[1]["originating_router_ip"] == "2001:db8::44"
    assert rows[2]["route_type_name"] == "ip-prefix"
    assert rows[2]["ip_prefix"] == "2001:db8:500::/64"
    assert rows[2]["gateway_ip"] == "2001:db8::1"
    assert rows[2]["overlay_index_kind"] == "gateway-ip"


def test_evpn_overlay_mp_unreach_removes_active_rt1_rt2_rt3_rt4_rt5_state() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    peer = "198.51.100.11"
    service_id = 9100
    esi = {"value_hex": "01" + "00" * 9, "zero": False}
    rd = {"hex": _evpn_rd_asn(65000, 300).hex()}
    routes = [
        {
            "route_type": 1, "route_type_name": "ethernet-auto-discovery",
            "route_distinguisher": rd, "ethernet_segment_identifier": esi,
            "ethernet_tag_id": 0, "service": {"service_id_24": service_id},
        },
        {
            "route_type": 2, "route_type_name": "mac-ip-advertisement",
            "ethernet_segment_identifier": esi, "ethernet_tag_id": 0,
            "mac_address": "00:11:22:33:44:66", "ip_address": "192.0.2.66",
            "service": {"service_id_24": service_id},
        },
        {
            "route_type": 3, "route_type_name": "inclusive-multicast-ethernet-tag",
            "ethernet_tag_id": 0, "originating_router_ip": peer,
        },
        {
            "route_type": 4, "route_type_name": "ethernet-segment",
            "ethernet_segment_identifier": esi, "originating_router_ip": peer,
        },
        {
            "route_type": 5, "route_type_name": "ip-prefix",
            "ethernet_tag_id": 0, "ip_prefix": "2001:db8:9100::/64",
            "gateway_ip": "2001:db8::11", "service": {"service_id_24": service_id},
        },
    ]
    announced = _packet_record(1, peer, "198.51.100.254", [{
        "name": "bgp", "fields": {"message_name": "update", "path_attributes": [
            {"name": "EXTENDED_COMMUNITIES", "communities": [
                {"name": "encapsulation", "tunnel_type_name": "vxlan"},
            ]},
            {"name": "MP_REACH_NLRI", "afi": 25, "safi": 70, "nlri": routes},
        ]},
    }])
    withdrawn = _packet_record(2, peer, "198.51.100.254", [{
        "name": "bgp", "fields": {"message_name": "update", "path_attributes": [
            {"name": "MP_UNREACH_NLRI", "afi": 25, "safi": 70, "withdrawn_nlri": routes},
        ]},
    }])
    overlay = forensic_summary_from_packets([announced, withdrawn])["evpn_overlay"]
    assert overlay["evpn"]["service_ids_24"] == {}
    assert overlay["evpn"]["ethernet_ad_routes"] == []
    assert overlay["evpn"]["mac_ip_routes"] == []
    assert overlay["evpn"]["imet_origins"] == []
    assert overlay["evpn"]["ethernet_segments"] == []
    assert overlay["evpn"]["ip_prefix_routes"] == []
    counts = overlay["evpn"]["route_type_counts"]
    assert counts["withdraw-ethernet-auto-discovery"] == 1
    assert counts["withdraw-mac-ip-advertisement"] == 1
    assert counts["withdraw-inclusive-multicast-ethernet-tag"] == 1
    assert counts["withdraw-ethernet-segment"] == 1
    assert counts["withdraw-ip-prefix"] == 1


def test_evpn_overlay_keeps_route_active_until_last_advertising_peer_withdraws() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    route = {
        "route_type": 2, "route_type_name": "mac-ip-advertisement", "ethernet_tag_id": 0,
        "ethernet_segment_identifier": {"value_hex": "00" * 10, "zero": True},
        "mac_address": "00:de:ad:be:ef:01", "service": {"service_id_24": 9200},
    }
    packets = [
        _packet_record(1, "198.51.100.1", "198.51.100.254", [{"name": "bgp", "fields": {
            "message_name": "update", "path_attributes": [
                {"name": "MP_REACH_NLRI", "afi": 25, "safi": 70, "nlri": [route]},
            ],
        }}]),
        _packet_record(2, "198.51.100.2", "198.51.100.254", [{"name": "bgp", "fields": {
            "message_name": "update", "path_attributes": [
                {"name": "MP_REACH_NLRI", "afi": 25, "safi": 70, "nlri": [route]},
            ],
        }}]),
        _packet_record(3, "198.51.100.1", "198.51.100.254", [{"name": "bgp", "fields": {
            "message_name": "update", "path_attributes": [
                {"name": "MP_UNREACH_NLRI", "afi": 25, "safi": 70, "withdrawn_nlri": [route]},
            ],
        }}]),
    ]
    overlay = forensic_summary_from_packets(packets)["evpn_overlay"]
    assert overlay["evpn"]["mac_ip_routes"][0]["advertising_peers"] == ["198.51.100.2"]
    assert overlay["evpn"]["service_ids_24"] == {9200: 1}


def test_evpn_overlay_reports_sticky_mac_location_conflict_across_peers() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    route = {
        "route_type": 2, "route_type_name": "mac-ip-advertisement", "ethernet_tag_id": 0,
        "ethernet_segment_identifier": {"value_hex": "00" * 10, "zero": True},
        "mac_address": "00:ca:fe:00:00:01", "service": {"service_id_24": 9300},
    }
    def advertisement(frame: int, peer: str, sequence: int, sticky: bool) -> object:
        return _packet_record(frame, peer, "198.51.100.254", [{"name": "bgp", "fields": {
            "message_name": "update", "path_attributes": [
                {"name": "EXTENDED_COMMUNITIES", "communities": [
                    {"name": "mac-mobility", "sequence": sequence, "sticky": sticky},
                ]},
                {"name": "MP_REACH_NLRI", "afi": 25, "safi": 70, "nlri": [route]},
            ],
        }}])
    overlay = forensic_summary_from_packets([
        advertisement(1, "198.51.100.1", 5, True),
        advertisement(2, "198.51.100.2", 6, False),
    ])["evpn_overlay"]
    assert overlay["evpn"]["sticky_mac_location_conflicts"] == 1
    assert overlay["evpn"]["mac_mobility_events"] == 1
    assert overlay["evpn"]["mac_location_variants"] == 1


def _bgp_tunnel_subtlv(sub_type: int, value: bytes) -> bytes:
    if sub_type < 128:
        assert len(value) <= 255
        return bytes((sub_type, len(value))) + value
    return bytes((sub_type,)) + struct.pack("!H", len(value)) + value


def _bgp_tunnel_tlv(tunnel_type: int, sub_tlvs: bytes) -> bytes:
    return struct.pack("!HH", tunnel_type, len(sub_tlvs)) + sub_tlvs


def test_bgp_tunnel_encapsulation_attribute_decodes_vxlan_vni_endpoint_and_outer_udp() -> None:
    vni = 9400
    vxlan_encap = bytes((0x80,)) + _evpn_service_id(vni) + b"\x00" * 6 + b"\x00\x00"
    endpoint = b"\x00" * 4 + struct.pack("!H", 1) + ipaddress.IPv4Address("198.51.100.94").packed
    tunnel_value = (
        _bgp_tunnel_subtlv(1, vxlan_encap)
        + _bgp_tunnel_subtlv(6, endpoint)
        + _bgp_tunnel_subtlv(8, struct.pack("!H", 4789))
        + _bgp_tunnel_subtlv(2, struct.pack("!H", 0x6558))
    )
    tunnel_attr_value = _bgp_tunnel_tlv(8, tunnel_value)
    tunnel_attr = bytes((0xC0, 23, len(tunnel_attr_value))) + tunnel_attr_value
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        _bgp_update_with_attributes(tunnel_attr), source_port=179, destination_port=50000, transport="tcp"
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "bgp")
    attribute = next(row for row in fields["path_attributes"] if row["name"] == "TUNNEL_ENCAPSULATION")
    assert attribute["malformed"] is False
    assert attribute["tunnel_count"] == 1
    tunnel = attribute["tunnels"][0]
    assert tunnel["tunnel_type_name"] == "vxlan"
    assert tunnel["tunnel_egress_endpoint_count"] == 1
    sub = {row["name"]: row for row in tunnel["sub_tlvs"]}
    assert sub["encapsulation"]["vni_present"] is True
    assert sub["encapsulation"]["virtual_network_id"] == vni
    assert sub["tunnel-egress-endpoint"]["address"] == "198.51.100.94"
    assert sub["udp-destination-port"]["port"] == 4789
    assert sub["protocol-type"]["ethertype"] == "0x6558"


def test_evpn_overlay_accepts_rfc9012_tunnel_attribute_as_explicit_vxlan_control_evidence() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    vni = 9500
    route = {
        "route_type": 2, "route_type_name": "mac-ip-advertisement", "ethernet_tag_id": 0,
        "ethernet_segment_identifier": {"value_hex": "00" * 10, "zero": True},
        "mac_address": "00:95:00:00:00:01", "service": {"service_id_24": vni},
    }
    tunnel = {
        "name": "TUNNEL_ENCAPSULATION", "malformed": False,
        "tunnels": [{
            "tunnel_type": 8, "tunnel_type_name": "vxlan", "malformed": False,
            "tunnel_egress_endpoint_count": 1,
            "sub_tlvs": [
                {"name": "encapsulation", "vni_present": True, "virtual_network_id": vni},
                {"name": "tunnel-egress-endpoint", "address_family": 1, "address": "198.51.100.95"},
            ],
        }],
    }
    control = _packet_record(1, "198.51.100.95", "198.51.100.254", [{"name": "bgp", "fields": {
        "message_name": "update", "path_attributes": [
            tunnel,
            {"name": "MP_REACH_NLRI", "afi": 25, "safi": 70, "nlri": [route]},
        ],
    }}])
    data = _packet_record(2, "198.51.100.95", "198.51.100.96", [
        {"name": "vxlan", "fields": {"vni": vni}},
        {"name": "ethernet", "fields": {"source": "00:95:00:00:00:01", "destination": "00:00:5e:00:01:01"}},
    ])
    overlay = forensic_summary_from_packets([control, data])["evpn_overlay"]
    assert overlay["evpn"]["encapsulation_counts"]["vxlan"] == 1
    assert overlay["evpn"]["tunnel_attribute_vnis"] == {vni: 1}
    assert overlay["correlation"]["control_plane_proven_vxlan_vni_matches"] == [vni]
    assert overlay["correlation"]["tunnel_attribute_vni_matches"] == [vni]


def test_bgp_tunnel_encapsulation_expert_requires_single_egress_endpoint_for_evpn() -> None:
    from arenyxa.infrastructure.capture.protocol_intelligence import ProtocolDecodeResult, ProtocolLayer

    fields = {
        "message_name": "update",
        "path_attributes": [
            {
                "name": "TUNNEL_ENCAPSULATION", "malformed": False,
                "tunnels": [{
                    "tunnel_type": 8, "tunnel_type_name": "vxlan", "malformed": False,
                    "tunnel_egress_endpoint_count": 0, "sub_tlvs": [],
                }],
            },
            {"name": "MP_REACH_NLRI", "afi": 25, "safi": 70, "nlri": []},
        ],
    }
    decoded = ProtocolDecodeResult(
        frame_length=0, link_type="synthetic", protocols=("bgp",),
        layers=[ProtocolLayer(name="bgp", offset=0, length=0, fields=fields)],
        application_protocol="bgp", encrypted=False, truncated=False, warnings=[],
    )
    codes = {row["code"] for row in ProtocolIntelligenceEngine.expert_findings(decoded)}
    assert "BGP_TUNNEL_EGRESS_ENDPOINT_CARDINALITY" in codes


def test_bgp_pmsi_tunnel_decodes_ingress_replication_and_preserves_full_24bit_field() -> None:
    vni = 9600
    pmsi_value = bytes((0x00, 0x06)) + _evpn_service_id(vni) + ipaddress.IPv4Address("198.51.100.96").packed
    pmsi_attr = bytes((0xC0, 22, len(pmsi_value))) + pmsi_value
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        _bgp_update_with_attributes(pmsi_attr), source_port=179, destination_port=50000, transport="tcp"
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "bgp")
    pmsi = next(row for row in fields["path_attributes"] if row["name"] == "PMSI_TUNNEL")
    assert pmsi["malformed"] is False
    assert pmsi["tunnel_type"] == 6
    assert pmsi["tunnel_type_name"] == "ingress-replication"
    assert pmsi["field24"] == vni
    assert pmsi["label20"] == vni >> 4
    assert pmsi["tunnel_endpoint"] == "198.51.100.96"


def test_evpn_imet_pmsi_vxlan_correlation_tracks_bum_replication_mode_and_vni() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    vni = 9700
    imet = {
        "route_type": 3, "route_type_name": "inclusive-multicast-ethernet-tag",
        "ethernet_tag_id": 0, "originating_router_ip": "198.51.100.97",
    }
    control = _packet_record(1, "198.51.100.97", "198.51.100.254", [{"name": "bgp", "fields": {
        "message_name": "update", "path_attributes": [
            {"name": "EXTENDED_COMMUNITIES", "communities": [
                {"name": "encapsulation", "tunnel_type_name": "vxlan"},
            ]},
            {
                "name": "PMSI_TUNNEL", "malformed": False, "tunnel_type": 6,
                "tunnel_type_name": "ingress-replication", "field24": vni,
                "tunnel_endpoint": "198.51.100.97",
            },
            {"name": "MP_REACH_NLRI", "afi": 25, "safi": 70, "nlri": [imet]},
        ],
    }}])
    data = _packet_record(2, "198.51.100.97", "198.51.100.98", [
        {"name": "vxlan", "fields": {"vni": vni}},
        {"name": "ethernet", "fields": {"source": "00:97:00:00:00:01", "destination": "ff:ff:ff:ff:ff:ff"}},
    ])
    overlay = forensic_summary_from_packets([control, data])["evpn_overlay"]
    assert overlay["evpn"]["pmsi_tunnel_type_counts"] == {"ingress-replication": 1}
    assert overlay["evpn"]["pmsi_vxlan_vnis"] == [vni]
    imet_row = overlay["evpn"]["imet_origins"][0]
    assert imet_row["pmsi_tunnel_types"] == ["ingress-replication"]
    assert imet_row["pmsi_field24_values"] == [vni]
    assert imet_row["tunnel_endpoints"] == ["198.51.100.97"]
    assert overlay["correlation"]["pmsi_vxlan_vni_matches"] == [vni]


def test_bgp_pmsi_expert_rejects_malformed_and_out_of_profile_evpn_vxlan_type() -> None:
    from arenyxa.infrastructure.capture.protocol_intelligence import ProtocolDecodeResult, ProtocolLayer

    imet = {"route_type": 3, "route_type_name": "inclusive-multicast-ethernet-tag"}
    fields = {
        "message_name": "update",
        "path_attributes": [
            {"name": "EXTENDED_COMMUNITIES", "communities": [
                {"name": "encapsulation", "tunnel_type_name": "vxlan"},
            ]},
            {"name": "PMSI_TUNNEL", "malformed": False, "tunnel_type": 1, "tunnel_type_name": "rsvp-te-p2mp-lsp"},
            {"name": "MP_REACH_NLRI", "afi": 25, "safi": 70, "nlri": [imet]},
        ],
    }
    decoded = ProtocolDecodeResult(
        frame_length=0, link_type="synthetic", protocols=("bgp",),
        layers=[ProtocolLayer(name="bgp", offset=0, length=0, fields=fields)],
        application_protocol="bgp", encrypted=False, truncated=False, warnings=[],
    )
    codes = {row["code"] for row in ProtocolIntelligenceEngine.expert_findings(decoded)}
    assert "BGP_EVPN_PMSI_TUNNEL_TYPE_UNSUPPORTED" in codes

    malformed_fields = dict(fields)
    malformed_fields["path_attributes"] = [
        {"name": "PMSI_TUNNEL", "malformed": True, "tunnel_type_name": "tunnel-254", "parse_error": "undefined PMSI tunnel type"},
    ]
    malformed = ProtocolDecodeResult(
        frame_length=0, link_type="synthetic", protocols=("bgp",),
        layers=[ProtocolLayer(name="bgp", offset=0, length=0, fields=malformed_fields)],
        application_protocol="bgp", encrypted=False, truncated=False, warnings=[],
    )
    malformed_codes = {row["code"] for row in ProtocolIntelligenceEngine.expert_findings(malformed)}
    assert "BGP_PMSI_TUNNEL_MALFORMED" in malformed_codes


def _server_hello_record() -> bytes:
    random = bytes(reversed(range(32)))
    extensions = b"".join((
        _extension(43, b"\x03\x04"),
        _extension(16, b"\x00\x03\x02h2"),
    ))
    hello = (
        b"\x03\x03" + random + b"\x00" + struct.pack("!H", 0x1301) + b"\x00"
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x02" + len(hello).to_bytes(3, "big") + hello
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def test_tls_server_hello_exposes_ja3s_and_selected_negotiation_metadata() -> None:
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        _server_hello_record(), source_port=443, destination_port=50000, transport="tcp"
    )
    fields = decoded.layers[-1].fields
    assert fields["selected_cipher_suite"] == "0x1301"
    assert fields["selected_version"] == "0x0304"
    assert fields["selected_alpn"] == "h2"
    assert fields["ja3s"] == "771,4865,43-16"
    assert len(fields["ja3s_md5"]) == 32


def _quic_packet_record(
    frame: int,
    source: str,
    source_port: int,
    destination: str,
    destination_port: int,
    fields: dict[str, object],
    *,
    quic_stream: int | None = None,
) -> object:
    from arenyxa.infrastructure.capture.packet_models import PacketRecord

    return PacketRecord(
        frame_number=frame,
        timestamp=f"2026-08-20T00:10:{frame:02d}+00:00",
        length=1200,
        captured_length=1200,
        protocols="udp:quic",
        protocol="quic",
        info="",
        source=source,
        destination=destination,
        source_port=source_port,
        destination_port=destination_port,
        tcp_stream=None,
        udp_stream=quic_stream,
        http2_stream=None,
        quic_stream=quic_stream,
        host="",
        method="",
        uri="",
        status=None,
        metadata={"native_layers": [{"name": "quic", "fields": fields}]},
    )


def test_quic_session_analysis_correlates_connection_ids_and_path_migration() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    packets = [
        _quic_packet_record(1, "192.0.2.10", 50000, "203.0.113.10", 443, {
            "header_form": "long", "fixed_bit": True, "version_name": "v1", "packet_type": "Initial",
            "destination_connection_id": "aabbccdd", "source_connection_id": "11223344",
            "initial_decryption": {"client_hello": {"server_name": "api.example", "alpn": ["h3"], "ja3_md5": "aa" * 16}},
        }, quic_stream=7),
        _quic_packet_record(2, "192.0.2.10", 50000, "203.0.113.10", 443, {
            "header_form": "long", "fixed_bit": True, "version_name": "v1", "packet_type": "Handshake",
            "destination_connection_id": "11223344", "source_connection_id": "aabbccdd",
        }, quic_stream=7),
        _quic_packet_record(3, "192.0.2.10", 50123, "203.0.113.10", 443, {
            "header_form": "long", "fixed_bit": True, "version_name": "v1", "packet_type": "0-RTT",
            "destination_connection_id": "aabbccdd", "source_connection_id": "55667788",
        }, quic_stream=7),
    ]
    summary = forensic_summary_from_packets(packets)["quic_sessions"]
    assert summary["session_count"] == 1
    assert summary["sessions_with_migration"] == 1
    assert summary["sessions_with_zero_rtt"] == 1
    session = summary["top_sessions"][0]
    assert session["path_count"] == 2
    assert session["public_initials_decrypted"] == 1
    assert session["alpn_hints"] == ["h3"]
    assert set(session["connection_ids"]) == {"11223344", "55667788", "aabbccdd"}


def test_network_evidence_graph_tracks_tls_direction_and_quic_handshake_identity() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    packets = [
        _quic_packet_record(1, "192.0.2.20", 53000, "203.0.113.20", 443, {
            "header_form": "long", "fixed_bit": True, "version_name": "v1", "packet_type": "Initial",
            "destination_connection_id": "cafebabe", "source_connection_id": "01020304",
            "initial_decryption": {"client_hello": {
                "server_name": "quic.example", "alpn": ["h3"], "ja3_md5": "12" * 16,
            }},
        }),
        _packet_record(2, "203.0.113.20", "192.0.2.20", [{
            "name": "tls",
            "fields": {
                "handshake_type": 11,
                "certificate_chain": [{"sha256": "34" * 32, "san_dns": ["quic.example"]}],
            },
        }]),
    ]
    graph = forensic_summary_from_packets(packets)["evidence_graph"]
    nodes = {(row["kind"], row["value"]): row["id"] for row in graph["nodes"]}
    edges = {(row["source"], row["target"], row["relation"]) for row in graph["edges"]}
    assert (nodes[("ip", "192.0.2.20")], nodes[("hostname", "quic.example")], "quic-client-offers-sni") in edges
    assert (nodes[("hostname", "quic.example")], nodes[("ip", "203.0.113.20")], "quic-served-by") in edges
    assert (nodes[("ip", "203.0.113.20")], nodes[("certificate-sha256", "34" * 32)], "presents-certificate") in edges


def test_bgp_extended_communities_decode_route_target_and_route_origin_formats() -> None:
    route_target_as2 = bytes((0x00, 0x02)) + struct.pack("!HI", 65000, 123456)
    route_origin_ipv4 = bytes((0x01, 0x03)) + ipaddress.IPv4Address("192.0.2.44").packed + struct.pack("!H", 77)
    route_target_as4 = bytes((0x02, 0x02)) + struct.pack("!IH", 4_200_000_000, 88)
    non_transitive_route_origin = bytes((0x42, 0x03)) + struct.pack("!IH", 4_000_000_001, 99)
    value = route_target_as2 + route_origin_ipv4 + route_target_as4 + non_transitive_route_origin
    attribute = bytes((0xC0, 16, len(value))) + value

    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        _bgp_update_with_attributes(attribute), source_port=179, destination_port=50000, transport="tcp"
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "bgp")
    ext = next(row for row in fields["path_attributes"] if row["name"] == "EXTENDED_COMMUNITIES")
    rows = ext["communities"]

    assert rows[0] == {
        "type": "0x00", "subtype": "0x02", "name": "route-target",
        "format": "two-octet-as-specific", "transitive": True,
        "global_administrator": 65000, "local_administrator": 123456,
        "value": "65000:123456",
    }
    assert rows[1]["name"] == "route-origin"
    assert rows[1]["format"] == "ipv4-address-specific"
    assert rows[1]["value"] == "192.0.2.44:77"
    assert rows[2]["name"] == "route-target"
    assert rows[2]["format"] == "four-octet-as-specific"
    assert rows[2]["value"] == "4200000000:88"
    assert rows[3]["name"] == "route-origin"
    assert rows[3]["transitive"] is False
    assert rows[3]["value"] == "4000000001:99"


def test_evpn_evidence_graph_links_route_targets_and_origins_to_route_observations() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    route = {
        "route_type": 2,
        "route_type_name": "mac-ip-advertisement",
        "ethernet_tag_id": 0,
        "ethernet_segment_identifier": {"value_hex": "00" * 10, "zero": True},
        "mac_address": "00:aa:00:00:98:01",
        "ip_address": "192.0.2.98",
        "service": {"service_id_24": 9800},
    }
    packet = _packet_record(1, "198.51.100.98", "198.51.100.254", [{
        "name": "bgp",
        "fields": {
            "message_name": "update",
            "path_attributes": [
                {"name": "EXTENDED_COMMUNITIES", "communities": [
                    {"name": "route-target", "value": "65000:9800", "format": "two-octet-as-specific"},
                    {"name": "route-origin", "value": "192.0.2.98:98", "format": "ipv4-address-specific"},
                ]},
                {"name": "MP_REACH_NLRI", "afi": 25, "safi": 70, "next_hops": ["198.51.100.98"], "nlri": [route]},
            ],
        },
    }])
    summary = forensic_summary_from_packets([packet])
    graph = summary["evidence_graph"]
    relations = {row["relation"] for row in graph["edges"]}
    kinds = {row["kind"] for row in graph["nodes"]}
    assert "bgp-route-target" in kinds
    assert "bgp-route-origin" in kinds
    assert "bgp-observes-route-target" in relations
    assert "bgp-observes-route-origin" in relations
    assert "evpn-route-target" in relations
    assert "evpn-route-origin" in relations

    overlay = summary["evpn_overlay"]["evpn"]
    assert overlay["observed_route_target_counts"] == {"65000:9800": 1}
    assert overlay["observed_route_origin_counts"] == {"192.0.2.98:98": 1}
    assert "not presented as active-state ownership" in overlay["route_policy_scope"]


def test_tcp_session_state_distinguishes_half_open_and_graceful_close() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    half_open = [
        _tcp_packet_record(1, "2026-08-20T00:20:00.000+00:00", "10.0.0.1", 40000, "10.0.0.2", 443, ["syn"]),
        _tcp_packet_record(2, "2026-08-20T00:20:00.100+00:00", "10.0.0.1", 40000, "10.0.0.2", 443, ["syn"], analysis=["retransmission"]),
    ]
    summary = forensic_summary_from_packets(half_open)["tcp_sessions"]
    assert summary["half_open_sessions"] == 1
    assert summary["top_sessions"][0]["state"] == "half-open"
    assert summary["top_sessions"][0]["handshake_incomplete"] is True
    assert summary["top_sessions"][0]["syn_count"] == 2

    graceful = [
        _tcp_packet_record(3, "2026-08-20T00:21:00.000+00:00", "10.0.0.1", 40001, "10.0.0.2", 443, ["syn"]),
        _tcp_packet_record(4, "2026-08-20T00:21:00.010+00:00", "10.0.0.2", 443, "10.0.0.1", 40001, ["syn", "ack"]),
        _tcp_packet_record(5, "2026-08-20T00:21:00.020+00:00", "10.0.0.1", 40001, "10.0.0.2", 443, ["ack"]),
        _tcp_packet_record(6, "2026-08-20T00:21:01.000+00:00", "10.0.0.1", 40001, "10.0.0.2", 443, ["fin", "ack"]),
        _tcp_packet_record(7, "2026-08-20T00:21:01.010+00:00", "10.0.0.2", 443, "10.0.0.1", 40001, ["fin", "ack"]),
    ]
    summary = forensic_summary_from_packets(graceful)["tcp_sessions"]
    assert summary["closed_sessions"] == 1
    assert summary["top_sessions"][0]["state"] == "closed"
    assert summary["top_sessions"][0]["bidirectional_fin_observed"] is True


def test_evpn_policy_domain_tracks_active_route_target_rd_vni_mac_prefix_and_vtep() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    rd = {"type": 0, "hex": _evpn_rd_asn(65000, 9800).hex(), "administrator": 65000, "assigned": 9800, "value": "65000:9800"}
    route = {
        "route_type": 2,
        "route_type_name": "mac-ip-advertisement",
        "route_distinguisher": rd,
        "ethernet_tag_id": 0,
        "ethernet_segment_identifier": {"value_hex": "00" * 10, "zero": True},
        "mac_address": "00:98:00:00:00:01",
        "ip_address": "192.0.2.98",
        "service": {"service_id_24": 9800},
    }
    control = _packet_record(1, "198.51.100.98", "198.51.100.254", [{
        "name": "bgp",
        "fields": {
            "message_name": "update",
            "path_attributes": [
                {"name": "EXTENDED_COMMUNITIES", "communities": [
                    {"name": "route-target", "value": "65000:9800"},
                    {"name": "route-origin", "value": "65000:98"},
                    {"name": "encapsulation", "tunnel_type_name": "vxlan"},
                ]},
                {"name": "MP_REACH_NLRI", "afi": 25, "safi": 70, "next_hops": ["198.51.100.98"], "nlri": [route]},
            ],
        },
    }])
    data = _packet_record(2, "198.51.100.98", "198.51.100.99", [{"name": "vxlan", "fields": {"vni": 9800}}])
    policy = forensic_summary_from_packets([control, data])["evpn_policy"]
    assert policy["active_route_count"] == 1
    assert policy["active_route_target_count"] == 1
    domain = policy["policy_domains"][0]
    assert domain["route_target"] == "65000:9800"
    assert domain["route_distinguishers"] == ["65000:9800"]
    assert domain["service_ids_24"] == [9800]
    assert domain["mac_addresses"] == ["00:98:00:00:00:01"]
    assert domain["ip_addresses"] == ["192.0.2.98"]
    assert domain["advertising_peers"] == ["198.51.100.98"]
    assert domain["next_hops"] == ["198.51.100.98"]
    assert domain["encapsulations"] == ["vxlan"]
    assert domain["observed_vxlan_vni_matches"] == [9800]
    assert policy["route_origins"] == {"65000:98": 1}


def test_evpn_policy_domain_mp_unreach_removes_only_withdrawing_peer_policy_binding() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    route = {
        "route_type": 5,
        "route_type_name": "ip-prefix",
        "route_distinguisher": {"type": 0, "hex": _evpn_rd_asn(65000, 9900).hex(), "administrator": 65000, "assigned": 9900, "value": "65000:9900"},
        "ethernet_segment_identifier": {"value_hex": "00" * 10, "zero": True},
        "ethernet_tag_id": 0,
        "ip_prefix": "203.0.113.0/24",
        "gateway_ip": "192.0.2.99",
        "service": {"service_id_24": 9900},
    }

    def advertise(frame: int, peer: str, target: str) -> object:
        return _packet_record(frame, peer, "198.51.100.254", [{"name": "bgp", "fields": {
            "message_name": "update",
            "path_attributes": [
                {"name": "EXTENDED_COMMUNITIES", "communities": [{"name": "route-target", "value": target}]},
                {"name": "MP_REACH_NLRI", "afi": 25, "safi": 70, "next_hops": [peer], "nlri": [route]},
            ],
        }}])

    def withdraw(frame: int, peer: str) -> object:
        return _packet_record(frame, peer, "198.51.100.254", [{"name": "bgp", "fields": {
            "message_name": "update",
            "path_attributes": [{"name": "MP_UNREACH_NLRI", "afi": 25, "safi": 70, "withdrawn_nlri": [route]}],
        }}])

    one_removed = forensic_summary_from_packets([
        advertise(1, "198.51.100.1", "65000:9900"),
        advertise(2, "198.51.100.2", "65100:9900"),
        withdraw(3, "198.51.100.1"),
    ])["evpn_policy"]
    assert one_removed["active_route_count"] == 1
    assert [row["route_target"] for row in one_removed["policy_domains"]] == ["65100:9900"]
    assert one_removed["policy_domains"][0]["advertising_peers"] == ["198.51.100.2"]

    all_removed = forensic_summary_from_packets([
        advertise(1, "198.51.100.1", "65000:9900"),
        advertise(2, "198.51.100.2", "65100:9900"),
        withdraw(3, "198.51.100.1"),
        withdraw(4, "198.51.100.2"),
    ])["evpn_policy"]
    assert all_removed["active_route_count"] == 0
    assert all_removed["active_route_target_count"] == 0
    assert all_removed["policy_domains"] == []


def _tls_packet_record(
    frame: int,
    timestamp: str,
    source: str,
    source_port: int,
    destination: str,
    destination_port: int,
    fields: dict[str, object],
    *,
    tcp_stream: int = 9,
) -> object:
    from arenyxa.infrastructure.capture.packet_models import PacketRecord

    return PacketRecord(
        frame_number=frame,
        timestamp=timestamp,
        length=220,
        captured_length=220,
        protocols="ipv4:tcp:tls",
        protocol="tls",
        info="",
        source=source,
        destination=destination,
        source_port=source_port,
        destination_port=destination_port,
        tcp_stream=tcp_stream,
        udp_stream=None,
        http2_stream=None,
        quic_stream=None,
        host="",
        method="",
        uri="",
        status=None,
        metadata={"native_layers": [{"name": "tls", "fields": fields}]},
    )


def test_tls_session_analyzer_correlates_client_server_fingerprints_and_selection() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    packets = [
        _tls_packet_record(1, "2026-08-20T00:30:00.000+00:00", "192.0.2.30", 54000, "203.0.113.30", 443, {
            "handshake_type": 1,
            "server_name": "secure.example",
            "ja3": "771,4865-4866,0-43-16,29,0",
            "ja3_md5": "aa" * 16,
            "supported_versions": ["0x0304", "0x0303"],
            "cipher_suites": ["0x1301", "0x1302"],
            "alpn": ["h2", "http/1.1"],
        }),
        _tls_packet_record(2, "2026-08-20T00:30:00.018+00:00", "203.0.113.30", 443, "192.0.2.30", 54000, {
            "handshake_type": 2,
            "server_legacy_version": "0303",
            "selected_version": "0x0304",
            "selected_cipher_suite": "0x1301",
            "selected_alpn": "h2",
            "ja3s": "771,4865,43-16",
            "ja3s_md5": "bb" * 16,
        }),
        _tls_packet_record(3, "2026-08-20T00:30:00.030+00:00", "203.0.113.30", 443, "192.0.2.30", 54000, {
            "handshake_type": 11,
            "certificate_chain": [{"sha256": "cc" * 32, "spki_sha256": "dd" * 32, "san_dns": ["secure.example"]}],
        }),
    ]
    summary = forensic_summary_from_packets(packets)
    tls = summary["tls_sessions"]
    assert tls["session_count"] == 1
    assert tls["complete_handshakes"] == 1
    assert tls["version_fallback_sessions"] == 0
    assert tls["cipher_selection_anomalies"] == 0
    assert tls["alpn_selection_anomalies"] == 0
    row = tls["top_sessions"][0]
    assert row["client"] == {"address": "192.0.2.30", "port": 54000}
    assert row["server"] == {"address": "203.0.113.30", "port": 443}
    assert row["server_name"] == "secure.example"
    assert row["selected_version_name"] == "TLS1.3"
    assert row["server_hello_latency_ms"] == 18.0
    assert row["certificate_sha256"] == "cc" * 32
    assert summary["tls"]["client_fingerprints"] == {"aa" * 16: 1}
    assert summary["tls"]["server_fingerprints"] == {"bb" * 16: 1}


def test_tls_session_analyzer_surfaces_negotiation_inconsistencies_without_calling_them_attacks() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    packets = [
        _tls_packet_record(1, "2026-08-20T00:31:00.000+00:00", "192.0.2.31", 54001, "203.0.113.31", 443, {
            "handshake_type": 1,
            "supported_versions": ["0x0304", "0x0303"],
            "cipher_suites": ["0x1301"],
            "alpn": ["h2"],
        }, tcp_stream=10),
        _tls_packet_record(2, "2026-08-20T00:31:00.030+00:00", "203.0.113.31", 443, "192.0.2.31", 54001, {
            "handshake_type": 2,
            "selected_version": "0x0303",
            "selected_cipher_suite": "0xc02f",
            "selected_alpn": "http/1.1",
        }, tcp_stream=10),
    ]
    tls = forensic_summary_from_packets(packets)["tls_sessions"]
    assert tls["version_fallback_sessions"] == 1
    assert tls["cipher_selection_anomalies"] == 1
    assert tls["alpn_selection_anomalies"] == 1
    row = tls["top_sessions"][0]
    assert row["version_fallback_observed"] is True
    assert row["selected_cipher_not_offered"] is True
    assert row["selected_alpn_not_offered"] is True


def test_network_evidence_graph_correlates_tls_sni_fingerprints_and_certificate_across_packets() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    packets = [
        _tls_packet_record(1, "2026-08-20T00:40:00.000+00:00", "192.0.2.40", 55000, "203.0.113.40", 443, {
            "handshake_type": 1,
            "server_name": "graph.example",
            "ja3_md5": "11" * 16,
            "supported_versions": ["0x0304"],
            "cipher_suites": ["0x1301"],
        }, tcp_stream=40),
        _tls_packet_record(2, "2026-08-20T00:40:00.010+00:00", "203.0.113.40", 443, "192.0.2.40", 55000, {
            "handshake_type": 2,
            "selected_version": "0x0304",
            "selected_cipher_suite": "0x1301",
            "ja3s_md5": "22" * 16,
        }, tcp_stream=40),
        _tls_packet_record(3, "2026-08-20T00:40:00.020+00:00", "203.0.113.40", 443, "192.0.2.40", 55000, {
            "handshake_type": 11,
            "certificate_chain": [{"sha256": "33" * 32, "san_dns": ["graph.example"]}],
        }, tcp_stream=40),
    ]
    graph = forensic_summary_from_packets(packets)["evidence_graph"]
    nodes = {(row["kind"], row["value"]): row["id"] for row in graph["nodes"]}
    edges = {(row["source"], row["target"], row["relation"]) for row in graph["edges"]}
    hostname = nodes[("hostname", "graph.example")]
    client_fp = nodes[("tls-ja3", "11" * 16)]
    server_fp = nodes[("tls-ja3s", "22" * 16)]
    cert = nodes[("certificate-sha256", "33" * 32)]
    assert (client_fp, server_fp, "tls-client-server-fingerprint-pair") in edges
    assert (server_fp, hostname, "tls-server-fingerprint-serves-sni") in edges
    assert (hostname, cert, "uses-certificate") in edges


def test_wireguard_native_deep_decodes_handshake_and_transport_without_retaining_crypto_material() -> None:
    initiation = bytearray(148)
    struct.pack_into("<I", initiation, 0, 1)
    struct.pack_into("<I", initiation, 4, 0x11223344)
    initiation[8:40] = bytes(range(32))
    initiation[40:88] = b"s" * 48
    initiation[88:116] = b"t" * 28
    initiation[116:132] = b"1" * 16
    initiation[132:148] = b"2" * 16
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        bytes(initiation), source_port=51820, destination_port=60000, transport="udp"
    )
    fields = decoded.layers[-1].fields
    assert decoded.application_protocol == "wireguard"
    assert decoded.encrypted is True
    assert fields["message_name"] == "handshake-initiation"
    assert fields["sender_index"] == 0x11223344
    assert fields["ephemeral_public_bytes"] == 32
    assert len(fields["ephemeral_public_sha256"]) == 64
    assert fields["key_material_retained"] is False
    assert fields["ciphertext_retained"] is False
    assert "ephemeral_public" not in fields
    assert "encrypted_static" not in fields

    transport = bytearray(48)
    struct.pack_into("<I", transport, 0, 4)
    struct.pack_into("<I", transport, 4, 0x55667788)
    struct.pack_into("<Q", transport, 8, 0x0102030405060708)
    transport[16:] = b"x" * 32
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        bytes(transport), source_port=51820, destination_port=60000, transport="udp"
    )
    fields = decoded.layers[-1].fields
    assert fields["message_name"] == "transport-data"
    assert fields["receiver_index"] == 0x55667788
    assert fields["counter"] == 0x0102030405060708
    assert fields["encrypted_payload_bytes"] == 32
    assert len(fields["encrypted_payload_sha256"]) == 64
    assert fields["encrypted_payload_retained"] is False


def test_ikev2_native_deep_decodes_nonce_chain_and_keeps_nonce_hashed_only() -> None:
    nonce = b"n" * 16
    payload = bytes((0, 0)) + struct.pack("!H", 4 + len(nonce)) + nonce
    header = (
        bytes.fromhex("0102030405060708")
        + b"\x00" * 8
        + bytes((40, 0x20, 34, 0x08))
        + struct.pack("!I", 0)
        + struct.pack("!I", 28 + len(payload))
    )
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        header + payload, source_port=50000, destination_port=500, transport="udp"
    )
    fields = decoded.layers[-1].fields
    assert decoded.application_protocol == "ike"
    assert fields["version_major"] == 2
    assert fields["exchange_name"] == "IKE_SA_INIT"
    assert fields["payload_count"] == 1
    assert fields["payloads"][0]["name"] == "NONCE"
    assert fields["payloads"][0]["nonce_bytes"] == 16
    assert len(fields["payloads"][0]["nonce_sha256"]) == 64
    assert fields["payloads"][0]["nonce_retained"] is False
    assert fields["deep_payload_decode"] is True


def test_protocol_catalog_marks_ike_and_wireguard_as_native_deep() -> None:
    modes = {row["protocol"]: row["mode"] for row in ProtocolIntelligenceEngine().protocol_catalog()}
    assert modes["ike"] == "native-deep"
    assert modes["wireguard"] == "native-deep"


def _ike_transform(transform_type: int, transform_id: int, *, more: bool, attributes: bytes = b"") -> bytes:
    length = 8 + len(attributes)
    return bytes((3 if more else 0, 0)) + struct.pack("!H", length) + bytes((transform_type, 0)) + struct.pack("!H", transform_id) + attributes


def _ike_payload(next_payload: int, body: bytes, *, critical: bool = False) -> bytes:
    return bytes((next_payload, 0x80 if critical else 0)) + struct.pack("!H", 4 + len(body)) + body


def _ikev2_message(first_payload: int, exchange: int, flags: int, message_id: int, payloads: bytes, *, responder: bytes = b"\x00" * 8, nat_t: bool = False) -> bytes:
    initiator = bytes.fromhex("0102030405060708")
    length = 28 + len(payloads)
    header = initiator + responder + bytes((first_payload, 0x20, exchange, flags)) + struct.pack("!II", message_id, length)
    return (b"\x00" * 4 if nat_t else b"") + header + payloads


def test_ikev2_sa_init_deep_decodes_proposals_ke_nonce_without_retaining_secret_material() -> None:
    key_length = struct.pack("!HH", 0x800E, 256)
    transforms = b"".join((
        _ike_transform(1, 12, more=True, attributes=key_length),
        _ike_transform(2, 5, more=True),
        _ike_transform(3, 12, more=True),
        _ike_transform(4, 19, more=False),
    ))
    proposal = bytes((0, 0)) + struct.pack("!H", 8 + len(transforms)) + bytes((1, 1, 0, 4)) + transforms
    sa = _ike_payload(34, proposal)
    ke_material = bytes(range(32))
    ke = _ike_payload(40, struct.pack("!HH", 19, 0) + ke_material)
    nonce_value = bytes(range(32, 64))
    nonce = _ike_payload(0, nonce_value)
    message = _ikev2_message(33, 34, 0x20, 0, sa + ke + nonce, responder=bytes.fromhex("1112131415161718"))

    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        message, source_port=500, destination_port=500, transport="udp"
    )
    assert decoded.application_protocol == "ike"
    assert decoded.encrypted is False
    fields = decoded.layers[-1].fields
    assert fields["version_major"] == 2
    assert fields["exchange_name"] == "IKE_SA_INIT"
    assert fields["response_flag"] is True
    assert [row["name"] for row in fields["payloads"]] == ["SA", "KE", "NONCE"]
    proposal_row = fields["payloads"][0]["proposals"][0]
    assert proposal_row["protocol_name"] == "ike"
    assert proposal_row["declared_transform_count"] == 4
    assert [row["id_name"] for row in proposal_row["transforms"]] == [
        "ENCR_AES_CBC", "PRF_HMAC_SHA2_256", "AUTH_HMAC_SHA2_256_128", "ke-method-19"
    ]
    assert proposal_row["transforms"][0]["attributes"][0]["value"] == 256
    ke_row = fields["payloads"][1]
    assert ke_row["key_exchange_method"] == 19
    assert ke_row["key_exchange_bytes"] == 32
    assert ke_row["key_exchange_retained"] is False
    assert "key_exchange" not in ke_row
    nonce_row = fields["payloads"][2]
    assert nonce_row["nonce_bytes"] == 32
    assert nonce_row["nonce_retained"] is False
    assert nonce_value.hex() not in repr(fields)


def test_ikev2_sk_marks_encryption_only_when_encrypted_payload_is_actually_present() -> None:
    ciphertext = bytes(range(64))
    encrypted = _ike_payload(35, ciphertext)
    message = _ikev2_message(46, 35, 0x08, 1, encrypted, responder=bytes.fromhex("1112131415161718"), nat_t=True)
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        message, source_port=4500, destination_port=4500, transport="udp"
    )
    assert decoded.encrypted is True
    fields = decoded.layers[-1].fields
    assert fields["nat_traversal_marker"] is True
    assert fields["encrypted_payload_present"] is True
    assert fields["payloads"][0]["name"] == "SK"
    assert fields["payloads"][0]["encrypted_payload_bytes"] == 64
    assert fields["payloads"][0]["encrypted_payload_retained"] is False
    assert ciphertext.hex() not in repr(fields)


def test_ipsec_nat_t_distinguishes_esp_and_keepalive_from_ike_non_esp_marker() -> None:
    esp_payload = struct.pack("!II", 0xAABBCCDD, 7) + b"ciphertext-value"
    esp = ProtocolIntelligenceEngine().decode_application_payload(
        esp_payload, source_port=4500, destination_port=4500, transport="udp"
    )
    assert [layer.name for layer in esp.layers] == ["ipsec-nat-t", "esp"]
    assert esp.application_protocol == "esp"
    assert esp.encrypted is True
    fields = esp.layers[-1].fields
    assert fields["spi_hex"] == "0xaabbccdd"
    assert fields["sequence"] == 7
    assert fields["nat_traversal"] is True
    assert fields["encrypted_payload_retained"] is False
    assert b"ciphertext-value".hex() not in repr(fields)

    keepalive = ProtocolIntelligenceEngine().decode_application_payload(
        b"\xff", source_port=4500, destination_port=4500, transport="udp"
    )
    assert keepalive.application_protocol == "ipsec-nat-keepalive"
    assert keepalive.layers[-1].fields["keepalive"] is True


def test_native_ipv4_esp_and_ah_expose_sa_metadata_without_plaintext_payload() -> None:
    def ipv4(protocol: int, payload: bytes) -> bytes:
        total = 20 + len(payload)
        return bytes((0x45, 0)) + struct.pack("!HHHBBH", total, 1, 0, 64, protocol, 0) + ipaddress.IPv4Address("192.0.2.1").packed + ipaddress.IPv4Address("192.0.2.2").packed + payload

    esp_frame = ipv4(50, struct.pack("!II", 0x01020304, 9) + b"opaque-esp-ciphertext")
    esp = ProtocolIntelligenceEngine().decode_frame(esp_frame, link_type="raw")
    esp_fields = next(layer.fields for layer in esp.layers if layer.name == "esp")
    assert esp_fields["spi_hex"] == "0x01020304"
    assert esp_fields["sequence"] == 9
    assert esp_fields["encrypted_payload_retained"] is False

    ah_header = bytes((6, 2)) + struct.pack("!HII", 0, 0x11223344, 3) + b"\xaa\xbb\xcc\xdd"
    ah_frame = ipv4(51, ah_header)
    ah = ProtocolIntelligenceEngine().decode_frame(ah_frame, link_type="raw")
    ah_fields = next(layer.fields for layer in ah.layers if layer.name == "ah")
    assert ah_fields["next_header"] == 6
    assert ah_fields["header_length"] == 16
    assert ah_fields["spi_hex"] == "0x11223344"
    assert ah_fields["sequence"] == 3
    assert ah_fields["icv_bytes"] == 4
    assert ah_fields["icv_retained"] is False


def test_ikev2_expert_reports_error_notify_and_deprecated_offer_without_claiming_negotiation() -> None:
    deprecated = _ike_transform(1, 2, more=False)
    proposal = bytes((0, 0)) + struct.pack("!H", 8 + len(deprecated)) + bytes((1, 1, 0, 1)) + deprecated
    sa = _ike_payload(41, proposal)
    notify_body = struct.pack("!BBH", 0, 0, 14)
    notify = _ike_payload(0, notify_body)
    message = _ikev2_message(33, 34, 0x08, 0, sa + notify)
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        message, source_port=500, destination_port=500, transport="udp"
    )
    findings = ProtocolIntelligenceEngine.expert_findings(decoded)
    codes = {row["code"] for row in findings}
    assert "IKEV2_DEPRECATED_TRANSFORM_OFFERED" in codes
    assert "IKEV2_ERROR_NOTIFY" in codes
    weak = next(row for row in findings if row["code"] == "IKEV2_DEPRECATED_TRANSFORM_OFFERED")
    assert weak["evidence"]["transforms"] == ["ENCR_DES"]
    assert "offer" in weak["detail"].casefold()


def test_ipsec_session_forensics_pairs_ike_requests_responses_and_retransmissions() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    base = {
        "initiator_spi": "0102030405060708",
        "responder_spi": "1112131415161718",
        "version_major": 2,
        "exchange_type": 34,
        "exchange_name": "IKE_SA_INIT",
        "message_id": 0,
        "encrypted_payload_present": False,
        "payloads": [],
    }
    request = _packet_record(1, "192.0.2.10", "192.0.2.20", [{"name": "ike", "fields": {**base, "response_flag": False}}])
    retransmit = _packet_record(2, "192.0.2.10", "192.0.2.20", [{"name": "ike", "fields": {**base, "response_flag": False}}])
    response = _packet_record(3, "192.0.2.20", "192.0.2.10", [{"name": "ike", "fields": {**base, "response_flag": True}}])
    auth_request = _packet_record(4, "192.0.2.10", "192.0.2.20", [{"name": "ike", "fields": {
        **base,
        "exchange_type": 35,
        "exchange_name": "IKE_AUTH",
        "message_id": 1,
        "response_flag": False,
        "encrypted_payload_present": True,
        "payloads": [],
    }}])
    auth_response = _packet_record(5, "192.0.2.20", "192.0.2.10", [{"name": "ike", "fields": {
        **base,
        "exchange_type": 35,
        "exchange_name": "IKE_AUTH",
        "message_id": 1,
        "response_flag": True,
        "encrypted_payload_present": True,
        "payloads": [{"name": "NOTIFY", "error_notification": True, "notify_name": "AUTHENTICATION_FAILED"}],
    }}])
    summary = forensic_summary_from_packets([request, retransmit, response, auth_request, auth_response])["ipsec_sessions"]
    assert summary["ike_session_count"] == 1
    session = summary["ike_sessions"][0]
    assert session["request_response_pairs"] == 2
    assert session["outstanding_requests"] == 0
    assert session["orphan_responses"] == 0
    assert session["request_retransmissions"] == 1
    assert session["response_retransmissions"] == 0
    assert session["encrypted_messages"] == 2
    assert session["exchange_counts"] == {"IKE_AUTH": 2, "IKE_SA_INIT": 3}
    assert session["error_notifications"] == {"AUTHENTICATION_FAILED": 1}


def test_ipsec_sa_sequence_forensics_reports_gap_duplicate_and_reordering_as_evidence_only() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    packets = [
        _packet_record(frame, "192.0.2.30", "192.0.2.40", [{"name": "esp", "fields": {
            "spi": 0xA1B2C3D4,
            "sequence": sequence,
            "encrypted_payload_retained": False,
        }}])
        for frame, sequence in enumerate((1, 2, 4, 4, 3), 1)
    ]
    summary = forensic_summary_from_packets(packets)["ipsec_sessions"]
    assert summary["ipsec_sa_direction_count"] == 1
    sa = summary["security_associations"][0]
    assert sa["spi_hex"] == "0xa1b2c3d4"
    assert sa["packets"] == 5
    assert sa["highest_sequence_observed"] == 4
    assert sa["duplicate_sequence_observations"] == 1
    assert sa["out_of_order_sequence_observations"] == 1
    assert sa["estimated_missing_sequence_numbers"] == 1
    assert sa["possible_replay_evidence"] is True
    assert "capture artifacts" in summary["interpretation"]


def test_wireguard_session_forensics_correlates_handshake_transport_and_counter_evidence() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    initiation_fields = {
        "message_type": 1,
        "message_name": "handshake-initiation",
        "sender_index": 100,
        "key_material_retained": False,
        "ciphertext_retained": False,
    }
    response_fields = {
        "message_type": 2,
        "message_name": "handshake-response",
        "sender_index": 200,
        "receiver_index": 100,
        "key_material_retained": False,
        "ciphertext_retained": False,
    }
    packets = [
        _packet_record(1, "192.0.2.10", "192.0.2.20", [{"name": "wireguard", "fields": initiation_fields}]),
        _packet_record(2, "192.0.2.10", "192.0.2.20", [{"name": "wireguard", "fields": initiation_fields}]),
        _packet_record(3, "192.0.2.20", "192.0.2.10", [{"name": "wireguard", "fields": response_fields}]),
        _packet_record(4, "192.0.2.20", "192.0.2.10", [{"name": "wireguard", "fields": {
            "message_type": 3,
            "message_name": "cookie-reply",
            "receiver_index": 100,
            "key_material_retained": False,
            "ciphertext_retained": False,
        }}]),
    ]
    for frame, counter in enumerate((0, 2, 2, 1), 5):
        packets.append(_packet_record(frame, "192.0.2.10", "192.0.2.20", [{"name": "wireguard", "fields": {
            "message_type": 4,
            "message_name": "transport-data",
            "receiver_index": 200,
            "counter": counter,
            "key_material_retained": False,
            "ciphertext_retained": False,
        }}]))
    packets.append(_packet_record(9, "192.0.2.20", "192.0.2.10", [{"name": "wireguard", "fields": {
        "message_type": 4,
        "message_name": "transport-data",
        "receiver_index": 100,
        "counter": 7,
        "key_material_retained": False,
        "ciphertext_retained": False,
    }}]))

    summary = forensic_summary_from_packets(packets)["wireguard_sessions"]
    assert summary["session_count"] == 1
    assert summary["sensitive_material_retained"] is False
    session = summary["sessions"][0]
    assert session["state"] == "transport-observed"
    assert session["initiation_retransmissions"] == 1
    assert session["response_observations"] == 1
    assert session["cookie_replies"] == 1
    assert session["initiator_sender_index"] == 100
    assert session["responder_sender_index"] == 200
    forward = session["initiator_to_responder"]
    assert forward["packets"] == 4
    assert forward["highest_counter_observed"] == 2
    assert forward["duplicate_counter_observations"] == 1
    assert forward["out_of_order_counter_observations"] == 1
    assert forward["estimated_missing_counters"] == 1
    assert forward["possible_replay_evidence"] is True
    assert session["responder_to_initiator"]["packets"] == 1
    assert session["path_change_evidence"] is False
    assert "capture duplication" in summary["interpretation"]


def test_wireguard_session_forensics_does_not_guess_orphan_transport_correlation() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    packet = _packet_record(1, "198.51.100.10", "198.51.100.20", [{"name": "wireguard", "fields": {
        "message_type": 4,
        "message_name": "transport-data",
        "receiver_index": 0xDEADBEEF,
        "counter": 22,
        "key_material_retained": False,
        "ciphertext_retained": False,
    }}])
    summary = forensic_summary_from_packets([packet])["wireguard_sessions"]
    assert summary["session_count"] == 0
    assert summary["orphan_transport_packets"] == 1
    assert summary["ambiguous_correlations"] == 0


def test_sip_invite_and_sdp_decode_media_identity_without_retaining_user_or_ice_secrets() -> None:
    sdp = (
        "v=0\r\n"
        "o=- 123 456 IN IP4 192.0.2.50\r\n"
        "s=-\r\n"
        "c=IN IP4 203.0.113.50\r\n"
        "t=0 0\r\n"
        "a=group:BUNDLE audio\r\n"
        "a=ice-ufrag:secretUfrag\r\n"
        "a=ice-pwd:superSecretIcePassword\r\n"
        "a=fingerprint:sha-256 AA:BB:CC:DD\r\n"
        "a=setup:actpass\r\n"
        "m=audio 49170 RTP/SAVPF 111 0\r\n"
        "a=mid:audio\r\n"
        "a=rtcp-mux\r\n"
        "a=rtpmap:111 opus/48000/2\r\n"
        "a=fmtp:111 minptime=10;useinbandfec=1\r\n"
        "a=sendrecv\r\n"
    ).encode()
    message = (
        b"INVITE sip:bob@example.net SIP/2.0\r\n"
        b"Via: SIP/2.0/UDP client.example.com:5060;branch=z9hG4bK-secret-branch\r\n"
        b"From: Alice <sip:alice@example.com>;tag=secret-from-tag\r\n"
        b"To: Bob <sip:bob@example.net>\r\n"
        b"Call-ID: super-sensitive-call-id@example.com\r\n"
        b"CSeq: 314159 INVITE\r\n"
        b"Contact: <sip:alice@192.0.2.50:5060>\r\n"
        b"Max-Forwards: 70\r\n"
        b"Content-Type: application/sdp\r\n"
        + f"Content-Length: {len(sdp)}\r\n\r\n".encode()
        + sdp
    )
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        message, source_port=5060, destination_port=5060, transport="udp"
    )
    assert decoded.application_protocol == "sip"
    fields = decoded.layers[-1].fields
    assert fields["method"] == "INVITE"
    assert fields["request_uri"]["host"] == "example.net"
    assert fields["from"]["host"] == "example.com"
    assert fields["to"]["host"] == "example.net"
    assert fields["cseq_number"] == 314159
    assert fields["cseq_method"] == "INVITE"
    assert fields["call_id_retained"] is False
    assert fields["vias"][0]["transport"] == "UDP"
    assert fields["vias"][0]["branch_retained"] is False
    sdp_fields = fields["sdp"]
    assert sdp_fields["session_connection_address"] == "203.0.113.50"
    media = sdp_fields["media"][0]
    assert media["media"] == "audio"
    assert media["port"] == 49170
    assert media["protocol"] == "RTP/SAVPF"
    assert media["rtcp_mux"] is True
    assert media["rtpmap"][0] == {"payload_type": "111", "encoding": "opus", "clock_rate": 48000, "channels": 2}
    assert media["fmtp"][0]["parameters_retained"] is False
    assert fields["body_retained"] is False
    rendered = repr(fields)
    assert "super-sensitive-call-id" not in rendered
    assert "secretUfrag" not in rendered
    assert "superSecretIcePassword" not in rendered
    assert "secret-branch" not in rendered


def test_rtp_decoder_exposes_header_extension_metadata_without_retaining_media_payload() -> None:
    first = 0x90  # V=2, extension=1, no padding, no CSRC
    second = 0xE0  # marker=1, dynamic payload type 96
    header = struct.pack("!BBHII", first, second, 32000, 0x10203040, 0x55667788)
    extension = struct.pack("!HH", 0xBEDE, 1) + b"\x10\x20\x30\x40"
    media_payload = b"encoded-media-payload"
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        header + extension + media_payload, source_port=40000, destination_port=40002, transport="udp"
    )
    assert decoded.application_protocol == "rtp"
    fields = decoded.layers[-1].fields
    assert fields["marker"] is True
    assert fields["payload_type"] == 96
    assert fields["sequence"] == 32000
    assert fields["timestamp"] == 0x10203040
    assert fields["ssrc"] == 0x55667788
    assert fields["extension"]["profile"] == "0xbede"
    assert fields["extension"]["bytes"] == 4
    assert fields["extension"]["retained"] is False
    assert fields["payload_bytes"] == len(media_payload)
    assert fields["payload_retained"] is False
    assert media_payload.hex() not in repr(fields)


def test_rtcp_receiver_report_decodes_loss_and_jitter_block() -> None:
    report = (
        struct.pack("!I", 0x01020304)
        + bytes((64,))
        + (5).to_bytes(3, "big")
        + struct.pack("!IIII", 0x00010020, 900, 0x11112222, 0x00008000)
    )
    body = struct.pack("!I", 0xAABBCCDD) + report
    packet = bytes((0x81, 201)) + struct.pack("!H", (4 + len(body)) // 4 - 1) + body
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        packet, source_port=40001, destination_port=40003, transport="udp"
    )
    assert decoded.application_protocol == "rtcp"
    fields = decoded.layers[-1].fields
    assert fields["packet_count"] == 1
    rr = fields["compound_packets"][0]
    assert rr["name"] == "receiver-report"
    assert rr["ssrc"] == 0xAABBCCDD
    block = rr["reports"][0]
    assert block["source_ssrc"] == 0x01020304
    assert block["fraction_lost"] == 64
    assert block["fraction_lost_ratio"] == 0.25
    assert block["cumulative_packets_lost"] == 5
    assert block["interarrival_jitter"] == 900


def test_ipsec_session_forensics_tracks_visible_ike_lifecycle_without_inferring_encrypted_contents() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    base = {
        "initiator_spi": "0102030405060708",
        "responder_spi": "1112131415161718",
        "version_major": 2,
        "encrypted_payload_present": False,
        "payloads": [],
    }

    def ike(frame: int, source: str, destination: str, exchange: int, name: str, message_id: int, response: bool, payloads: list[dict[str, object]] | None = None) -> object:
        return _packet_record(frame, source, destination, [{"name": "ike", "fields": {
            **base,
            "exchange_type": exchange,
            "exchange_name": name,
            "message_id": message_id,
            "response_flag": response,
            "payloads": payloads or [],
        }}])

    packets = [
        ike(1, "192.0.2.10", "192.0.2.20", 34, "IKE_SA_INIT", 0, False),
        ike(2, "192.0.2.20", "192.0.2.10", 34, "IKE_SA_INIT", 0, True),
        ike(3, "192.0.2.10", "192.0.2.20", 35, "IKE_AUTH", 1, False),
        ike(4, "192.0.2.20", "192.0.2.10", 35, "IKE_AUTH", 1, True, [{
            "name": "NOTIFY", "notify_name": "MOBIKE_SUPPORTED", "error_notification": False,
        }, {
            "name": "NOTIFY", "notify_name": "IKEV2_FRAGMENTATION_SUPPORTED", "error_notification": False,
        }]),
        ike(5, "192.0.2.10", "192.0.2.20", 36, "CREATE_CHILD_SA", 2, False, [{
            "name": "NOTIFY", "notify_name": "REKEY_SA", "error_notification": False, "rekey_spi": "aabbccdd",
        }]),
        ike(6, "192.0.2.20", "192.0.2.10", 36, "CREATE_CHILD_SA", 2, True),
        ike(7, "192.0.2.10", "192.0.2.20", 37, "INFORMATIONAL", 3, False, [{
            "name": "DELETE", "protocol_name": "esp", "spis": ["aabbccdd", "01020304"],
        }]),
        ike(8, "192.0.2.20", "192.0.2.10", 37, "INFORMATIONAL", 3, True),
    ]
    summary = forensic_summary_from_packets(packets)["ipsec_sessions"]
    session = summary["ike_sessions"][0]
    assert session["paired_exchanges"] == {
        "IKE_SA_INIT": 1,
        "IKE_AUTH": 1,
        "CREATE_CHILD_SA": 1,
        "INFORMATIONAL": 1,
    }
    assert session["lifecycle_evidence"] == [
        "ike-sa-init-pair-observed",
        "ike-auth-pair-observed",
        "create-child-sa-pair-observed",
        "rekey-notify-observed",
        "visible-delete-observed",
        "mobike-signal-observed",
    ]
    assert session["rekey_notifications"] == 1
    assert session["mobike_notifications"] == 1
    assert session["fragmentation_support_notifications"] == 1
    assert session["visible_delete_payloads"] == 1
    assert session["visible_deleted_spis"] == ["01020304", "aabbccdd"]
    assert "encrypted SK payload contents are not inferred" in summary["interpretation"]


def _l2tp_avp(attr_type: int, value: bytes, *, mandatory: bool = False, hidden: bool = False, vendor_id: int = 0) -> bytes:
    flags_length = 6 + len(value)
    if mandatory:
        flags_length |= 0x8000
    if hidden:
        flags_length |= 0x4000
    return struct.pack("!HHH", flags_length, vendor_id, attr_type) + value


def test_l2tpv2_control_deep_decodes_avps_and_redacts_authentication_material() -> None:
    avps = b"".join((
        _l2tp_avp(0, struct.pack("!H", 1), mandatory=True),
        _l2tp_avp(7, b"edge-lns-01", mandatory=True),
        _l2tp_avp(9, struct.pack("!H", 77), mandatory=True),
        _l2tp_avp(11, b"super-secret-challenge", mandatory=True),
    ))
    total = 12 + len(avps)
    packet = struct.pack("!HHHHHH", 0xC802, total, 0, 0, 5, 4) + avps
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        packet, source_port=1701, destination_port=1701, transport="udp"
    )
    fields = decoded.layers[-1].fields
    assert decoded.application_protocol == "l2tp"
    assert fields["version"] == 2
    assert fields["control"] is True
    assert fields["control_required_header_fields_present"] is True
    assert fields["message_type"] == 1
    assert fields["message_name"] == "SCCRQ"
    assert fields["message_type_first_avp"] is True
    assert fields["avp_count"] == 4
    host = next(row for row in fields["avps"] if row["attribute_type"] == 7)
    assert host["text"] == "edge-lns-01"
    tunnel = next(row for row in fields["avps"] if row["attribute_type"] == 9)
    assert tunnel["value"] == 77
    challenge = next(row for row in fields["avps"] if row["attribute_type"] == 11)
    assert challenge["value_retained"] is False
    assert challenge["value_bytes"] == len(b"super-secret-challenge")
    assert "super-secret-challenge" not in repr(fields)
    assert fields["sensitive_avp_values_retained"] is False


def test_l2tpv2_data_exposes_header_and_payload_digest_without_retaining_payload() -> None:
    payload = b"\xff\x03\x00\x21private-ppp-payload"
    packet = struct.pack("!HHH", 0x0002, 77, 88) + payload
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        packet, source_port=1701, destination_port=1701, transport="udp"
    )
    fields = decoded.layers[-1].fields
    assert fields["control"] is False
    assert fields["tunnel_id"] == 77
    assert fields["session_id"] == 88
    assert fields["data_payload_bytes"] == len(payload)
    assert fields["data_payload_retained"] is False
    assert payload.hex() not in repr(fields)


def _packet_record_with_ports(
    frame: int,
    source: str,
    source_port: int,
    destination: str,
    destination_port: int,
    layers: list[dict[str, object]],
) -> object:
    from arenyxa.infrastructure.capture.packet_models import PacketRecord

    return PacketRecord(
        frame_number=frame,
        timestamp=f"2026-08-20T00:10:{frame:02d}+00:00",
        length=160,
        captured_length=160,
        protocols=":".join(str(row.get("name") or "") for row in layers),
        protocol=str(layers[-1].get("name") or "unknown") if layers else "unknown",
        info="",
        source=source,
        destination=destination,
        source_port=source_port,
        destination_port=destination_port,
        tcp_stream=None,
        udp_stream=1,
        http2_stream=None,
        quic_stream=None,
        host="",
        method="",
        uri="",
        status=None,
        metadata={"native_layers": layers},
    )


def test_realtime_media_forensics_correlates_sdp_rtp_path_and_sequence_evidence_without_payload() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    call_hash = "ab" * 32
    sip = _packet_record_with_ports(1, "192.0.2.10", 5060, "192.0.2.20", 5060, [{
        "name": "sip",
        "fields": {
            "response": False,
            "method": "INVITE",
            "call_id_sha256": call_hash,
            "call_id_retained": False,
            "sdp": {
                "session_connection_address": "203.0.113.50",
                "malformed": False,
                "media": [{
                    "media": "audio",
                    "port": 49170,
                    "protocol": "RTP/SAVPF",
                    "connection_address": "203.0.113.50",
                    "direction": "sendrecv",
                    "mid": "audio",
                    "rtcp_mux": True,
                    "rtcp_port": None,
                    "formats": ["111"],
                    "rtpmap": [{"payload_type": "111", "encoding": "opus", "clock_rate": 48000, "channels": 2}],
                }],
            },
        },
    }])
    packets = [sip]
    for frame, sequence in enumerate((100, 101, 103, 102, 103), start=2):
        packets.append(_packet_record_with_ports(frame, "203.0.113.50", 49170, "192.0.2.10", 40000, [{
            "name": "rtp",
            "fields": {
                "ssrc": 0x11223344,
                "sequence": sequence,
                "timestamp": 90000 + frame * 960,
                "payload_type": 111,
                "marker": frame == 2,
                "payload_bytes": 160,
                "payload_retained": False,
                "csrcs": [],
            },
        }]))
    summary = forensic_summary_from_packets(packets)["realtime_media"]
    assert summary["sip_call_count"] == 1
    assert summary["rtp_stream_count"] == 1
    call = summary["calls"][0]
    assert call["call_id_sha256"] == call_hash
    assert call["call_id_retained"] is False
    assert call["declared_media"][0]["endpoint"] == "203.0.113.50:49170"
    assert call["declared_media"][0]["codecs"] == ["opus/48000/2"]
    stream = summary["rtp_streams"][0]
    assert stream["packets"] == 5
    assert stream["sdp_endpoint_match"] is True
    assert stream["sdp_payload_type_match"] is True
    assert stream["forward_sequence_gap_packets"] == 1
    assert stream["out_of_order_sequence_observations"] == 1
    assert stream["duplicate_sequence_observations"] == 1
    assert stream["possible_capture_loss_evidence"] is True
    assert summary["media_payload_retained"] is False
    assert "capture evidence" in summary["interpretation"]


def test_realtime_media_forensics_aggregates_rtcp_reported_loss_and_jitter_as_evidence() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    rtcp = _packet_record_with_ports(1, "203.0.113.50", 49171, "192.0.2.10", 40001, [{
        "name": "rtcp",
        "fields": {
            "malformed": False,
            "compound_packets": [{
                "name": "receiver-report",
                "ssrc": 0xAABBCCDD,
                "reports": [
                    {
                        "source_ssrc": 0x11223344,
                        "fraction_lost_ratio": 0.25,
                        "cumulative_packets_lost": 5,
                        "interarrival_jitter": 900,
                    },
                    {
                        "source_ssrc": 0x11223344,
                        "fraction_lost_ratio": 0.125,
                        "cumulative_packets_lost": 6,
                        "interarrival_jitter": 1200,
                    },
                ],
            }],
        },
    }])
    summary = forensic_summary_from_packets([rtcp])["realtime_media"]
    assert summary["rtcp_source_count"] == 1
    source = summary["rtcp_sources"][0]
    assert source["receiver_reports"] == 1
    assert source["report_blocks"] == 2
    assert source["reported_sources"][str(0x11223344)] == 2
    assert source["fraction_lost_ratio_average_reported"] == 0.1875
    assert source["fraction_lost_ratio_max_reported"] == 0.25
    assert source["cumulative_packets_lost_max_reported"] == 6
    assert source["interarrival_jitter_max_reported"] == 1200
    assert "end-to-end media impairment" in summary["interpretation"]


def test_l2tpv2_expert_reports_incomplete_control_header_without_attack_claim() -> None:
    # T + L + version 2, but no S bit. The structure remains decodable so the
    # expert layer can report a standards-level control-header inconsistency.
    avp = _l2tp_avp(0, struct.pack("!H", 6), mandatory=True)
    total = 8 + len(avp)
    packet = struct.pack("!HHHH", 0xC002, total, 1, 0) + avp
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        packet, source_port=1701, destination_port=1701, transport="udp"
    )
    findings = ProtocolIntelligenceEngine.expert_findings(decoded)
    row = next(item for item in findings if item["code"] == "L2TP_CONTROL_HEADER_INCOMPLETE")
    assert row["protocol"] == "l2tp"
    assert row["evidence"]["sequence_present"] is False
    assert "attack" not in row["detail"].casefold()


def test_protocol_coverage_marks_vpn_and_l2tp_session_depth_explicitly() -> None:
    from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine

    coverage = PacketAnalysisEngine("").protocol_coverage()
    deep = set(coverage["native_deep_protocols"])
    sessions = set(coverage["stream_deep_decoders"])
    assert {"ike", "wireguard", "l2tp"}.issubset(deep)
    assert {
        "tcp-conversation-state",
        "tls-handshake-session",
        "quic-cid-path-session",
        "ikev2-ipsec-session",
        "wireguard-handshake-transport-session",
        "l2tpv2-control-avp",
    }.issubset(sessions)


def _ipv4_udp_payload(source: str = "10.0.0.1", destination: str = "10.0.0.2") -> bytes:
    udp = struct.pack("!HHHH", 12345, 53, 8, 0)
    total = 20 + len(udp)
    return (
        bytes((0x45, 0))
        + struct.pack("!HHHBBH", total, 1, 0, 64, 17, 0)
        + ipaddress.IPv4Address(source).packed
        + ipaddress.IPv4Address(destination).packed
        + udp
    )


def test_gtpv1u_gpdu_deep_decodes_teid_and_inner_ip_without_retaining_user_payload() -> None:
    inner = _ipv4_udp_payload()
    packet = struct.pack("!BBHI", 0x30, 255, len(inner), 0x10203040) + inner
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        packet, source_port=2152, destination_port=2152, transport="udp"
    )
    gtp = next(layer.fields for layer in decoded.layers if layer.name == "gtp")
    assert gtp["version"] == 1
    assert gtp["protocol_family"] == "gtpv1"
    assert gtp["message_name"] == "g-pdu"
    assert gtp["teid"] == 0x10203040
    assert gtp["user_payload_bytes"] == len(inner)
    assert gtp["user_payload_retained"] is False
    ipv4 = next(layer.fields for layer in decoded.layers if layer.name == "ipv4")
    assert ipv4["source"] == "10.0.0.1"
    assert ipv4["destination"] == "10.0.0.2"


def _gtpv2_ie(ie_type: int, value: bytes, instance: int = 0) -> bytes:
    return struct.pack("!BHB", ie_type, len(value), instance & 0x0F) + value


def test_gtpv2c_deep_decodes_apn_fteid_rat_and_hashes_subscriber_identifiers() -> None:
    imsi = b"\x21\x43\x65\x87\x09\xf1"
    apn = b"\x08internet"
    fteid = bytes((0x80 | 10,)) + struct.pack("!I", 0xAABBCCDD) + ipaddress.IPv4Address("198.51.100.7").packed
    ies = b"".join((
        _gtpv2_ie(1, imsi),
        _gtpv2_ie(71, apn),
        _gtpv2_ie(82, b"\x06"),
        _gtpv2_ie(87, fteid),
        _gtpv2_ie(99, b"\x03"),
    ))
    total = 12 + len(ies)
    packet = bytes((0x48, 32)) + struct.pack("!H", total - 4) + struct.pack("!I", 0x11223344) + b"\x00\x00\x05\x00" + ies
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        packet, source_port=2123, destination_port=2123, transport="udp"
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "gtp")
    assert fields["version"] == 2
    assert fields["protocol_family"] == "gtpv2-c"
    assert fields["message_name"] == "create-session-request"
    assert fields["teid"] == 0x11223344
    assert fields["sequence_number"] == 5
    rows = fields["information_elements"]
    imsi_row = next(row for row in rows if row["type"] == 1)
    assert imsi_row["imsi_retained"] is False
    assert imsi_row["imsi_bytes"] == len(imsi)
    assert imsi.hex() not in repr(fields)
    assert next(row for row in rows if row["type"] == 71)["apn"] == "internet"
    assert next(row for row in rows if row["type"] == 82)["rat_name"] == "eutran"
    fteid_row = next(row for row in rows if row["type"] == 87)
    assert fteid_row["teid"] == 0xAABBCCDD
    assert fteid_row["ipv4"] == "198.51.100.7"
    assert next(row for row in rows if row["type"] == 99)["pdn_type_name"] == "ipv4v6"
    assert fields["subscriber_identifier_values_retained"] is False


def test_gtp_tunnel_forensics_correlates_control_fteid_with_user_plane_teid() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    control_request = {
        "version": 2,
        "protocol_family": "gtpv2-c",
        "message_type": 32,
        "message_name": "create-session-request",
        "sequence_number": 5,
        "information_elements": [
            {"type": 1, "name": "imsi", "imsi_sha256": "a" * 64, "imsi_retained": False},
            {"type": 71, "name": "apn", "apn": "internet"},
            {"type": 82, "name": "rat-type", "rat_name": "eutran"},
            {"type": 87, "name": "f-teid", "interface_type": 10, "teid": 0xAABBCCDD, "ipv4": "198.51.100.7"},
        ],
    }
    control_response = {
        "version": 2,
        "protocol_family": "gtpv2-c",
        "message_type": 33,
        "message_name": "create-session-response",
        "sequence_number": 5,
        "information_elements": [{"type": 2, "name": "cause", "cause": 16, "response_accepted": True}],
    }
    user_fields = {
        "version": 1,
        "protocol_family": "gtpv1",
        "message_type": 255,
        "message_name": "g-pdu",
        "teid": 0xAABBCCDD,
        "decoded_length": 128,
        "sequence_number": 7,
        "extension_headers": [{"type": 0x85}],
    }
    packets = [
        _packet_record(1, "192.0.2.10", "192.0.2.20", [{"name": "gtp", "fields": control_request}]),
        _packet_record(2, "192.0.2.10", "192.0.2.20", [{"name": "gtp", "fields": control_request}]),
        _packet_record(3, "192.0.2.20", "192.0.2.10", [{"name": "gtp", "fields": control_response}]),
        _packet_record(4, "198.51.100.7", "198.51.100.8", [
            {"name": "gtp", "fields": user_fields},
            {"name": "ipv4", "fields": {"source": "10.10.0.1", "destination": "10.20.0.2"}},
        ]),
    ]
    summary = forensic_summary_from_packets(packets)["gtp_tunnels"]
    assert summary["control_session_count"] == 1
    assert summary["user_tunnel_direction_count"] == 1
    assert summary["control_plane_matched_user_directions"] == 1
    assert summary["subscriber_identifier_values_retained"] is False
    control = summary["control_sessions"][0]
    assert control["paired_transactions"] == 1
    assert control["request_retransmissions"] == 1
    assert control["apns"] == ["internet"]
    assert control["rat_types"] == ["eutran"]
    assert control["subscriber_identity_hashes"] == ["a" * 64]
    user = summary["user_tunnels"][0]
    assert user["control_plane_match"] is True
    assert user["control_plane_fteid_matches"][0]["teid"] == 0xAABBCCDD
    assert user["inner_endpoints"] == [["10.10.0.1", "10.20.0.2"]]
    assert user["extension_types"] == {"133": 1}
    assert "TEID reuse" in summary["interpretation"]


def test_gtpv2_expert_reports_nonaccepted_cause_as_service_state_not_attack() -> None:
    cause = _gtpv2_ie(2, bytes((64, 0)))
    total = 12 + len(cause)
    packet = bytes((0x48, 33)) + struct.pack("!H", total - 4) + struct.pack("!I", 0x11223344) + b"\x00\x00\x05\x00" + cause
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        packet, source_port=2123, destination_port=2123, transport="udp"
    )
    findings = ProtocolIntelligenceEngine.expert_findings(decoded)
    row = next(item for item in findings if item["code"] == "GTPV2_NON_ACCEPTED_CAUSE")
    assert row["evidence"]["cause"] == 64
    assert "not by itself evidence of attack" in row["detail"]


def test_protocol_coverage_reports_gtp_control_user_plane_correlation_depth() -> None:
    from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine

    coverage = PacketAnalysisEngine("").protocol_coverage()
    assert "gtp" in set(coverage["native_deep_protocols"])
    assert "gtpv2-control+gtpv1u-tunnel-correlation" in set(coverage["stream_deep_decoders"])


def test_l2tp_session_forensics_correlates_recipient_local_tunnel_and_session_ids() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    def avp_id(attr_type: int, value: int) -> dict[str, object]:
        return {"vendor_id": 0, "attribute_type": attr_type, "value": value, "hidden": False}

    def control(frame: int, source: str, destination: str, name: str, tunnel_id: int, session_id: int, ns: int, avps: list[dict[str, object]] | None = None) -> object:
        return _packet_record(frame, source, destination, [{"name": "l2tp", "fields": {
            "version": 2,
            "control": True,
            "message_name": name,
            "tunnel_id": tunnel_id,
            "session_id": session_id,
            "ns": ns,
            "nr": 0,
            "avps": avps or [],
            "sensitive_avp_values_retained": False,
        }}])

    packets = [
        control(1, "192.0.2.10", "192.0.2.20", "SCCRQ", 0, 0, 0, [avp_id(9, 100)]),
        control(2, "192.0.2.10", "192.0.2.20", "SCCRQ", 0, 0, 0, [avp_id(9, 100)]),
        control(3, "192.0.2.20", "192.0.2.10", "SCCRP", 100, 0, 0, [avp_id(9, 200)]),
        control(4, "192.0.2.10", "192.0.2.20", "SCCCN", 200, 0, 1),
        control(5, "192.0.2.10", "192.0.2.20", "ICRQ", 200, 0, 2, [avp_id(14, 300)]),
        control(6, "192.0.2.20", "192.0.2.10", "ICRP", 100, 300, 1, [avp_id(14, 400)]),
        control(7, "192.0.2.10", "192.0.2.20", "ICCN", 200, 400, 3),
        _packet_record(8, "192.0.2.10", "192.0.2.20", [{"name": "l2tp", "fields": {
            "version": 2, "control": False, "tunnel_id": 200, "session_id": 400, "ns": 0, "decoded_length": 120,
            "data_payload_retained": False,
        }}]),
        _packet_record(9, "192.0.2.20", "192.0.2.10", [{"name": "l2tp", "fields": {
            "version": 2, "control": False, "tunnel_id": 100, "session_id": 300, "ns": 0, "decoded_length": 130,
            "data_payload_retained": False,
        }}]),
        control(10, "192.0.2.20", "192.0.2.10", "CDN", 100, 300, 2),
    ]
    summary = forensic_summary_from_packets(packets)["l2tp_sessions"]
    assert summary["tunnel_count"] == 1
    assert summary["call_count"] == 1
    assert summary["ppp_payload_retained"] is False
    tunnel = summary["tunnels"][0]
    assert tunnel["local_tunnel_ids"] == {"192.0.2.10": 100, "192.0.2.20": 200}
    assert tunnel["control_handshake_signals_complete"] is True
    assert tunnel["control_sequences"]["192.0.2.10"]["duplicate_observations"] == 1
    call = tunnel["calls"][0]
    assert call["kind"] == "incoming"
    assert call["local_session_ids"] == {"192.0.2.10": 300, "192.0.2.20": 400}
    assert call["connected_signal_observed"] is True
    assert call["disconnect_signal_observed"] is True
    assert call["data_packets"] == {"192.0.2.10->192.0.2.20": 1, "192.0.2.20->192.0.2.10": 1}
    assert call["data_bytes"] == {"192.0.2.20->192.0.2.10": 130, "192.0.2.10->192.0.2.20": 120}
    assert "local significance" in summary["interpretation"]


def test_protocol_coverage_reports_l2tp_tunnel_session_state() -> None:
    from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine

    coverage = PacketAnalysisEngine("").protocol_coverage()
    assert "l2tp-tunnel-session-state" in set(coverage["stream_deep_decoders"])


def _pfcp_ie(ie_type: int, value: bytes) -> bytes:
    return struct.pack("!HH", ie_type, len(value)) + value


def test_pfcp_session_establishment_deep_decodes_seid_node_fseid_fteid_and_network_instance() -> None:
    fseid = b"\x02" + struct.pack("!Q", 0x0102030405060708) + ipaddress.IPv4Address("198.51.100.20").packed
    fteid = b"\x01" + struct.pack("!I", 0xA1B2C3D4) + ipaddress.IPv4Address("203.0.113.20").packed
    node_id = b"\x00" + ipaddress.IPv4Address("192.0.2.100").packed
    network_instance = b"\x08internet"
    ies = b"".join((
        _pfcp_ie(57, fseid),
        _pfcp_ie(21, fteid),
        _pfcp_ie(60, node_id),
        _pfcp_ie(22, network_instance),
        _pfcp_ie(56, struct.pack("!H", 77)),
    ))
    total = 16 + len(ies)
    packet = bytes((0x21, 50)) + struct.pack("!H", total - 4) + struct.pack("!Q", 0x8877665544332211) + b"\x00\x00\x2a\x00" + ies
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        packet, source_port=8805, destination_port=8805, transport="udp"
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "pfcp")
    assert fields["version"] == 1
    assert fields["message_name"] == "session-establishment-request"
    assert fields["seid"] == 0x8877665544332211
    assert fields["sequence_number"] == 42
    rows = fields["information_elements"]
    fseid_row = next(row for row in rows if row["type"] == 57)
    assert fseid_row["seid"] == 0x0102030405060708
    assert fseid_row["ipv4"] == "198.51.100.20"
    fteid_row = next(row for row in rows if row["type"] == 21)
    assert fteid_row["teid"] == 0xA1B2C3D4
    assert fteid_row["ipv4"] == "203.0.113.20"
    node = next(row for row in rows if row["type"] == 60)
    assert node["node_id_kind"] == "ipv4"
    assert node["node_id"] == "192.0.2.100"
    assert next(row for row in rows if row["type"] == 22)["network_instance"] == "internet"
    assert next(row for row in rows if row["type"] == 56)["pdr_id"] == 77


def test_pfcp_expert_reports_rejected_cause_without_attack_claim() -> None:
    ies = _pfcp_ie(19, b"\x40")
    total = 8 + len(ies)
    packet = bytes((0x20, 51)) + struct.pack("!H", total - 4) + b"\x00\x00\x03\x00" + ies
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        packet, source_port=8805, destination_port=8805, transport="udp"
    )
    finding = next(row for row in ProtocolIntelligenceEngine.expert_findings(decoded) if row["code"] == "PFCP_NON_ACCEPTED_CAUSE")
    assert finding["evidence"]["cause"] == 64
    assert "attack" not in finding["detail"].casefold()


def _diameter_avp(code: int, value: bytes, *, flags: int = 0x40, vendor_id: int | None = None) -> bytes:
    if vendor_id is not None:
        flags |= 0x80
        header_length = 12
    else:
        header_length = 8
    length = header_length + len(value)
    header = struct.pack("!I", code) + bytes((flags,)) + length.to_bytes(3, "big")
    if vendor_id is not None:
        header += struct.pack("!I", vendor_id)
    raw = header + value
    return raw + (b"\x00" * ((4 - len(raw) % 4) % 4))


def _diameter_message(command: int, avps: bytes, *, request: bool, hop: int, end: int, application_id: int = 0, error: bool = False) -> bytes:
    flags = (0x80 if request else 0) | 0x40 | (0x20 if error else 0)
    total = 20 + len(avps)
    return b"\x01" + total.to_bytes(3, "big") + bytes((flags,)) + command.to_bytes(3, "big") + struct.pack("!III", application_id, hop, end) + avps


def test_diameter_deep_decodes_base_avps_padding_and_hashes_session_identity() -> None:
    session = b"mme.example.net;123456789;42"
    avps = b"".join((
        _diameter_avp(263, session),
        _diameter_avp(264, b"mme.example.net"),
        _diameter_avp(296, b"example.net"),
        _diameter_avp(257, b"\x00\x01" + ipaddress.IPv4Address("192.0.2.30").packed),
        _diameter_avp(266, struct.pack("!I", 10415)),
        _diameter_avp(269, b"Arenyxa-Test-Peer"),
    ))
    packet = _diameter_message(257, avps, request=True, hop=0x11223344, end=0x55667788)
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        packet, source_port=3868, destination_port=3868, transport="tcp"
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "diameter")
    assert fields["version"] == 1
    assert fields["command_name"] == "capabilities-exchange-request"
    assert fields["hop_by_hop_id"] == 0x11223344
    rows = fields["avps"]
    session_row = next(row for row in rows if row["code"] == 263)
    assert session_row["session_id_retained"] is False
    assert session.decode() not in repr(fields)
    assert next(row for row in rows if row["code"] == 264)["text"] == "mme.example.net"
    assert next(row for row in rows if row["code"] == 257)["address"] == "192.0.2.30"
    assert next(row for row in rows if row["code"] == 266)["unsigned32"] == 10415
    assert fields["identity_values_retained"] is False


def test_diameter_grouped_vendor_application_and_non_success_expert_are_bounded() -> None:
    grouped = b"".join((
        _diameter_avp(266, struct.pack("!I", 10415)),
        _diameter_avp(258, struct.pack("!I", 16777251)),
    ))
    avps = b"".join((
        _diameter_avp(260, grouped),
        _diameter_avp(268, struct.pack("!I", 5005)),
    ))
    packet = _diameter_message(257, avps, request=False, hop=7, end=9, error=True)
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        packet, source_port=3868, destination_port=3868, transport="tcp"
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "diameter")
    grouped_row = next(row for row in fields["avps"] if row["code"] == 260)
    assert grouped_row["grouped"] is True
    assert {row["code"] for row in grouped_row["children"]} == {258, 266}
    findings = ProtocolIntelligenceEngine.expert_findings(decoded)
    assert any(row["code"] == "DIAMETER_PROTOCOL_ERROR_ANSWER" for row in findings)
    result = next(row for row in findings if row["code"] == "DIAMETER_NON_SUCCESS_RESULT")
    assert result["evidence"]["result_code"] == 5005
    assert "attack" not in result["detail"].casefold()


def test_diameter_tcp_payload_can_expose_multiple_consecutive_messages() -> None:
    first = _diameter_message(280, b"", request=True, hop=1, end=11)
    second = _diameter_message(280, b"", request=False, hop=1, end=11)
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        first + second, source_port=3868, destination_port=3868, transport="tcp"
    )
    rows = [layer.fields for layer in decoded.layers if layer.name == "diameter"]
    assert len(rows) == 2
    assert rows[0]["command_name"] == "device-watchdog-request"
    assert rows[1]["command_name"] == "device-watchdog-answer"
    assert [row["stream_message_index"] for row in rows] == [0, 1]


def test_mobile_core_forensics_correlates_pfcp_fteid_with_observed_gtpu_without_subscriber_plaintext() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    pfcp_request = _packet_record_with_ports(1, "192.0.2.10", 8805, "192.0.2.20", 8805, [{
        "name": "pfcp",
        "fields": {
            "message_type": 50,
            "message_name": "session-establishment-request",
            "sequence_number": 44,
            "seid": 0x100,
            "information_elements": [
                {"type": 60, "node_id": "upf.example.net"},
                {"type": 22, "network_instance": "internet"},
                {"type": 21, "teid": 0x0A0B0C0D, "ipv4": "203.0.113.8"},
                {"type": 57, "seid": 0x200, "ipv4": "198.51.100.8"},
            ],
        },
    }])
    pfcp_response = _packet_record_with_ports(2, "192.0.2.20", 8805, "192.0.2.10", 8805, [{
        "name": "pfcp",
        "fields": {
            "message_type": 51,
            "message_name": "session-establishment-response",
            "sequence_number": 44,
            "seid": 0x100,
            "information_elements": [{"type": 19, "cause": 1, "request_accepted": True}],
        },
    }])
    gtpu = _packet_record_with_ports(3, "203.0.113.8", 2152, "203.0.113.9", 2152, [{
        "name": "gtp",
        "fields": {"version": 1, "teid": 0x0A0B0C0D, "message_type": 255, "message_name": "g-pdu"},
    }])
    summary = forensic_summary_from_packets([pfcp_request, pfcp_response, gtpu])["mobile_core"]
    assert summary["pfcp_peer_count"] == 1
    peer = summary["pfcp_peers"][0]
    assert peer["paired_transactions"] == 1
    assert peer["paired_procedures"] == {"session-establishment": 1}
    assert peer["transaction_latency_ms"]["p99"] == 1000.0
    assert summary["pfcp_gtpu_matched_teid_count"] == 1
    assert summary["pfcp_gtpu_matched_teids"][0]["teid"] == 0x0A0B0C0D
    assert summary["subscriber_identity_values_retained"] is False


def test_mobile_core_forensics_pairs_diameter_transactions_and_retains_session_hash_only() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    session_hash = "cd" * 32
    request = _packet_record_with_ports(1, "192.0.2.30", 3868, "192.0.2.40", 3868, [{
        "name": "diameter",
        "fields": {
            "request": True,
            "command_code": 275,
            "command_name": "session-termination-request",
            "hop_by_hop_id": 0x1122,
            "end_to_end_id": 0x3344,
            "application_id": 0,
            "potential_retransmission": False,
            "avps": [
                {"code": 263, "session_id_sha256": session_hash, "session_id_retained": False},
                {"code": 264, "text": "mme.example.net"},
                {"code": 296, "text": "example.net"},
            ],
        },
    }])
    answer = _packet_record_with_ports(2, "192.0.2.40", 3868, "192.0.2.30", 3868, [{
        "name": "diameter",
        "fields": {
            "request": False,
            "command_code": 275,
            "command_name": "session-termination-answer",
            "hop_by_hop_id": 0x1122,
            "end_to_end_id": 0x3344,
            "application_id": 0,
            "potential_retransmission": False,
            "avps": [
                {"code": 268, "unsigned32": 2001},
                {"code": 293, "text": "mme.example.net"},
                {"code": 283, "text": "example.net"},
            ],
        },
    }])
    summary = forensic_summary_from_packets([request, answer])["mobile_core"]
    assert summary["diameter_peer_count"] == 1
    peer = summary["diameter_peers"][0]
    assert peer["paired_transactions"] == 1
    assert peer["paired_command_codes"] == {"275": 1}
    assert peer["transaction_latency_ms"]["p99"] == 1000.0
    assert peer["session_id_hashes"] == [session_hash]
    assert peer["result_codes"] == {"2001": 1}
    assert "mme.example.net" in peer["origin_hosts"]
    assert summary["subscriber_identity_values_retained"] is False


def test_gtpv2_grouped_bearer_context_and_extended_ie_are_bounded_and_structured() -> None:
    child = b"".join((
        _gtpv2_ie(73, b"\x05"),
        _gtpv2_ie(94, struct.pack("!I", 0x01020304)),
    ))
    extended = struct.pack("!H", 0x1234) + b"opaque-extension"
    ies = b"".join((
        _gtpv2_ie(93, child),
        _gtpv2_ie(254, extended),
    ))
    total = 12 + len(ies)
    packet = bytes((0x48, 32)) + struct.pack("!H", total - 4) + struct.pack("!I", 0x11112222) + b"\x00\x00\x08\x00" + ies
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        packet, source_port=2123, destination_port=2123, transport="udp"
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "gtp")
    bearer = next(row for row in fields["information_elements"] if row["type"] == 93)
    assert bearer["grouped"] is True
    assert bearer["child_count"] == 2
    assert next(row for row in bearer["children"] if row["type"] == 73)["eps_bearer_id"] == 5
    assert next(row for row in bearer["children"] if row["type"] == 94)["charging_id"] == 0x01020304
    ext = next(row for row in fields["information_elements"] if row["type"] == 254)
    assert ext["ie_type_extension"] == 0x1234
    assert ext["extended-ie-4660-value_retained"] is False
    assert b"opaque-extension".decode() not in repr(fields)

def test_mobile_core_transaction_keys_keep_opposite_direction_same_identifiers_distinct() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    left_request = _packet_record_with_ports(1, "192.0.2.30", 3868, "192.0.2.40", 3868, [{
        "name": "diameter",
        "fields": {
            "request": True, "command_code": 280, "command_name": "device-watchdog-request",
            "hop_by_hop_id": 7, "end_to_end_id": 9, "application_id": 0, "avps": [],
        },
    }])
    right_request = _packet_record_with_ports(2, "192.0.2.40", 3868, "192.0.2.30", 3868, [{
        "name": "diameter",
        "fields": {
            "request": True, "command_code": 280, "command_name": "device-watchdog-request",
            "hop_by_hop_id": 7, "end_to_end_id": 9, "application_id": 0, "avps": [],
        },
    }])
    left_answer = _packet_record_with_ports(3, "192.0.2.40", 3868, "192.0.2.30", 3868, [{
        "name": "diameter",
        "fields": {
            "request": False, "command_code": 280, "command_name": "device-watchdog-answer",
            "hop_by_hop_id": 7, "end_to_end_id": 9, "application_id": 0, "avps": [],
        },
    }])
    summary = forensic_summary_from_packets([left_request, right_request, left_answer])["mobile_core"]
    peer = summary["diameter_peers"][0]
    assert peer["paired_transactions"] == 1
    assert peer["outstanding_requests"] == 1
    assert peer["request_retransmissions"] == 0
    assert peer["orphan_answers"] == 0


def test_mobile_core_evidence_graph_links_pfcp_gtpu_and_diameter_without_session_plaintext() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    session_hash = "ef" * 32
    packets = [
        _packet_record_with_ports(1, "192.0.2.10", 8805, "192.0.2.20", 8805, [{
            "name": "pfcp",
            "fields": {
                "seid": 0x1010,
                "information_elements": [
                    {"type": 60, "node_id": "upf.example.net"},
                    {"type": 22, "network_instance": "internet"},
                    {"type": 21, "teid": 0xABCDEF01, "ipv4": "203.0.113.9"},
                    {"type": 57, "seid": 0x2020, "ipv4": "198.51.100.9"},
                ],
            },
        }]),
        _packet_record_with_ports(2, "203.0.113.9", 2152, "203.0.113.10", 2152, [{
            "name": "gtp", "fields": {"version": 1, "teid": 0xABCDEF01},
        }]),
        _packet_record_with_ports(3, "192.0.2.30", 3868, "192.0.2.40", 3868, [{
            "name": "diameter",
            "fields": {
                "avps": [
                    {"code": 263, "session_id_sha256": session_hash, "session_id_retained": False},
                    {"code": 264, "text": "mme.example.net"},
                    {"code": 296, "text": "example.net"},
                    {"code": 293, "text": "hss.example.net"},
                    {"code": 283, "text": "example.net"},
                ],
            },
        }]),
    ]
    graph = forensic_summary_from_packets(packets)["evidence_graph"]
    kinds = {row["kind"] for row in graph["nodes"]}
    assert {"gtp-teid", "pfcp-seid", "pfcp-node", "pfcp-network-instance", "diameter-session-sha256", "diameter-host", "diameter-realm"}.issubset(kinds)
    values = {row["value"] for row in graph["nodes"]}
    assert "0xabcdef01" in values
    assert session_hash in values
    assert "upf.example.net" in values
    assert "mme.example.net" in values
    assert "internet" in values


def _coap_option(previous: int, number: int, value: bytes) -> tuple[int, bytes]:
    delta = number - previous
    if delta < 0:
        raise ValueError("CoAP options must be ordered")

    def encoded(value_number: int) -> tuple[int, bytes]:
        if value_number <= 12:
            return value_number, b""
        if value_number <= 268:
            return 13, bytes([value_number - 13])
        return 14, struct.pack("!H", value_number - 269)

    delta_nibble, delta_extra = encoded(delta)
    length_nibble, length_extra = encoded(len(value))
    return number, bytes([(delta_nibble << 4) | length_nibble]) + delta_extra + length_extra + value


def test_coap_deep_decodes_options_blocks_and_hashes_query_payload_and_token() -> None:
    token = b"Q7"
    packet = bytearray(bytes([(1 << 6) | len(token), 1]) + struct.pack("!H", 0x1234) + token)
    previous = 0
    for number, value in (
        (3, b"sensor.example"),
        (11, b"telemetry"),
        (12, b"\x32"),
        (15, b"access_token=secret"),
        (23, b"\x1a"),
    ):
        previous, encoded = _coap_option(previous, number, value)
        packet.extend(encoded)
    packet.extend(b"\xffpayload-secret")

    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        bytes(packet), source_port=50000, destination_port=5683, transport="udp"
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "coap")
    assert fields["code_name"] == "get"
    assert fields["uri_host"] == "sensor.example"
    assert fields["uri_path"] == "/telemetry"
    assert fields["content_formats"] == [50]
    assert fields["block_options"][0]["block_number"] == 1
    assert fields["block_options"][0]["more"] is True
    assert fields["block_options"][0]["block_size"] == 64
    assert fields["token_retained"] is False
    assert fields["payload_retained"] is False
    assert fields["query_and_proxy_values_retained"] is False
    rendered = repr(fields)
    assert "access_token=secret" not in rendered
    assert "payload-secret" not in rendered
    assert token.decode() not in rendered


def test_coap_decoder_rejects_payload_marker_without_payload() -> None:
    from arenyxa.infrastructure.capture.protocol_coap import decode_coap_message

    try:
        decode_coap_message(b"\x40\x01\x00\x01\xff")
    except ValueError as exc:
        assert "payload marker" in str(exc).casefold()
    else:
        raise AssertionError("CoAP payload marker without payload must fail")


def test_coap_expert_reports_empty_message_with_content_without_attack_claim() -> None:
    packet = bytes([(1 << 6) | 1, 0, 0, 1]) + b"x"
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        packet, source_port=5683, destination_port=50000, transport="udp"
    )
    finding = next(
        row for row in ProtocolIntelligenceEngine.expert_findings(decoded)
        if row["code"] == "COAP_EMPTY_MESSAGE_HAS_CONTENT"
    )
    assert "attack" not in finding["detail"].casefold()
    assert finding["evidence"]["token_length"] == 1


def test_protocol_coverage_marks_coap_as_native_deep() -> None:
    from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine

    coverage = PacketAnalysisEngine("").protocol_coverage()
    assert "coap" in set(coverage["native_deep_protocols"])


def test_coap_session_forensics_correlates_token_ack_retransmission_observe_and_blocks() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    token_hash = "ab" * 32
    request_fields = {
        "type": 0, "type_name": "confirmable", "code": 1, "code_class": 0, "code_detail": 1,
        "code_name": "get", "message_id": 10, "token_sha256": token_hash,
        "observe_values": [0], "block_options": [{"number": 23, "block_number": 0, "more": True}],
    }
    request = _packet_record_with_ports(1, "192.0.2.10", 50000, "192.0.2.20", 5683, [{"name": "coap", "fields": request_fields}])
    retransmit = _packet_record_with_ports(2, "192.0.2.10", 50000, "192.0.2.20", 5683, [{"name": "coap", "fields": request_fields}])
    ack = _packet_record_with_ports(3, "192.0.2.20", 5683, "192.0.2.10", 50000, [{
        "name": "coap", "fields": {
            "type": 2, "type_name": "acknowledgement", "code": 0, "code_class": 0, "code_detail": 0,
            "code_name": "empty", "message_id": 10, "token_sha256": "", "observe_values": [], "block_options": [],
        },
    }])
    response = _packet_record_with_ports(4, "192.0.2.20", 5683, "192.0.2.10", 50000, [{
        "name": "coap", "fields": {
            "type": 0, "type_name": "confirmable", "code": 69, "code_class": 2, "code_detail": 5,
            "code_name": "2.05", "message_id": 20, "token_sha256": token_hash,
            "observe_values": [7], "block_options": [{"number": 23, "block_number": 1, "more": False}],
        },
    }])
    summary = forensic_summary_from_packets([request, retransmit, ack, response])["coap_sessions"]
    assert summary["peer_count"] == 1
    peer = summary["peers"][0]
    assert peer["request_count"] == 1
    assert peer["request_retransmissions"] == 1
    assert peer["acknowledged_requests"] == 1
    assert peer["responses_correlated"] == 1
    assert peer["response_latency_ms"]["p99"] == 3000.0
    assert peer["observe_messages"] == 3
    assert peer["block_messages"] == 3
    assert peer["unique_block_numbers"] == 2
    assert summary["token_values_retained"] is False
    assert summary["payload_values_retained"] is False


def test_protocol_coverage_reports_coap_session_depth() -> None:
    from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine

    coverage = PacketAnalysisEngine("").protocol_coverage()
    assert "coap-token-blockwise-session" in set(coverage["stream_deep_decoders"])


def _stun_attr(attr_type: int, value: bytes) -> bytes:
    raw = struct.pack("!HH", attr_type, len(value)) + value
    return raw + (b"\x00" * ((-len(value)) % 4))


def _stun_message(message_type: int, transaction_id: bytes, attributes: bytes) -> bytes:
    assert len(transaction_id) == 12
    return struct.pack("!HHI", message_type, len(attributes), 0x2112A442) + transaction_id + attributes


def _stun_xor_ipv4(address: str, port: int) -> bytes:
    encoded_port = port ^ 0x2112
    raw_address = ipaddress.IPv4Address(address).packed
    mask = struct.pack("!I", 0x2112A442)
    encoded_address = bytes(left ^ right for left, right in zip(raw_address, mask))
    return struct.pack("!BBH", 0, 1, encoded_port) + encoded_address


def test_stun_ice_deep_decodes_transaction_attributes_and_redacts_credentials() -> None:
    transaction = bytes.fromhex("0102030405060708090a0b0c")
    attributes = b"".join((
        _stun_attr(0x0006, b"private-user"),
        _stun_attr(0x0024, struct.pack("!I", 123456789)),
        _stun_attr(0x0025, b""),
        _stun_attr(0x802A, struct.pack("!Q", 0x1122334455667788)),
    ))
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        _stun_message(0x0001, transaction, attributes),
        source_port=50000, destination_port=3478, transport="udp",
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "stun")
    assert fields["method_name"] == "binding"
    assert fields["class_name"] == "request"
    assert fields["transaction_id_retained"] is False
    username = next(row for row in fields["attributes"] if row["type"] == 0x0006)
    assert username["value_retained"] is False
    assert next(row for row in fields["attributes"] if row["type"] == 0x0024)["priority"] == 123456789
    assert next(row for row in fields["attributes"] if row["type"] == 0x0025)["flag_present"] is True
    assert next(row for row in fields["attributes"] if row["type"] == 0x802A)["tiebreaker"] == 0x1122334455667788
    rendered = repr(fields)
    assert "private-user" not in rendered
    assert transaction.hex() not in rendered


def test_stun_and_turn_deep_decode_reflexive_relay_and_channel_data_without_payload_retention() -> None:
    transaction = bytes.fromhex("1112131415161718191a1b1c")
    binding = _stun_message(0x0101, transaction, _stun_attr(0x0020, _stun_xor_ipv4("203.0.113.9", 50000)))
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        binding, source_port=3478, destination_port=50000, transport="udp",
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "stun")
    mapped = next(row for row in fields["attributes"] if row["type"] == 0x0020)
    assert fields["class_name"] == "success-response"
    assert mapped["address"] == "203.0.113.9"
    assert mapped["port"] == 50000

    allocation = _stun_message(0x0103, transaction, b"".join((
        _stun_attr(0x0016, _stun_xor_ipv4("198.51.100.7", 55000)),
        _stun_attr(0x000D, struct.pack("!I", 600)),
    )))
    decoded_allocate = ProtocolIntelligenceEngine().decode_application_payload(
        allocation, source_port=3478, destination_port=50000, transport="udp",
    )
    allocate_fields = next(layer.fields for layer in decoded_allocate.layers if layer.name == "stun")
    assert allocate_fields["method_name"] == "allocate"
    relayed = next(row for row in allocate_fields["attributes"] if row["type"] == 0x0016)
    assert relayed["address"] == "198.51.100.7"
    assert relayed["port"] == 55000
    assert next(row for row in allocate_fields["attributes"] if row["type"] == 0x000D)["lifetime_seconds"] == 600

    channel = struct.pack("!HH", 0x4001, 7) + b"secret!"
    decoded_channel = ProtocolIntelligenceEngine().decode_application_payload(
        channel, source_port=50000, destination_port=3478, transport="udp",
    )
    channel_fields = next(layer.fields for layer in decoded_channel.layers if layer.name == "turn-channel-data")
    assert channel_fields["channel_number"] == 0x4001
    assert channel_fields["data_bytes"] == 7
    assert channel_fields["data_retained"] is False
    assert "secret!" not in repr(channel_fields)


def test_protocol_coverage_marks_stun_turn_as_native_deep() -> None:
    from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine

    coverage = PacketAnalysisEngine("").protocol_coverage()
    deep = set(coverage["native_deep_protocols"])
    assert {"stun", "turn-channel-data"} <= deep


def test_stun_turn_session_forensics_pairs_transactions_retransmissions_ice_and_channel_state() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets
    from arenyxa.infrastructure.capture.protocol_stun import decode_stun_message, decode_turn_channel_data

    transaction = bytes.fromhex("aaaaaaaaaaaaaaaaaaaaaaaa")
    request_raw = _stun_message(0x0001, transaction, b"".join((
        _stun_attr(0x0025, b""),
        _stun_attr(0x802A, struct.pack("!Q", 99)),
    )))
    response_raw = _stun_message(0x0101, transaction, _stun_attr(0x0020, _stun_xor_ipv4("203.0.113.20", 51000)))
    request_fields = decode_stun_message(request_raw)
    response_fields = decode_stun_message(response_raw)
    request = _packet_record_with_ports(1, "10.0.0.10", 51000, "192.0.2.53", 3478, [{"name": "stun", "fields": request_fields}])
    retransmit = _packet_record_with_ports(2, "10.0.0.10", 51000, "192.0.2.53", 3478, [{"name": "stun", "fields": request_fields}])
    response = _packet_record_with_ports(3, "192.0.2.53", 3478, "10.0.0.10", 51000, [{"name": "stun", "fields": response_fields}])
    channel_fields = decode_turn_channel_data(struct.pack("!HH", 0x4005, 4) + b"data")
    channel = _packet_record_with_ports(4, "10.0.0.10", 51000, "192.0.2.53", 3478, [{"name": "turn-channel-data", "fields": channel_fields}])

    summary = forensic_summary_from_packets([request, retransmit, response, channel])["stun_turn_sessions"]
    assert summary["peer_count"] == 1
    peer = summary["peers"][0]
    assert peer["paired_transactions"] == 1
    assert peer["request_retransmissions"] == 1
    assert peer["transaction_latency_ms"]["p99"] == 2000.0
    assert peer["mapped_addresses"] == [{"address": "203.0.113.20", "port": 51000}]
    assert peer["ice_nominations"] == 2
    assert peer["ice_controlling_messages"] == 2
    assert peer["channel_numbers"] == [0x4005]
    assert peer["channel_data_packets"] == 1
    assert peer["channel_data_bytes"] == 4
    assert summary["credential_values_retained"] is False
    assert summary["relay_data_values_retained"] is False


def test_protocol_coverage_reports_stun_ice_turn_session_depth() -> None:
    from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine

    coverage = PacketAnalysisEngine("").protocol_coverage()
    assert "stun-ice-turn-transaction-session" in set(coverage["stream_deep_decoders"])


def _gtpu_with_extension(teid: int, extension_type: int, content: bytes, *, payload: bytes = b"") -> bytes:
    total_extension = len(content) + 2
    assert total_extension % 4 == 0
    units = total_extension // 4
    optional = b"\x00\x01\x00" + bytes((extension_type,))
    extension = bytes((units,)) + content + b"\x00"
    length = len(optional) + len(extension) + len(payload)
    return bytes((0x34, 255)) + struct.pack("!H", length) + struct.pack("!I", teid) + optional + extension + payload


def test_gtpu_pdu_session_container_decodes_dl_qfi_rqi_from_r19_fixed_prefix() -> None:
    packet = _gtpu_with_extension(0x11223344, 0x85, bytes((0x00, 0x40 | 9)))
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        packet, source_port=2152, destination_port=2152, transport="udp"
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "gtp")
    extension = fields["extension_headers"][0]
    assert extension["type"] == 0x85
    assert extension["type_name"] == "pdu-session-container"
    assert extension["pdu_type"] == 0
    assert extension["pdu_type_name"] == "dl-pdu-session-information"
    assert extension["direction"] == "downlink"
    assert extension["qfi"] == 9
    assert extension["reflective_qos_indicator"] is True
    assert extension["paging_policy_present"] is False
    assert extension["content_retained"] is False


def test_gtpu_pdu_session_container_decodes_ul_qfi_and_delay_flags() -> None:
    packet = _gtpu_with_extension(0x55667788, 0x85, bytes((0x1F, 0xC0 | 17)))
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        packet, source_port=2152, destination_port=2152, transport="udp"
    )
    extension = next(layer.fields for layer in decoded.layers if layer.name == "gtp")["extension_headers"][0]
    assert extension["pdu_type"] == 1
    assert extension["direction"] == "uplink"
    assert extension["qfi"] == 17
    assert extension["qos_monitoring_packet"] is True
    assert extension["dl_delay_indicator"] is True
    assert extension["ul_delay_indicator"] is True
    assert extension["sequence_number_present"] is True
    assert extension["n3_n9_delay_indicator"] is True
    assert extension["new_ie_flag"] is True


def test_pfcp_grouped_pdr_far_qer_decodes_qfi_rule_graph_and_fteid() -> None:
    fteid = b"\x01" + struct.pack("!I", 0x10203040) + ipaddress.IPv4Address("203.0.113.40").packed
    pdi = _pfcp_ie(2, _pfcp_ie(21, fteid) + _pfcp_ie(22, b"\x08internet"))
    create_pdr = _pfcp_ie(
        1,
        _pfcp_ie(56, struct.pack("!H", 77))
        + pdi
        + _pfcp_ie(108, struct.pack("!I", 300))
        + _pfcp_ie(109, struct.pack("!I", 400)),
    )
    create_far = _pfcp_ie(3, _pfcp_ie(108, struct.pack("!I", 300)))
    create_qer = _pfcp_ie(7, _pfcp_ie(109, struct.pack("!I", 400)) + _pfcp_ie(124, bytes((0xC0 | 9,))))
    ies = create_pdr + create_far + create_qer
    total = 16 + len(ies)
    packet = bytes((0x21, 50)) + struct.pack("!H", total - 4) + struct.pack("!Q", 0x100) + b"\x00\x00\x2c\x00" + ies
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        packet, source_port=8805, destination_port=8805, transport="udp"
    )
    fields = next(layer.fields for layer in decoded.layers if layer.name == "pfcp")
    qer = next(row for row in fields["information_elements"] if row["type"] == 7)
    qfi = next(row for row in qer["children"] if row["type"] == 124)
    assert qfi["qfi"] == 9
    assert qfi["spare_bits"] == 0xC0
    from arenyxa.infrastructure.capture.pfcp_rule_graph import extract_pfcp_rule_observations

    rules = extract_pfcp_rule_observations(fields["information_elements"])
    pdr = next(row for row in rules if row["rule_kind"] == "pdr")
    assert pdr["pdr_ids"] == [77]
    assert pdr["far_ids"] == [300]
    assert pdr["qer_ids"] == [400]
    assert pdr["resolved_qfis"] == [9]
    assert pdr["fteids"][0]["teid"] == 0x10203040
    assert pdr["network_instances"] == ["internet"]


def test_mobile_core_confirms_pfcp_rule_only_after_accepted_response_and_matches_gtpu_qfi() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    request = _packet_record_with_ports(1, "192.0.2.50", 8805, "192.0.2.60", 8805, [{
        "name": "pfcp",
        "fields": {
            "message_type": 50,
            "message_name": "session-establishment-request",
            "sequence_number": 70,
            "seid": 0x700,
            "information_elements": [
                {"type": 1, "children": [
                    {"type": 56, "pdr_id": 77},
                    {"type": 2, "children": [
                        {"type": 21, "teid": 0x10203040, "ipv4": "203.0.113.40"},
                        {"type": 22, "network_instance": "internet"},
                    ]},
                    {"type": 108, "rule_id": 300},
                    {"type": 109, "rule_id": 400},
                ]},
                {"type": 3, "children": [{"type": 108, "rule_id": 300}]},
                {"type": 7, "children": [{"type": 109, "rule_id": 400}, {"type": 124, "qfi": 9}]},
            ],
        },
    }])
    response = _packet_record_with_ports(2, "192.0.2.60", 8805, "192.0.2.50", 8805, [{
        "name": "pfcp",
        "fields": {
            "message_type": 51,
            "message_name": "session-establishment-response",
            "sequence_number": 70,
            "seid": 0x700,
            "information_elements": [{"type": 19, "cause": 1, "request_accepted": True}],
        },
    }])
    gtpu = _packet_record_with_ports(3, "203.0.113.40", 2152, "203.0.113.41", 2152, [{
        "name": "gtp",
        "fields": {
            "version": 1,
            "teid": 0x10203040,
            "message_type": 255,
            "message_name": "g-pdu",
            "extension_headers": [{"type": 0x85, "qfi": 9, "pdu_type": 0}],
        },
    }])
    summary = forensic_summary_from_packets([request, response, gtpu])["mobile_core"]
    peer = summary["pfcp_peers"][0]
    assert peer["confirmed_rule_event_count"] == 3
    assert peer["pending_rule_event_count"] == 0
    correlation = next(row for row in summary["pfcp_gtpu_qos_correlations"] if row["pdr_ids"] == [77])
    assert correlation["teid"] == 0x10203040
    assert correlation["qfi"] == 9
    assert correlation["gtpu_packets"] == 1
    assert correlation["gtpu_qfi_packets"] == 1
    assert correlation["correlation_status"] == "teid-and-qfi-observed"
    assert summary["gtpu_qfi_observations"] == {"0x10203040": {"9": 1}}


def test_mobile_core_rejected_pfcp_response_never_promotes_rule_to_confirmed_qos_state() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    request = _packet_record_with_ports(1, "192.0.2.70", 8805, "192.0.2.80", 8805, [{
        "name": "pfcp",
        "fields": {
            "message_type": 52,
            "message_name": "session-modification-request",
            "sequence_number": 71,
            "seid": 0x701,
            "information_elements": [{
                "type": 9,
                "children": [
                    {"type": 56, "pdr_id": 88},
                    {"type": 21, "teid": 0x50607080, "ipv4": "203.0.113.80"},
                    {"type": 109, "rule_id": 401},
                ],
            }, {
                "type": 14,
                "children": [{"type": 109, "rule_id": 401}, {"type": 124, "qfi": 21}],
            }],
        },
    }])
    response = _packet_record_with_ports(2, "192.0.2.80", 8805, "192.0.2.70", 8805, [{
        "name": "pfcp",
        "fields": {
            "message_type": 53,
            "message_name": "session-modification-response",
            "sequence_number": 71,
            "seid": 0x701,
            "information_elements": [{"type": 19, "cause": 64, "request_accepted": False}],
        },
    }])
    gtpu = _packet_record_with_ports(3, "203.0.113.80", 2152, "203.0.113.81", 2152, [{
        "name": "gtp",
        "fields": {
            "version": 1, "teid": 0x50607080, "message_type": 255,
            "extension_headers": [{"type": 0x85, "qfi": 21}],
        },
    }])
    summary = forensic_summary_from_packets([request, response, gtpu])["mobile_core"]
    peer = summary["pfcp_peers"][0]
    assert peer["confirmed_rule_event_count"] == 0
    assert peer["rejected_rule_event_count"] == 2
    assert summary["pfcp_gtpu_qos_correlations"] == []


def test_mobile_core_evidence_graph_links_pfcp_pdr_qer_qfi_to_gtpu_qfi_without_payload() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    pfcp = _packet_record_with_ports(1, "192.0.2.90", 8805, "192.0.2.91", 8805, [{
        "name": "pfcp",
        "fields": {
            "information_elements": [
                {"type": 1, "children": [
                    {"type": 56, "pdr_id": 90},
                    {"type": 21, "teid": 0x90ABCDEF, "ipv4": "203.0.113.90"},
                    {"type": 109, "rule_id": 490},
                ]},
                {"type": 7, "children": [{"type": 109, "rule_id": 490}, {"type": 124, "qfi": 33}]},
            ],
        },
    }])
    gtpu = _packet_record_with_ports(2, "203.0.113.90", 2152, "203.0.113.91", 2152, [{
        "name": "gtp",
        "fields": {"version": 1, "teid": 0x90ABCDEF, "extension_headers": [{"type": 0x85, "qfi": 33}]},
    }])
    graph = forensic_summary_from_packets([pfcp, gtpu])["evidence_graph"]
    kinds = {row["kind"] for row in graph["nodes"]}
    relations = {row["relation"] for row in graph["edges"]}
    assert {"pfcp-pdr", "pfcp-qer", "gtp-teid", "qos-flow-qfi"}.issubset(kinds)
    assert "pfcp-observed-pdr-qer" in relations
    assert "pfcp-observed-pdr-fteid" in relations
    assert "pfcp-observed-qer-qfi" in relations
    assert "gtpu-pdu-session-qfi" in relations


def test_gtpu_pdu_session_expert_reports_reserved_type_as_protocol_evidence_only() -> None:
    packet = _gtpu_with_extension(0x12345678, 0x85, bytes((0x20, 5)))
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        packet, source_port=2152, destination_port=2152, transport="udp"
    )
    finding = next(
        row for row in ProtocolIntelligenceEngine.expert_findings(decoded)
        if row["code"] == "GTPU_PDU_SESSION_RESERVED_TYPE"
    )
    assert finding["evidence"]["pdu_type"] == 2
    assert "security conclusion" not in finding["detail"].casefold()


def _bacnet_bvlc(function: int, body: bytes) -> bytes:
    return struct.pack("!BBH", 0x81, function, 4 + len(body)) + body


def test_bacnet_ip_confirmed_read_property_decodes_bvlc_npdu_and_apdu_without_body_retention() -> None:
    # Original-Unicast-NPDU -> local NPDU -> Confirmed-Request(ReadProperty).
    apdu = bytes((0x02, 0x05, 0x07, 0x0C)) + b"\x0c\x02\x3f\xff\x19\x55"
    packet = _bacnet_bvlc(0x0A, bytes((0x01, 0x04)) + apdu)
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        packet, source_port=47808, destination_port=47808, transport="udp"
    )
    assert decoded.application_protocol == "bacnet-ip"
    fields = decoded.layers[-1].fields
    assert fields["bvlc_function_name"] == "original-unicast-npdu"
    assert fields["npdu"]["version"] == 1
    assert fields["npdu"]["expecting_reply"] is True
    application = fields["npdu"]["apdu"]
    assert application["pdu_type_name"] == "confirmed-request"
    assert application["invoke_id"] == 7
    assert application["service_name"] == "read-property"
    assert application["payload_bytes"] == 6
    assert len(application["payload_sha256"]) == 64
    assert application["payload_retained"] is False


def test_bacnet_ip_unconfirmed_who_is_and_forwarded_source_are_structured() -> None:
    who_is = _bacnet_bvlc(0x0B, bytes((0x01, 0x00, 0x10, 0x08)))
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        who_is, source_port=47808, destination_port=47808, transport="udp"
    )
    apdu = decoded.layers[-1].fields["npdu"]["apdu"]
    assert apdu["pdu_type_name"] == "unconfirmed-request"
    assert apdu["service_name"] == "who-is"

    source = ipaddress.IPv4Address("192.0.2.44").packed + struct.pack("!H", 47808)
    forwarded = _bacnet_bvlc(0x04, source + bytes((0x01, 0x00, 0x10, 0x00)))
    forwarded_decoded = ProtocolIntelligenceEngine().decode_application_payload(
        forwarded, source_port=47808, destination_port=47808, transport="udp"
    )
    forwarded_fields = forwarded_decoded.layers[-1].fields
    assert forwarded_fields["bvlc_function_name"] == "forwarded-npdu"
    assert forwarded_fields["original_source"] == "192.0.2.44:47808"
    assert forwarded_fields["npdu"]["apdu"]["service_name"] == "i-am"


def test_bacnet_ip_foreign_device_registration_and_native_deep_catalog() -> None:
    registration = _bacnet_bvlc(0x05, struct.pack("!H", 300))
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        registration, source_port=47808, destination_port=47808, transport="udp"
    )
    fields = decoded.layers[-1].fields
    assert fields["foreign_device_ttl_seconds"] == 300

    from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine

    coverage = PacketAnalysisEngine("").protocol_coverage()
    assert "bacnet-ip" in coverage["native_deep_protocols"]


def test_bacnet_session_forensics_correlates_confirmed_request_ack_discovery_and_bbmd_state() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    request = _packet_record_with_ports(1, "192.0.2.10", 47808, "192.0.2.20", 47808, [{
        "name": "bacnet-ip",
        "fields": {
            "bvlc_function_name": "original-unicast-npdu",
            "npdu": {"network_layer_message": False, "apdu": {
                "pdu_type_name": "confirmed-request", "invoke_id": 17,
                "service_name": "read-property", "payload_retained": False,
            }},
        },
    }])
    retransmit = _packet_record_with_ports(2, "192.0.2.10", 47808, "192.0.2.20", 47808, [{
        "name": "bacnet-ip",
        "fields": {
            "bvlc_function_name": "original-unicast-npdu",
            "npdu": {"network_layer_message": False, "apdu": {
                "pdu_type_name": "confirmed-request", "invoke_id": 17,
                "service_name": "read-property", "payload_retained": False,
            }},
        },
    }])
    ack = _packet_record_with_ports(3, "192.0.2.20", 47808, "192.0.2.10", 47808, [{
        "name": "bacnet-ip",
        "fields": {
            "bvlc_function_name": "original-unicast-npdu",
            "npdu": {"network_layer_message": False, "apdu": {
                "pdu_type_name": "simple-ack", "invoke_id": 17,
                "service_name": "read-property", "payload_retained": False,
            }},
        },
    }])
    who_is = _packet_record_with_ports(4, "192.0.2.10", 47808, "192.0.2.255", 47808, [{
        "name": "bacnet-ip",
        "fields": {
            "bvlc_function_name": "original-broadcast-npdu",
            "npdu": {"network_layer_message": False, "apdu": {
                "pdu_type_name": "unconfirmed-request", "service_name": "who-is", "payload_retained": False,
            }},
        },
    }])
    register = _packet_record_with_ports(5, "192.0.2.30", 47808, "192.0.2.1", 47808, [{
        "name": "bacnet-ip",
        "fields": {"bvlc_function_name": "register-foreign-device", "foreign_device_ttl_seconds": 600},
    }])
    summary = forensic_summary_from_packets([request, retransmit, ack, who_is, register])["bacnet_sessions"]
    transaction_peer = next(row for row in summary["peers"] if row["confirmed_requests"] == 1)
    assert transaction_peer["correlated_responses"] == 1
    assert transaction_peer["request_retransmissions"] == 1
    assert transaction_peer["services"]["read-property"] == 3
    assert transaction_peer["response_latency_ms"]["samples"] == 1
    assert summary["service_payload_values_retained"] is False
    assert any(row["discovery"]["who_is"] == 1 for row in summary["peers"])
    assert any(row["bbmd"]["foreign_registrations"] == 1 and row["bbmd"]["max_requested_ttl_seconds"] == 600 for row in summary["peers"])


def test_bacnet_session_capability_is_declared_as_stream_deep_decoder() -> None:
    from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine

    coverage = PacketAnalysisEngine("").protocol_coverage()
    assert "bacnet-transaction-bbmd-session" in coverage["stream_deep_decoders"]


def _opcua_message(message_type: bytes, body: bytes, *, chunk: bytes = b"F") -> bytes:
    size = 8 + len(body)
    return message_type + chunk + struct.pack("<I", size) + body


def _opcua_string(value: bytes) -> bytes:
    return struct.pack("<i", len(value)) + value


def test_opcua_hello_and_ack_decode_connection_negotiation_fields() -> None:
    hello_body = struct.pack("<IIIII", 0, 65536, 65536, 16_777_216, 1024) + _opcua_string(b"opc.tcp://plc.example:4840")
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        _opcua_message(b"HEL", hello_body), source_port=55000, destination_port=4840, transport="tcp"
    )
    fields = decoded.layers[-1].fields
    assert fields["message_type"] == "HEL"
    assert fields["connection"]["receive_buffer_size"] == 65536
    assert fields["connection"]["endpoint_url"] == "opc.tcp://plc.example:4840"

    ack_body = struct.pack("<IIIII", 0, 32768, 65536, 8_388_608, 256)
    ack = ProtocolIntelligenceEngine().decode_application_payload(
        _opcua_message(b"ACK", ack_body), source_port=4840, destination_port=55000, transport="tcp"
    )
    assert ack.layers[-1].fields["connection"]["max_chunk_count"] == 256


def test_opcua_open_secure_channel_none_exposes_sequence_ids_but_hashes_certificate_material() -> None:
    policy = b"http://opcfoundation.org/UA/SecurityPolicy#None"
    certificate = b"synthetic-certificate-material"
    thumbprint = b"synthetic-thumbprint"
    body = (
        struct.pack("<I", 0)
        + _opcua_string(policy)
        + struct.pack("<i", len(certificate)) + certificate
        + struct.pack("<i", len(thumbprint)) + thumbprint
        + struct.pack("<II", 9, 33)
        + b"synthetic-service-body"
    )
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        _opcua_message(b"OPN", body), source_port=55000, destination_port=4840, transport="tcp"
    )
    secure = decoded.layers[-1].fields["secure"]
    assert secure["secure_channel_id"] == 0
    assert secure["security_policy_none"] is True
    assert secure["sequence_number"] == 9
    assert secure["request_id"] == 33
    security = secure["asymmetric_security_header"]
    assert security["sender_certificate_bytes"] == len(certificate)
    assert len(security["sender_certificate_sha256"]) == 64
    assert security["certificate_material_retained"] is False
    assert certificate.hex() not in repr(secure)
    assert secure["payload_retained"] is False


def test_opcua_msg_does_not_interpret_potential_ciphertext_as_sequence_header() -> None:
    body = struct.pack("<II", 77, 5) + b"\x01\x02\x03\x04\x05\x06\x07\x08ciphertext"
    decoded = ProtocolIntelligenceEngine().decode_application_payload(
        _opcua_message(b"MSG", body), source_port=4840, destination_port=55000, transport="tcp"
    )
    secure = decoded.layers[-1].fields["secure"]
    assert secure["secure_channel_id"] == 77
    assert secure["security_token_id"] == 5
    assert secure["sequence_header_visible"] is False
    assert "request_id" not in secure
    assert secure["payload_retained"] is False


def test_opcua_is_declared_native_deep() -> None:
    from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine

    assert "opcua" in PacketAnalysisEngine("").protocol_coverage()["native_deep_protocols"]


def test_opcua_session_forensics_tracks_negotiation_securechannel_and_visible_open_transaction() -> None:
    from arenyxa.infrastructure.capture.packet_forensics import forensic_summary_from_packets

    hello = _packet_record_with_ports(1, "192.0.2.10", 55000, "192.0.2.20", 4840, [{
        "name": "opcua",
        "fields": {"message_type": "HEL", "chunk_type": "F", "connection": {
            "protocol_version": 0, "receive_buffer_size": 65536, "send_buffer_size": 65536,
            "max_message_size": 16_777_216, "max_chunk_count": 1024,
            "endpoint_url": "opc.tcp://192.0.2.20:4840",
        }},
    }])
    ack = _packet_record_with_ports(2, "192.0.2.20", 4840, "192.0.2.10", 55000, [{
        "name": "opcua",
        "fields": {"message_type": "ACK", "chunk_type": "F", "connection": {
            "protocol_version": 0, "receive_buffer_size": 32768, "send_buffer_size": 32768,
            "max_message_size": 8_388_608, "max_chunk_count": 256,
        }},
    }])
    open_request = _packet_record_with_ports(3, "192.0.2.10", 55000, "192.0.2.20", 4840, [{
        "name": "opcua",
        "fields": {"message_type": "OPN", "chunk_type": "F", "secure": {
            "secure_channel_id": 0, "sequence_header_visible": True,
            "sequence_number": 1, "request_id": 77, "security_policy_none": True,
        }},
    }])
    open_response = _packet_record_with_ports(4, "192.0.2.20", 4840, "192.0.2.10", 55000, [{
        "name": "opcua",
        "fields": {"message_type": "OPN", "chunk_type": "F", "secure": {
            "secure_channel_id": 9001, "sequence_header_visible": True,
            "sequence_number": 1, "request_id": 77, "security_policy_none": True,
        }},
    }])
    protected_msg = _packet_record_with_ports(5, "192.0.2.10", 55000, "192.0.2.20", 4840, [{
        "name": "opcua",
        "fields": {"message_type": "MSG", "chunk_type": "C", "secure": {
            "secure_channel_id": 9001, "security_token_id": 12,
            "sequence_header_visible": False, "payload_retained": False,
        }},
    }])
    summary = forensic_summary_from_packets([hello, ack, open_request, open_response, protected_msg])["opcua_sessions"]
    peer = summary["peers"][0]
    assert peer["negotiation"]["complete"] is True
    assert peer["negotiation"]["constraint_findings"] == []
    assert peer["secure_channel_ids"] == [9001]
    assert peer["security_token_ids"] == [12]
    assert peer["open_secure_channel_requests"] == 1
    assert peer["open_secure_channel_correlated"] == 1
    assert peer["open_secure_channel_latency_ms"]["samples"] == 1
    assert peer["intermediate_chunks"] == 1
    assert peer["protected_chunks_not_interpreted"] == 1
    assert summary["protected_service_payloads_interpreted_without_verified_decryption"] is False


def test_opcua_session_capability_is_declared_stream_deep() -> None:
    from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine

    assert "opcua-securechannel-session" in PacketAnalysisEngine("").protocol_coverage()["stream_deep_decoders"]
