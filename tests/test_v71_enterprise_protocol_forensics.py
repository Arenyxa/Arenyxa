from __future__ import annotations

import json
import struct

from arenyxa.infrastructure.capture.enterprise_auth_forensics import EnterpriseAuthForensicsAnalyzer
from arenyxa.infrastructure.capture.network_evidence_graph import NetworkEvidenceGraphBuilder
from arenyxa.infrastructure.capture.packet_models import PacketRecord
from arenyxa.infrastructure.capture.protocol_enterprise_directory import (
    decode_kerberos_message,
    decode_ldap_message,
    decode_ntlmssp,
    decode_smb_message,
)


def _ber(tag: int, payload: bytes) -> bytes:
    if len(payload) < 128:
        return bytes([tag, len(payload)]) + payload
    raw = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + payload


def _integer(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _ber(0x02, raw)


def _packet(frame: int, timestamp: str, source: str, destination: str, sport: int, dport: int, name: str, fields: dict) -> PacketRecord:
    return PacketRecord(
        frame_number=frame,
        timestamp=timestamp,
        length=128,
        captured_length=128,
        protocols=f"eth:ip:tcp:{name}",
        protocol=name,
        info=name,
        source=source,
        destination=destination,
        source_port=sport,
        destination_port=dport,
        tcp_stream=1,
        udp_stream=None,
        http2_stream=None,
        quic_stream=None,
        host="",
        method="",
        uri="",
        status=None,
        metadata={"native_layers": [{"name": name, "fields": fields}]},
    )


def _smb2_header(command: int, *, response: bool, message_id: int, session_id: int = 0, tree_id: int = 0, body: bytes = b"") -> bytes:
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    struct.pack_into("<H", header, 4, 64)
    struct.pack_into("<H", header, 6, 1)
    struct.pack_into("<H", header, 12, command)
    struct.pack_into("<H", header, 14, 1)
    struct.pack_into("<I", header, 16, 1 if response else 0)
    struct.pack_into("<Q", header, 24, message_id)
    struct.pack_into("<I", header, 32, 4242)
    struct.pack_into("<I", header, 36, tree_id)
    struct.pack_into("<Q", header, 40, session_id)
    return bytes(header) + body


def test_smb2_negotiate_and_ntlm_are_deep_but_do_not_retain_identity_plaintext() -> None:
    body = bytearray(40)
    struct.pack_into("<H", body, 0, 36)
    struct.pack_into("<H", body, 2, 2)
    struct.pack_into("<H", body, 4, 1)
    struct.pack_into("<I", body, 8, 0x44)
    body[12:28] = bytes(range(16))
    struct.pack_into("<H", body, 36, 0x0202)
    struct.pack_into("<H", body, 38, 0x0311)
    fields = decode_smb_message(_smb2_header(0, response=False, message_id=7, body=bytes(body)))
    assert fields["command_name"] == "negotiate"
    assert fields["body"]["dialects"] == ["0x0202", "0x0311"]

    domain = "CORP".encode("utf-16-le")
    user = "Alice".encode("utf-16-le")
    workstation = "WS-01".encode("utf-16-le")
    lm = b"L" * 24
    nt = b"N" * 24
    values = [lm, nt, domain, user, workstation]
    payload = bytearray(64 + sum(len(v) for v in values))
    payload[:8] = b"NTLMSSP\x00"
    struct.pack_into("<I", payload, 8, 3)
    cursor = 64
    for sec_offset, raw in zip((12, 20, 28, 36, 44), values):
        struct.pack_into("<HHI", payload, sec_offset, len(raw), len(raw), cursor)
        payload[cursor : cursor + len(raw)] = raw
        cursor += len(raw)
    struct.pack_into("<HHI", payload, 52, 0, 0, cursor)
    struct.pack_into("<I", payload, 60, 0x8201)
    ntlm = decode_ntlmssp(bytes(payload))
    assert ntlm is not None and ntlm["message_name"] == "authenticate"
    rendered = json.dumps(ntlm)
    assert "Alice" not in rendered and "CORP" not in rendered and "WS-01" not in rendered
    assert ntlm["credentials_retained"] is False


def test_ldap_bind_and_result_preserve_hashes_not_credentials() -> None:
    bind_body = _integer(3) + _ber(0x04, b"CN=Alice") + _ber(0x80, b"super-secret")
    bind = _ber(0x30, _integer(1) + _ber(0x60, bind_body))
    request = decode_ldap_message(bind)
    assert request["operation"] == "bind-request"
    assert request["ldap_version"] == 3
    assert request["bind_name_bytes"] == len(b"CN=Alice")
    assert "CN=Alice" not in json.dumps(request)
    assert "super-secret" not in json.dumps(request)

    result_body = _ber(0x0A, b"\x00") + _ber(0x04, b"") + _ber(0x04, b"")
    response = decode_ldap_message(_ber(0x30, _integer(1) + _ber(0x61, result_body)))
    assert response["operation"] == "bind-response"
    assert response["result_code"] == 0


def test_kerberos_error_metadata_is_structured_without_encrypted_material() -> None:
    error_body = _ber(0xA0, _integer(5)) + _ber(0xA1, _integer(30)) + _ber(0xA6, _integer(24))
    decoded = decode_kerberos_message(_ber(0x7E, error_body), tcp=False)
    assert decoded["message_name"] == "error"
    assert decoded["error_code"] == 24
    assert decoded["error_name"] == "preauth-failed"
    assert decoded["encrypted_material_retained"] is False


def test_enterprise_auth_session_forensics_correlates_smb_ldap_and_kerberos() -> None:
    analyzer = EnterpriseAuthForensicsAnalyzer()
    smb_req = {
        "dialect": "smb2+", "command": 1, "command_name": "session-setup", "response": False,
        "signed": False, "message_id": 10, "session_id": 0, "tree_id": 0,
        "body": {"ntlmssp": {"message_name": "authenticate", "user_sha256": "a" * 64}},
    }
    smb_resp = {
        "dialect": "smb2+", "command": 1, "command_name": "session-setup", "response": True,
        "signed": True, "message_id": 10, "session_id": 55, "status": 0, "body": {},
    }
    analyzer.feed(_packet(1, "2026-08-20T00:00:00+00:00", "10.0.0.5", "10.0.0.10", 50000, 445, "smb", smb_req))
    analyzer.feed(_packet(2, "2026-08-20T00:00:00.100000+00:00", "10.0.0.10", "10.0.0.5", 445, 50000, "smb", smb_resp))
    analyzer.feed(_packet(3, "2026-08-20T00:00:01+00:00", "10.0.0.5", "10.0.0.10", 50001, 389, "ldap", {"message_id": 1, "operation": "bind-request", "bind_name_sha256": "b" * 64}))
    analyzer.feed(_packet(4, "2026-08-20T00:00:01.050000+00:00", "10.0.0.10", "10.0.0.5", 389, 50001, "ldap", {"message_id": 1, "operation": "bind-response", "result_code": 0}))
    analyzer.feed(_packet(5, "2026-08-20T00:00:02+00:00", "10.0.0.5", "10.0.0.10", 50002, 88, "kerberos", {"message_name": "as-req"}))
    analyzer.feed(_packet(6, "2026-08-20T00:00:02.010000+00:00", "10.0.0.10", "10.0.0.5", 88, 50002, "kerberos", {"message_name": "as-rep"}))
    summary = analyzer.finalize()
    assert summary["unmatched_smb_requests"] == 0
    assert summary["unmatched_ldap_requests"] == 0
    assert summary["smb"][0]["response_latency_ms"]["p50"] == 100.0
    assert summary["ldap"][0]["response_latency_ms"]["p50"] == 50.0
    assert any(row["windows_auth_chain_observed"] for row in summary["auth_paths"])
    assert any(row["directory_auth_chain_observed"] for row in summary["auth_paths"])
    assert summary["sensitive_identity_plaintext_retained"] is False


def test_evidence_graph_accepts_enterprise_auth_hashes_without_plaintext_nodes() -> None:
    graph = NetworkEvidenceGraphBuilder()
    graph.feed(_packet(1, "2026-08-20T00:00:00+00:00", "10.0.0.5", "10.0.0.10", 50000, 445, "smb", {
        "session_id": 42, "tree_id": 7, "body": {"ntlmssp": {"user_sha256": "c" * 64}}
    }))
    graph.feed(_packet(2, "2026-08-20T00:00:01+00:00", "10.0.0.5", "10.0.0.10", 50001, 389, "ldap", {
        "operation": "bind-request", "bind_name_sha256": "d" * 64
    }))
    result = graph.finalize()
    kinds = {row["kind"] for row in result["nodes"]}
    assert "smb-session" in kinds
    assert "ntlm-user-sha256" in kinds
    assert "ldap-dn-sha256" in kinds
