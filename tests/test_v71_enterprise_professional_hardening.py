from __future__ import annotations

import json
from pathlib import Path

import pytest

from arenyxa.application.mitm_analytics import MitmFlowAnalyzer
from arenyxa.application.packet_intelligence_report import PacketIntelligenceReporter
from arenyxa.application.proxy_profiler import ProxyProfiler
from arenyxa.enterprise import LocalEnterpriseIdentityService
from arenyxa.infrastructure.capture.mitm_engine import MitmEngine, MitmEvent
from arenyxa.infrastructure.capture.packet_models import PacketRecord
from arenyxa.infrastructure.capture.proxy_models import ProxyFlow
from arenyxa.security import SecurityKernel


ADMIN_PASSWORD = "Root-Admin-Password-V71-0001"
VAULT_PASSWORD = "Vault-Passphrase-V71-0001"
NEW_VAULT_PASSWORD = "Vault-Passphrase-V71-ROTATED-0002"


def _service(tmp_path: Path) -> LocalEnterpriseIdentityService:
    service = LocalEnterpriseIdentityService(SecurityKernel.local_foundation(tmp_path), tmp_path)
    service.create_enterprise("V71 Enterprise", "root", "Root", ADMIN_PASSWORD, VAULT_PASSWORD)
    service.login("root", ADMIN_PASSWORD)
    service.step_up(ADMIN_PASSWORD)
    return service


def test_enterprise_vault_health_and_passphrase_rewrap(tmp_path: Path) -> None:
    service = _service(tmp_path)
    before_payload = json.loads(json.dumps(service._require_handle().payload))
    health = service.vault_health()
    assert health["ciphertext_sha256_valid"] is True
    assert health["unlocked_binding_valid"] is True
    assert health["kdf"]["algorithm"] == "scrypt"

    service.rotate_vault_passphrase(VAULT_PASSWORD, NEW_VAULT_PASSWORD)
    assert service._require_handle().payload == before_payload
    service.lock()
    with pytest.raises(Exception):
        service.unlock(VAULT_PASSWORD)
    assert service.unlock(NEW_VAULT_PASSWORD).unlocked is True


def test_administrator_cannot_promote_or_take_over_super_admin(tmp_path: Path) -> None:
    service = _service(tmp_path)
    admin_id = service.create_account("admin", "Administrator", "Administrator-Password-0001", ["administrator"])
    root_id = next(row["id"] for row in service.accounts() if row["username"] == "root")
    service.logout()
    service.login("admin", "Administrator-Password-0001")
    service.step_up("Administrator-Password-0001")

    with pytest.raises(Exception) as promoted:
        service.set_account_roles(admin_id, ["administrator", "super_admin"])
    assert getattr(promoted.value, "code", "") == "ENTERPRISE_SUPER_ADMIN_REQUIRED"

    with pytest.raises(Exception) as created:
        service.create_account("rogue-root", "Rogue", "Rogue-Root-Password-0001", ["super_admin"])
    assert getattr(created.value, "code", "") == "ENTERPRISE_SUPER_ADMIN_REQUIRED"

    with pytest.raises(Exception) as takeover:
        service.change_password(root_id, "Replaced-Root-Password-0001")
    assert getattr(takeover.value, "code", "") == "ENTERPRISE_SUPER_ADMIN_REQUIRED"
    assert "enterprise.vault.manage" not in service.status().permissions


def test_network_roles_and_rbac_matrix_are_least_privilege(tmp_path: Path) -> None:
    service = _service(tmp_path)
    analyst_id = service.create_account("netanalyst", "Network Analyst", "Network-Analyst-Password-0001", ["network_analyst"])
    matrix = service.rbac_matrix()
    role_ids = {row["id"] for row in matrix["roles"]}
    assert {"network_security_admin", "network_analyst", "proxy_operator", "security_auditor"} <= role_ids
    effective = service.effective_permissions(analyst_id)
    assert "enterprise.packet.analyze" in effective["permissions"]
    assert "enterprise.network.observe" in effective["permissions"]
    assert "enterprise.proxy.manage" not in effective["permissions"]
    assert "enterprise.account.manage" not in effective["permissions"]


def test_proxy_profiler_reports_latency_hosts_and_findings() -> None:
    response = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
    flows = [
        ProxyFlow(
            id="f1", sequence=1, started_at="2026-08-19T00:00:00+00:00", client="127.0.0.1",
            scheme="https", method="GET", host="example.com", port=443, target="/api",
            response_raw=response, status=503, duration_ms=2500.0, request_bytes=128,
            response_bytes=len(response), tls_intercepted=True, completed_at="2026-08-19T00:00:03+00:00",
        ),
        ProxyFlow(
            id="f2", sequence=2, started_at="2026-08-19T00:00:04+00:00", client="127.0.0.1",
            scheme="https", method="POST", host="example.com", port=443, target="/submit",
            response_raw=b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nStrict-Transport-Security: max-age=31536000\r\nContent-Security-Policy: default-src 'none'\r\n\r\nOK",
            status=200, duration_ms=50.0, request_bytes=256, response_bytes=128,
            tls_intercepted=True, completed_at="2026-08-19T00:00:04+00:00",
        ),
    ]
    snapshot = ProxyProfiler().analyze(flows).snapshot()
    assert snapshot["flow_count"] == 2
    assert snapshot["duration_p95_ms"] >= 2000.0
    assert snapshot["status_families"]["5xx"] == 1
    assert snapshot["hosts"][0]["host"] == "example.com"
    kinds = {row["kind"] for row in snapshot["findings"]}
    assert "server-error" in kinds
    assert "slow-response" in kinds
    assert "security-header-gap" in kinds


def test_mitm_professional_analytics_timeline_and_normalized_export(tmp_path: Path) -> None:
    rows = [
        MitmEvent(1, 1.0, "http.request", "flow-a", "HTTP", "request", method="GET", url="https://example.com/api", host="example.com", size=100, payload={"content_type": "application/json"}),
        MitmEvent(2, 1.2, "http.response", "flow-a", "HTTP", "response", url="https://example.com/api", host="example.com", status=503, size=200, payload={"content_type": "application/json"}),
        MitmEvent(3, 2.0, "websocket.message", "flow-b", "WebSocket", "message", direction="server", size=17, payload={}),
    ]
    analyzer = MitmFlowAnalyzer()
    snapshot = analyzer.analyze(rows).snapshot()
    assert snapshot["event_types"]["http.request"] == 1
    assert snapshot["methods"]["GET"] == 1
    assert snapshot["transports"]["HTTP"]["flows"] == 1
    assert snapshot["anomaly_severity"]["high"] == 1
    timeline = analyzer.flow_timeline(rows, "flow-a")
    assert [row["sequence"] for row in timeline] == [1, 2]
    assert timeline[1]["offset_ms"] == pytest.approx(200.0)

    engine = MitmEngine(tmp_path / "mitm")
    engine.events_path.write_text("\n".join(json.dumps({
        "sequence": row.sequence, "timestamp": row.timestamp, "event": row.event, "flow_id": row.flow_id,
        "protocol": row.protocol, "phase": row.phase, "method": row.method, "url": row.url,
        "host": row.host, "status": row.status, "direction": row.direction, "size": row.size,
        "replay": row.replay, "intercepted": row.intercepted, "payload": row.payload,
    }) for row in rows) + "\n", encoding="utf-8")
    destination = engine.export_events(tmp_path / "events.jsonl")
    exported = [json.loads(line) for line in destination.read_text(encoding="utf-8").splitlines()]
    assert len(exported) == 3
    assert "payload" not in exported[0]
    assert exported[0]["flow_id"] == "flow-a"


def test_packet_intelligence_report_surfaces_tcp_http_tls_dns_signals() -> None:
    rows = [
        PacketRecord(
            frame_number=1, timestamp="2026-08-19T00:00:00+00:00", length=1500, captured_length=1500,
            protocols="eth:ip:tcp:tls:http2", protocol="HTTP2", info="GET /api", source="10.0.0.2",
            destination="203.0.113.9", source_port=53000, destination_port=443, tcp_stream=7,
            udp_stream=None, http2_stream=1, quic_stream=None, host="example.com", method="GET", uri="/api",
            status=None, tcp_analysis=["retransmission"], metadata={"tcp_ack_rtt_ms": 650.0},
        ),
        PacketRecord(
            frame_number=2, timestamp="2026-08-19T00:00:01+00:00", length=900, captured_length=900,
            protocols="eth:ip:tcp:tls:http2", protocol="HTTP2", info="503", source="203.0.113.9",
            destination="10.0.0.2", source_port=443, destination_port=53000, tcp_stream=7,
            udp_stream=None, http2_stream=1, quic_stream=None, host="example.com", method="", uri="/api",
            status=503, tcp_analysis=[], metadata={"tcp_ack_rtt_ms": 40.0},
        ),
        PacketRecord(
            frame_number=3, timestamp="2026-08-19T00:00:02+00:00", length=90, captured_length=90,
            protocols="eth:ip:udp:dns", protocol="DNS", info="A example.com", source="10.0.0.2",
            destination="1.1.1.1", source_port=55000, destination_port=53, tcp_stream=None,
            udp_stream=3, http2_stream=None, quic_stream=None, host="example.com", method="", uri="",
            status=None, tcp_analysis=[], metadata={},
        ),
    ]
    snapshot = PacketIntelligenceReporter().analyze(rows).snapshot()
    assert snapshot["packet_count"] == 3
    assert snapshot["tcp_streams"] == 1
    assert snapshot["udp_streams"] == 1
    assert snapshot["tcp_analysis"]["retransmission"] == 1
    assert snapshot["tcp_ack_rtt_p95_ms"] >= 500.0
    assert snapshot["status_families"]["5xx"] == 1
    assert snapshot["tls_hosts"][0]["host"] == "example.com"
    assert snapshot["dns_queries"][0]["query"] == "example.com"
    kinds = {row["kind"] for row in snapshot["findings"]}
    assert {"tcp-loss-recovery", "high-tcp-rtt", "http-server-error"} <= kinds


def test_existing_v1_vault_receives_builtin_network_role_catalog_on_unlock(tmp_path: Path) -> None:
    service = _service(tmp_path)
    handle = service._require_handle()
    # Simulate a pre-hardening v1 role catalog while preserving a valid authenticated Vault.
    for role_id in ("network_security_admin", "network_analyst", "proxy_operator", "security_auditor"):
        handle.payload["roles"].pop(role_id, None)
    handle.payload["roles"]["super_admin"]["permissions"] = [
        item for item in handle.payload["roles"]["super_admin"]["permissions"]
        if not item.startswith("enterprise.proxy")
        and not item.startswith("enterprise.mitm")
        and not item.startswith("enterprise.packet")
        and item not in {"enterprise.network.observe", "enterprise.vault.manage"}
    ]
    service.vault.save(handle)
    service.lock()
    service.unlock(VAULT_PASSWORD)
    service.login("root", ADMIN_PASSWORD)
    status = service.status()
    assert "enterprise.vault.manage" in status.permissions
    assert "enterprise.proxy.manage" in status.permissions
    assert {"network_security_admin", "network_analyst", "proxy_operator", "security_auditor"} <= {
        row["id"] for row in service.roles()
    }


def test_vault_passphrase_rotation_rolls_back_if_audit_commit_fails(tmp_path: Path, monkeypatch) -> None:
    service = _service(tmp_path)
    original_emit = service.security.audit.emit

    def fail_emit(*_args, **_kwargs):
        raise OSError("synthetic audit failure")

    monkeypatch.setattr(service.security.audit, "emit", fail_emit)
    with pytest.raises(OSError):
        service.rotate_vault_passphrase(VAULT_PASSWORD, NEW_VAULT_PASSWORD)
    monkeypatch.setattr(service.security.audit, "emit", original_emit)
    service.lock()
    assert service.unlock(VAULT_PASSWORD).unlocked is True
    service.lock()
    with pytest.raises(Exception):
        service.unlock(NEW_VAULT_PASSWORD)
