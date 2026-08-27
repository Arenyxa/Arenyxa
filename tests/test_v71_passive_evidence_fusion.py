from __future__ import annotations

import json
from pathlib import Path

from arenyxa.infrastructure.capture.passive_evidence import fuse_passive_evidence, summarize_suricata_eve, summarize_zeek_json


def _jsonl(path: Path, rows: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n", encoding="utf-8")
    return path


def test_zeek_json_summary_keeps_evidence_attribution_and_protocol_counts(tmp_path: Path) -> None:
    conn = _jsonl(tmp_path / "conn.json", [
        {"uid": "C1", "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2", "proto": "tcp", "service": "ssl"},
        {"uid": "C2", "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.3", "proto": "udp", "service": "dns"},
    ])
    dns = _jsonl(tmp_path / "dns.json", [{"query": "example.test", "qtype_name": "A", "rcode_name": "NOERROR"}])
    result = summarize_zeek_json([conn, dns])
    assert result["records"] == 3
    assert result["protocols"] == {"tcp": 1, "udp": 1}
    assert result["services"] == {"ssl": 1, "dns": 1}
    assert result["dns_rcodes"] == {"NOERROR": 1}
    assert all(len(row["sha256"]) == 64 for row in result["files"])


def test_suricata_eve_summary_is_bounded_and_keeps_alert_origin(tmp_path: Path) -> None:
    eve = _jsonl(tmp_path / "eve.json", [
        {"event_type": "alert", "proto": "TCP", "app_proto": "tls", "alert": {"signature": "Example passive alert", "category": "Policy", "severity": 2}},
        {"event_type": "tls", "proto": "TCP", "app_proto": "tls", "tls": {"version": "TLS 1.3"}},
        {"event_type": "dns", "proto": "UDP", "app_proto": "dns", "dns": {"rcode": "NXDOMAIN"}},
    ])
    result = summarize_suricata_eve(eve)
    assert result["records"] == 3
    assert result["event_types"]["alert"] == 1
    assert result["alerts"]["signatures"]["Example passive alert"] == 1
    assert result["tls_versions"]["TLS 1.3"] == 1
    assert len(result["file"]["sha256"]) == 64


def test_passive_evidence_fusion_does_not_promote_external_alerts_to_native_findings(tmp_path: Path) -> None:
    zeek = _jsonl(tmp_path / "notice.json", [{"note": "SSL::Invalid_Server_Cert", "notice": True}])
    eve = _jsonl(tmp_path / "eve.json", [{"event_type": "alert", "alert": {"signature": "External engine claim", "category": "Test", "severity": 1}}])
    packet = {"schema": "arenyxa.packet-forensics/v1", "expert_findings": {"DNS_NONZERO_RCODE": 2}}
    fused = fuse_passive_evidence(packet_forensics=packet, zeek_json_paths=[zeek], suricata_eve_path=eve)
    assert fused["evidence_source_count"] == 3
    assert fused["cross_source"]["suricata_alert_count"] == 1
    assert fused["cross_source"]["zeek_notice_count"] == 1
    assert fused["cross_source"]["packet_expert_finding_count"] == 2
    assert "not promoted" in fused["interpretation"]
