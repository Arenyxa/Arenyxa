from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any, Iterable

from arenyxa.infrastructure.streaming_io import sha256_file

MAX_EVIDENCE_FILE_BYTES = 512 * 1024 * 1024
MAX_EVIDENCE_RECORDS = 1_000_000
MAX_DISTINCT_KEYS = 8192


def _bounded_json_lines(path: Path) -> Iterable[dict[str, Any]]:
    resolved = Path(path).resolve()
    if not resolved.is_file():
        raise ValueError(f"evidence file does not exist: {resolved}")
    size = resolved.stat().st_size
    if size > MAX_EVIDENCE_FILE_BYTES:
        raise ValueError(f"evidence file exceeds {MAX_EVIDENCE_FILE_BYTES} bytes: {resolved.name}")
    with resolved.open("r", encoding="utf-8", errors="strict") as handle:
        for index, line in enumerate(handle):
            if index >= MAX_EVIDENCE_RECORDS:
                raise ValueError(f"evidence file exceeds {MAX_EVIDENCE_RECORDS} records: {resolved.name}")
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            try:
                value = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON evidence at {resolved.name}:{index + 1}: {exc.msg}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"evidence record must be a JSON object: {resolved.name}:{index + 1}")
            yield value


def _increment(counter: Counter[str], value: Any, *, fallback: str = "unknown") -> None:
    if len(counter) >= MAX_DISTINCT_KEYS and str(value or fallback) not in counter:
        counter["other"] += 1
        return
    counter[str(value or fallback)] += 1


def _zeek_kind(row: dict[str, Any], fallback: str) -> str:
    if fallback and fallback != "auto":
        return fallback.casefold()
    keys = row.keys()
    if {"query", "qtype_name"} & keys:
        return "dns"
    if "status_code" in row or ({"method", "host"} <= keys):
        return "http"
    if {"server_name", "version", "cipher"} & keys:
        return "ssl"
    if {"proto", "id.orig_h", "id.resp_h"} <= keys:
        return "conn"
    if "notice" in row or "note" in row:
        return "notice"
    return "other"


def summarize_zeek_json(paths: Iterable[Path | str]) -> dict[str, Any]:
    kinds: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    services: Counter[str] = Counter()
    dns_rcodes: Counter[str] = Counter()
    http_status: Counter[str] = Counter()
    tls_versions: Counter[str] = Counter()
    tls_ciphers: Counter[str] = Counter()
    notices: Counter[str] = Counter()
    records = 0
    files: list[dict[str, Any]] = []
    for raw in paths:
        path = Path(raw).resolve()
        digest = sha256_file(path) if path.is_file() else ""
        fallback = path.stem.casefold().split(".", 1)[0]
        file_records = 0
        for row in _bounded_json_lines(path):
            records += 1
            file_records += 1
            kind = _zeek_kind(row, fallback if fallback in {"conn", "dns", "http", "ssl", "notice"} else "auto")
            kinds[kind] += 1
            if kind == "conn":
                _increment(protocols, row.get("proto"))
                _increment(services, row.get("service"))
            elif kind == "dns":
                _increment(dns_rcodes, row.get("rcode_name") or row.get("rcode"))
            elif kind == "http":
                _increment(http_status, row.get("status_code"))
            elif kind == "ssl":
                _increment(tls_versions, row.get("version"))
                _increment(tls_ciphers, row.get("cipher"))
            elif kind == "notice":
                _increment(notices, row.get("note") or row.get("notice"))
        files.append({"path": str(path), "sha256": digest, "records": file_records})
    return {
        "schema": "arenyxa.zeek-evidence/v1",
        "records": records,
        "files": files,
        "kinds": dict(kinds.most_common()),
        "protocols": dict(protocols.most_common(256)),
        "services": dict(services.most_common(256)),
        "dns_rcodes": dict(dns_rcodes.most_common(128)),
        "http_status": dict(http_status.most_common(128)),
        "tls_versions": dict(tls_versions.most_common(64)),
        "tls_ciphers": dict(tls_ciphers.most_common(256)),
        "notices": dict(notices.most_common(512)),
    }


def summarize_suricata_eve(path: Path | str) -> dict[str, Any]:
    resolved = Path(path).resolve()
    event_types: Counter[str] = Counter()
    alert_signatures: Counter[str] = Counter()
    alert_categories: Counter[str] = Counter()
    alert_severity: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    app_protocols: Counter[str] = Counter()
    dns_rcodes: Counter[str] = Counter()
    http_status: Counter[str] = Counter()
    tls_versions: Counter[str] = Counter()
    records = 0
    for row in _bounded_json_lines(resolved):
        records += 1
        kind = str(row.get("event_type") or "unknown")
        event_types[kind] += 1
        _increment(protocols, row.get("proto"))
        _increment(app_protocols, row.get("app_proto"))
        if kind == "alert" and isinstance(row.get("alert"), dict):
            alert = row["alert"]
            _increment(alert_signatures, alert.get("signature"))
            _increment(alert_categories, alert.get("category"))
            _increment(alert_severity, alert.get("severity"))
        elif kind == "dns" and isinstance(row.get("dns"), dict):
            dns = row["dns"]
            _increment(dns_rcodes, dns.get("rcode") or dns.get("rcode_name"))
        elif kind == "http" and isinstance(row.get("http"), dict):
            _increment(http_status, row["http"].get("status"))
        elif kind == "tls" and isinstance(row.get("tls"), dict):
            _increment(tls_versions, row["tls"].get("version"))
    return {
        "schema": "arenyxa.suricata-eve-evidence/v1",
        "records": records,
        "file": {"path": str(resolved), "sha256": sha256_file(resolved)},
        "event_types": dict(event_types.most_common()),
        "protocols": dict(protocols.most_common(256)),
        "app_protocols": dict(app_protocols.most_common(256)),
        "alerts": {
            "signatures": dict(alert_signatures.most_common(1024)),
            "categories": dict(alert_categories.most_common(256)),
            "severity": dict(alert_severity.most_common(32)),
        },
        "dns_rcodes": dict(dns_rcodes.most_common(128)),
        "http_status": dict(http_status.most_common(128)),
        "tls_versions": dict(tls_versions.most_common(64)),
    }


def fuse_passive_evidence(
    *,
    packet_forensics: dict[str, Any] | None = None,
    zeek_json_paths: Iterable[Path | str] = (),
    suricata_eve_path: Path | str | None = None,
) -> dict[str, Any]:
    zeek_paths = list(zeek_json_paths)
    zeek = summarize_zeek_json(zeek_paths) if zeek_paths else None
    suricata = summarize_suricata_eve(suricata_eve_path) if suricata_eve_path is not None else None
    packet = dict(packet_forensics or {})
    evidence_sources = int(bool(packet)) + int(zeek is not None) + int(suricata is not None)
    alert_total = 0
    if suricata is not None:
        alert_total = sum(int(value) for value in suricata["alerts"]["signatures"].values())
    return {
        "schema": "arenyxa.passive-evidence-fusion/v1",
        "evidence_source_count": evidence_sources,
        "packet_forensics": packet or None,
        "zeek": zeek,
        "suricata": suricata,
        "cross_source": {
            "suricata_alert_count": alert_total,
            "zeek_notice_count": 0 if zeek is None else sum(int(value) for value in zeek["notices"].values()),
            "packet_expert_finding_count": 0 if not packet else sum(int(value) for value in dict(packet.get("expert_findings") or {}).values()),
        },
        "interpretation": "Evidence is passively fused; external alerts/notices remain attributed to their originating engine and are not promoted to Arenyxa-native findings without packet evidence.",
    }
