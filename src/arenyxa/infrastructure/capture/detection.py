from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import datetime
from ipaddress import ip_address
from statistics import mean, pstdev
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse

from arenyxa.compat import UTC, dataclass
from arenyxa.domain.models import NetworkEvent, new_id, utc_now

_SECRET_HEADER = re.compile(r"^(authorization|proxy-authorization|cookie|set-cookie|x-api-key)$", re.I)
_BASE64ISH = re.compile(r"^[A-Za-z0-9_-]{24,}$")


@dataclass(frozen=True, slots=True)
class DetectionAlert:
    id: str
    session_id: str
    event_id: str
    rule_id: str
    severity: str
    title: str
    confidence: float
    timestamp: str
    evidence: dict[str, Any]

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ThreatFinding:
    kind: str
    severity: str
    confidence: float
    title: str
    evidence: dict[str, Any]

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DetectionRule:
    """Declarative passive IDS rule evaluated against normalized NetworkEvent metadata."""

    rule_id: str
    title: str
    severity: str = "medium"
    confidence: float = 0.8
    protocols: tuple[str, ...] = ()
    destination_ports: tuple[int, ...] = ()
    host_suffixes: tuple[str, ...] = ()
    methods: tuple[str, ...] = ()
    status_min: int | None = None
    status_max: int | None = None
    metadata_equals: tuple[tuple[str, str], ...] = ()

    def snapshot(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "protocols": list(self.protocols),
            "destination_ports": list(self.destination_ports),
            "host_suffixes": list(self.host_suffixes),
            "methods": list(self.methods),
            "status_min": self.status_min,
            "status_max": self.status_max,
            "metadata_equals": dict(self.metadata_equals),
        }


def _mapping_event(row: Mapping[str, Any]) -> NetworkEvent:
    source_value = row.get("source_type") or "system"
    from arenyxa.domain.enums import CaptureSource
    try:
        source = source_value if isinstance(source_value, CaptureSource) else CaptureSource(str(source_value))
    except ValueError:
        source = CaptureSource.SYSTEM
    return NetworkEvent(
        id=str(row.get("id") or new_id("event")),
        session_id=str(row.get("session_id") or ""),
        source_type=source,
        timestamp=str(row.get("timestamp") or utc_now()),
        process_ref=row.get("process_ref"),
        flow_ref=row.get("flow_ref"),
        request_ref=row.get("request_ref"),
        protocol=str(row.get("protocol") or "unknown"),
        direction=str(row.get("direction") or "unknown"),
        size=max(0, int(row.get("size") or 0)),
        method=row.get("method"),
        url=row.get("url"),
        status=row.get("status"),
        host=row.get("host"),
        timing=dict(row.get("timing") or {}),
        request_headers=dict(row.get("request_headers") or {}),
        response_headers=dict(row.get("response_headers") or {}),
        request_body_ref=row.get("request_body_ref"),
        response_body_ref=row.get("response_body_ref"),
        sensitivity_flags=list(row.get("sensitivity_flags") or row.get("sensitivity") or []),
        initiator=row.get("initiator"),
        metadata=dict(row.get("metadata") or {}),
    )


class PassiveDetectionEngine:
    """Deterministic passive IDS with bounded declarative rule extension.

    Built-in rules cover high-value unsafe transport and protocol anomalies. Optional
    declarative rules can be registered at runtime without arbitrary code execution.
    """

    _SEVERITIES = {"critical", "high", "medium", "low", "info"}

    def __init__(self, rules: Iterable[DetectionRule | Mapping[str, Any]] = ()) -> None:
        self._rules: dict[str, DetectionRule] = {}
        for rule in rules:
            self.register_rule(rule, replace=True)

    def register_rule(self, rule: DetectionRule | Mapping[str, Any], *, replace: bool = False) -> DetectionRule:
        normalized = self._normalize_rule(rule)
        if normalized.rule_id in self._rules and not replace:
            raise ValueError(f"detection rule already registered: {normalized.rule_id}")
        self._rules[normalized.rule_id] = normalized
        return normalized

    def unregister_rule(self, rule_id: str) -> bool:
        return self._rules.pop(str(rule_id or "").strip().upper(), None) is not None

    def rules(self) -> list[dict[str, Any]]:
        return [self._rules[key].snapshot() for key in sorted(self._rules)]

    def load_rule_catalog(self, rows: Iterable[Mapping[str, Any]], *, replace: bool = True, limit: int = 10_000) -> int:
        count = 0
        bounded = max(1, min(100_000, int(limit)))
        for row in rows:
            self.register_rule(row, replace=replace)
            count += 1
            if count >= bounded:
                break
        return count

    @classmethod
    def _normalize_rule(cls, raw: DetectionRule | Mapping[str, Any]) -> DetectionRule:
        if isinstance(raw, DetectionRule):
            data = raw.snapshot()
        else:
            data = dict(raw)
        rule_id = str(data.get("rule_id") or data.get("id") or "").strip().upper()
        if not rule_id or len(rule_id) > 128 or any(ord(ch) < 32 for ch in rule_id):
            raise ValueError("rule_id must be 1..128 printable characters")
        title = str(data.get("title") or rule_id).strip()[:512]
        severity = str(data.get("severity") or "medium").casefold()
        if severity not in cls._SEVERITIES:
            raise ValueError("unsupported detection rule severity")
        confidence = max(0.0, min(1.0, float(data.get("confidence", 0.8))))
        protocols = tuple(sorted({str(v).strip().casefold() for v in data.get("protocols", ()) if str(v).strip()}))
        if len(protocols) > 128:
            raise ValueError("too many protocol matchers")
        ports = tuple(sorted({int(v) for v in data.get("destination_ports", data.get("ports", ())) }))
        if any(v <= 0 or v > 65535 for v in ports) or len(ports) > 1024:
            raise ValueError("destination_ports are out of bounds")
        host_suffixes = tuple(sorted({str(v).strip().casefold().lstrip(".") for v in data.get("host_suffixes", ()) if str(v).strip()}))
        methods = tuple(sorted({str(v).strip().upper() for v in data.get("methods", ()) if str(v).strip()}))
        status_min = data.get("status_min")
        status_max = data.get("status_max")
        status_min = None if status_min is None else int(status_min)
        status_max = None if status_max is None else int(status_max)
        raw_equals = data.get("metadata_equals", {})
        if isinstance(raw_equals, Mapping):
            metadata_equals = tuple(sorted((str(k), str(v)) for k, v in raw_equals.items()))
        else:
            metadata_equals = tuple((str(k), str(v)) for k, v in raw_equals)
        if len(metadata_equals) > 128:
            raise ValueError("too many metadata matchers")
        return DetectionRule(
            rule_id=rule_id, title=title, severity=severity, confidence=confidence,
            protocols=protocols, destination_ports=ports, host_suffixes=host_suffixes,
            methods=methods, status_min=status_min, status_max=status_max,
            metadata_equals=metadata_equals,
        )

    def inspect(self, event: NetworkEvent | Mapping[str, Any]) -> list[DetectionAlert]:
        if not isinstance(event, NetworkEvent):
            event = _mapping_event(event)
        alerts: list[DetectionAlert] = []
        protocol = str(event.protocol or "").casefold()
        url = str(event.url or "")
        scheme = urlparse(url).scheme.casefold() if url else ""
        headers = {str(k): str(v) for k, v in event.request_headers.items()}
        metadata = dict(event.metadata or {})

        if scheme == "http" and any(_SECRET_HEADER.match(name) for name in headers):
            alerts.append(self._alert(
                event, "NET-CLEAR-CREDENTIAL", "high", "Sensitive HTTP header sent over cleartext transport", 0.98,
                {"host": event.host, "headers": sorted(name for name in headers if _SECRET_HEADER.match(name))},
            ))
        if event.sensitivity_flags and scheme == "http":
            alerts.append(self._alert(
                event, "NET-CLEAR-SENSITIVE", "medium", "Sensitive request content observed over cleartext HTTP", 0.9,
                {"host": event.host, "flags": list(event.sensitivity_flags)},
            ))
        if isinstance(event.status, int) and event.status >= 500:
            alerts.append(self._alert(
                event, "HTTP-SERVER-ERROR", "low", "Repeated server-side errors may indicate service instability or probing", 0.65,
                {"host": event.host, "status": event.status, "method": event.method},
            ))
        tls_version = str(metadata.get("tls_version") or metadata.get("tls.record.version") or "").casefold()
        if tls_version and any(marker in tls_version for marker in ("ssl", "tlsv1.0", "tls 1.0", "tlsv1.1", "tls 1.1")):
            alerts.append(self._alert(
                event, "TLS-LEGACY-VERSION", "medium", "Legacy TLS/SSL version observed", 0.95,
                {"host": event.host, "tls_version": tls_version},
            ))
        if protocol in {"dns", "doh", "dot", "doq"}:
            qname = self._dns_name(event)
            score = self._dns_tunnel_score(qname)
            if score >= 0.75:
                alerts.append(self._alert(
                    event, "DNS-HIGH-ENTROPY-NAME", "medium", "High-entropy or oversized DNS name observed", score,
                    {"query": qname[:512], "score": round(score, 3)},
                ))
        destination_port = self._port(metadata, "dst_port", "destination_port", "tcp.dstport", "udp.dstport")
        if destination_port in {23, 21, 110, 143} and protocol not in {"tls", "https"}:
            alerts.append(self._alert(
                event, "NET-LEGACY-CLEARTEXT-SERVICE", "low", "Legacy cleartext application protocol observed", 0.8,
                {"host": event.host, "port": destination_port, "protocol": protocol},
            ))
        alerts.extend(self._custom_alerts(event, protocol=protocol, destination_port=destination_port))
        return self._deduplicate(alerts)

    def _custom_alerts(self, event: NetworkEvent, *, protocol: str, destination_port: int | None) -> list[DetectionAlert]:
        alerts: list[DetectionAlert] = []
        host = str(event.host or "").casefold().rstrip(".")
        method = str(event.method or "").upper()
        metadata = {str(k): str(v) for k, v in (event.metadata or {}).items()}
        for rule in tuple(self._rules.values()):
            if rule.protocols and protocol not in rule.protocols:
                continue
            if rule.destination_ports and destination_port not in rule.destination_ports:
                continue
            if rule.host_suffixes and not any(host == suffix or host.endswith("." + suffix) for suffix in rule.host_suffixes):
                continue
            if rule.methods and method not in rule.methods:
                continue
            if rule.status_min is not None and (not isinstance(event.status, int) or event.status < rule.status_min):
                continue
            if rule.status_max is not None and (not isinstance(event.status, int) or event.status > rule.status_max):
                continue
            if rule.metadata_equals and any(metadata.get(key) != value for key, value in rule.metadata_equals):
                continue
            alerts.append(self._alert(
                event, rule.rule_id, rule.severity, rule.title, rule.confidence,
                {
                    "host": event.host,
                    "protocol": protocol,
                    "destination_port": destination_port,
                    "method": event.method,
                    "status": event.status,
                    "rule_source": "declarative",
                },
            ))
        return alerts

    @staticmethod
    def _alert(event: NetworkEvent, rule_id: str, severity: str, title: str, confidence: float, evidence: dict[str, Any]) -> DetectionAlert:
        return DetectionAlert(
            id=new_id("alert"), session_id=event.session_id, event_id=event.id, rule_id=rule_id,
            severity=severity, title=title, confidence=max(0.0, min(1.0, float(confidence))),
            timestamp=event.timestamp or utc_now(), evidence=evidence,
        )

    @staticmethod
    def _deduplicate(alerts: list[DetectionAlert]) -> list[DetectionAlert]:
        seen: set[str] = set()
        result: list[DetectionAlert] = []
        for alert in alerts:
            key = f"{alert.event_id}:{alert.rule_id}"
            if key in seen:
                continue
            seen.add(key)
            result.append(alert)
        return result

    @staticmethod
    def _port(metadata: Mapping[str, Any], *names: str) -> int | None:
        for name in names:
            value = metadata.get(name)
            try:
                port = int(value)
            except (TypeError, ValueError, OverflowError):
                continue
            if 0 < port <= 65535:
                return port
        return None

    @staticmethod
    def _dns_name(event: NetworkEvent) -> str:
        metadata = event.metadata or {}
        for key in ("dns.qry.name", "dns_query", "query_name", "qname"):
            value = metadata.get(key)
            if value:
                return str(value).strip().rstrip(".")
        if event.host:
            return str(event.host).strip().rstrip(".")
        return ""

    @staticmethod
    def _dns_tunnel_score(name: str) -> float:
        qname = str(name or "").strip().rstrip(".")
        if not qname:
            return 0.0
        labels = [part for part in qname.split(".") if part]
        longest = max((len(part) for part in labels), default=0)
        total = len(qname)
        entropy = 0.0
        candidate = max(labels, key=len, default="")
        if candidate:
            counts = Counter(candidate.casefold())
            length = len(candidate)
            entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
        score = 0.0
        if total >= 120:
            score += 0.35
        elif total >= 80:
            score += 0.2
        if longest >= 50:
            score += 0.35
        elif longest >= 35:
            score += 0.2
        if entropy >= 4.2:
            score += 0.35
        elif entropy >= 3.8:
            score += 0.2
        if _BASE64ISH.fullmatch(candidate or ""):
            score += 0.15
        return min(1.0, score)


class ThreatHunter:
    """Cross-event passive hunting for beaconing, DNS tunneling and lateral movement."""

    def hunt(self, events: Iterable[NetworkEvent | Mapping[str, Any]], *, limit: int = 200_000) -> dict[str, Any]:
        bounded = max(1, min(1_000_000, int(limit)))
        normalized: list[NetworkEvent] = []
        for raw in events:
            normalized.append(raw if isinstance(raw, NetworkEvent) else _mapping_event(raw))
            if len(normalized) >= bounded:
                break
        findings: list[ThreatFinding] = []
        findings.extend(self._beacon_findings(normalized))
        findings.extend(self._dns_findings(normalized))
        findings.extend(self._lateral_findings(normalized))
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda item: (severity_order.get(item.severity, 9), -item.confidence, item.kind))
        return {
            "events_analyzed": len(normalized),
            "finding_count": len(findings),
            "findings": [item.snapshot() for item in findings[:1000]],
        }

    def _beacon_findings(self, events: list[NetworkEvent]) -> list[ThreatFinding]:
        groups: dict[str, list[float]] = defaultdict(list)
        for event in events:
            key = self._destination_key(event)
            timestamp = self._timestamp(event.timestamp)
            if key and timestamp is not None:
                groups[key].append(timestamp)
        findings: list[ThreatFinding] = []
        for key, timestamps in groups.items():
            if len(timestamps) < 6:
                continue
            timestamps.sort()
            gaps = [b - a for a, b in zip(timestamps, timestamps[1:]) if b > a]
            if len(gaps) < 5:
                continue
            avg = mean(gaps)
            if avg < 1.0 or avg > 24 * 3600:
                continue
            deviation = pstdev(gaps) if len(gaps) > 1 else 0.0
            jitter = deviation / avg if avg else 1.0
            confidence = max(0.0, min(0.99, 1.0 - jitter))
            if jitter <= 0.20:
                findings.append(ThreatFinding(
                    "periodic-beacon", "medium" if jitter > 0.08 else "high", confidence,
                    "Highly periodic network communication observed",
                    {"destination": key, "samples": len(timestamps), "mean_interval_seconds": round(avg, 3), "jitter_ratio": round(jitter, 4)},
                ))
        return findings

    def _dns_findings(self, events: list[NetworkEvent]) -> list[ThreatFinding]:
        detector = PassiveDetectionEngine()
        suspicious: dict[str, list[tuple[str, float]]] = defaultdict(list)
        for event in events:
            if str(event.protocol or "").casefold() not in {"dns", "doh", "dot", "doq"}:
                continue
            name = detector._dns_name(event)
            score = detector._dns_tunnel_score(name)
            if score >= 0.55:
                parent = ".".join(name.split(".")[-2:]).casefold() if "." in name else name.casefold()
                suspicious[parent].append((name, score))
        findings: list[ThreatFinding] = []
        for parent, rows in suspicious.items():
            if len(rows) < 3:
                continue
            avg_score = mean(score for _name, score in rows)
            findings.append(ThreatFinding(
                "dns-tunneling", "high" if avg_score >= 0.8 else "medium", min(0.99, avg_score),
                "Repeated high-entropy DNS queries may indicate tunneling",
                {"domain": parent, "queries": len(rows), "average_score": round(avg_score, 3), "examples": [name[:256] for name, _ in rows[:5]]},
            ))
        return findings

    def _lateral_findings(self, events: list[NetworkEvent]) -> list[ThreatFinding]:
        by_source: dict[str, set[str]] = defaultdict(set)
        ports: dict[str, Counter[int]] = defaultdict(Counter)
        for event in events:
            metadata = event.metadata or {}
            source = str(metadata.get("src_ip") or metadata.get("source_ip") or metadata.get("source_address") or "").strip()
            destination = str(metadata.get("dst_ip") or metadata.get("destination_ip") or metadata.get("destination_address") or "").strip()
            if not source or not destination or not self._private_ip(destination):
                continue
            port = PassiveDetectionEngine._port(metadata, "dst_port", "destination_port", "tcp.dstport", "udp.dstport")
            if port not in {22, 135, 139, 445, 3389, 5985, 5986}:
                continue
            by_source[source].add(destination)
            ports[source][int(port)] += 1
        findings: list[ThreatFinding] = []
        for source, destinations in by_source.items():
            if len(destinations) < 5:
                continue
            count = sum(ports[source].values())
            confidence = min(0.98, 0.55 + min(0.4, len(destinations) / 30.0))
            findings.append(ThreatFinding(
                "lateral-movement-pattern", "high" if len(destinations) >= 10 else "medium", confidence,
                "One source contacted many private hosts on remote-administration services",
                {"source": source, "unique_destinations": len(destinations), "events": count, "ports": dict(ports[source].most_common())},
            ))
        return findings

    @staticmethod
    def _timestamp(value: str) -> float | None:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
        except ValueError:
            try:
                return float(text)
            except (TypeError, ValueError, OverflowError):
                return None

    @staticmethod
    def _destination_key(event: NetworkEvent) -> str:
        metadata = event.metadata or {}
        destination = str(metadata.get("dst_ip") or metadata.get("destination_ip") or metadata.get("destination_address") or event.host or "").strip()
        if not destination:
            return ""
        port = PassiveDetectionEngine._port(metadata, "dst_port", "destination_port", "tcp.dstport", "udp.dstport")
        protocol = str(event.protocol or "").casefold()
        return f"{destination}:{port or 0}/{protocol}"

    @staticmethod
    def _private_ip(value: str) -> bool:
        try:
            return ip_address(value).is_private
        except ValueError:
            return False
