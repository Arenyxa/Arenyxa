from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from arenyxa.compat import dataclass
from arenyxa.domain.models import NetworkEvent

EventLike = NetworkEvent | Mapping[str, Any]


@dataclass(slots=True)
class TrafficForensicsSnapshot:
    event_count: int
    bytes_total: int
    host_count: int
    flow_count: int
    first_timestamp: str
    last_timestamp: str
    protocols: dict[str, int]
    status_families: dict[str, int]
    severity_counts: dict[str, int]
    duration_ms: dict[str, float]
    dns_queries: list[dict[str, Any]]
    dns_rcodes: dict[str, int]
    tls_servers: list[dict[str, Any]]
    tls_versions: dict[str, int]
    tcp_analysis: dict[str, int]
    top_hosts: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    timeline: list[dict[str, Any]]

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_count": self.event_count,
            "bytes_total": self.bytes_total,
            "host_count": self.host_count,
            "flow_count": self.flow_count,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
            "protocols": dict(self.protocols),
            "status_families": dict(self.status_families),
            "severity_counts": dict(self.severity_counts),
            "duration_ms": dict(self.duration_ms),
            "dns_queries": list(self.dns_queries),
            "dns_rcodes": dict(self.dns_rcodes),
            "tls_servers": list(self.tls_servers),
            "tls_versions": dict(self.tls_versions),
            "tcp_analysis": dict(self.tcp_analysis),
            "top_hosts": list(self.top_hosts),
            "findings": list(self.findings),
            "timeline": list(self.timeline),
        }


class TrafficForensicsAnalyzer:
    """Bounded, passive analysis for captured traffic and imported network evidence."""

    DEFAULT_TIMELINE_LIMIT = 500
    MAX_TIMELINE_LIMIT = 5_000
    LARGE_TRANSFER_BYTES = 10 * 1024 * 1024
    SLOW_EVENT_MS = 2_000.0

    def analyze(
        self,
        events: Sequence[EventLike],
        *,
        timeline_limit: int = DEFAULT_TIMELINE_LIMIT,
    ) -> TrafficForensicsSnapshot:
        limit = max(1, min(self.MAX_TIMELINE_LIMIT, int(timeline_limit)))
        protocols: Counter[str] = Counter()
        statuses: Counter[str] = Counter()
        severity: Counter[str] = Counter()
        hosts: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"events": 0, "bytes": 0, "errors": 0, "slow": 0, "durations": []}
        )
        flows: set[str] = set()
        timestamps: list[str] = []
        durations: list[float] = []
        findings: list[dict[str, Any]] = []
        timeline: list[dict[str, Any]] = []
        bytes_total = 0
        dns_queries: Counter[str] = Counter()
        dns_rcodes: Counter[str] = Counter()
        tls_servers: Counter[str] = Counter()
        tls_versions: Counter[str] = Counter()
        tcp_analysis: Counter[str] = Counter()

        for index, event in enumerate(events):
            protocol = str(self._get(event, "protocol", "unknown") or "unknown").casefold()
            url = str(self._get(event, "url", "") or "")
            host = str(self._get(event, "host", "") or self._host_from_url(url))
            timestamp = str(self._get(event, "timestamp", "") or "")
            status = self._status(self._get(event, "status", None))
            size = self._non_negative_int(self._get(event, "size", 0))
            duration = self._duration(event)
            flow_ref = str(
                self._get(event, "flow_ref", "")
                or self._get(event, "request_ref", "")
                or self._get(event, "id", "")
                or f"event-{index}"
            )
            event_id = str(self._get(event, "id", "") or f"event-{index}")
            method = str(self._get(event, "method", "") or "")
            flags = self._sensitivity_flags(event)
            request_headers = self._mapping(self._get(event, "request_headers", {}))
            metadata = self._mapping(self._get(event, "metadata", {}))
            dissector_fields = self._mapping(metadata.get("dissector_fields", {}))
            dns_name = str(dissector_fields.get("dns.qry.name") or (host if protocol in {"dns", "mdns"} else "")).strip().casefold()
            if dns_name:
                dns_queries[dns_name] += 1
            rcode = str(dissector_fields.get("dns.flags.rcode") or "").strip()
            if rcode:
                dns_rcodes[rcode] += 1
            tls_server = str(dissector_fields.get("tls.handshake.extensions_server_name") or (host if protocol in {"tls", "ssl"} else "")).strip().casefold()
            if tls_server:
                tls_servers[tls_server] += 1
            tls_version = str(dissector_fields.get("tls.handshake.version") or dissector_fields.get("tls.record.version") or "").strip()
            if tls_version:
                tls_versions[tls_version] += 1
            analysis_flags = metadata.get("tcp_analysis") or metadata.get("native_tcp_analysis") or []
            if isinstance(analysis_flags, (list, tuple, set, frozenset)):
                for analysis_flag in analysis_flags:
                    normalized_flag = str(analysis_flag).strip().casefold().replace("tcp.analysis.", "")
                    if normalized_flag:
                        tcp_analysis[normalized_flag] += 1

            protocols[protocol] += 1
            statuses[self._status_family(status)] += 1
            bytes_total += size
            flows.add(flow_ref)
            if timestamp:
                timestamps.append(timestamp)
            if duration is not None:
                durations.append(duration)

            if host:
                state = hosts[host]
                state["events"] += 1
                state["bytes"] += size
                if status is not None and status >= 400:
                    state["errors"] += 1
                if duration is not None:
                    state["durations"].append(duration)
                    if duration >= self.SLOW_EVENT_MS:
                        state["slow"] += 1

            evidence_flags: list[str] = []
            if status is not None and status >= 500:
                evidence_flags.append("server-error")
            if duration is not None and duration >= self.SLOW_EVENT_MS:
                evidence_flags.append("slow")
            if size >= self.LARGE_TRANSFER_BYTES:
                evidence_flags.append("large-transfer")
                self._append_finding(
                    findings,
                    severity,
                    severity_name="medium",
                    kind="large-transfer",
                    title="Large captured transfer",
                    host=host,
                    event_id=event_id,
                    evidence={"bytes": size, "protocol": protocol},
                )
            if flags:
                evidence_flags.append("sensitive")
            if self._is_plaintext_sensitive(url, request_headers, flags):
                evidence_flags.append("plaintext-sensitive")
                self._append_finding(
                    findings,
                    severity,
                    severity_name="high",
                    kind="plaintext-sensitive",
                    title="Sensitive request metadata observed over plaintext HTTP",
                    host=host,
                    event_id=event_id,
                    evidence={"sensitivity_flags": sorted(flags), "header_names": self._sensitive_header_names(request_headers)},
                )

            timeline.append(
                {
                    "timestamp": timestamp,
                    "event_id": event_id,
                    "flow_ref": flow_ref,
                    "host": host,
                    "protocol": protocol,
                    "method": method,
                    "status": status,
                    "bytes": size,
                    "duration_ms": duration,
                    "flags": evidence_flags,
                }
            )

        for host, state in hosts.items():
            event_count = int(state["events"])
            error_count = int(state["errors"])
            slow_count = int(state["slow"])
            if event_count >= 5 and error_count >= 3 and (error_count / event_count) >= 0.20:
                self._append_finding(
                    findings,
                    severity,
                    severity_name="high",
                    kind="host-error-spike",
                    title="Elevated HTTP error rate",
                    host=host,
                    event_id="",
                    evidence={"events": event_count, "errors": error_count, "error_rate": round(error_count / event_count, 4)},
                )
            if slow_count >= 3:
                self._append_finding(
                    findings,
                    severity,
                    severity_name="medium",
                    kind="host-latency-spike",
                    title="Repeated high-latency events",
                    host=host,
                    event_id="",
                    evidence={"events": event_count, "slow_events": slow_count, "threshold_ms": self.SLOW_EVENT_MS},
                )

        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda row: (severity_rank.get(str(row["severity"]), 9), str(row.get("host", "")), str(row.get("kind", ""))))
        timeline.sort(key=lambda row: (str(row.get("timestamp", "")), str(row.get("event_id", ""))))
        if len(timeline) > limit:
            timeline = timeline[-limit:]

        top_hosts = []
        for host, state in sorted(hosts.items(), key=lambda item: (int(item[1]["bytes"]), int(item[1]["events"])), reverse=True)[:50]:
            host_durations = [float(value) for value in state["durations"]]
            top_hosts.append(
                {
                    "host": host,
                    "events": int(state["events"]),
                    "bytes": int(state["bytes"]),
                    "errors": int(state["errors"]),
                    "error_rate": round(int(state["errors"]) / max(1, int(state["events"])), 4),
                    "duration_p95_ms": self._percentile(host_durations, 0.95),
                }
            )

        return TrafficForensicsSnapshot(
            event_count=len(events),
            bytes_total=bytes_total,
            host_count=len(hosts),
            flow_count=len(flows),
            first_timestamp=min(timestamps) if timestamps else "",
            last_timestamp=max(timestamps) if timestamps else "",
            protocols=dict(protocols.most_common()),
            status_families=dict(statuses),
            severity_counts=dict(severity),
            duration_ms={
                "p50": self._percentile(durations, 0.50),
                "p95": self._percentile(durations, 0.95),
                "p99": self._percentile(durations, 0.99),
                "max": round(max(durations), 3) if durations else 0.0,
            },
            dns_queries=[{"query": key, "events": value} for key, value in dns_queries.most_common(100)],
            dns_rcodes=dict(dns_rcodes.most_common()),
            tls_servers=[{"server": key, "events": value} for key, value in tls_servers.most_common(100)],
            tls_versions=dict(tls_versions.most_common()),
            tcp_analysis=dict(tcp_analysis.most_common()),
            top_hosts=top_hosts,
            findings=findings[:1_000],
            timeline=timeline,
        )

    @staticmethod
    def _get(event: EventLike, name: str, default: Any) -> Any:
        if isinstance(event, Mapping):
            return event.get(name, default)
        return getattr(event, name, default)

    @staticmethod
    def _mapping(value: Any) -> dict[str, Any]:
        return dict(value) if isinstance(value, Mapping) else {}

    @classmethod
    def _sensitivity_flags(cls, event: EventLike) -> set[str]:
        value = cls._get(event, "sensitivity_flags", None)
        if value is None:
            value = cls._get(event, "sensitivity", [])
        if isinstance(value, (list, tuple, set, frozenset)):
            return {str(item) for item in value if str(item).strip()}
        return set()

    @staticmethod
    def _status(value: Any) -> int | None:
        if value in (None, ""):
            return None
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return result if 100 <= result <= 999 else None

    @staticmethod
    def _status_family(status: int | None) -> str:
        if status is None:
            return "none"
        if 100 <= status <= 599:
            return f"{status // 100}xx"
        return "other"

    @staticmethod
    def _non_negative_int(value: Any) -> int:
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError):
            return 0
        return max(0, result)

    @classmethod
    def _duration(cls, event: EventLike) -> float | None:
        timing = cls._mapping(cls._get(event, "timing", {}))
        metadata = cls._mapping(cls._get(event, "metadata", {}))
        for container, names in (
            (timing, ("duration_ms", "total_ms", "elapsed_ms")),
            (metadata, ("duration_ms", "har_total_ms", "elapsed_ms")),
        ):
            for name in names:
                if name not in container:
                    continue
                try:
                    value = float(container[name])
                except (TypeError, ValueError, OverflowError):
                    continue
                if math.isfinite(value) and value >= 0:
                    return value
        return None

    @staticmethod
    def _host_from_url(url: str) -> str:
        if not url:
            return ""
        try:
            return str(urlsplit(url).hostname or "")
        except ValueError:
            return ""

    @staticmethod
    def _sensitive_header_names(headers: Mapping[str, Any]) -> list[str]:
        sensitive = {"authorization", "proxy-authorization", "cookie"}
        return sorted(str(name).casefold() for name in headers if str(name).casefold() in sensitive)

    @classmethod
    def _is_plaintext_sensitive(cls, url: str, headers: Mapping[str, Any], flags: set[str]) -> bool:
        if not str(url).casefold().startswith("http://"):
            return False
        return bool(flags or cls._sensitive_header_names(headers))

    @staticmethod
    def _append_finding(
        findings: list[dict[str, Any]],
        severity: Counter[str],
        *,
        severity_name: str,
        kind: str,
        title: str,
        host: str,
        event_id: str,
        evidence: Mapping[str, Any],
    ) -> None:
        severity[severity_name] += 1
        findings.append(
            {
                "severity": severity_name,
                "kind": kind,
                "title": title,
                "host": host,
                "event_id": event_id,
                "evidence": dict(evidence),
            }
        )

    @staticmethod
    def _percentile(values: Sequence[float], fraction: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(float(value) for value in values)
        if len(ordered) == 1:
            return round(ordered[0], 3)
        position = max(0.0, min(1.0, float(fraction))) * (len(ordered) - 1)
        lower = int(math.floor(position))
        upper = int(math.ceil(position))
        if lower == upper:
            return round(ordered[lower], 3)
        weight = position - lower
        return round(ordered[lower] * (1.0 - weight) + ordered[upper] * weight, 3)
