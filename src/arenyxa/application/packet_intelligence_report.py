from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from itertools import islice
from typing import Any, Iterable

from arenyxa.infrastructure.capture.packet_models import PacketRecord


@dataclass(slots=True)
class PacketIntelligenceSnapshot:
    packet_count: int
    wire_bytes: int
    captured_bytes: int
    protocols: list[dict[str, Any]]
    endpoints: list[dict[str, Any]]
    conversations: list[dict[str, Any]]
    tcp_streams: int
    udp_streams: int
    http2_streams: int
    quic_streams: int
    tcp_analysis: dict[str, int]
    tcp_ack_rtt_p50_ms: float
    tcp_ack_rtt_p95_ms: float
    tcp_ack_rtt_p99_ms: float
    methods: dict[str, int]
    status_families: dict[str, int]
    tls_hosts: list[dict[str, Any]]
    dns_queries: list[dict[str, Any]]
    findings: list[dict[str, Any]]

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


class PacketIntelligenceReporter:
    """Build a bounded, passive network-analysis report from normalized packet records."""

    MAX_PACKETS = 200_000
    MAX_FINDINGS = 500

    @staticmethod
    def _percentile(values: list[float], fraction: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(max(0.0, float(value)) for value in values)
        index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * fraction))))
        return round(ordered[index], 3)

    @staticmethod
    def _endpoint(address: str, port: int | None) -> str:
        address = str(address or "")
        return f"{address}:{port}" if port is not None and address else address

    @staticmethod
    def _transport(record: PacketRecord) -> str:
        protocols = f":{str(record.protocols or '').casefold()}:"
        if ":tcp:" in protocols:
            return "tcp"
        if ":udp:" in protocols:
            return "udp"
        return str(record.protocol or "unknown").casefold() or "unknown"

    def analyze(self, records: Iterable[PacketRecord], *, limit: int = 100_000) -> PacketIntelligenceSnapshot:
        bounded = max(1, min(int(limit), self.MAX_PACKETS))
        rows = list(islice(records, bounded))
        protocols: Counter[str] = Counter()
        endpoints: Counter[str] = Counter()
        conversations: dict[tuple[str, str, str], dict[str, int]] = {}
        tcp_analysis: Counter[str] = Counter()
        methods: Counter[str] = Counter()
        statuses = {"1xx": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
        tls_hosts: Counter[str] = Counter()
        dns_queries: Counter[str] = Counter()
        rtts: list[float] = []
        findings: list[dict[str, Any]] = []
        tcp_streams: set[int] = set()
        udp_streams: set[int] = set()
        http2_streams: set[int] = set()
        quic_streams: set[int] = set()

        def add_finding(record: PacketRecord, severity: str, kind: str, detail: str) -> None:
            if len(findings) >= self.MAX_FINDINGS:
                return
            findings.append({
                "severity": severity,
                "kind": kind,
                "frame_number": int(record.frame_number),
                "source": self._endpoint(record.source, record.source_port),
                "destination": self._endpoint(record.destination, record.destination_port),
                "protocol": record.protocol,
                "detail": str(detail)[:500],
            })

        for record in rows:
            protocol = str(record.protocol or "unknown").upper()
            protocols[protocol] += 1
            source = self._endpoint(record.source, record.source_port)
            destination = self._endpoint(record.destination, record.destination_port)
            if source:
                endpoints[source] += 1
            if destination:
                endpoints[destination] += 1
            if source and destination:
                left, right = sorted((source, destination))
                key = (self._transport(record), left, right)
                conv = conversations.setdefault(key, {"packets": 0, "bytes": 0})
                conv["packets"] += 1
                conv["bytes"] += max(0, int(record.length or 0))

            for flag in record.tcp_analysis:
                normalized = str(flag).strip().casefold().replace("tcp.analysis.", "")
                if not normalized:
                    continue
                tcp_analysis[normalized] += 1
                if normalized in {"retransmission", "fast_retransmission", "spurious_retransmission", "lost_segment"}:
                    add_finding(record, "medium", "tcp-loss-recovery", normalized)
                elif normalized in {"zero_window", "window_full"}:
                    add_finding(record, "medium", "tcp-flow-control-pressure", normalized)
                elif normalized == "out_of_order":
                    add_finding(record, "low", "tcp-out-of-order", normalized)

            metadata = dict(record.metadata or {})
            try:
                rtt = float(metadata.get("tcp_ack_rtt_ms"))
            except (TypeError, ValueError, OverflowError):
                rtt = -1.0
            if rtt >= 0:
                rtts.append(rtt)
                if rtt >= 500.0:
                    add_finding(record, "medium", "high-tcp-rtt", f"ack_rtt_ms={rtt:.3f}")
            method = str(record.method or "").upper()
            if method:
                methods[method] += 1
            status = record.status
            if isinstance(status, int) and 100 <= status <= 599:
                statuses[f"{status // 100}xx"] += 1
                if status >= 500:
                    add_finding(record, "high", "http-server-error", f"HTTP {status}")
            else:
                statuses["other"] += 1

            protocol_chain = f":{str(record.protocols or '').casefold()}:"
            host = str(record.host or "").strip().casefold()
            if host and (":tls:" in protocol_chain or protocol.casefold() in {"tls", "ssl"}):
                tls_hosts[host] += 1
            if host and (":dns:" in protocol_chain or ":mdns:" in protocol_chain or protocol.casefold() in {"dns", "mdns"}):
                dns_queries[host] += 1
            if record.tcp_stream is not None:
                tcp_streams.add(int(record.tcp_stream))
            if record.udp_stream is not None:
                udp_streams.add(int(record.udp_stream))
            if record.http2_stream is not None:
                http2_streams.add(int(record.http2_stream))
            if record.quic_stream is not None:
                quic_streams.add(int(record.quic_stream))
            if int(record.length or 0) >= 16 * 1024:
                add_finding(record, "info", "large-frame", f"wire_length={int(record.length)}")
            if int(record.captured_length or 0) < int(record.length or 0):
                add_finding(record, "low", "capture-truncation", f"captured={record.captured_length}, wire={record.length}")

        protocol_rows = [{"protocol": key, "packets": value} for key, value in protocols.most_common(100)]
        endpoint_rows = [{"endpoint": key, "packets": value} for key, value in endpoints.most_common(200)]
        conversation_rows = [
            {"transport": key[0], "endpoint_a": key[1], "endpoint_b": key[2], **value}
            for key, value in sorted(conversations.items(), key=lambda item: (-item[1]["bytes"], -item[1]["packets"], item[0]))[:500]
        ]
        findings.sort(key=lambda row: ({"high": 0, "medium": 1, "low": 2, "info": 3}.get(str(row["severity"]), 9), int(row["frame_number"])))
        return PacketIntelligenceSnapshot(
            packet_count=len(rows),
            wire_bytes=sum(max(0, int(row.length or 0)) for row in rows),
            captured_bytes=sum(max(0, int(row.captured_length or 0)) for row in rows),
            protocols=protocol_rows,
            endpoints=endpoint_rows,
            conversations=conversation_rows,
            tcp_streams=len(tcp_streams),
            udp_streams=len(udp_streams),
            http2_streams=len(http2_streams),
            quic_streams=len(quic_streams),
            tcp_analysis=dict(sorted(tcp_analysis.items())),
            tcp_ack_rtt_p50_ms=self._percentile(rtts, 0.50),
            tcp_ack_rtt_p95_ms=self._percentile(rtts, 0.95),
            tcp_ack_rtt_p99_ms=self._percentile(rtts, 0.99),
            methods=dict(sorted(methods.items())),
            status_families=statuses,
            tls_hosts=[{"host": key, "packets": value} for key, value in tls_hosts.most_common(100)],
            dns_queries=[{"query": key, "packets": value} for key, value in dns_queries.most_common(100)],
            findings=findings,
        )
