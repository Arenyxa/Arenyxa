from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import ipaddress
import math
from itertools import islice
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

from arenyxa.domain.models import NetworkEvent


@dataclass(slots=True)
class PacketConversation:
    key: str
    protocol: str
    endpoint_a: str
    endpoint_b: str
    packets: int
    bytes: int
    errors: int
    first_at: str
    last_at: str




@dataclass(slots=True)
class TcpStreamQuality:
    key: str
    packets: int
    bytes: int
    retransmissions: int
    fast_retransmissions: int
    spurious_retransmissions: int
    out_of_order: int
    lost_segments: int
    duplicate_acks: int
    zero_window: int
    window_full: int
    keep_alive: int
    ack_rtt_p50_ms: float
    ack_rtt_p95_ms: float
    ack_rtt_max_ms: float
    bytes_in_flight_max: int
    health_score: float
    severity: str
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class TcpQualitySummary:
    stream_count: int
    packet_count: int
    issue_count: int
    retransmissions: int
    lost_segments: int
    out_of_order: int
    duplicate_acks: int
    zero_window: int
    ack_rtt_p50_ms: float
    ack_rtt_p95_ms: float
    ack_rtt_p99_ms: float
    streams: list[TcpStreamQuality] = field(default_factory=list)

@dataclass(slots=True)
class PacketAnalyticsSnapshot:
    event_count: int
    protocols: list[dict[str, Any]]
    endpoints: list[dict[str, Any]]
    conversations: list[PacketConversation]
    status_families: dict[str, int]
    duration_p50_ms: float
    duration_p95_ms: float
    duration_p99_ms: float
    anomalies: list[dict[str, Any]]
    private_endpoint_count: int
    public_endpoint_count: int
    tcp_quality: TcpQualitySummary
    transports: dict[str, int] = field(default_factory=dict)
    tls_versions: dict[str, int] = field(default_factory=dict)
    dns_response_codes: dict[str, int] = field(default_factory=dict)
    address_families: dict[str, int] = field(default_factory=dict)
    encrypted_event_count: int = 0
    fragmented_event_count: int = 0

    def snapshot(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["conversations"] = [asdict(item) for item in self.conversations]
        return payload


class PacketAdvancedAnalyzer:
    MAX_EVENTS = 100000
    MAX_CONVERSATIONS = 1000

    def analyze(self, events: Iterable[NetworkEvent], *, limit: int = 50000) -> PacketAnalyticsSnapshot:
        cap = max(1, min(int(limit), self.MAX_EVENTS))
        rows = list(islice(events, cap))
        protocols: dict[str, dict[str, int]] = {}
        transports: dict[str, int] = {}
        tls_versions: dict[str, int] = {}
        dns_response_codes: dict[str, int] = {}
        address_families = {"ipv4": 0, "ipv6": 0, "other": 0}
        encrypted_event_count = 0
        fragmented_event_count = 0
        endpoints: dict[str, dict[str, int]] = {}
        conversations: dict[str, dict[str, Any]] = {}
        durations: list[float] = []
        status_families = {"1xx": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
        private_endpoints: set[str] = set()
        public_endpoints: set[str] = set()
        anomalies: list[dict[str, Any]] = []
        for event in rows:
            metadata = dict(event.metadata or {})
            protocol = self._protocol(event, metadata)
            byte_count = self._bytes(event, metadata)
            transport = str(metadata.get("transport") or "").strip().upper()
            if transport:
                transports[transport] = transports.get(transport, 0) + 1
            dissector = metadata.get("dissector_fields") if isinstance(metadata.get("dissector_fields"), dict) else {}
            tls_version = str(
                dissector.get("tls.handshake.extensions.supported_version")
                or dissector.get("tls.handshake.version")
                or dissector.get("tls.record.version")
                or metadata.get("tls_version")
                or ""
            ).strip()
            if tls_version:
                tls_versions[tls_version] = tls_versions.get(tls_version, 0) + 1
            rcode = str(dissector.get("dns.flags.rcode") or "").strip()
            if rcode:
                dns_response_codes[rcode] = dns_response_codes.get(rcode, 0) + 1
            frame_protocols = str(metadata.get("frame_protocols") or "").casefold()
            if bool(metadata.get("encrypted_payload")) or any(token in protocol.casefold() for token in ("tls", "quic", "https", "wss")):
                encrypted_event_count += 1
            fragment_offset = str(dissector.get("ip.frag_offset") or "0").strip()
            if fragment_offset not in {"", "0", "0x0000"} or "ipv6-fragment" in frame_protocols:
                fragmented_event_count += 1
            error_text = str(metadata.get("error") or metadata.get("diagnostic") or "")
            error = bool(error_text)
            stat = protocols.setdefault(protocol, {"events": 0, "bytes": 0, "errors": 0})
            stat["events"] += 1
            stat["bytes"] += byte_count
            stat["errors"] += int(error)
            source, destination = self._endpoints(event, metadata)
            for endpoint in (source, destination):
                family = self._address_family(endpoint)
                address_families[family] = address_families.get(family, 0) + 1
                if not endpoint:
                    continue
                entry = endpoints.setdefault(endpoint, {"events": 0, "bytes": 0, "errors": 0})
                entry["events"] += 1
                entry["bytes"] += byte_count
                entry["errors"] += int(error)
                self._classify_endpoint(endpoint, private_endpoints, public_endpoints)
            if source or destination:
                a, b = sorted((source or "?", destination or "?"))
                key = f"{protocol}|{a}|{b}"
                conv = conversations.setdefault(key, {
                    "protocol": protocol,
                    "endpoint_a": a,
                    "endpoint_b": b,
                    "packets": 0,
                    "bytes": 0,
                    "errors": 0,
                    "first_at": str(event.timestamp),
                    "last_at": str(event.timestamp),
                })
                conv["packets"] += 1
                conv["bytes"] += byte_count
                conv["errors"] += int(error)
                conv["last_at"] = str(event.timestamp)
            duration = self._duration(event, metadata)
            if duration is not None:
                durations.append(duration)
            status = self._status(event, metadata)
            if 100 <= status <= 599:
                status_families[f"{status // 100}xx"] += 1
            else:
                status_families["other"] += 1
            if error and len(anomalies) < 200:
                anomalies.append({"event_id": event.id, "kind": "error", "protocol": protocol, "detail": error_text[:500]})
            if duration is not None and duration >= 5000 and len(anomalies) < 200:
                anomalies.append({"event_id": event.id, "kind": "slow", "protocol": protocol, "duration_ms": round(duration, 3)})
            if byte_count >= 16 * 1024 * 1024 and len(anomalies) < 200:
                anomalies.append({"event_id": event.id, "kind": "large-transfer", "protocol": protocol, "bytes": byte_count})
        sorted_durations = sorted(durations)
        protocol_rows = [
            {"protocol": name, **values}
            for name, values in sorted(protocols.items(), key=lambda item: (-item[1]["events"], item[0]))[:256]
        ]
        endpoint_rows = [
            {"endpoint": name, **values}
            for name, values in sorted(endpoints.items(), key=lambda item: (-item[1]["bytes"], item[0]))[:1000]
        ]
        conversation_rows = [
            PacketConversation(key, value["protocol"], value["endpoint_a"], value["endpoint_b"], value["packets"], value["bytes"], value["errors"], value["first_at"], value["last_at"])
            for key, value in sorted(conversations.items(), key=lambda item: (-item[1]["bytes"], -item[1]["packets"], item[0]))[: self.MAX_CONVERSATIONS]
        ]
        return PacketAnalyticsSnapshot(
            event_count=len(rows),
            protocols=protocol_rows,
            endpoints=endpoint_rows,
            conversations=conversation_rows,
            status_families=status_families,
            duration_p50_ms=self._percentile(sorted_durations, 0.50),
            duration_p95_ms=self._percentile(sorted_durations, 0.95),
            duration_p99_ms=self._percentile(sorted_durations, 0.99),
            anomalies=anomalies,
            private_endpoint_count=len(private_endpoints),
            public_endpoint_count=len(public_endpoints),
            tcp_quality=self._tcp_quality(rows),
            transports=dict(sorted(transports.items())),
            tls_versions=dict(sorted(tls_versions.items(), key=lambda item: (-item[1], item[0]))),
            dns_response_codes=dict(sorted(dns_response_codes.items(), key=lambda item: (-item[1], item[0]))),
            address_families=address_families,
            encrypted_event_count=encrypted_event_count,
            fragmented_event_count=fragmented_event_count,
        )

    @classmethod
    def _tcp_quality(cls, events: list[NetworkEvent]) -> TcpQualitySummary:
        streams, all_rtt, packet_total = cls._tcp_stream_states(events)
        issue_total = 0
        retrans_total = 0
        lost_total = 0
        out_total = 0
        dup_total = 0
        zero_total = 0

        rows: list[TcpStreamQuality] = []
        for key, state in streams.items():
            counts = state["analysis"]
            retrans = int(counts.get("retransmission", 0))
            fast = int(counts.get("fast_retransmission", 0))
            spurious = int(counts.get("spurious_retransmission", 0))
            out_of_order = int(counts.get("out_of_order", 0))
            lost = int(counts.get("lost_segment", 0))
            duplicate = int(counts.get("duplicate_ack", 0))
            zero = int(counts.get("zero_window", 0))
            full = int(counts.get("window_full", 0))
            keep_alive = int(counts.get("keep_alive", 0))
            issues = retrans + fast + spurious + out_of_order + lost + duplicate + zero + full
            issue_total += issues
            retrans_total += retrans + fast + spurious
            lost_total += lost
            out_total += out_of_order
            dup_total += duplicate
            zero_total += zero
            packets = max(1, int(state["packets"]))
            weighted = (
                (retrans + fast + spurious) * 5.0 + lost * 10.0 + out_of_order * 2.5
                + duplicate * 1.5 + zero * 8.0 + full * 2.0
            ) / packets
            score = round(max(0.0, min(100.0, 100.0 - weighted * 10.0)), 2)
            severity = "critical" if score < 50 else "warning" if score < 80 else "ok"
            rtts = sorted(float(value) for value in state["rtt"])
            warnings: list[str] = []
            if lost:
                warnings.append(f"{lost} lost TCP segment indicators")
            if retrans + fast + spurious:
                warnings.append(f"{retrans + fast + spurious} retransmission indicators")
            if zero:
                warnings.append(f"{zero} zero-window indicators")
            p95 = cls._percentile(rtts, 0.95)
            if p95 >= 250.0:
                warnings.append(f"high ACK RTT p95: {p95:.1f} ms")
            rows.append(TcpStreamQuality(
                key=key, packets=int(state["packets"]), bytes=int(state["bytes"]),
                retransmissions=retrans, fast_retransmissions=fast, spurious_retransmissions=spurious,
                out_of_order=out_of_order, lost_segments=lost, duplicate_acks=duplicate,
                zero_window=zero, window_full=full, keep_alive=keep_alive,
                ack_rtt_p50_ms=cls._percentile(rtts, 0.50), ack_rtt_p95_ms=p95,
                ack_rtt_max_ms=round(max(rtts), 3) if rtts else 0.0,
                bytes_in_flight_max=int(state["bif_max"]), health_score=score, severity=severity, warnings=warnings,
            ))
        rows.sort(key=lambda item: (item.health_score, -(item.lost_segments + item.retransmissions + item.out_of_order), -item.bytes))
        sorted_rtt = sorted(all_rtt)
        return TcpQualitySummary(
            stream_count=len(rows), packet_count=packet_total, issue_count=issue_total,
            retransmissions=retrans_total, lost_segments=lost_total, out_of_order=out_total,
            duplicate_acks=dup_total, zero_window=zero_total,
            ack_rtt_p50_ms=cls._percentile(sorted_rtt, 0.50),
            ack_rtt_p95_ms=cls._percentile(sorted_rtt, 0.95),
            ack_rtt_p99_ms=cls._percentile(sorted_rtt, 0.99), streams=rows[:256],
        )

    @classmethod
    def _tcp_stream_states(
        cls, events: list[NetworkEvent]
    ) -> tuple[dict[str, dict[str, Any]], list[float], int]:
        streams: dict[str, dict[str, Any]] = {}
        all_rtt: list[float] = []
        packet_total = 0
        for event in events:
            metadata = dict(event.metadata or {})
            raw_analysis = metadata.get("tcp_analysis") or []
            if isinstance(raw_analysis, str):
                analysis = [
                    part.strip().casefold()
                    for part in raw_analysis.replace(",", " ").split()
                    if part.strip()
                ]
            elif isinstance(raw_analysis, (list, tuple, set)):
                analysis = [str(part).strip().casefold() for part in raw_analysis if str(part).strip()]
            else:
                analysis = []
            transport = str(metadata.get("transport") or event.protocol or "").casefold()
            tcp_stream = metadata.get("tcp_stream")
            if "tcp" not in transport and tcp_stream in (None, "") and not analysis:
                continue
            packet_total += 1
            source, destination = cls._endpoints(event, metadata)
            stream_key = str(event.flow_ref or "").strip()
            if not stream_key:
                if tcp_stream not in (None, ""):
                    stream_key = f"tcp:{tcp_stream}"
                else:
                    a, b = sorted((source or "?", destination or "?"))
                    stream_key = f"tcp:{a}|{b}"
            state = streams.setdefault(
                stream_key, {"packets": 0, "bytes": 0, "analysis": {}, "rtt": [], "bif_max": 0}
            )
            state["packets"] += 1
            state["bytes"] += cls._bytes(event, metadata)
            counts = state["analysis"]
            for name in analysis:
                counts[name] = int(counts.get(name, 0)) + 1
            rtt = cls._finite_nonnegative(metadata.get("tcp_ack_rtt_ms"))
            if rtt is not None:
                state["rtt"].append(rtt)
                all_rtt.append(rtt)
            try:
                state["bif_max"] = max(
                    int(state["bif_max"]), max(0, int(metadata.get("tcp_bytes_in_flight") or 0))
                )
            except (TypeError, ValueError):
                record_current_exception(__name__, 'PacketAdvancedAnalyzer._tcp_stream_states:337')
        return streams, all_rtt, packet_total

    @staticmethod
    def _finite_nonnegative(value: Any) -> float | None:
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return None
        return numeric if math.isfinite(numeric) and numeric >= 0.0 else None

    @staticmethod
    def _protocol(event: NetworkEvent, metadata: dict[str, Any]) -> str:
        highest = metadata.get("highest_protocol")
        if isinstance(highest, str) and highest.strip():
            return highest.strip().upper()[:64]
        event_protocol = str(event.protocol or "").strip()
        if event_protocol and event_protocol.casefold() not in {"unknown", "system"}:
            return event_protocol.upper()[:64]
        for key in ("protocol", "protocol_stack", "transport"):
            value = metadata.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().upper()[:64]
        if event.method:
            return "HTTP"
        return str(event.source_type.value if hasattr(event.source_type, "value") else event.source_type).upper()[:64] or "UNKNOWN"

    @staticmethod
    def _bytes(event: NetworkEvent, metadata: dict[str, Any]) -> int:
        candidates = [event.size, metadata.get("frame_len"), metadata.get("length"), metadata.get("bytes"), metadata.get("response_bytes")]
        for value in candidates:
            try:
                numeric = int(value)
            except (TypeError, ValueError):
                continue
            if numeric >= 0:
                return numeric
        return 0

    @staticmethod
    def _endpoints(event: NetworkEvent, metadata: dict[str, Any]) -> tuple[str, str]:
        source = str(
            metadata.get("src") or metadata.get("source") or metadata.get("source_ip")
            or metadata.get("source_address") or ""
        ).strip()
        destination = str(
            metadata.get("dst") or metadata.get("destination") or metadata.get("destination_ip")
            or metadata.get("destination_address") or ""
        ).strip()
        if not destination and event.host:
            destination = str(event.host).strip()
        source_port = metadata.get("src_port") or metadata.get("source_port")
        destination_port = metadata.get("dst_port") or metadata.get("destination_port")
        if source and source_port:
            source = PacketAdvancedAnalyzer._endpoint_with_port(source, source_port)
        if destination and destination_port:
            destination = PacketAdvancedAnalyzer._endpoint_with_port(destination, destination_port)
        return source[:512], destination[:512]

    @staticmethod
    def _endpoint_with_port(address: str, port: Any) -> str:
        text = str(address).strip()
        if ":" in text and not text.startswith("["):
            return f"[{text}]:{port}"
        return f"{text}:{port}"

    @staticmethod
    def _duration(event: NetworkEvent, metadata: dict[str, Any]) -> float | None:
        for value in (event.timing.get("elapsed_ms"), event.timing.get("duration_ms"), metadata.get("elapsed_ms"), metadata.get("duration_ms")):
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                continue
            if math.isfinite(numeric) and numeric >= 0:
                return numeric
        return None

    @staticmethod
    def _status(event: NetworkEvent, metadata: dict[str, Any]) -> int:
        for value in (event.status, metadata.get("status"), metadata.get("status_code")):
            try:
                return int(value)
            except (TypeError, ValueError):
                continue
        return 0

    @staticmethod
    def _address_family(endpoint: str) -> str:
        if not endpoint:
            return "other"
        text = str(endpoint).strip()
        if text.startswith("[") and "]" in text:
            host = text[1:text.index("]")]
        elif text.count(":") == 1:
            host = text.rsplit(":", 1)[0]
        else:
            host = text
        try:
            address = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            return "other"
        return "ipv6" if address.version == 6 else "ipv4"

    @staticmethod
    def _classify_endpoint(endpoint: str, private_endpoints: set[str], public_endpoints: set[str]) -> None:
        text = str(endpoint).strip()
        if text.startswith("[") and "]" in text:
            host = text[1:text.index("]")]
        elif text.count(":") == 1:
            host = text.rsplit(":", 1)[0]
        else:
            host = text.strip("[]")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return
        if address.is_private or address.is_loopback or address.is_link_local:
            private_endpoints.add(str(address))
        else:
            public_endpoints.add(str(address))

    @staticmethod
    def _percentile(rows: list[float], fraction: float) -> float:
        if not rows:
            return 0.0
        index = min(len(rows) - 1, max(0, int(round((len(rows) - 1) * fraction))))
        return round(float(rows[index]), 3)
