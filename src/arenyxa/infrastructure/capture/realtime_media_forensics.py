from __future__ import annotations
from arenyxa.recoverable import record_current_exception

from collections import Counter
from datetime import datetime
from typing import Any, Mapping

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.packet_models import PacketRecord


_MAX_CALLS = 100_000
_MAX_MEDIA_ENDPOINTS_PER_CALL = 128
_MAX_RTP_STREAMS = 200_000
_MAX_RTCP_SOURCES = 200_000
_MAX_SEQUENCE_TRACK = 131_072
_MAX_CALL_ENDPOINTS = 128


def _layers(packet: PacketRecord) -> list[Mapping[str, Any]]:
    raw = packet.metadata.get("native_layers")
    return [row for row in raw if isinstance(row, Mapping)] if isinstance(raw, list) else []


def _fields(layer: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = layer.get("fields")
    return raw if isinstance(raw, Mapping) else {}


def _epoch(value: str) -> float | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def _endpoint(address: str, port: int | None) -> str:
    host = str(address or "")
    return f"{host}:{port}" if port is not None else host


def _media_endpoint(address: str, port: int | None) -> str:
    host = str(address or "").strip()
    return f"{host}:{int(port)}" if host and port is not None else ""


@dataclass(slots=True)
class _DeclaredMedia:
    endpoint: str
    rtcp_endpoint: str
    media: str
    protocol: str
    direction: str
    mid: str
    rtcp_mux: bool
    codecs: tuple[str, ...]
    payload_types: tuple[int, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "rtcp_endpoint": self.rtcp_endpoint,
            "media": self.media,
            "protocol": self.protocol,
            "direction": self.direction,
            "mid": self.mid,
            "rtcp_mux": self.rtcp_mux,
            "codecs": list(self.codecs),
            "payload_types": list(self.payload_types),
        }


@dataclass(slots=True)
class _SipCall:
    call_id_sha256: str
    first_seen: float | None = None
    last_seen: float | None = None
    packets: int = 0
    requests: Counter[str] | None = None
    responses: Counter[int] | None = None
    endpoints: set[str] | None = None
    declared_media: dict[str, _DeclaredMedia] | None = None
    sdp_observations: int = 0
    malformed_sdp_observations: int = 0

    def __post_init__(self) -> None:
        if self.requests is None:
            self.requests = Counter()
        if self.responses is None:
            self.responses = Counter()
        if self.endpoints is None:
            self.endpoints = set()
        if self.declared_media is None:
            self.declared_media = {}


@dataclass(slots=True)
class _RtpSequenceState:
    packets: int = 0
    highest_extended: int = -1
    cycles: int = 0
    highest_raw: int = -1
    seen: set[int] | None = None
    duplicate: int = 0
    out_of_order: int = 0
    forward_gap_packets: int = 0
    wrap_observations: int = 0

    def __post_init__(self) -> None:
        if self.seen is None:
            self.seen = set()

    def _extended(self, sequence: int) -> int:
        if self.highest_raw < 0:
            return sequence
        if sequence < self.highest_raw and self.highest_raw - sequence > 0x8000:
            self.cycles += 0x10000
            self.wrap_observations += 1
            return self.cycles + sequence
        if sequence > self.highest_raw and sequence - self.highest_raw > 0x8000 and self.cycles >= 0x10000:
            return self.cycles - 0x10000 + sequence
        return self.cycles + sequence

    def observe(self, sequence: int) -> None:
        self.packets += 1
        extended = self._extended(sequence & 0xFFFF)
        seen = self.seen
        assert seen is not None
        if extended in seen:
            self.duplicate += 1
            return
        if len(seen) < _MAX_SEQUENCE_TRACK:
            seen.add(extended)
        if self.highest_extended >= 0:
            if extended < self.highest_extended:
                self.out_of_order += 1
            elif extended > self.highest_extended + 1:
                self.forward_gap_packets += extended - self.highest_extended - 1
        if extended > self.highest_extended:
            self.highest_extended = extended
            self.highest_raw = sequence & 0xFFFF


@dataclass(slots=True)
class _RtpStream:
    source: str
    destination: str
    source_port: int | None
    destination_port: int | None
    ssrc: int
    sequence: _RtpSequenceState | None = None
    packets: int = 0
    media_payload_bytes: int = 0
    marker_packets: int = 0
    payload_types: Counter[int] | None = None
    csrcs: set[int] | None = None
    first_seen: float | None = None
    last_seen: float | None = None

    def __post_init__(self) -> None:
        if self.sequence is None:
            self.sequence = _RtpSequenceState()
        if self.payload_types is None:
            self.payload_types = Counter()
        if self.csrcs is None:
            self.csrcs = set()


@dataclass(slots=True)
class _RtcpSource:
    reporter_ssrc: int
    packets: int = 0
    sender_reports: int = 0
    receiver_reports: int = 0
    bye_observations: int = 0
    report_blocks: int = 0
    fraction_lost_sum: float = 0.0
    fraction_lost_samples: int = 0
    fraction_lost_max: float = 0.0
    jitter_max: int = 0
    jitter_latest: int = 0
    cumulative_lost_max: int | None = None
    reported_sources: Counter[int] | None = None

    def __post_init__(self) -> None:
        if self.reported_sources is None:
            self.reported_sources = Counter()


class RealtimeMediaSessionAnalyzer:
    """Bounded passive SIP/SDP/RTP/RTCP correlation.

    SIP identifiers remain hash-only. RTP sequence gaps and RTCP quality fields are
    capture evidence, not proof of end-to-end packet loss or media impairment.
    """

    def __init__(self) -> None:
        self._calls: dict[str, _SipCall] = {}
        self._rtp: dict[tuple[str, int | None, str, int | None, int], _RtpStream] = {}
        self._rtcp: dict[tuple[str, int | None, str, int | None, int], _RtcpSource] = {}
        self._call_limit_reached = False
        self._rtp_limit_reached = False
        self._rtcp_limit_reached = False
        self._orphan_sip_packets = 0
        self._malformed_rtcp_packets = 0

    def feed(self, packet: PacketRecord) -> None:
        for layer in _layers(packet):
            name = str(layer.get("name") or "").casefold()
            fields = _fields(layer)
            if name == "sip":
                self._feed_sip(packet, fields)
            elif name == "rtp":
                self._feed_rtp(packet, fields)
            elif name == "rtcp":
                self._feed_rtcp(packet, fields)

    def _feed_sip(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        call_id = str(fields.get("call_id_sha256") or "")
        if not call_id:
            self._orphan_sip_packets += 1
            return
        call = self._calls.get(call_id)
        if call is None:
            if len(self._calls) >= _MAX_CALLS:
                self._call_limit_reached = True
                return
            call = _SipCall(call_id)
            self._calls[call_id] = call
        timestamp = _epoch(packet.timestamp)
        if timestamp is not None:
            call.first_seen = timestamp if call.first_seen is None else min(call.first_seen, timestamp)
            call.last_seen = timestamp if call.last_seen is None else max(call.last_seen, timestamp)
        call.packets += 1
        endpoints = call.endpoints
        assert endpoints is not None
        if len(endpoints) < _MAX_CALL_ENDPOINTS:
            endpoints.add(_endpoint(packet.source, packet.source_port))
            endpoints.add(_endpoint(packet.destination, packet.destination_port))
        requests = call.requests
        responses = call.responses
        assert requests is not None and responses is not None
        if bool(fields.get("response")):
            try:
                status = int(fields.get("status_code") or 0)
            except (TypeError, ValueError, OverflowError):
                status = 0
            if status:
                responses[status] += 1
        else:
            method = str(fields.get("method") or fields.get("cseq_method") or "").upper()
            if method:
                requests[method] += 1
        sdp = fields.get("sdp")
        if isinstance(sdp, Mapping):
            self._feed_sdp(call, sdp)

    def _feed_sdp(self, call: _SipCall, sdp: Mapping[str, Any]) -> None:
        call.sdp_observations += 1
        if bool(sdp.get("malformed")):
            call.malformed_sdp_observations += 1
        session_address = str(sdp.get("session_connection_address") or "")
        rows = sdp.get("media")
        if not isinstance(rows, list):
            return
        declared = call.declared_media
        assert declared is not None
        for raw in rows[:64]:
            if not isinstance(raw, Mapping):
                continue
            address = str(raw.get("connection_address") or session_address or "")
            try:
                port = int(raw.get("port"))
            except (TypeError, ValueError, OverflowError):
                continue
            endpoint = _media_endpoint(address, port)
            if not endpoint or (len(declared) >= _MAX_MEDIA_ENDPOINTS_PER_CALL and endpoint not in declared):
                continue
            rtcp_mux = bool(raw.get("rtcp_mux"))
            try:
                explicit_rtcp = int(raw.get("rtcp_port")) if raw.get("rtcp_port") is not None else None
            except (TypeError, ValueError, OverflowError):
                explicit_rtcp = None
            rtcp_endpoint = endpoint if rtcp_mux else _media_endpoint(address, explicit_rtcp if explicit_rtcp is not None else port + 1)
            codecs: set[str] = set()
            payload_types: set[int] = set()
            rtpmap = raw.get("rtpmap")
            if isinstance(rtpmap, list):
                for codec in rtpmap[:64]:
                    if not isinstance(codec, Mapping):
                        continue
                    encoding = str(codec.get("encoding") or "").casefold()
                    rate = codec.get("clock_rate")
                    channels = codec.get("channels")
                    if encoding:
                        suffix = f"/{rate}" if rate is not None else ""
                        suffix += f"/{channels}" if channels is not None else ""
                        codecs.add(encoding + suffix)
                    try:
                        payload_types.add(int(codec.get("payload_type")))
                    except (TypeError, ValueError, OverflowError):
                        record_current_exception(__name__, 'RealtimeMediaSessionAnalyzer._feed_sdp:303')
            formats = raw.get("formats")
            if isinstance(formats, list):
                for value in formats[:64]:
                    try:
                        payload_types.add(int(value))
                    except (TypeError, ValueError, OverflowError):
                        record_current_exception(__name__, 'RealtimeMediaSessionAnalyzer._feed_sdp:310')
            declared[endpoint] = _DeclaredMedia(
                endpoint=endpoint,
                rtcp_endpoint=rtcp_endpoint,
                media=str(raw.get("media") or ""),
                protocol=str(raw.get("protocol") or ""),
                direction=str(raw.get("direction") or ""),
                mid=str(raw.get("mid") or "")[:128],
                rtcp_mux=rtcp_mux,
                codecs=tuple(sorted(codecs)),
                payload_types=tuple(sorted(payload_types)),
            )

    def _feed_rtp(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        try:
            ssrc = int(fields.get("ssrc"))
            sequence = int(fields.get("sequence"))
        except (TypeError, ValueError, OverflowError):
            return
        key = (packet.source, packet.source_port, packet.destination, packet.destination_port, ssrc)
        stream = self._rtp.get(key)
        if stream is None:
            if len(self._rtp) >= _MAX_RTP_STREAMS:
                self._rtp_limit_reached = True
                return
            stream = _RtpStream(packet.source, packet.destination, packet.source_port, packet.destination_port, ssrc)
            self._rtp[key] = stream
        stream.packets += 1
        try:
            stream.media_payload_bytes += max(0, int(fields.get("payload_bytes") or 0))
        except (TypeError, ValueError, OverflowError):
            record_current_exception(__name__, 'RealtimeMediaSessionAnalyzer._feed_rtp:341')
        if bool(fields.get("marker")):
            stream.marker_packets += 1
        payload_types = stream.payload_types
        assert payload_types is not None
        try:
            payload_types[int(fields.get("payload_type"))] += 1
        except (TypeError, ValueError, OverflowError):
            record_current_exception(__name__, 'RealtimeMediaSessionAnalyzer._feed_rtp:349')
        csrcs = stream.csrcs
        assert csrcs is not None
        raw_csrcs = fields.get("csrcs")
        if isinstance(raw_csrcs, list):
            for value in raw_csrcs[:64]:
                if len(csrcs) >= 256:
                    break
                try:
                    csrcs.add(int(value))
                except (TypeError, ValueError, OverflowError):
                    continue
        state = stream.sequence
        assert state is not None
        state.observe(sequence)
        timestamp = _epoch(packet.timestamp)
        if timestamp is not None:
            stream.first_seen = timestamp if stream.first_seen is None else min(stream.first_seen, timestamp)
            stream.last_seen = timestamp if stream.last_seen is None else max(stream.last_seen, timestamp)

    def _feed_rtcp(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        if bool(fields.get("malformed")):
            self._malformed_rtcp_packets += 1
        rows = fields.get("compound_packets")
        if not isinstance(rows, list):
            return
        for row in rows[:64]:
            if not isinstance(row, Mapping):
                continue
            name = str(row.get("name") or "")
            try:
                reporter = int(row.get("ssrc"))
            except (TypeError, ValueError, OverflowError):
                reporter = 0
            if not reporter and name == "bye":
                sources = row.get("sources")
                if isinstance(sources, list) and sources:
                    try:
                        reporter = int(sources[0])
                    except (TypeError, ValueError, OverflowError):
                        reporter = 0
            if not reporter:
                continue
            key = (packet.source, packet.source_port, packet.destination, packet.destination_port, reporter)
            source = self._rtcp.get(key)
            if source is None:
                if len(self._rtcp) >= _MAX_RTCP_SOURCES:
                    self._rtcp_limit_reached = True
                    return
                source = _RtcpSource(reporter)
                self._rtcp[key] = source
            source.packets += 1
            if name == "sender-report":
                source.sender_reports += 1
            elif name == "receiver-report":
                source.receiver_reports += 1
            elif name == "bye":
                source.bye_observations += 1
            reports = row.get("reports")
            if not isinstance(reports, list):
                continue
            reported_sources = source.reported_sources
            assert reported_sources is not None
            for report in reports[:64]:
                if not isinstance(report, Mapping):
                    continue
                source.report_blocks += 1
                try:
                    target_ssrc = int(report.get("source_ssrc"))
                    reported_sources[target_ssrc] += 1
                except (TypeError, ValueError, OverflowError):
                    record_current_exception(__name__, 'RealtimeMediaSessionAnalyzer._feed_rtcp:420')
                try:
                    ratio = float(report.get("fraction_lost_ratio") or 0.0)
                    source.fraction_lost_sum += ratio
                    source.fraction_lost_samples += 1
                    source.fraction_lost_max = max(source.fraction_lost_max, ratio)
                except (TypeError, ValueError, OverflowError):
                    record_current_exception(__name__, 'RealtimeMediaSessionAnalyzer._feed_rtcp:427')
                try:
                    jitter = int(report.get("interarrival_jitter") or 0)
                    source.jitter_latest = jitter
                    source.jitter_max = max(source.jitter_max, jitter)
                except (TypeError, ValueError, OverflowError):
                    record_current_exception(__name__, 'RealtimeMediaSessionAnalyzer._feed_rtcp:433')
                try:
                    cumulative = int(report.get("cumulative_packets_lost"))
                    source.cumulative_lost_max = cumulative if source.cumulative_lost_max is None else max(source.cumulative_lost_max, cumulative)
                except (TypeError, ValueError, OverflowError):
                    record_current_exception(__name__, 'RealtimeMediaSessionAnalyzer._feed_rtcp:438')

    def _declared_media_index(self) -> tuple[set[str], set[str], dict[str, set[int]]]:
        rtp_endpoints: set[str] = set()
        rtcp_endpoints: set[str] = set()
        payloads: dict[str, set[int]] = {}
        for call in self._calls.values():
            declared = call.declared_media
            assert declared is not None
            for row in declared.values():
                rtp_endpoints.add(row.endpoint)
                if row.rtcp_endpoint:
                    rtcp_endpoints.add(row.rtcp_endpoint)
                payloads.setdefault(row.endpoint, set()).update(row.payload_types)
        return rtp_endpoints, rtcp_endpoints, payloads

    def _call_rows(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for call in sorted(self._calls.values(), key=lambda item: item.call_id_sha256):
            requests, responses, endpoints, declared = call.requests, call.responses, call.endpoints, call.declared_media
            assert requests is not None and responses is not None and endpoints is not None and declared is not None
            duration = None
            if call.first_seen is not None and call.last_seen is not None and call.last_seen >= call.first_seen:
                duration = round(call.last_seen - call.first_seen, 6)
            rows.append({
                "call_id_sha256": call.call_id_sha256, "call_id_retained": False, "sip_packets": call.packets,
                "duration_seconds_observed": duration, "request_methods": dict(requests.most_common()),
                "response_statuses": {str(key): value for key, value in sorted(responses.items())},
                "signaling_endpoints": sorted(endpoints), "sdp_observations": call.sdp_observations,
                "malformed_sdp_observations": call.malformed_sdp_observations,
                "declared_media": [row.as_dict() for row in sorted(declared.values(), key=lambda item: item.endpoint)],
            })
        return rows

    def _rtp_rows(self, declared: set[str], payload_index: dict[str, set[int]]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        ordering = lambda item: (item.source, item.source_port or -1, item.destination, item.destination_port or -1, item.ssrc)
        for stream in sorted(self._rtp.values(), key=ordering):
            sequence, payload_types, csrcs = stream.sequence, stream.payload_types, stream.csrcs
            assert sequence is not None and payload_types is not None and csrcs is not None
            source = _media_endpoint(stream.source, stream.source_port)
            destination = _media_endpoint(stream.destination, stream.destination_port)
            declared_for_path = payload_index.get(source, set()) | payload_index.get(destination, set())
            observed_types = set(payload_types)
            rows.append({
                "source": source or stream.source, "destination": destination or stream.destination, "ssrc": stream.ssrc,
                "packets": stream.packets, "media_payload_bytes": stream.media_payload_bytes, "marker_packets": stream.marker_packets,
                "payload_type_counts": {str(key): value for key, value in sorted(payload_types.items())},
                "payload_type_change_evidence": len(observed_types) > 1, "csrcs": sorted(csrcs),
                "highest_extended_sequence_observed": sequence.highest_extended, "duplicate_sequence_observations": sequence.duplicate,
                "out_of_order_sequence_observations": sequence.out_of_order, "forward_sequence_gap_packets": sequence.forward_gap_packets,
                "sequence_wrap_observations": sequence.wrap_observations, "possible_capture_loss_evidence": sequence.forward_gap_packets > 0,
                "sdp_endpoint_match": source in declared or destination in declared,
                "sdp_payload_type_match": bool(declared_for_path & observed_types) if declared_for_path else None,
            })
        return rows

    def _rtcp_rows(self, declared: set[str]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for key, source in sorted(self._rtcp.items(), key=lambda item: item[0]):
            src, src_port, dst, dst_port, reporter = key
            reports = source.reported_sources
            assert reports is not None
            source_endpoint, destination_endpoint = _media_endpoint(src, src_port), _media_endpoint(dst, dst_port)
            average_loss = round(source.fraction_lost_sum / source.fraction_lost_samples, 6) if source.fraction_lost_samples else None
            rows.append({
                "source": source_endpoint or src, "destination": destination_endpoint or dst, "reporter_ssrc": reporter,
                "packets": source.packets, "sender_reports": source.sender_reports, "receiver_reports": source.receiver_reports,
                "bye_observations": source.bye_observations, "report_blocks": source.report_blocks,
                "reported_sources": {str(key): value for key, value in reports.most_common(128)},
                "fraction_lost_ratio_average_reported": average_loss,
                "fraction_lost_ratio_max_reported": round(source.fraction_lost_max, 6) if source.fraction_lost_samples else None,
                "cumulative_packets_lost_max_reported": source.cumulative_lost_max,
                "interarrival_jitter_latest_reported": source.jitter_latest if source.report_blocks else None,
                "interarrival_jitter_max_reported": source.jitter_max if source.report_blocks else None,
                "sdp_rtcp_endpoint_match": source_endpoint in declared or destination_endpoint in declared,
            })
        return rows

    def finalize(self) -> dict[str, Any]:
        rtp_declared, rtcp_declared, declared_payloads = self._declared_media_index()
        calls, streams, rtcp_rows = self._call_rows(), self._rtp_rows(rtp_declared, declared_payloads), self._rtcp_rows(rtcp_declared)
        return {
            "schema": "arenyxa.realtime-media-forensics/v1", "sip_call_count": len(calls), "rtp_stream_count": len(streams),
            "rtcp_source_count": len(rtcp_rows), "call_limit_reached": self._call_limit_reached,
            "rtp_stream_limit_reached": self._rtp_limit_reached, "rtcp_source_limit_reached": self._rtcp_limit_reached,
            "orphan_sip_packets": self._orphan_sip_packets, "malformed_rtcp_packets": self._malformed_rtcp_packets,
            "calls": calls, "rtp_streams": streams, "rtcp_sources": rtcp_rows,
            "sensitive_identity_material_retained": False, "media_payload_retained": False,
            "interpretation": (
                "RTP sequence gaps, duplicates, reordering and RTCP loss/jitter fields are passive capture evidence. "
                "Capture drops, duplicated frames, asymmetric capture paths, retransmission at lower layers, codec clock rates "
                "and endpoint reporting semantics must be considered before concluding end-to-end media impairment."
            ),
        }
