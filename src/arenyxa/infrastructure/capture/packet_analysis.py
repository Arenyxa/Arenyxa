from __future__ import annotations
from arenyxa.infrastructure.capture.packet_analysis_native import PacketAnalysisNativeMixin
from arenyxa.recoverable import record_current_exception

import json
from collections import Counter
import shutil
from pathlib import Path
from typing import Any, Iterable, Sequence

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import CaptureSession, NetworkEvent
from arenyxa.infrastructure.capture.protocol_intelligence import ProtocolIntelligenceEngine
from arenyxa.infrastructure.capture.native_capture import NativeCaptureReader, NativeCapturePacket
from arenyxa.infrastructure.capture.packet_runtime import PacketRuntimeMixin
from arenyxa.infrastructure.capture.packet_forensics import PacketForensicsMixin
from arenyxa.infrastructure.capture.packet_row_projection import PacketRowProjectionMixin
from arenyxa.infrastructure.capture.tcp_reassembly import TcpReassemblyManager
from arenyxa.infrastructure.capture.protocol_registry import DynamicProtocolRegistry, ProtocolField, global_protocol_registry
from arenyxa.infrastructure.capture.packet_analysis_constants import PACKET_SUMMARY_FIELDS
from arenyxa.infrastructure.external_tools import ExternalToolProbe, ExternalToolCapability
from arenyxa.infrastructure.capture.packet_models import (
    PacketCaptureInfo,
    PacketExecutionProfile,
    PacketRecord,
    PacketStatistics,
    PacketToolCapabilities,
)

class PacketAnalysisEngine(PacketAnalysisNativeMixin, PacketRowProjectionMixin, PacketForensicsMixin, PacketRuntimeMixin):
    """Combine Arenyxa native decoding with an optional deep external dissector runtime."""
    SUMMARY_FIELDS = PACKET_SUMMARY_FIELDS
    FOLLOW_PROTOCOLS = {"tcp", "udp", "dccp", "tls", "dtls", "http", "http2", "quic", "mp2t", "mpeg-pes"}
    FOLLOW_MODES = {"ascii", "ebcdic", "hex", "raw", "utf-8", "yaml"}
    CONVERSATION_TYPES = {
        "bluetooth", "bpv7", "dccp", "dnp3", "eth", "fc", "fddi", "ip", "ipv6", "ipx", "jxta",
        "ltp", "mptcp", "ncp", "openSAFETY", "rsvp", "sctp", "sll", "tcp", "tr", "udp", "usb",
        "wlan", "wpan", "zbee_nwk",
    }
    OUTPUT_FORMATS = {"ek", "fields", "json", "jsonraw", "pdml", "psml", "tabs", "text"}
    TOOL_NAMES = ("tshark", "dumpcap", "capinfos", "editcap", "mergecap", "reordercap", "text2pcap", "rawshark", "sharkd")

    def __init__(self, executable: str | None = None, timeout_seconds: float = 90.0) -> None:
        self.executable = executable or shutil.which("tshark") or ""
        self.timeout_seconds = max(1.0, float(timeout_seconds))
        self._supported_field_cache: set[str] | None = None
        self._external_runtime_failed = False
        self._external_capability: ExternalToolCapability | None = None

    def _tool_capability(self) -> ExternalToolCapability:
        cached = self._external_capability
        if cached is not None:
            return cached
        capability = ExternalToolProbe.tshark(
            executable=self.executable or None,
            required_fields=("frame.number", "frame.time_epoch", "frame.len", "frame.protocols"),
        )
        self._external_capability = capability
        if capability.executable:
            self.executable = capability.executable
        return capability

    @property
    def available(self) -> bool:
        """Return whether an external runtime candidate exists and has not failed.

        Compatibility is enforced immediately before subprocess execution by the runtime
        bridge.  Keeping discovery separate from execution preserves injectable test and
        embedded adapters while still preventing an incompatible binary from running.
        """
        return bool(self.executable) and not bool(self._external_runtime_failed)

    def capabilities(self) -> PacketToolCapabilities:
        """Return native and optional external packet-analysis capability metadata."""
        native_protocols = [row["protocol"] for row in ProtocolIntelligenceEngine().protocol_catalog()]
        if not self.available:
            return PacketToolCapabilities(
                available=False,
                capture_formats=["pcap", "pcapng"],
                native_protocol_count=len(native_protocols),
                native_protocols=native_protocols,
            )
        try:
            version_output = self._run_tshark(["-v"], timeout=15)
            version = version_output.splitlines()[0].strip() if version_output.strip() else ""
            protocols = self.glossary("protocols")
            fields = self.glossary("fields")
            tools = {name: str(shutil.which(name) or "") for name in self.TOOL_NAMES}
            tools = {key: value for key, value in tools.items() if value}
            return PacketToolCapabilities(
                available=True, tshark=self.executable, version=version, tools=tools,
                interfaces=self.interfaces(), protocol_count=len(protocols), field_count=len(fields),
                object_exporters=self.object_exporters(), capture_formats=self.capture_formats(),
                native_protocol_count=len(native_protocols), native_protocols=native_protocols,
            )
        except ArenyxaError:
            self._external_runtime_failed = True
            return PacketToolCapabilities(
                available=False, capture_formats=["pcap", "pcapng"],
                native_protocol_count=len(native_protocols), native_protocols=native_protocols,
            )

    @staticmethod
    def native_protocol_catalog() -> list[dict[str, Any]]:
        """Return the protocols decoded directly by the Arenyxa native core."""
        return ProtocolIntelligenceEngine().protocol_catalog()

    @staticmethod
    def decode_raw_frame(frame: bytes | bytearray | memoryview, *, link_type: str = "ethernet") -> Any:
        """Decode one bounded raw frame with the native link and protocol stack."""
        return ProtocolIntelligenceEngine().decode_frame(frame, link_type=link_type)

    def unified_protocol_registry(self, *, include_external: bool = True, field_limit: int = 100_000) -> DynamicProtocolRegistry:
        """Populate and return the process-wide runtime protocol/field registry.

        Native metadata is always available. When TShark is installed, its protocol and
        field glossary is imported dynamically so callers no longer depend on a static
        field list for discovery.
        """
        registry = global_protocol_registry()
        registry.import_native_catalog(self.native_protocol_catalog())
        for abbreviation in self.SUMMARY_FIELDS:
            protocol = abbreviation.split(".", 1)[0].casefold() if "." in abbreviation else "frame"
            registry.register_field(
                ProtocolField(
                    abbreviation=abbreviation,
                    name=abbreviation,
                    field_type="normalized",
                    protocol=protocol,
                    description="Arenyxa normalized packet field",
                    source="arenyxa-core",
                ),
                replace=False,
            )
        if include_external and self.available:
            registry.import_external_catalog(
                self.protocol_catalog(),
                self.field_catalog(limit=max(1, min(100_000, int(field_limit)))),
                source="tshark",
            )
        return registry

    def unified_protocol_catalog(self, *, contains: str = "", limit: int = 5000) -> list[dict[str, Any]]:
        return self.unified_protocol_registry().protocols(contains=contains, limit=limit)

    def unified_field_catalog(
        self, *, contains: str = "", protocol: str = "", limit: int = 5000
    ) -> list[dict[str, str]]:
        return self.unified_protocol_registry(field_limit=max(limit, 5000)).fields(
            contains=contains, protocol=protocol, limit=limit
        )

    def packet_summaries(
        self,
        capture: Path | str,
        display_filter: str = "",
        limit: int = 20_000,
        profile: PacketExecutionProfile | None = None,
    ) -> list[PacketRecord]:
        """Return bounded normalized packet summaries for a capture file."""
        if not self.available:
            if display_filter:
                raise ArenyxaError(
                    "PACKET_NATIVE_FILTER_UNSUPPORTED",
                    "Native packet fallback does not implement display-filter expressions; install the external dissector runtime for filter evaluation.",
                    domain="CAPTURE",
                )
            return list(self._iter_native_packet_summaries(capture, limit=limit))
        path = self._capture_path(capture)
        try:
            supported = self._supported_fields()
        except ArenyxaError:
            if display_filter:
                raise
            return list(self._iter_native_packet_summaries(capture, limit=limit))
        fields = tuple(field for field in self.SUMMARY_FIELDS if field in supported)
        args = self._base_read_args(path, profile)
        args.extend(["-T", "fields", "-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=a", "-E", "aggregator=,"])
        for name in fields:
            args.extend(["-e", name])
        bounded_limit = min(max(0, int(limit)), 1_000_000)
        if bounded_limit > 0:
            args.extend(["-c", str(bounded_limit)])
        if display_filter:
            args.extend(["-Y", display_filter])
        try:
            output = self._run_tshark(args, timeout=max(self.timeout_seconds, 120.0))
        except ArenyxaError:
            if display_filter:
                raise
            return list(self._iter_native_packet_summaries(capture, limit=limit))
        packets: list[PacketRecord] = []
        for line in output.splitlines():
            values = [self._unquote(value) for value in line.split("\t")]
            values.extend([""] * (len(fields) - len(values)))
            packet = self._packet_from_row(dict(zip(fields, values)))
            if packet is not None:
                packets.append(packet)
        return packets

    def iter_packet_summaries(
        self,
        capture: Path | str,
        display_filter: str = "",
        limit: int = 200_000,
        profile: PacketExecutionProfile | None = None,
    ) -> Iterable[PacketRecord]:
        """Stream normalized packet summaries without loading the complete capture into memory."""
        if not self.available:
            if display_filter:
                raise ArenyxaError(
                    "PACKET_NATIVE_FILTER_UNSUPPORTED",
                    "Native packet fallback does not implement display-filter expressions; install the external dissector runtime for filter evaluation.",
                    domain="CAPTURE",
                )
            yield from self._iter_native_packet_summaries(capture, limit=limit)
            return
        path = self._capture_path(capture)
        try:
            supported = self._supported_fields()
        except ArenyxaError:
            if display_filter:
                raise
            yield from self._iter_native_packet_summaries(capture, limit=limit)
            return
        fields = tuple(field for field in self.SUMMARY_FIELDS if field in supported)
        args = self._base_read_args(path, profile)
        args.extend(["-T", "fields", "-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=a", "-E", "aggregator=,"])
        for name in fields:
            args.extend(["-e", name])
        bounded_limit = min(max(0, int(limit)), 1_000_000)
        if bounded_limit > 0:
            args.extend(["-c", str(bounded_limit)])
        if display_filter:
            args.extend(["-Y", display_filter])
        timeout = max(self.timeout_seconds, 120.0)
        yielded = 0
        try:
            for line in self._iter_tshark_lines(args, timeout=timeout):
                values = [self._unquote(value) for value in line.split("\t")]
                values.extend([""] * (len(fields) - len(values)))
                packet = self._packet_from_row(dict(zip(fields, values)))
                if packet is not None:
                    yielded += 1
                    yield packet
        except ArenyxaError:
            if display_filter or yielded:
                raise
            yield from self._iter_native_packet_summaries(capture, limit=limit)

    def packet_tree(
        self,
        capture: Path | str,
        frame_number: int,
        profile: PacketExecutionProfile | None = None,
        include_raw: bool = True,
    ) -> dict[str, Any]:
        """Return a structured protocol tree for one capture frame."""
        if not self.available:
            target = int(frame_number)
            for packet in NativeCaptureReader().iter_packets(capture, limit=max(1, target)):
                if packet.frame_number == target:
                    decoded = ProtocolIntelligenceEngine().decode_frame(
                        packet.data, link_type=self._native_link_type(packet.link_type)
                    )
                    return self._native_decode_dict(packet, decoded, include_raw=include_raw)
            return {}
        path = self._capture_path(capture)
        args = self._base_read_args(path, profile)
        args.extend(["-Y", f"frame.number == {int(frame_number)}", "-T", "json", "--no-duplicate-keys"])
        if include_raw:
            args.append("-x")
        output = self._run_tshark(args)
        decoded = json.loads(output or "[]")
        return decoded[0] if isinstance(decoded, list) and decoded else {}

    def packet_text(
        self,
        capture: Path | str,
        frame_number: int,
        profile: PacketExecutionProfile | None = None,
    ) -> str:
        """Render one packet as bounded human-readable protocol text."""
        if not self.available:
            return json.dumps(self.packet_tree(capture, frame_number, profile, include_raw=True), ensure_ascii=False, indent=2, default=str)
        path = self._capture_path(capture)
        args = self._base_read_args(path, profile)
        args.extend(["-Y", f"frame.number == {int(frame_number)}", "-V", "-x"])
        return self._run_tshark(args)

    def filtered_packets_json(
        self,
        capture: Path | str,
        display_filter: str = "",
        limit: int = 5000,
        protocols: Sequence[str] = (),
        profile: PacketExecutionProfile | None = None,
        include_raw: bool = False,
    ) -> list[dict[str, Any]]:
        """Return bounded packet JSON matching a display filter."""
        if not self.available:
            if display_filter:
                raise ArenyxaError(
                    "PACKET_NATIVE_FILTER_UNSUPPORTED",
                    "Native packet fallback does not implement display-filter expressions.",
                    domain="CAPTURE",
                )
            requested = {str(item).strip().casefold() for item in protocols if str(item).strip()}
            rows: list[dict[str, Any]] = []
            for packet in NativeCaptureReader().iter_packets(capture, limit=min(max(0, int(limit)), 1_000_000)):
                decoded = ProtocolIntelligenceEngine().decode_frame(packet.data, link_type=self._native_link_type(packet.link_type))
                names = {layer.name.casefold() for layer in decoded.layers}
                if requested and not requested.intersection(names):
                    continue
                rows.append(self._native_decode_dict(packet, decoded, include_raw=include_raw))
            return rows
        path = self._capture_path(capture)
        args = self._base_read_args(path, profile)
        args.extend(["-T", "json", "--no-duplicate-keys"])
        if protocols:
            args.extend(["-J", " ".join(str(item) for item in protocols if str(item).strip())])
        if include_raw:
            args.append("-x")
        if limit > 0:
            args.extend(["-c", str(int(limit))])
        if display_filter:
            args.extend(["-Y", display_filter])
        output = self._run_tshark(args, timeout=max(self.timeout_seconds, 120.0))
        decoded = json.loads(output or "[]")
        return decoded if isinstance(decoded, list) else []

    def protocol_coverage(self) -> dict[str, Any]:
        """Report graded native coverage plus all dynamically discovered external dissectors."""
        native = ProtocolIntelligenceEngine().protocol_catalog()
        external = self.protocol_catalog() if self.available else []
        external_names = {
            str(row.get("filter_name") or row.get("short_name") or row.get("name") or "").casefold()
            for row in external
            if str(row.get("filter_name") or row.get("short_name") or row.get("name") or "").strip()
        }
        native_names = {str(row.get("protocol") or "").casefold() for row in native}
        native_deep = {str(row.get("protocol") or "").casefold() for row in native if row.get("mode") == "native-deep"}
        native_metadata = native_names - native_deep
        return {
            "native_protocol_count": len(native_names),
            "native_deep_count": len(native_deep),
            "native_metadata_count": len(native_metadata),
            "external_protocol_count": len(external_names),
            "combined_protocol_count": len(native_names | external_names),
            "native_protocols": sorted(native_names),
            "native_deep_protocols": sorted(native_deep),
            "stream_deep_decoders": [
                "http2+hpack+grpc+doh", "http3-decrypted-stream", "websocket-rfc6455",
                "doh-application-dns-message", "doq-decrypted-stream",
                "tls-clienthello+serverhello+tls12-certificate", "quic-v1-v2-public-initial",
                "tcp-conversation-state", "tls-handshake-session", "quic-cid-path-session",
                "ikev2-ipsec-session", "wireguard-handshake-transport-session", "l2tpv2-control-avp",
                "gtpv2-control+gtpv1u-tunnel-correlation", "gtpv2+pfcp+gtpv1u-mobile-core-correlation", "l2tp-tunnel-session-state", "coap-token-blockwise-session", "stun-ice-turn-transaction-session", "bacnet-transaction-bbmd-session", "opcua-securechannel-session",
            ],
            "coverage_model": {
                "native-deep": "Arenyxa bounded structural/state-aware decoder",
                "structured-metadata": "Arenyxa bounded protocol metadata decoder",
                "external-deep": "dynamically discovered external dissector runtime",
            },
            "external_available": self.available,
        }

    def fuse_passive_evidence(
        self,
        capture: Path | str | None = None,
        *,
        display_filter: str = "",
        profile: PacketExecutionProfile | None = None,
        zeek_json_paths: Sequence[Path | str] = (),
        suricata_eve_path: Path | str | None = None,
    ) -> dict[str, Any]:
        """Fuse Arenyxa packet evidence with operator-supplied Zeek/Suricata JSON evidence."""
        from arenyxa.infrastructure.capture.passive_evidence import fuse_passive_evidence

        packet = None
        if capture is not None:
            packet = self.forensic_summary(capture, display_filter=display_filter, limit=200_000, profile=profile)
        return fuse_passive_evidence(
            packet_forensics=packet, zeek_json_paths=zeek_json_paths, suricata_eve_path=suricata_eve_path,
        )

    def extract_fields(
        self,
        capture: Path | str,
        fields: Sequence[str],
        *,
        display_filter: str = "",
        limit: int = 20_000,
        profile: PacketExecutionProfile | None = None,
    ) -> list[dict[str, str]]:
        """Extract selected protocol fields from bounded capture records."""
        path = self._capture_path(capture)
        supported = self._supported_fields()
        requested: list[str] = []
        for raw_name in fields:
            name = str(raw_name).strip()
            if not name or name not in supported:
                raise ValueError(f"unsupported packet field: {name}")
            if name not in requested:
                requested.append(name)
        if not requested:
            raise ValueError("at least one packet field is required")
        if len(requested) > 256:
            raise ValueError("packet field extraction is limited to 256 fields")
        args = self._base_read_args(path, profile)
        args.extend(["-T", "fields", "-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=a", "-E", "aggregator=,"])
        for name in requested:
            args.extend(["-e", name])
        if limit > 0:
            args.extend(["-c", str(min(int(limit), 1_000_000))])
        if display_filter:
            args.extend(["-Y", str(display_filter)])
        output = self._run_tshark(args, timeout=max(self.timeout_seconds, 120.0))
        rows: list[dict[str, str]] = []
        for line in output.splitlines():
            values = [self._unquote(value) for value in line.split("\t")]
            values.extend([""] * (len(requested) - len(values)))
            rows.append(dict(zip(requested, values)))
        return rows

    def full_statistics(self, capture: Path | str, display_filter: str = "", profile: PacketExecutionProfile | None = None) -> PacketStatistics:
        """Compute protocol, endpoint, conversation, flow, and expert statistics."""
        if not self.available:
            self._require_native_empty_filter(display_filter)
            snapshot = self._native_statistics_snapshot(capture)

            def encode(key: str) -> str:
                return json.dumps(snapshot.get(key, {}), ensure_ascii=False, indent=2, sort_keys=True)

            return PacketStatistics(
                protocol_hierarchy=encode("protocol_hierarchy"),
                conversations=encode("conversations"),
                endpoints=encode("endpoints"),
                expert=encode("expert"),
                io_graph=encode("io_graph"),
                packet_lengths=encode("packet_lengths"),
                flow_graph=encode("flow_graph"),
                service_statistics=encode("service_statistics"),
                rtp_streams=encode("rtp_streams"),
            )
        try:
            return PacketStatistics(
                protocol_hierarchy=self.protocol_hierarchy(capture, display_filter, profile),
                conversations=self.conversations(capture, display_filter=display_filter, profile=profile),
                endpoints=self.endpoints(capture, display_filter=display_filter, profile=profile),
                expert=self.expert_information(capture, display_filter, profile=profile),
                io_graph=self.io_statistics(capture, 1.0, (display_filter,) if display_filter else (), profile),
                packet_lengths=self.packet_length_statistics(capture, display_filter, profile),
                flow_graph=self.flow_graph(capture, display_filter=display_filter, profile=profile),
                service_statistics=self.service_statistics(capture, display_filter, profile),
                rtp_streams=self.rtp_streams(capture, profile),
            )
        except ArenyxaError:
            if display_filter:
                raise
            self._external_runtime_failed = True
            snapshot = self._native_statistics_snapshot(capture)
            def encode(key: str) -> str:
                return json.dumps(snapshot.get(key, {}), ensure_ascii=False, indent=2, sort_keys=True)
            return PacketStatistics(
                protocol_hierarchy=encode("protocol_hierarchy"), conversations=encode("conversations"),
                endpoints=encode("endpoints"), expert=encode("expert"), io_graph=encode("io_graph"),
                packet_lengths=encode("packet_lengths"), flow_graph=encode("flow_graph"),
                service_statistics=encode("service_statistics"), rtp_streams=encode("rtp_streams"),
            )

    def capture_info(self, capture: Path | str) -> PacketCaptureInfo:
        """Read capture format, link-layer, timing, and packet-count metadata."""
        source = self._capture_path(capture)
        executable = shutil.which("capinfos")
        if executable:
            completed = self._run_process([executable, "-M", "-A", str(source)], timeout=60, check=True)
            return PacketCaptureInfo(path=str(source), output=completed.stdout or "")
        if not self.available:
            info = NativeCaptureReader().inspect(source)
            return PacketCaptureInfo(
                path=str(source),
                output=json.dumps({
                    "backend": "arenyxa-native",
                    "format": info.format,
                    "file_size": info.file_size,
                    "packet_count": info.packet_count,
                    "captured_bytes": info.captured_bytes,
                    "original_bytes": info.original_bytes,
                    "first_timestamp_epoch": info.first_timestamp_epoch,
                    "last_timestamp_epoch": info.last_timestamp_epoch,
                    "link_types": list(info.link_types),
                    "truncated": info.truncated,
                }, ensure_ascii=False, indent=2),
            )
        output = self._run_tshark(["-n", "-r", str(source), "-q", "-z", "io,stat,0"], timeout=90)
        return PacketCaptureInfo(path=str(source), output=output)

    def to_network_events(
        self,
        capture: Path | str,
        session: CaptureSession,
        display_filter: str = "",
        limit: int = 200_000,
        profile: PacketExecutionProfile | None = None,
    ) -> list[NetworkEvent]:
        """Convert bounded packet summaries into Arenyxa network events."""
        capture_path = self._capture_path(capture)
        return [
            self._network_event_from_packet(packet, session, capture_path)
            for packet in self.packet_summaries(
                capture_path,
                display_filter=display_filter,
                limit=limit,
                profile=profile,
            )
        ]

    def iter_network_events(
        self,
        capture: Path | str,
        session: CaptureSession,
        display_filter: str = "",
        limit: int = 1_000_000,
        profile: PacketExecutionProfile | None = None,
    ) -> Iterable[NetworkEvent]:
        """Stream Arenyxa network events for large capture imports."""
        capture_path = self._capture_path(capture)
        for packet in self.iter_packet_summaries(
            capture_path,
            display_filter=display_filter,
            limit=limit,
            profile=profile,
        ):
            yield self._network_event_from_packet(packet, session, capture_path)


    def _iter_native_packet_summaries(self, capture: Path | str, *, limit: int) -> Iterable[PacketRecord]:
        reader = NativeCaptureReader()
        decoder = ProtocolIntelligenceEngine()
        tcp_state: dict[tuple[str, int, str, int], int] = {}
        reassembly = TcpReassemblyManager()
        for packet in reader.iter_packets(capture, limit=min(max(0, int(limit)), 1_000_000)):
            decoded = decoder.decode_frame(packet.data, link_type=self._native_link_type(packet.link_type))
            analysis = self._native_tcp_analysis(decoded, tcp_state)
            stream_probe = self._native_tcp_reassembly(packet, decoded, decoder, reassembly)
            record = self._native_packet_record(packet, decoded, tcp_analysis=analysis)
            if stream_probe:
                record.metadata["native_tcp_reassembly"] = stream_probe
                application = str(stream_probe.get("application_protocol") or "")
                if application and application not in {part.casefold() for part in record.protocols.split(":") if part}:
                    record.protocols = f"{record.protocols}:{application}" if record.protocols else application
                if application and record.protocol.casefold() in {"", "unknown", "tcp"}:
                    record.protocol = application
                if application and f"reassembled:{application}" not in record.info:
                    record.info = " / ".join(part for part in (record.info, f"reassembled:{application}") if part)
            yield record








