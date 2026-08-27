from __future__ import annotations

from arenyxa.infrastructure.process_safety import validated_argv
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from dataclasses import field

from arenyxa.compat import dataclass
from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import CaptureSession, NetworkEvent
from arenyxa.infrastructure.capture.adapters import TsharkPacketAdapter


@dataclass(slots=True)
class PacketExecutionProfile:
    configuration_profile: str = ""
    decode_as: tuple[str, ...] = ()
    preferences: dict[str, str] = field(default_factory=dict)
    name_resolution: str = ""
    keytab: str = ""
    tls_keylog: str = ""
    enabled_protocols: tuple[str, ...] = ()
    disabled_protocols: tuple[str, ...] = ()
    enabled_heuristics: tuple[str, ...] = ()
    disabled_heuristics: tuple[str, ...] = ()


@dataclass(slots=True)
class PacketToolCapabilities:
    available: bool
    tshark: str = ""
    version: str = ""
    tools: dict[str, str] = field(default_factory=dict)
    interfaces: list[str] = field(default_factory=list)
    protocol_count: int = 0
    field_count: int = 0
    object_exporters: list[str] = field(default_factory=list)
    capture_formats: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PacketRecord:
    frame_number: int
    timestamp: str
    length: int
    captured_length: int
    protocols: str
    protocol: str
    info: str
    source: str
    destination: str
    source_port: int | None
    destination_port: int | None
    tcp_stream: int | None
    udp_stream: int | None
    http2_stream: int | None
    quic_stream: int | None
    host: str
    method: str
    uri: str
    status: int | None
    tcp_analysis: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PacketStatistics:
    protocol_hierarchy: str
    conversations: str
    endpoints: str
    expert: str
    io_graph: str
    packet_lengths: str
    flow_graph: str
    service_statistics: str
    rtp_streams: str


@dataclass(slots=True)
class PacketCaptureInfo:
    path: str
    output: str


class PacketAnalysisEngine:
    SUMMARY_FIELDS = (
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "frame.cap_len",
        "frame.protocols",
        "_ws.col.Protocol",
        "_ws.col.Info",
        "eth.src",
        "eth.dst",
        "ip.src",
        "ip.dst",
        "ipv6.src",
        "ipv6.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "tcp.stream",
        "udp.stream",
        "http2.streamid",
        "quic.stream.stream_id",
        "dns.qry.name",
        "tls.handshake.extensions_server_name",
        "http.request.method",
        "http.host",
        "http.request.uri",
        "http.response.code",
        "tcp.analysis.retransmission",
        "tcp.analysis.fast_retransmission",
        "tcp.analysis.spurious_retransmission",
        "tcp.analysis.out_of_order",
        "tcp.analysis.lost_segment",
        "tcp.analysis.duplicate_ack",
        "tcp.analysis.zero_window",
        "tcp.analysis.window_full",
        "tcp.analysis.keep_alive",
        "tcp.analysis.bytes_in_flight",
        "tcp.analysis.ack_rtt",
    )
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

    @property
    def available(self) -> bool:
        return bool(self.executable)

    def capabilities(self) -> PacketToolCapabilities:
        if not self.available:
            return PacketToolCapabilities(available=False)
        version_output = self._run_tshark(["-v"], timeout=15)
        version = version_output.splitlines()[0].strip() if version_output.strip() else ""
        protocols = self.glossary("protocols")
        fields = self.glossary("fields")
        tools = {name: str(shutil.which(name) or "") for name in self.TOOL_NAMES}
        tools = {key: value for key, value in tools.items() if value}
        return PacketToolCapabilities(
            available=True,
            tshark=self.executable,
            version=version,
            tools=tools,
            interfaces=self.interfaces(),
            protocol_count=len(protocols),
            field_count=len(fields),
            object_exporters=self.object_exporters(),
            capture_formats=self.capture_formats(),
        )

    def interfaces(self) -> list[str]:
        if not self.available:
            return []
        output = self._run_tshark(["-D"], timeout=20)
        return [line.strip() for line in output.splitlines() if line.strip()]

    def glossary(self, kind: str) -> list[str]:
        allowed = {"protocols", "fields", "values", "folders", "heuristic-decodes", "currentprefs", "defaultprefs"}
        if kind not in allowed:
            raise ValueError(f"unsupported glossary: {kind}")
        output = self._run_tshark(["-G", kind], timeout=45)
        return [line for line in output.splitlines() if line.strip()]

    def protocol_catalog(self) -> list[dict[str, str]]:
        result: list[dict[str, str]] = []
        for line in self.glossary("protocols"):
            parts = line.split("\t")
            if len(parts) >= 3:
                result.append({"name": parts[0], "short_name": parts[1], "filter_name": parts[2]})
        return result

    def field_catalog(self, limit: int | None = None) -> list[dict[str, str]]:
        result: list[dict[str, str]] = []
        for line in self.glossary("fields"):
            parts = line.split("\t")
            if len(parts) >= 7 and parts[0] == "F":
                result.append({
                    "name": parts[1],
                    "abbreviation": parts[2],
                    "type": parts[3],
                    "protocol": parts[4],
                    "base": parts[5],
                    "description": parts[6],
                })
                if limit is not None and len(result) >= max(0, int(limit)):
                    break
        return result

    def object_exporters(self) -> list[str]:
        if not self.available:
            return []
        completed = self._run_process([self.executable, "--export-objects", "help"], timeout=20, check=False)
        text = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
        names: list[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            match = re.match(r"^([A-Za-z0-9_.+-]+)\s", stripped)
            if match:
                names.append(match.group(1))
        return sorted(set(names))

    def capture_formats(self) -> list[str]:
        if not self.available:
            return []
        completed = self._run_process([self.executable, "-F"], timeout=20, check=False)
        text = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
        result: list[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.casefold().startswith("tshark"):
                continue
            token = stripped.split()[0].strip()
            if re.fullmatch(r"[A-Za-z0-9_.+-]+", token):
                result.append(token)
        return sorted(set(result))

    def list_data_link_types(self, interface: str) -> list[str]:
        output = self._run_tshark(["-i", str(interface), "-L"], timeout=20)
        return [line.strip() for line in output.splitlines() if line.strip()]

    def packet_summaries(
        self,
        capture: Path | str,
        display_filter: str = "",
        limit: int = 20_000,
        profile: PacketExecutionProfile | None = None,
    ) -> list[PacketRecord]:
        path = self._capture_path(capture)
        supported = self._supported_fields()
        fields = tuple(field for field in self.SUMMARY_FIELDS if field in supported)
        args = self._base_read_args(path, profile)
        args.extend(["-T", "fields", "-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=a", "-E", "aggregator=,"])
        for name in fields:
            args.extend(["-e", name])
        if limit > 0:
            args.extend(["-c", str(int(limit))])
        if display_filter:
            args.extend(["-Y", display_filter])
        output = self._run_tshark(args, timeout=max(self.timeout_seconds, 120.0))
        packets: list[PacketRecord] = []
        for line in output.splitlines():
            values = [self._unquote(value) for value in line.split("\t")]
            values.extend([""] * (len(fields) - len(values)))
            row = dict(zip(fields, values))
            packet = self._packet_from_row(row)
            if packet is not None:
                packets.append(packet)
        return packets

    def packet_tree(
        self,
        capture: Path | str,
        frame_number: int,
        profile: PacketExecutionProfile | None = None,
        include_raw: bool = True,
    ) -> dict[str, Any]:
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

    def validate_display_filter(self, capture: Path | str, expression: str) -> tuple[bool, str]:
        path = self._capture_path(capture)
        completed = self._run_process(
            [self.executable, "-n", "-r", str(path), "-c", "1", "-Y", str(expression), "-T", "fields", "-e", "frame.number"],
            timeout=30,
            check=False,
        )
        return completed.returncode == 0, (completed.stderr or "").strip()

    def protocol_hierarchy(self, capture: Path | str, display_filter: str = "", profile: PacketExecutionProfile | None = None) -> str:
        return self._tap(capture, self._tap_filter("io,phs", display_filter), profile)

    def conversations(self, capture: Path | str, types: Sequence[str] = ("eth", "ip", "ipv6", "tcp", "udp"), display_filter: str = "", profile: PacketExecutionProfile | None = None) -> str:
        taps = [self._tap_filter(f"conv,{kind}", display_filter) for kind in types if kind in self.CONVERSATION_TYPES]
        return self._taps(capture, taps, profile)

    def endpoints(self, capture: Path | str, types: Sequence[str] = ("eth", "ip", "ipv6", "tcp", "udp"), display_filter: str = "", profile: PacketExecutionProfile | None = None) -> str:
        taps = [self._tap_filter(f"endpoints,{kind}", display_filter) for kind in types if kind in self.CONVERSATION_TYPES]
        return self._taps(capture, taps, profile)

    def expert_information(self, capture: Path | str, display_filter: str = "", minimum: str = "note", profile: PacketExecutionProfile | None = None) -> str:
        levels = {"error", "warn", "note", "chat", "comment"}
        level = minimum if minimum in levels else "note"
        tap = f"expert,{level}"
        if display_filter:
            tap = f"{tap},{display_filter}"
        return self._tap(capture, tap, profile)

    def io_statistics(self, capture: Path | str, interval: float = 1.0, filters: Sequence[str] = (), profile: PacketExecutionProfile | None = None) -> str:
        value = max(0.000001, float(interval))
        tap = f"io,stat,{value:g}"
        for expression in filters:
            if str(expression).strip():
                tap += f",{expression}"
        return self._tap(capture, tap, profile)

    def packet_length_statistics(self, capture: Path | str, display_filter: str = "", profile: PacketExecutionProfile | None = None) -> str:
        return self._tap(capture, self._tap_filter("plen,tree", display_filter), profile)

    def flow_graph(self, capture: Path | str, protocol: str = "tcp", address_mode: str = "network", display_filter: str = "", profile: PacketExecutionProfile | None = None) -> str:
        protocol_value = protocol if protocol in {"any", "icmp", "icmpv6", "lbm_uim", "tcp"} else "tcp"
        address_value = address_mode if address_mode in {"standard", "network"} else "network"
        return self._tap(capture, self._tap_filter(f"flow,{protocol_value},{address_value}", display_filter), profile)

    def service_statistics(self, capture: Path | str, display_filter: str = "", profile: PacketExecutionProfile | None = None) -> str:
        taps = [
            self._tap_filter("dns,tree", display_filter),
            self._tap_filter("http,stat", display_filter),
            self._tap_filter("http,tree", display_filter),
            self._tap_filter("http_req,tree", display_filter),
            self._tap_filter("http_srv,tree", display_filter),
            self._tap_filter("http2,tree", display_filter),
            self._tap_filter("icmp,srt", display_filter),
            self._tap_filter("icmpv6,srt", display_filter),
        ]
        return self._taps(capture, taps, profile)

    def rtp_streams(self, capture: Path | str, profile: PacketExecutionProfile | None = None) -> str:
        return self._tap(capture, "rtp,streams", profile)

    def statistics_tap(self, capture: Path | str, tap: str, profile: PacketExecutionProfile | None = None) -> str:
        value = str(tap).strip()
        if not value or any(character in value for character in "\r\n"):
            raise ValueError("invalid statistics tap")
        return self._tap(capture, value, profile)

    def statistics_taps(self, capture: Path | str, taps: Sequence[str], profile: PacketExecutionProfile | None = None) -> str:
        values = [str(tap).strip() for tap in taps if str(tap).strip()]
        if not values or any(any(character in value for character in "\r\n") for value in values):
            raise ValueError("invalid statistics taps")
        return self._taps(capture, values, profile)

    def full_statistics(self, capture: Path | str, display_filter: str = "", profile: PacketExecutionProfile | None = None) -> PacketStatistics:
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

    def follow_stream(
        self,
        capture: Path | str,
        protocol: str,
        stream_filter: str | int,
        mode: str = "utf-8",
        range_spec: str = "",
        profile: PacketExecutionProfile | None = None,
    ) -> str:
        protocol_value = str(protocol).casefold()
        mode_value = str(mode).casefold()
        if protocol_value not in self.FOLLOW_PROTOCOLS:
            raise ValueError(f"unsupported follow protocol: {protocol}")
        if mode_value not in self.FOLLOW_MODES:
            raise ValueError(f"unsupported follow mode: {mode}")
        stream_value = str(stream_filter).strip()
        if not stream_value or any(character in stream_value for character in "\r\n"):
            raise ValueError("invalid stream filter")
        tap = f"follow,{protocol_value},{mode_value},{stream_value}"
        if range_spec:
            range_value = str(range_spec).strip()
            if any(character in range_value for character in "\r\n"):
                raise ValueError("invalid stream range")
            tap += f",{range_value}"
        return self._tap(capture, tap, profile)

    def export_filtered_capture(
        self,
        capture: Path | str,
        destination: Path | str,
        display_filter: str = "",
        output_format: str = "pcapng",
        profile: PacketExecutionProfile | None = None,
    ) -> Path:
        source = self._capture_path(capture)
        target = Path(destination).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        args = self._base_read_args(source, profile)
        if display_filter:
            args.extend(["-Y", display_filter])
        args.extend(["-F", str(output_format), "-w", str(target)])
        self._run_tshark(args, timeout=max(self.timeout_seconds, 300.0))
        if not target.exists():
            raise ArenyxaError("PACKET_ANALYSIS_EXPORT_FAILED", "Packet-analysis runtime did not create the requested capture file.", domain="CAPTURE")
        return target

    def export_dissections(
        self,
        capture: Path | str,
        destination: Path | str,
        output_format: str = "json",
        display_filter: str = "",
        profile: PacketExecutionProfile | None = None,
        include_raw: bool = False,
    ) -> Path:
        if output_format not in self.OUTPUT_FORMATS:
            raise ValueError(f"unsupported output format: {output_format}")
        source = self._capture_path(capture)
        target = Path(destination).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        args = self._base_read_args(source, profile)
        args.extend(["-T", output_format])
        if include_raw and output_format in {"ek", "json", "jsonraw", "text"}:
            args.append("-x")
        if display_filter:
            args.extend(["-Y", display_filter])
        completed = self._run_process([self.executable, *args], timeout=max(self.timeout_seconds, 300.0), check=True)
        target.write_text(completed.stdout or "", encoding="utf-8")
        return target

    def export_objects(self, capture: Path | str, protocol: str, destination: Path | str, profile: PacketExecutionProfile | None = None) -> list[Path]:
        source = self._capture_path(capture)
        target = Path(destination).expanduser().resolve()
        target.mkdir(parents=True, exist_ok=True)
        before = {path.name for path in target.iterdir() if path.is_file()}
        args = self._base_read_args(source, profile)
        args.extend(["--export-objects", f"{str(protocol).strip()},{target}"])
        self._run_tshark(args, timeout=max(self.timeout_seconds, 300.0))
        return sorted((path for path in target.iterdir() if path.is_file() and path.name not in before), key=lambda item: item.name.casefold())

    def capture_info(self, capture: Path | str) -> PacketCaptureInfo:
        source = self._capture_path(capture)
        executable = shutil.which("capinfos")
        if executable:
            completed = self._run_process([executable, "-M", "-A", str(source)], timeout=60, check=True)
            return PacketCaptureInfo(path=str(source), output=completed.stdout or "")
        output = self._run_tshark(["-n", "-r", str(source), "-q", "-z", "io,stat,0"], timeout=90)
        return PacketCaptureInfo(path=str(source), output=output)

    def merge_captures(self, captures: Sequence[Path | str], destination: Path | str, chronological: bool = True) -> Path:
        executable = shutil.which("mergecap")
        if not executable:
            raise ArenyxaError("PACKET_ANALYSIS_MERGECAP_MISSING", "mergecap is required for capture merging.", domain="CAPTURE")
        sources = [self._capture_path(item) for item in captures]
        if len(sources) < 2:
            raise ValueError("at least two capture files are required")
        target = Path(destination).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        args = [executable, "-w", str(target)]
        if not chronological:
            args.append("-a")
        args.extend(str(item) for item in sources)
        self._run_process(args, timeout=300, check=True)
        return target

    def convert_capture(self, capture: Path | str, destination: Path | str, output_format: str = "pcapng") -> Path:
        executable = shutil.which("editcap")
        if not executable:
            return self.export_filtered_capture(capture, destination, output_format=output_format)
        source = self._capture_path(capture)
        target = Path(destination).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        self._run_process([executable, "-F", str(output_format), str(source), str(target)], timeout=300, check=True)
        return target

    def reorder_capture(self, capture: Path | str, destination: Path | str) -> Path:
        executable = shutil.which("reordercap")
        if not executable:
            raise ArenyxaError("PACKET_ANALYSIS_REORDERCAP_MISSING", "reordercap is required for timestamp reordering.", domain="CAPTURE")
        source = self._capture_path(capture)
        target = Path(destination).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        self._run_process([executable, str(source), str(target)], timeout=300, check=True)
        return target

    def to_network_events(
        self,
        capture: Path | str,
        session: CaptureSession,
        display_filter: str = "",
        limit: int = 200_000,
        profile: PacketExecutionProfile | None = None,
    ) -> list[NetworkEvent]:
        packets = self.packet_summaries(capture, display_filter=display_filter, limit=limit, profile=profile)
        events: list[NetworkEvent] = []
        for packet in packets:
            transport = "tcp" if packet.tcp_stream is not None or packet.source_port is not None and "tcp" in packet.protocols else "udp" if packet.udp_stream is not None or "udp" in packet.protocols else "unknown"
            stream_ref = f"tcp:{packet.tcp_stream}" if packet.tcp_stream is not None else f"udp:{packet.udp_stream}" if packet.udp_stream is not None else None
            url = ""
            if packet.host and packet.uri:
                scheme = "https" if any(token in packet.protocols for token in ("tls", "http2", "quic", "http3")) else "http"
                url = f"{scheme}://{packet.host}{packet.uri}"
            metadata = dict(packet.metadata)
            metadata.update({
                "frame_number": packet.frame_number,
                "captured_length": packet.captured_length,
                "frame_protocols": packet.protocols,
                "packet_info": packet.info,
                "source_address": packet.source,
                "destination_address": packet.destination,
                "source_port": packet.source_port,
                "destination_port": packet.destination_port,
                "transport": transport,
                "tcp_stream": packet.tcp_stream,
                "udp_stream": packet.udp_stream,
                "http2_stream": packet.http2_stream,
                "quic_stream": packet.quic_stream,
                "tcp_analysis": packet.tcp_analysis,
                "raw_capture_path": str(self._capture_path(capture)),
            })
            events.append(NetworkEvent(
                session_id=session.id,
                source_type=session.source_type,
                protocol=packet.protocol.casefold() or "unknown",
                direction="unknown",
                size=packet.length,
                timestamp=packet.timestamp,
                flow_ref=stream_ref,
                method=packet.method or None,
                url=url or None,
                status=packet.status,
                host=packet.host or None,
                metadata=metadata,
            ))
        return events

    def _base_read_args(self, path: Path, profile: PacketExecutionProfile | None) -> list[str]:
        args = ["-2", "-n", "-r", str(path)]
        if profile is None:
            return args
        if profile.configuration_profile:
            args.extend(["-C", profile.configuration_profile])
        if profile.name_resolution:
            args.extend(["-N", profile.name_resolution])
        for decode in profile.decode_as:
            value = str(decode).strip()
            if value:
                args.extend(["-d", value])
        for key, value in profile.preferences.items():
            if str(key).strip():
                args.extend(["-o", f"{key}:{value}"])
        if profile.keytab:
            args.extend(["-K", str(Path(profile.keytab).expanduser().resolve())])
        if profile.tls_keylog:
            args.extend(["-o", f"tls.keylog_file:{Path(profile.tls_keylog).expanduser().resolve()}"])
        if profile.enabled_protocols:
            args.extend(["--enable-protocol", ",".join(profile.enabled_protocols)])
        if profile.disabled_protocols:
            args.extend(["--disable-protocol", ",".join(profile.disabled_protocols)])
        for name in profile.enabled_heuristics:
            args.extend(["--enable-heuristic", str(name)])
        for name in profile.disabled_heuristics:
            args.extend(["--disable-heuristic", str(name)])
        return args

    def _tap(self, capture: Path | str, tap: str, profile: PacketExecutionProfile | None) -> str:
        return self._taps(capture, [tap], profile)

    def _taps(self, capture: Path | str, taps: Iterable[str], profile: PacketExecutionProfile | None) -> str:
        path = self._capture_path(capture)
        args = self._base_read_args(path, profile)
        args.insert(0, "-q")
        for tap in taps:
            if str(tap).strip():
                args.extend(["-z", str(tap)])
        return self._run_tshark(args, timeout=max(self.timeout_seconds, 180.0))

    @staticmethod
    def _tap_filter(base: str, display_filter: str) -> str:
        return f"{base},{display_filter}" if display_filter else base

    def _supported_fields(self) -> set[str]:
        if self._supported_field_cache is not None:
            return self._supported_field_cache
        supported: set[str] = set()
        for line in self.glossary("fields"):
            parts = line.split("\t")
            if len(parts) >= 3 and parts[0] == "F":
                supported.add(parts[2])
        self._supported_field_cache = supported
        return supported

    def _run_tshark(self, args: Sequence[str], timeout: float | None = None) -> str:
        if not self.available:
            raise ArenyxaError(
                "PACKET_ANALYSIS_TSHARK_MISSING",
                "packet-analysis runtime is required for packet intelligence.",
                domain="CAPTURE",
                suggested_action="Install a compatible packet-analysis runtime and packet-capture driver, then restart Arenyxa.",
            )
        completed = self._run_process([self.executable, *[str(item) for item in args]], timeout=timeout, check=True)
        return completed.stdout or ""

    def _run_process(self, args: Sequence[str], timeout: float | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
        try:
            completed = subprocess.run(
                validated_argv(list(args)),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout or self.timeout_seconds,
                check=False,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
        except subprocess.TimeoutExpired as exc:
            raise ArenyxaError(
                "PACKET_ANALYSIS_TIMEOUT",
                "Packet analysis exceeded the configured execution deadline.",
                domain="CAPTURE",
                context={"command": Path(str(args[0])).name},
            ) from exc
        except OSError as exc:
            raise ArenyxaError(
                "PACKET_ANALYSIS_EXECUTION_FAILED",
                "packet-analysis tooling could not be started.",
                domain="CAPTURE",
                context={"command": Path(str(args[0])).name, "error": str(exc)},
            ) from exc
        if check and completed.returncode != 0:
            stderr = (completed.stderr or "").strip()
            raise ArenyxaError(
                "PACKET_ANALYSIS_COMMAND_FAILED",
                stderr[-3000:] or f"Packet-analysis command failed with exit code {completed.returncode}.",
                domain="CAPTURE",
                context={"command": Path(str(args[0])).name, "returncode": completed.returncode},
            )
        return completed

    @staticmethod
    def _capture_path(capture: Path | str) -> Path:
        path = Path(capture).expanduser().resolve()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(path)
        return path

    @staticmethod
    def _unquote(value: str) -> str:
        text = str(value)
        if len(text) >= 2 and text[0] == text[-1] == '"':
            return text[1:-1].replace('""', '"')
        return text

    @staticmethod
    def _first(value: str) -> str:
        return str(value or "").split(",", 1)[0].strip()

    @classmethod
    def _int_or_none(cls, value: str) -> int | None:
        text = cls._first(value)
        try:
            return int(text) if text else None
        except (TypeError, ValueError, OverflowError):
            return None

    @staticmethod
    def _float_text_to_iso(value: str) -> str:
        return TsharkPacketAdapter._epoch_timestamp(PacketAnalysisEngine._first(value))

    @classmethod
    def _packet_from_row(cls, row: Mapping[str, str]) -> PacketRecord | None:
        frame_number = cls._int_or_none(row.get("frame.number", ""))
        if frame_number is None:
            return None
        source = cls._first(row.get("ip.src", "")) or cls._first(row.get("ipv6.src", "")) or cls._first(row.get("eth.src", ""))
        destination = cls._first(row.get("ip.dst", "")) or cls._first(row.get("ipv6.dst", "")) or cls._first(row.get("eth.dst", ""))
        source_port = cls._int_or_none(row.get("tcp.srcport", ""))
        if source_port is None:
            source_port = cls._int_or_none(row.get("udp.srcport", ""))
        destination_port = cls._int_or_none(row.get("tcp.dstport", ""))
        if destination_port is None:
            destination_port = cls._int_or_none(row.get("udp.dstport", ""))
        analysis_fields = (
            "tcp.analysis.retransmission",
            "tcp.analysis.fast_retransmission",
            "tcp.analysis.spurious_retransmission",
            "tcp.analysis.out_of_order",
            "tcp.analysis.lost_segment",
            "tcp.analysis.duplicate_ack",
            "tcp.analysis.zero_window",
            "tcp.analysis.window_full",
            "tcp.analysis.keep_alive",
        )
        tcp_analysis = [name[len("tcp.analysis."):] if name.startswith("tcp.analysis.") else name for name in analysis_fields if row.get(name, "")]
        protocols = row.get("frame.protocols", "")
        protocol = cls._first(row.get("_ws.col.Protocol", "")) or (protocols.split(":")[-1] if protocols else "unknown")
        host = cls._first(row.get("http.host", "")) or cls._first(row.get("dns.qry.name", "")) or cls._first(row.get("tls.handshake.extensions_server_name", ""))
        metadata: dict[str, Any] = {}
        bytes_in_flight = cls._int_or_none(row.get("tcp.analysis.bytes_in_flight", ""))
        if bytes_in_flight is not None:
            metadata["tcp_bytes_in_flight"] = bytes_in_flight
        ack_rtt = cls._first(row.get("tcp.analysis.ack_rtt", ""))
        if ack_rtt:
            try:
                metadata["tcp_ack_rtt_ms"] = float(ack_rtt) * 1000.0
            except (TypeError, ValueError, OverflowError):
                pass
        return PacketRecord(
            frame_number=frame_number,
            timestamp=cls._float_text_to_iso(row.get("frame.time_epoch", "")),
            length=cls._int_or_none(row.get("frame.len", "")) or 0,
            captured_length=cls._int_or_none(row.get("frame.cap_len", "")) or 0,
            protocols=protocols,
            protocol=protocol,
            info=row.get("_ws.col.Info", ""),
            source=source,
            destination=destination,
            source_port=source_port,
            destination_port=destination_port,
            tcp_stream=cls._int_or_none(row.get("tcp.stream", "")),
            udp_stream=cls._int_or_none(row.get("udp.stream", "")),
            http2_stream=cls._int_or_none(row.get("http2.streamid", "")),
            quic_stream=cls._int_or_none(row.get("quic.stream.stream_id", "")),
            host=host,
            method=cls._first(row.get("http.request.method", "")),
            uri=cls._first(row.get("http.request.uri", "")),
            status=cls._int_or_none(row.get("http.response.code", "")),
            tcp_analysis=tcp_analysis,
            metadata=metadata,
        )
