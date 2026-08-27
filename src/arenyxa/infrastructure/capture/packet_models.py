from __future__ import annotations

from dataclasses import field
from typing import Any

from arenyxa.compat import dataclass


@dataclass(slots=True)
class PacketExecutionProfile:
    """Describe one bounded external packet-analysis execution policy."""

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
    """Report native and optional external packet-analysis capabilities."""

    available: bool
    tshark: str = ""
    version: str = ""
    tools: dict[str, str] = field(default_factory=dict)
    interfaces: list[str] = field(default_factory=list)
    protocol_count: int = 0
    field_count: int = 0
    object_exporters: list[str] = field(default_factory=list)
    capture_formats: list[str] = field(default_factory=list)
    native_protocol_count: int = 0
    native_protocols: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PacketRecord:
    """Represent one normalized packet summary independent of the decode backend."""

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
    """Collect high-level packet, protocol, endpoint, and flow statistics."""

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
    """Describe capture-file format, link type, timing, and packet-count metadata."""

    path: str
    output: str
