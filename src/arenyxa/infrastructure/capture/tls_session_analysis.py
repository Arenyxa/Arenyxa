from __future__ import annotations

from dataclasses import field
from datetime import datetime
from typing import Any, Mapping

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.packet_models import PacketRecord


_MAX_SESSIONS = 100_000
_MAX_SESSION_ROWS = 2048
_MAX_VALUES = 256


def _timestamp(value: str) -> float | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def _tls_fields(packet: PacketRecord) -> dict[str, Any]:
    layers = packet.metadata.get("native_layers")
    if not isinstance(layers, list):
        return {}
    for layer in layers:
        if isinstance(layer, Mapping) and str(layer.get("name") or "").casefold() == "tls":
            fields = layer.get("fields")
            return dict(fields) if isinstance(fields, Mapping) else {}
    return {}


def _canonical_flow(packet: PacketRecord) -> tuple[tuple[str, int], tuple[str, int]] | None:
    if packet.source_port is None or packet.destination_port is None or not packet.source or not packet.destination:
        return None
    left = (packet.source, int(packet.source_port))
    right = (packet.destination, int(packet.destination_port))
    return (left, right) if left <= right else (right, left)


def _version_number(value: object) -> int:
    text = str(value or "").strip().casefold()
    if text.startswith("0x"):
        try:
            return int(text, 16)
        except ValueError:
            return 0
    try:
        return int(text)
    except (TypeError, ValueError, OverflowError):
        return 0


def _version_name(value: int) -> str:
    return {
        0x0300: "SSLv3",
        0x0301: "TLS1.0",
        0x0302: "TLS1.1",
        0x0303: "TLS1.2",
        0x0304: "TLS1.3",
    }.get(value, f"0x{value:04x}" if value else "unknown")


def _string_values(raw: object) -> tuple[str, ...]:
    if not isinstance(raw, list):
        return ()
    values: list[str] = []
    for item in raw[:_MAX_VALUES]:
        value = str(item or "").strip()
        if value and value not in values:
            values.append(value)
    return tuple(values)


@dataclass(slots=True)
class _TlsSession:
    session_id: int
    endpoint_a: tuple[str, int]
    endpoint_b: tuple[str, int]
    first_seen: float | None = None
    last_seen: float | None = None
    packets: int = 0
    bytes: int = 0
    client: tuple[str, int] | None = None
    server: tuple[str, int] | None = None
    client_hello_frame: int | None = None
    server_hello_frame: int | None = None
    client_hello_time: float | None = None
    server_hello_time: float | None = None
    certificate_frame: int | None = None
    server_name: str = ""
    ja3: str = ""
    ja3_md5: str = ""
    ja4: str = ""
    ja4_raw: str = ""
    ja3s: str = ""
    ja3s_md5: str = ""
    offered_versions: set[str] = field(default_factory=set)
    offered_ciphers: set[str] = field(default_factory=set)
    offered_alpn: set[str] = field(default_factory=set)
    selected_version: str = ""
    selected_cipher: str = ""
    selected_alpn: str = ""
    certificate_sha256: str = ""
    certificate_spki_sha256: str = ""
    certificate_sans: set[str] = field(default_factory=set)
    malformed_records: int = 0

    def feed(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        timestamp = _timestamp(packet.timestamp)
        if timestamp is not None:
            self.first_seen = timestamp if self.first_seen is None else min(self.first_seen, timestamp)
            self.last_seen = timestamp if self.last_seen is None else max(self.last_seen, timestamp)
        self.packets += 1
        self.bytes += max(0, int(packet.length))
        try:
            handshake_type = int(fields.get("handshake_type") or 0)
        except (TypeError, ValueError, OverflowError):
            handshake_type = 0
        source = (packet.source, int(packet.source_port or 0))
        destination = (packet.destination, int(packet.destination_port or 0))
        if handshake_type == 1:
            self.client, self.server = source, destination
            if self.client_hello_frame is None:
                self.client_hello_frame = int(packet.frame_number)
                self.client_hello_time = timestamp
            self.server_name = str(fields.get("server_name") or self.server_name)
            self.ja3 = str(fields.get("ja3") or self.ja3)
            self.ja3_md5 = str(fields.get("ja3_md5") or self.ja3_md5)
            self.ja4 = str(fields.get("ja4") or self.ja4)
            self.ja4_raw = str(fields.get("ja4_raw") or self.ja4_raw)
            self.offered_versions.update(_string_values(fields.get("supported_versions")))
            self.offered_ciphers.update(_string_values(fields.get("cipher_suites")))
            self.offered_alpn.update(_string_values(fields.get("alpn")))
        elif handshake_type == 2:
            self.server, self.client = source, destination
            if self.server_hello_frame is None:
                self.server_hello_frame = int(packet.frame_number)
                self.server_hello_time = timestamp
            self.ja3s = str(fields.get("ja3s") or self.ja3s)
            self.ja3s_md5 = str(fields.get("ja3s_md5") or self.ja3s_md5)
            self.selected_version = str(fields.get("selected_version") or fields.get("server_legacy_version") or self.selected_version)
            self.selected_cipher = str(fields.get("selected_cipher_suite") or self.selected_cipher)
            self.selected_alpn = str(fields.get("selected_alpn") or self.selected_alpn)
        elif handshake_type == 11:
            self.server, self.client = source, destination
            if self.certificate_frame is None:
                self.certificate_frame = int(packet.frame_number)
            chain = fields.get("certificate_chain") if isinstance(fields.get("certificate_chain"), list) else []
            leaf = chain[0] if chain and isinstance(chain[0], Mapping) else {}
            self.certificate_sha256 = str(leaf.get("sha256") or self.certificate_sha256)
            self.certificate_spki_sha256 = str(leaf.get("spki_sha256") or self.certificate_spki_sha256)
            self.certificate_sans.update(_string_values(leaf.get("san_dns")))
        self.malformed_records += int(bool(fields.get("malformed_extensions")))

    def summary(self) -> dict[str, Any]:
        selected_numeric = _version_number(self.selected_version)
        offered_numeric = {_version_number(value) for value in self.offered_versions}
        offered_numeric.discard(0)
        strongest_offer = max(offered_numeric) if offered_numeric else 0
        version_fallback = bool(selected_numeric and strongest_offer and selected_numeric < strongest_offer)
        selected_cipher_not_offered = bool(
            self.selected_cipher and self.offered_ciphers and self.selected_cipher not in self.offered_ciphers
        )
        selected_alpn_not_offered = bool(
            self.selected_alpn and self.offered_alpn and self.selected_alpn not in self.offered_alpn
        )
        ordering_anomaly = bool(
            self.server_hello_frame is not None
            and self.client_hello_frame is not None
            and self.server_hello_frame < self.client_hello_frame
        )
        duration_ms = None
        if self.first_seen is not None and self.last_seen is not None and self.last_seen >= self.first_seen:
            duration_ms = round((self.last_seen - self.first_seen) * 1000.0, 3)
        handshake_ms = None
        if (
            self.client_hello_time is not None
            and self.server_hello_time is not None
            and self.server_hello_time >= self.client_hello_time
        ):
            handshake_ms = round((self.server_hello_time - self.client_hello_time) * 1000.0, 3)
        return {
            "session_id": self.session_id,
            "endpoint_a": {"address": self.endpoint_a[0], "port": self.endpoint_a[1]},
            "endpoint_b": {"address": self.endpoint_b[0], "port": self.endpoint_b[1]},
            "client": {"address": self.client[0], "port": self.client[1]} if self.client else None,
            "server": {"address": self.server[0], "port": self.server[1]} if self.server else None,
            "packets": self.packets,
            "bytes": self.bytes,
            "duration_ms": duration_ms,
            "handshake_observed": self.client_hello_frame is not None and self.server_hello_frame is not None,
            "client_hello_frame": self.client_hello_frame,
            "server_hello_frame": self.server_hello_frame,
            "certificate_frame": self.certificate_frame,
            "server_name": self.server_name,
            "ja3": self.ja3,
            "ja3_md5": self.ja3_md5,
            "ja4": self.ja4,
            "ja4_raw": self.ja4_raw,
            "ja3s": self.ja3s,
            "ja3s_md5": self.ja3s_md5,
            "offered_versions": sorted(self.offered_versions),
            "selected_version": self.selected_version,
            "selected_version_name": _version_name(selected_numeric),
            "offered_ciphers": sorted(self.offered_ciphers),
            "selected_cipher": self.selected_cipher,
            "offered_alpn": sorted(self.offered_alpn),
            "selected_alpn": self.selected_alpn,
            "certificate_sha256": self.certificate_sha256,
            "certificate_spki_sha256": self.certificate_spki_sha256,
            "certificate_sans": sorted(self.certificate_sans),
            "version_fallback_observed": version_fallback,
            "selected_cipher_not_offered": selected_cipher_not_offered,
            "selected_alpn_not_offered": selected_alpn_not_offered,
            "ordering_anomaly": ordering_anomaly,
            "malformed_records": self.malformed_records,
            "server_hello_latency_ms": handshake_ms,
        }


class TlsSessionAnalyzer:
    """Bounded TLS handshake correlation without retaining application plaintext."""

    def __init__(self) -> None:
        self._sessions: dict[object, _TlsSession] = {}
        self._next_id = 1
        self._session_limit_reached = False

    def feed(self, packet: PacketRecord) -> None:
        fields = _tls_fields(packet)
        if not fields:
            return
        flow = _canonical_flow(packet)
        if flow is None:
            return
        key: object = ("tcp-stream", int(packet.tcp_stream)) if packet.tcp_stream is not None else ("flow", flow)
        session = self._sessions.get(key)
        if session is None:
            if len(self._sessions) >= _MAX_SESSIONS:
                self._session_limit_reached = True
                return
            session = _TlsSession(session_id=self._next_id, endpoint_a=flow[0], endpoint_b=flow[1])
            self._sessions[key] = session
            self._next_id += 1
        session.feed(packet, fields)

    def finalize(self) -> dict[str, Any]:
        summaries = [session.summary() for session in self._sessions.values()]
        return {
            "schema": "arenyxa.tls-session-analysis/v1",
            "session_count": len(summaries),
            "session_limit_reached": self._session_limit_reached,
            "complete_handshakes": sum(1 for row in summaries if bool(row.get("handshake_observed"))),
            "version_fallback_sessions": sum(1 for row in summaries if bool(row.get("version_fallback_observed"))),
            "cipher_selection_anomalies": sum(1 for row in summaries if bool(row.get("selected_cipher_not_offered"))),
            "alpn_selection_anomalies": sum(1 for row in summaries if bool(row.get("selected_alpn_not_offered"))),
            "ordering_anomalies": sum(1 for row in summaries if bool(row.get("ordering_anomaly"))),
            "top_sessions": sorted(
                summaries,
                key=lambda row: (int(row.get("bytes") or 0), int(row.get("packets") or 0)),
                reverse=True,
            )[:_MAX_SESSION_ROWS],
        }
