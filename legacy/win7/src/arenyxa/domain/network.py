from __future__ import annotations

import hashlib
from dataclasses import field
from arenyxa.compat import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlparse

from arenyxa.domain.models import NetworkEvent


def _stable_id(prefix: str, *parts: str) -> str:
    payload = "\x1f".join(str(part) for part in parts).encode("utf-8", errors="surrogatepass")
    return f"{prefix}_{hashlib.sha256(payload).hexdigest()[:32]}"


def _header(headers: dict[str, str], name: str) -> str:
    target = name.casefold()
    for key, value in headers.items():
        if str(key).casefold() == target:
            return str(value)
    return ""


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _safe_float(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if number == number and abs(number) != float("inf") else None


def _timing_map(value: Any) -> dict[str, float]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, float] = {}
    for key, raw in value.items():
        number = _safe_float(raw)
        if number is not None:
            result[str(key)] = number
    return result


@dataclass(slots=True)
class BodyArtifact:
    id: str
    session_id: str
    sha256: str
    stored_sha256: str
    byte_size: int
    stored_size: int
    content_type: str = ""
    encoding: str = ""
    storage_kind: str = "file"
    storage_ref: str = ""
    truncated: bool = False
    sensitive: bool = False
    created_at: str = ""


@dataclass(slots=True)
class NetworkFlow:
    id: str
    session_id: str
    source_type: str
    protocol: str
    transport: str
    first_seen: str
    last_seen: str
    event_count: int = 1
    bytes_seen: int = 0
    process_ref: str | None = None
    local_address: str | None = None
    remote_address: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class HttpRequestRecord:
    id: str
    event_id: str
    session_id: str
    flow_id: str | None
    timestamp: str
    method: str
    url: str
    host: str
    query: dict[str, list[str]] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    body_ref: str | None = None
    initiator: str | None = None


@dataclass(slots=True)
class HttpResponseRecord:
    id: str
    request_id: str
    event_id: str
    session_id: str
    timestamp: str
    status: int | None
    headers: dict[str, str] = field(default_factory=dict)
    body_ref: str | None = None
    content_type: str = ""
    size: int = 0
    timing: dict[str, float] = field(default_factory=dict)


@dataclass(slots=True)
class DnsTransaction:
    id: str
    event_id: str
    session_id: str
    timestamp: str
    query_name: str
    query_type: str = "A"
    answers: list[str] = field(default_factory=list)
    elapsed_ms: float | None = None
    error: str | None = None


@dataclass(slots=True)
class TlsHandshake:
    id: str
    event_id: str
    session_id: str
    flow_id: str | None
    timestamp: str
    host: str
    version: str = ""
    cipher: str = ""
    alpn: str = ""
    certificate_ref: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class WebSocketChannel:
    id: str
    session_id: str
    flow_id: str | None
    url: str
    host: str
    opened_at: str
    closed_at: str | None = None
    message_count: int = 0
    bytes_seen: int = 0


@dataclass(slots=True)
class WebSocketMessage:
    id: str
    channel_id: str
    event_id: str
    timestamp: str
    direction: str
    opcode: str
    size: int
    payload_ref: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class NormalizedNetworkBundle:
    flow: NetworkFlow
    request: HttpRequestRecord | None = None
    response: HttpResponseRecord | None = None
    dns: DnsTransaction | None = None
    tls: TlsHandshake | None = None
    websocket_channel: WebSocketChannel | None = None
    websocket_message: WebSocketMessage | None = None
    body_artifacts: list[BodyArtifact] = field(default_factory=list)


class NetworkNormalizer:
    






    HTTP_PROTOCOLS = {"http", "https", "h2", "h3", "http2", "http3"}
    WS_PROTOCOLS = {"ws", "wss", "websocket"}

    @classmethod
    def normalize(cls, event: NetworkEvent) -> NormalizedNetworkBundle:
        metadata = event.metadata if isinstance(event.metadata, dict) else {}
        protocol = str(event.protocol or "unknown").casefold()
        flow_key = event.flow_ref or str(metadata.get("connection_id") or event.id)
        flow_id = _stable_id("flow", event.session_id, flow_key)
        transport = str(metadata.get("transport") or ("udp" if protocol in {"dns", "quic", "h3", "http3"} else "tcp"))
        flow = NetworkFlow(
            id=flow_id,
            session_id=event.session_id,
            source_type=event.source_type.value,
            protocol=protocol,
            transport=transport.casefold(),
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            bytes_seen=max(0, _safe_int(event.size)),
            process_ref=event.process_ref,
            local_address=cls._endpoint(metadata, "local"),
            remote_address=cls._endpoint(metadata, "remote"),
            metadata={
                key: value
                for key, value in metadata.items()
                if key in {
                    "resource_type", "mime_type", "connection_id", "connection_confidence",
                    "tls_version", "alpn", "http_version", "encrypted_payload", "server_name",
                    "source_endpoint", "destination_endpoint",
                }
            },
        )
        bundle = NormalizedNetworkBundle(flow=flow)
        artifacts = metadata.get("body_artifacts", [])
        if isinstance(artifacts, list):
            for raw in artifacts:
                if not isinstance(raw, dict):
                    continue
                try:
                    artifact = BodyArtifact(
                        id=str(raw["id"]),
                        session_id=str(raw.get("session_id") or event.session_id),
                        sha256=str(raw["sha256"]),
                        stored_sha256=str(raw.get("stored_sha256") or raw["sha256"]),
                        byte_size=max(0, _safe_int(raw.get("byte_size"))),
                        stored_size=max(0, _safe_int(raw.get("stored_size"))),
                        content_type=str(raw.get("content_type") or ""),
                        encoding=str(raw.get("encoding") or ""),
                        storage_kind=str(raw.get("storage_kind") or "file"),
                        storage_ref=str(raw.get("storage_ref") or ""),
                        truncated=bool(raw.get("truncated", False)),
                        sensitive=bool(raw.get("sensitive", False)),
                        created_at=str(raw.get("created_at") or event.timestamp),
                    )
                except (KeyError, TypeError, ValueError):
                    continue
                if artifact.session_id == event.session_id and artifact.id:
                    bundle.body_artifacts.append(artifact)
        if cls._is_http(event):
            request_id = _stable_id("request", event.session_id, event.request_ref or event.id)
            parsed = urlparse(event.url or "")
            query: dict[str, list[str]] = {}
            for key, value in parse_qsl(parsed.query, keep_blank_values=True):
                query.setdefault(key, []).append(value)
            method = (event.method or "GET").upper()
            request = HttpRequestRecord(
                id=request_id,
                event_id=event.id,
                session_id=event.session_id,
                flow_id=flow_id,
                timestamp=event.timestamp,
                method=method,
                url=event.url or "",
                host=event.host or parsed.hostname or "",
                query=query,
                headers={str(key): str(value) for key, value in event.request_headers.items()} if isinstance(event.request_headers, dict) else {},
                body_ref=event.request_body_ref,
                initiator=event.initiator,
            )
            bundle.request = request
            if event.status is not None or event.response_headers or event.response_body_ref:
                bundle.response = HttpResponseRecord(
                    id=_stable_id("response", request_id),
                    request_id=request_id,
                    event_id=event.id,
                    session_id=event.session_id,
                    timestamp=event.timestamp,
                    status=event.status,
                    headers={str(key): str(value) for key, value in event.response_headers.items()} if isinstance(event.response_headers, dict) else {},
                    body_ref=event.response_body_ref,
                    content_type=_header(event.response_headers if isinstance(event.response_headers, dict) else {}, "content-type")
                    or str(metadata.get("mime_type") or ""),
                    size=max(0, _safe_int(event.size)),
                    timing=_timing_map(event.timing),
                )
        if protocol == "dns" or str(metadata.get("resource_type", "")).casefold() == "dns":
            query_name = str(metadata.get("query_name") or event.host or "")
            answers_value = metadata.get("answers", [])
            answers = [str(item) for item in answers_value] if isinstance(answers_value, (list, tuple)) else []
            elapsed = metadata.get("elapsed_ms", event.timing.get("total_ms") if isinstance(event.timing, dict) else None)
            elapsed_ms = _safe_float(elapsed) if elapsed is not None else None
            bundle.dns = DnsTransaction(
                id=_stable_id("dns", event.session_id, event.id),
                event_id=event.id,
                session_id=event.session_id,
                timestamp=event.timestamp,
                query_name=query_name,
                query_type=str(metadata.get("query_type") or "A"),
                answers=answers,
                elapsed_ms=elapsed_ms,
                error=str(metadata.get("error")) if metadata.get("error") is not None else None,
            )
        if protocol in {"tls", "ssl"} or any(key in metadata for key in ("tls_version", "cipher", "alpn", "certificate_ref")):
            bundle.tls = TlsHandshake(
                id=_stable_id("tls", event.session_id, event.id),
                event_id=event.id,
                session_id=event.session_id,
                flow_id=flow_id,
                timestamp=event.timestamp,
                host=event.host or str(metadata.get("server_name") or metadata.get("sni") or ""),
                version=str(metadata.get("tls_version") or ""),
                cipher=str(metadata.get("cipher") or ""),
                alpn=str(metadata.get("alpn") or ""),
                certificate_ref=str(metadata.get("certificate_ref")) if metadata.get("certificate_ref") else None,
                metadata={key: value for key, value in metadata.items() if key.startswith("tls_") or key.startswith("cert_")},
            )
        if protocol in cls.WS_PROTOCOLS or str(metadata.get("resource_type", "")).casefold() == "websocket":
            channel_key = str(metadata.get("websocket_id") or event.flow_ref or event.url or event.id)
            channel_id = _stable_id("ws", event.session_id, channel_key)
            parsed = urlparse(event.url or "")
            bundle.websocket_channel = WebSocketChannel(
                id=channel_id,
                session_id=event.session_id,
                flow_id=flow_id,
                url=event.url or "",
                host=event.host or parsed.hostname or "",
                opened_at=str(metadata.get("opened_at") or event.timestamp),
                closed_at=str(metadata.get("closed_at")) if metadata.get("closed_at") else None,
                message_count=1 if metadata.get("opcode") or event.request_body_ref or event.response_body_ref else 0,
                bytes_seen=max(0, _safe_int(event.size)),
            )
            if bundle.websocket_channel.message_count:
                bundle.websocket_message = WebSocketMessage(
                    id=_stable_id("wsmsg", event.session_id, event.id),
                    channel_id=channel_id,
                    event_id=event.id,
                    timestamp=event.timestamp,
                    direction=event.direction,
                    opcode=str(metadata.get("opcode") or "data"),
                    size=max(0, _safe_int(event.size)),
                    payload_ref=event.request_body_ref or event.response_body_ref,
                    metadata={key: value for key, value in metadata.items() if key.startswith("websocket_")},
                )
        return bundle

    @classmethod
    def _is_http(cls, event: NetworkEvent) -> bool:
        if event.url and urlparse(event.url).scheme.casefold() in {"http", "https"}:
            return True
        return str(event.protocol or "").casefold() in cls.HTTP_PROTOCOLS and bool(event.method or event.status is not None)

    @staticmethod
    def _endpoint(metadata: dict[str, Any], side: str) -> str | None:
        direct = metadata.get(side) or metadata.get(f"{side}_endpoint")
        if direct:
            return str(direct)
        address = metadata.get(f"{side}_address")
        port = metadata.get(f"{side}_port")
        if address and port is not None:
            text = str(address)
            return f"[{text}]:{port}" if ":" in text and not text.startswith("[") else f"{text}:{port}"
        return str(address) if address else None
