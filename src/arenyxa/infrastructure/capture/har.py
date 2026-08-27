from __future__ import annotations

import base64
import binascii
import json
import math
from dataclasses import field
from arenyxa.compat import dataclass
from datetime import datetime
from arenyxa.compat import UTC
from pathlib import Path
from statistics import median
from typing import Any
from urllib.parse import urlparse

from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import CaptureSession, NetworkEvent
from arenyxa.infrastructure.atomic_io import read_text_limited
from arenyxa.infrastructure.capture.bodies import NetworkBodyStore


@dataclass(slots=True)
class HarSummary:
    request_count: int = 0
    total_bytes: int = 0
    failed_requests: int = 0
    redirects: int = 0
    cache_hits: int = 0
    third_party_domains: int = 0
    domains: dict[str, int] = field(default_factory=dict)
    mime_types: dict[str, int] = field(default_factory=dict)
    timing_p50_ms: float = 0.0
    timing_p95_ms: float = 0.0
    slowest: list[dict[str, Any]] = field(default_factory=list)


class HarAnalyzer:
    @staticmethod
    def load(
        path: Path,
        session: CaptureSession,
        body_store: NetworkBodyStore | None = None,
    ) -> tuple[list[NetworkEvent], HarSummary]:
        try:
            raw = read_text_limited(path, 256 * 1024 * 1024, encoding="utf-8-sig")
        except ValueError as exc:
            raise ArenyxaError(
                "HAR_IMPORT_TOO_LARGE",
                "HAR 文件超过 256 MiB 安全导入上限；请拆分 HAR 后再导入。",
                domain="CAPTURE",
            ) from exc
        try:
            data = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ArenyxaError("HAR_IMPORT_INVALID", "HAR 文件不是有效 JSON。", domain="CAPTURE") from exc
        if not isinstance(data, dict) or not isinstance(data.get("log"), dict):
            raise ArenyxaError("HAR_IMPORT_INVALID", "HAR 根结构无效。", domain="CAPTURE")
        entries = data["log"].get("entries", [])
        if not isinstance(entries, list):
            raise ArenyxaError("HAR_IMPORT_INVALID", "HAR entries 必须是数组。", domain="CAPTURE")
        if len(entries) > 250_000:
            raise ArenyxaError(
                "HAR_IMPORT_TOO_MANY_ENTRIES",
                "HAR 请求数量超过 250,000 条安全导入上限；请拆分 HAR 后再导入。",
                domain="CAPTURE",
            )
        events: list[NetworkEvent] = []
        summary = HarSummary()
        page_host = ""
        pages = data["log"].get("pages", [])
        if not isinstance(pages, list):
            raise ArenyxaError("HAR_IMPORT_INVALID", "HAR pages 必须是数组。", domain="CAPTURE")
        if pages and isinstance(pages[0], dict):
            page_host = urlparse(str(pages[0].get("title", ""))).hostname or ""
        timings: list[float] = []
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise ArenyxaError(
                    "HAR_IMPORT_INVALID", f"HAR entries[{index}] 不是对象。", domain="CAPTURE"
                )
            request = entry.get("request", {})
            response = entry.get("response", {})
            if not isinstance(request, dict) or not isinstance(response, dict):
                raise ArenyxaError(
                    "HAR_IMPORT_INVALID", f"HAR entries[{index}] request/response 结构无效。", domain="CAPTURE"
                )
            url = str(request.get("url", ""))
            host = urlparse(url).hostname or ""
            total_ms = HarAnalyzer._finite_number(entry.get("time", 0), default=0.0)
            timings.append(total_ms)
            content = response.get("content", {})
            if not isinstance(content, dict):
                content = {}
            size = max(
                0,
                HarAnalyzer._integer(response.get("bodySize", 0), default=0),
                HarAnalyzer._integer(content.get("size", 0), default=0),
            )
            status = HarAnalyzer._integer(response.get("status", 0), default=0)
            raw_timings = entry.get("timings", {})
            if not isinstance(raw_timings, dict):
                raw_timings = {}
            request_headers = HarAnalyzer._headers(request.get("headers", []))
            response_headers = HarAnalyzer._headers(response.get("headers", []))
            request_body_ref: str | None = None
            response_body_ref: str | None = None
            body_artifacts: list[dict[str, Any]] = []
            if body_store is not None:
                post_data = request.get("postData")
                if isinstance(post_data, dict) and isinstance(post_data.get("text"), str):
                    artifact = body_store.put(
                        session.id,
                        post_data["text"],
                        content_type=str(post_data.get("mimeType") or request_headers.get("Content-Type") or request_headers.get("content-type") or ""),
                        encoding="utf-8",
                        sensitive=bool(HarAnalyzer._sensitivity(request)),
                    )
                    request_body_ref = artifact.id
                    body_artifacts.append(body_store.metadata(artifact))
                response_payload = HarAnalyzer._content_payload(content)
                if response_payload is not None:
                    artifact = body_store.put(
                        session.id,
                        response_payload,
                        content_type=str(content.get("mimeType") or ""),
                        encoding="utf-8" if isinstance(response_payload, str) else "",
                    )
                    response_body_ref = artifact.id
                    body_artifacts.append(body_store.metadata(artifact))
            connection_id = str(entry.get("connection") or "")
            server_ip = str(entry.get("serverIPAddress") or "")
            security = entry.get("_securityDetails") if isinstance(entry.get("_securityDetails"), dict) else {}
            metadata = {
                "har_total_ms": total_ms,
                "mime_type": content.get("mimeType", ""),
                "connection_id": connection_id or None,
                "connection_confidence": "har",
                "remote_address": server_ip or None,
                "transport": "tcp",
                "encrypted_payload": urlparse(url).scheme.casefold() == "https",
            }
            if security:
                metadata.update({
                    "tls_version": str(security.get("protocol") or ""),
                    "cipher": str(security.get("cipher") or ""),
                    "server_name": host,
                    "cert_subject": str(security.get("subjectName") or ""),
                    "tls_issuer": str(security.get("issuer") or ""),
                    "cert_valid_from": security.get("validFrom"),
                    "cert_valid_to": security.get("validTo"),
                })
            if body_artifacts:
                metadata["body_artifacts"] = body_artifacts
            event = NetworkEvent(
                session_id=session.id,
                source_type=CaptureSource.HAR_IMPORT,
                protocol=str(entry.get("_resourceType", "http")),
                direction="bidirectional",
                size=size,
                timestamp=str(entry.get("startedDateTime", datetime.now(UTC).isoformat())),
                method=str(request.get("method", "GET")),
                url=url,
                status=status,
                host=host,
                timing={str(key): HarAnalyzer._finite_number(value, default=0.0) for key, value in raw_timings.items()},
                flow_ref=f"har:{connection_id}" if connection_id else None,
                request_headers=request_headers,
                response_headers=response_headers,
                request_body_ref=request_body_ref,
                response_body_ref=response_body_ref,
                sensitivity_flags=HarAnalyzer._sensitivity(request),
                metadata=metadata,
            )
            events.append(event)
            summary.total_bytes += size
            summary.failed_requests += int(status >= 400 or status == 0)
            summary.redirects += int(300 <= status < 400)
            summary.cache_hits += int(bool(entry.get("cache")))
            summary.domains[host] = summary.domains.get(host, 0) + 1
            mime = str(content.get("mimeType", "unknown")).split(";")[0]
            summary.mime_types[mime] = summary.mime_types.get(mime, 0) + 1
        summary.request_count = len(events)
        summary.third_party_domains = sum(1 for host in summary.domains if page_host and host != page_host)
        timings.sort()
        if timings:
            summary.timing_p50_ms = median(timings)
            summary.timing_p95_ms = timings[min(len(timings) - 1, math.ceil(len(timings) * 0.95) - 1)]
        summary.slowest = sorted(
            (
                {"url": event.url, "ms": event.metadata.get("har_total_ms", 0), "status": event.status}
                for event in events
            ),
            key=lambda item: item["ms"],
            reverse=True,
        )[:20]
        return events, summary


    @staticmethod
    def _content_payload(content: dict[str, Any]) -> bytes | str | None:
        text = content.get("text")
        if not isinstance(text, str):
            return None
        if str(content.get("encoding") or "").casefold() == "base64":
            try:
                return base64.b64decode(text, validate=True)
            except (ValueError, binascii.Error):
                return None
        return text

    @staticmethod
    def _integer(value: Any, *, default: int = 0) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError, OverflowError):
            return default

    @staticmethod
    def _finite_number(value: Any, *, default: float = 0.0) -> float:
        try:
            number = float(value or 0.0)
        except (TypeError, ValueError, OverflowError):
            return default
        return number if math.isfinite(number) else default

    @staticmethod
    def _headers(value: Any) -> dict[str, str]:
        if not isinstance(value, list):
            return {}
        result: dict[str, str] = {}
        for item in value:
            if not isinstance(item, dict):
                continue
            result[str(item.get("name", ""))] = str(item.get("value", ""))
        return result

    @staticmethod
    def compare(left: HarSummary, right: HarSummary) -> dict[str, Any]:
        fields = (
            "request_count",
            "total_bytes",
            "failed_requests",
            "redirects",
            "cache_hits",
            "third_party_domains",
            "timing_p50_ms",
            "timing_p95_ms",
        )
        return {
            field: {
                "before": getattr(left, field),
                "after": getattr(right, field),
                "delta": getattr(right, field) - getattr(left, field),
            }
            for field in fields
        }

    @staticmethod
    def _sensitivity(request: dict[str, Any]) -> list[str]:
        flags = []
        names = {name.lower() for name in HarAnalyzer._headers(request.get("headers", [])).keys()}
        if "authorization" in names:
            flags.append("authorization")
        if request.get("cookies") or "cookie" in names:
            flags.append("cookie")
        if request.get("postData"):
            flags.append("request_body")
        return flags
