from __future__ import annotations

import re
from collections import Counter
from dataclasses import asdict
from typing import Any, Sequence
from urllib.parse import parse_qsl, urlsplit

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.proxy_models import ProxyFlow
from arenyxa.infrastructure.capture.proxy_transport import _header, _parse_raw_message


_LOGIN_PATH = re.compile(r"(?:^|/)(?:login|signin|sign-in|oauth|authorize|token|session)(?:/|$)", re.IGNORECASE)
_SENSITIVE_QUERY = re.compile(r"(?:token|secret|password|api[_-]?key|session)", re.IGNORECASE)
_JWT_SHAPE = re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")


@dataclass(slots=True)
class TrafficSummary:
    flow_count: int
    api_count: int
    authentication_flow_count: int
    upload_count: int
    anomaly_count: int
    token_leak_count: int
    hosts: list[dict[str, Any]]
    findings: list[dict[str, Any]]

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


class TrafficIntelligenceAnalyzer:
    """Deterministic local traffic intelligence; no payload is sent to an AI service."""

    LARGE_UPLOAD = 1024 * 1024

    def analyze(self, flows: Sequence[ProxyFlow]) -> TrafficSummary:
        api_signatures: set[str] = set()
        auth_flows: set[str] = set()
        uploads: set[str] = set()
        anomalies: set[str] = set()
        token_leaks: set[str] = set()
        hosts: Counter[str] = Counter()
        findings: list[dict[str, Any]] = []
        for flow in flows:
            hosts[flow.host] += 1
            try:
                _line, request_headers, request_body = _parse_raw_message(flow.request_raw)
            except ValueError:
                request_headers, request_body = [], b""
            content_type = _header(request_headers, "Content-Type").casefold()
            authorization = bool(_header(request_headers, "Authorization"))
            parsed = urlsplit(flow.url)
            path = parsed.path or "/"
            is_api = (
                path.casefold().startswith(("/api/", "/graphql", "/v1/", "/v2/", "/v3/"))
                or "json" in content_type
            )
            if is_api:
                api_signatures.add(f"{flow.method.upper()} {flow.host}{path}")
            if _LOGIN_PATH.search(path) or authorization:
                auth_flows.add(flow.id)
            if (
                "multipart/form-data" in content_type
                or "application/octet-stream" in content_type
                or len(request_body) >= self.LARGE_UPLOAD
            ):
                uploads.add(flow.id)
            if (isinstance(flow.status, int) and flow.status >= 400) or flow.duration_ms >= 5_000 or flow.error:
                anomalies.add(flow.id)
            query_names = [name for name, _value in parse_qsl(parsed.query, keep_blank_values=True)]
            token_shape = bool(_JWT_SHAPE.search(request_body[:2 * 1024 * 1024]))
            sensitive_query = sorted(name for name in query_names if _SENSITIVE_QUERY.search(name))
            if sensitive_query or (parsed.scheme == "http" and (authorization or token_shape)):
                token_leaks.add(flow.id)
                findings.append({
                    "severity": "high" if parsed.scheme == "http" else "medium",
                    "kind": "token-leak-risk",
                    "flow_id": flow.id,
                    "host": flow.host,
                    "transport": parsed.scheme,
                    "query_parameter_names": sensitive_query[:32],
                    "token_shape_in_body": token_shape,
                })
            if flow.duration_ms >= 5_000:
                findings.append({
                    "severity": "medium",
                    "kind": "high-latency",
                    "flow_id": flow.id,
                    "host": flow.host,
                    "latency_ms": round(float(flow.duration_ms), 3),
                })
        return TrafficSummary(
            flow_count=len(flows),
            api_count=len(api_signatures),
            authentication_flow_count=len(auth_flows),
            upload_count=len(uploads),
            anomaly_count=len(anomalies),
            token_leak_count=len(token_leaks),
            hosts=[{"host": host, "flows": count} for host, count in hosts.most_common(100)],
            findings=findings[:2_000],
        )


__all__ = ["TrafficIntelligenceAnalyzer", "TrafficSummary"]
