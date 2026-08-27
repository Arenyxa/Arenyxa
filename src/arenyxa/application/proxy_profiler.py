from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass
from typing import Any, Iterable

from arenyxa.infrastructure.capture.proxy_models import ProxyFlow
from arenyxa.infrastructure.capture.proxy_transport import _parse_raw_message


@dataclass(slots=True)
class ProxyProfilerSnapshot:
    flow_count: int
    completed_count: int
    error_count: int
    dropped_count: int
    tls_intercepted_count: int
    tunnel_count: int
    rewritten_flow_count: int
    request_bytes: int
    response_bytes: int
    duration_p50_ms: float
    duration_p95_ms: float
    duration_p99_ms: float
    duration_max_ms: float
    methods: dict[str, int]
    status_families: dict[str, int]
    hosts: list[dict[str, Any]]
    content_types: list[dict[str, Any]]
    findings: list[dict[str, Any]]

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


class ProxyProfiler:
    """Perform bounded, passive profiling over already-captured proxy flows."""

    MAX_FLOWS = 10_000
    MAX_FINDINGS = 300
    SLOW_MS = 2_000.0
    LARGE_RESPONSE_BYTES = 8 * 1024 * 1024

    @staticmethod
    def _percentile(values: list[float], fraction: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(max(0.0, float(value)) for value in values)
        index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * fraction))))
        return round(ordered[index], 3)

    def analyze(self, flows: Iterable[ProxyFlow], *, limit: int = 5000) -> ProxyProfilerSnapshot:
        bounded = max(1, min(int(limit), self.MAX_FLOWS))
        rows = list(deque(flows, maxlen=bounded))
        methods: dict[str, int] = {}
        statuses = {"1xx": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
        hosts: dict[str, dict[str, int]] = {}
        content_types: dict[str, int] = {}
        findings: list[dict[str, Any]] = []
        durations: list[float] = []

        def finding(flow: ProxyFlow, severity: str, kind: str, detail: str) -> None:
            if len(findings) >= self.MAX_FINDINGS:
                return
            findings.append({
                "severity": severity,
                "kind": kind,
                "flow_id": flow.id,
                "sequence": flow.sequence,
                "method": flow.method,
                "url": flow.url[:2000],
                "detail": detail[:500],
            })

        for flow in rows:
            duration = max(0.0, float(flow.duration_ms or 0.0))
            durations.append(duration)
            method = str(flow.method or "UNKNOWN").upper()
            methods[method] = methods.get(method, 0) + 1
            host = str(flow.host or "").casefold()
            if host:
                host_row = hosts.setdefault(host, {"flows": 0, "bytes": 0, "errors": 0, "server_errors": 0})
                host_row["flows"] += 1
                host_row["bytes"] += max(0, int(flow.request_bytes)) + max(0, int(flow.response_bytes))
                host_row["errors"] += int(bool(flow.error))
            status = flow.status
            if isinstance(status, int) and 100 <= status <= 599:
                statuses[f"{status // 100}xx"] += 1
                if status >= 500:
                    if host:
                        hosts[host]["server_errors"] += 1
                    finding(flow, "high", "server-error", f"HTTP {status}")
            else:
                statuses["other"] += 1
            if flow.error:
                finding(flow, "high", "transport-error", str(flow.error))
            if flow.dropped:
                finding(flow, "info", "operator-drop", "Flow was explicitly dropped")
            if duration >= self.SLOW_MS:
                finding(flow, "medium", "slow-response", f"duration={duration:.1f} ms")
            if int(flow.response_bytes or 0) >= self.LARGE_RESPONSE_BYTES:
                finding(flow, "medium", "large-response", f"response_bytes={int(flow.response_bytes)}")

            response_headers: list[tuple[str, str]] = []
            if flow.response_raw:
                try:
                    _line, response_headers, _body = _parse_raw_message(flow.response_raw)
                except ValueError:
                    response_headers = []
            if response_headers:
                header_map = {str(name).casefold(): str(value) for name, value in response_headers}
                content_type = header_map.get("content-type", "").split(";", 1)[0].strip().casefold()
                if content_type:
                    content_types[content_type] = content_types.get(content_type, 0) + 1
                if flow.scheme.casefold() == "https" and not flow.tunnel:
                    missing = [name for name in ("strict-transport-security", "content-security-policy") if name not in header_map]
                    if missing:
                        finding(flow, "low", "security-header-gap", "missing=" + ",".join(missing))

        host_rows = [
            {"host": host, **metrics}
            for host, metrics in sorted(hosts.items(), key=lambda item: (-item[1]["bytes"], -item[1]["flows"], item[0]))[:100]
        ]
        content_rows = [
            {"content_type": name, "flows": count}
            for name, count in sorted(content_types.items(), key=lambda item: (-item[1], item[0]))[:50]
        ]
        findings.sort(key=lambda row: ({"high": 0, "medium": 1, "low": 2, "info": 3}.get(str(row["severity"]), 9), int(row["sequence"])))
        return ProxyProfilerSnapshot(
            flow_count=len(rows),
            completed_count=sum(1 for item in rows if bool(item.completed_at)),
            error_count=sum(1 for item in rows if bool(item.error)),
            dropped_count=sum(1 for item in rows if bool(item.dropped)),
            tls_intercepted_count=sum(1 for item in rows if bool(item.tls_intercepted)),
            tunnel_count=sum(1 for item in rows if bool(item.tunnel)),
            rewritten_flow_count=sum(1 for item in rows if bool(item.rewrite_rule_ids)),
            request_bytes=sum(max(0, int(item.request_bytes)) for item in rows),
            response_bytes=sum(max(0, int(item.response_bytes)) for item in rows),
            duration_p50_ms=self._percentile(durations, 0.50),
            duration_p95_ms=self._percentile(durations, 0.95),
            duration_p99_ms=self._percentile(durations, 0.99),
            duration_max_ms=round(max(durations, default=0.0), 3),
            methods=dict(sorted(methods.items())),
            status_families=statuses,
            hosts=host_rows,
            content_types=content_rows,
            findings=findings,
        )
