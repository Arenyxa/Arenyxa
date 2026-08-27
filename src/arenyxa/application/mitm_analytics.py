from __future__ import annotations

from dataclasses import asdict, dataclass
from itertools import islice
from typing import Any, Iterable

from arenyxa.infrastructure.capture.mitm_engine import MitmEvent


@dataclass(slots=True)
class MitmAnalyticsSnapshot:
    event_count: int
    unique_flows: int
    intercepted_events: int
    replay_events: int
    total_bytes: int
    protocols: list[dict[str, Any]]
    phases: dict[str, int]
    directions: dict[str, int]
    status_families: dict[str, int]
    event_types: dict[str, int]
    methods: dict[str, int]
    content_types: list[dict[str, Any]]
    endpoints: list[dict[str, Any]]
    transports: dict[str, dict[str, int]]
    anomaly_severity: dict[str, int]
    hosts: list[dict[str, Any]]
    flow_activity: list[dict[str, Any]]
    anomalies: list[dict[str, Any]]

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


class MitmFlowAnalyzer:
    MAX_EVENTS = 100000

    def analyze(self, events: Iterable[MitmEvent], *, limit: int = 50000) -> MitmAnalyticsSnapshot:
        rows = list(islice(events, max(1, min(int(limit), self.MAX_EVENTS))))
        protocols: dict[str, dict[str, int]] = {}
        phases: dict[str, int] = {}
        directions: dict[str, int] = {}
        event_types: dict[str, int] = {}
        methods: dict[str, int] = {}
        content_types: dict[str, int] = {}
        endpoints: dict[str, dict[str, int]] = {}
        transports: dict[str, dict[str, int]] = {}
        severity = {"high": 0, "medium": 0, "low": 0, "info": 0}
        hosts: dict[str, dict[str, int]] = {}
        flows: dict[str, dict[str, Any]] = {}
        statuses = {"1xx": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
        anomalies: list[dict[str, Any]] = []
        for event in rows:
            protocol = str(event.protocol or "unknown").upper()
            phase = str(event.phase or "unknown").casefold()
            direction = str(event.direction or "unknown").casefold()
            size = max(0, int(event.size or 0))
            proto = protocols.setdefault(protocol, {"events": 0, "bytes": 0, "intercepted": 0, "replay": 0})
            proto["events"] += 1
            proto["bytes"] += size
            proto["intercepted"] += int(bool(event.intercepted))
            proto["replay"] += int(bool(event.replay))
            phases[phase] = phases.get(phase, 0) + 1
            directions[direction] = directions.get(direction, 0) + 1
            event_type = str(event.event or "unknown").casefold()
            event_types[event_type] = event_types.get(event_type, 0) + 1
            method = str(event.method or "").upper()
            if method:
                methods[method] = methods.get(method, 0) + 1
            transport = transports.setdefault(protocol, {"events": 0, "bytes": 0, "flows": 0})
            transport["events"] += 1
            transport["bytes"] += size
            host = str(event.host or "").casefold()
            if host:
                host_row = hosts.setdefault(host, {"events": 0, "bytes": 0, "errors": 0})
                host_row["events"] += 1
                host_row["bytes"] += size
            flow_id = str(event.flow_id or "")
            if flow_id:
                flow = flows.setdefault(flow_id, {
                    "flow_id": flow_id,
                    "events": 0,
                    "bytes": 0,
                    "protocols": set(),
                    "host": host,
                    "intercepted": False,
                    "replay": False,
                })
                flow["events"] += 1
                flow["bytes"] += size
                flow["protocols"].add(protocol)
                flow["intercepted"] = bool(flow["intercepted"] or event.intercepted)
                flow["replay"] = bool(flow["replay"] or event.replay)
            status = event.status
            if isinstance(status, int) and 100 <= status <= 599:
                statuses[f"{status // 100}xx"] += 1
                if status >= 500 and len(anomalies) < 200:
                    anomalies.append({"severity": "high", "sequence": event.sequence, "flow_id": flow_id, "kind": "server-error", "status": status, "url": event.url[:2000]}); severity["high"] += 1
                    if host:
                        hosts[host]["errors"] += 1
            else:
                statuses["other"] += 1
            payload = dict(event.payload or {})
            content_type = str(payload.get("content_type") or payload.get("content-type") or "").split(";", 1)[0].strip().casefold()
            if content_type:
                content_types[content_type] = content_types.get(content_type, 0) + 1
            endpoint_key = str(event.url or host or "").strip()
            if endpoint_key:
                endpoint = endpoints.setdefault(endpoint_key[:2000], {"events": 0, "bytes": 0, "errors": 0})
                endpoint["events"] += 1
                endpoint["bytes"] += size
                if isinstance(event.status, int) and event.status >= 500:
                    endpoint["errors"] += 1
            error = str(payload.get("error") or payload.get("exception") or "")
            if error and len(anomalies) < 200:
                anomalies.append({"severity": "high", "sequence": event.sequence, "flow_id": flow_id, "kind": "error", "detail": error[:500]}); severity["high"] += 1
            if size >= 16 * 1024 * 1024 and len(anomalies) < 200:
                anomalies.append({"severity": "medium", "sequence": event.sequence, "flow_id": flow_id, "kind": "large-message", "bytes": size}); severity["medium"] += 1
        protocol_rows = [{"protocol": key, **value} for key, value in sorted(protocols.items(), key=lambda item: (-item[1]["events"], item[0]))]
        host_rows = [{"host": key, **value} for key, value in sorted(hosts.items(), key=lambda item: (-item[1]["bytes"], item[0]))[:200]]
        for value in flows.values():
            for proto_name in value["protocols"]:
                if proto_name in transports:
                    transports[proto_name]["flows"] += 1
        flow_rows = []
        for _key, value in sorted(flows.items(), key=lambda item: (-item[1]["bytes"], -item[1]["events"], item[0]))[:1000]:
            row = dict(value)
            row["protocols"] = sorted(row["protocols"])
            flow_rows.append(row)
        return MitmAnalyticsSnapshot(
            event_count=len(rows),
            unique_flows=len(flows),
            intercepted_events=sum(1 for item in rows if item.intercepted),
            replay_events=sum(1 for item in rows if bool(item.replay)),
            total_bytes=sum(max(0, int(item.size or 0)) for item in rows),
            protocols=protocol_rows,
            phases=dict(sorted(phases.items())),
            directions=dict(sorted(directions.items())),
            status_families=statuses,
            event_types=dict(sorted(event_types.items())),
            methods=dict(sorted(methods.items())),
            content_types=[{"content_type": key, "events": value} for key, value in sorted(content_types.items(), key=lambda item: (-item[1], item[0]))[:100]],
            endpoints=[{"endpoint": key, **value} for key, value in sorted(endpoints.items(), key=lambda item: (-item[1]["bytes"], -item[1]["events"], item[0]))[:200]],
            transports={key: value for key, value in sorted(transports.items())},
            anomaly_severity=severity,
            hosts=host_rows,
            flow_activity=flow_rows,
            anomalies=anomalies,
        )


    def flow_timeline(self, events: Iterable[MitmEvent], flow_id: str, *, limit: int = 1000) -> list[dict[str, Any]]:
        """Return a bounded, normalized event timeline for a single captured flow."""
        target = str(flow_id).strip()
        if not target:
            return []
        rows = [event for event in events if str(event.flow_id) == target][: max(1, min(int(limit), 5000))]
        rows.sort(key=lambda event: (float(event.timestamp or 0.0), int(event.sequence or 0)))
        if not rows:
            return []
        origin = float(rows[0].timestamp or 0.0)
        return [{
            "sequence": event.sequence,
            "offset_ms": round(max(0.0, (float(event.timestamp or 0.0) - origin) * 1000.0), 3),
            "event": event.event,
            "protocol": event.protocol,
            "phase": event.phase,
            "direction": event.direction,
            "method": event.method,
            "url": event.url[:2000],
            "status": event.status,
            "size": max(0, int(event.size or 0)),
            "intercepted": bool(event.intercepted),
            "replay": event.replay,
        } for event in rows]
