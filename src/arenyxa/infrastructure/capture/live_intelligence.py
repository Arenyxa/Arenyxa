from __future__ import annotations

import logging
import threading
from collections import Counter, defaultdict, deque
from typing import Any, Iterable, Mapping

from arenyxa.domain.models import NetworkEvent
from arenyxa.infrastructure.capture.detection import DetectionAlert, PassiveDetectionEngine, ThreatHunter, _mapping_event
from arenyxa.infrastructure.capture.event_stream import BoundedEventStream

LOGGER = logging.getLogger(__name__)


class LiveIntelligencePipeline:
    """Capture listener that turns committed events into stream records and alerts."""

    def __init__(self, stream: BoundedEventStream | None = None, *, alert_capacity: int = 20_000) -> None:
        self.stream = stream or BoundedEventStream()
        self.detector = PassiveDetectionEngine()
        self.hunter = ThreatHunter()
        self._lock = threading.RLock()
        self._alerts: dict[str, deque[DetectionAlert]] = defaultdict(lambda: deque(maxlen=max(128, int(alert_capacity))))
        self._event_counts: Counter[str] = Counter()
        self._protocol_counts: dict[str, Counter[str]] = defaultdict(Counter)
        self._host_counts: dict[str, Counter[str]] = defaultdict(Counter)
        self._byte_counts: Counter[str] = Counter()
        self._batch_count = 0
        self._processing_errors = 0

    def on_capture_batch(self, events: list[NetworkEvent]) -> None:
        if not events:
            return
        with self._lock:
            self._batch_count += 1
        for event in events:
            try:
                self._process_event(event)
            except Exception:
                with self._lock:
                    self._processing_errors += 1
                LOGGER.exception("Live intelligence processing failed for event %s", getattr(event, "id", ""))

    def _process_event(self, event: NetworkEvent) -> None:
        session_id = str(event.session_id or "")
        protocol = str(event.protocol or "unknown").casefold() or "unknown"
        with self._lock:
            self._event_counts[session_id] += 1
            self._protocol_counts[session_id][protocol] += 1
            if event.host:
                self._host_counts[session_id][str(event.host)] += 1
            destination = str((event.metadata or {}).get("dst_ip") or (event.metadata or {}).get("destination_ip") or "").strip()
            if destination and destination != event.host:
                self._host_counts[session_id][destination] += 1
            self._byte_counts[session_id] += max(0, int(event.size or 0))
        self.stream.publish(f"capture.{session_id}.event", {
            "event_id": event.id,
            "session_id": session_id,
            "timestamp": event.timestamp,
            "protocol": event.protocol,
            "direction": event.direction,
            "size": event.size,
            "host": event.host,
            "status": event.status,
            "flow_ref": event.flow_ref,
        })
        alerts = self.detector.inspect(event)
        if alerts:
            with self._lock:
                target = self._alerts[session_id]
                target.extend(alerts)
            for alert in alerts:
                self.stream.publish(f"capture.{session_id}.alert", alert.snapshot())

    def alerts(self, session_id: str, *, limit: int = 1000) -> list[dict[str, Any]]:
        bounded = max(1, min(100_000, int(limit)))
        with self._lock:
            rows = tuple(self._alerts.get(str(session_id), ()))
        return [item.snapshot() for item in rows[-bounded:]]

    def analyze_events(self, session_id: str, events: Iterable[NetworkEvent | Mapping[str, Any]], *, limit: int = 100_000) -> dict[str, Any]:
        normalized: list[NetworkEvent] = []
        protocols: Counter[str] = Counter()
        hosts: Counter[str] = Counter()
        total_bytes = 0
        errors = 0
        alerts: list[dict[str, Any]] = []
        bounded = max(1, min(1_000_000, int(limit)))
        for raw in events:
            event = raw if isinstance(raw, NetworkEvent) else _mapping_event(raw)
            normalized.append(event)
            protocol = str(event.protocol or "unknown").casefold() or "unknown"
            protocols[protocol] += 1
            if event.host:
                hosts[str(event.host)] += 1
            total_bytes += max(0, int(event.size or 0))
            if isinstance(event.status, int) and event.status >= 400:
                errors += 1
            alerts.extend(item.snapshot() for item in self.detector.inspect(event))
            if len(normalized) >= bounded:
                break
        hunt = self.hunter.hunt(normalized, limit=bounded)
        return {
            "session_id": str(session_id),
            "events": len(normalized),
            "bytes": total_bytes,
            "error_events": errors,
            "protocols": dict(protocols.most_common()),
            "top_hosts": [{"host": host, "events": count} for host, count in hosts.most_common(20)],
            "alerts": alerts[:5000],
            "alert_count": len(alerts),
            "threat_hunt": hunt,
        }

    def live_snapshot(self, session_id: str = "") -> dict[str, Any]:
        with self._lock:
            if session_id:
                return {
                    "session_id": session_id,
                    "events": self._event_counts[session_id],
                    "bytes": self._byte_counts[session_id],
                    "protocols": dict(self._protocol_counts[session_id].most_common()),
                    "top_hosts": [
                        {"host": host, "events": count}
                        for host, count in self._host_counts[session_id].most_common(20)
                    ],
                    "alerts": len(self._alerts.get(session_id, ())),
                    "stream": self.stream.stats(),
                    "processing_errors": self._processing_errors,
                }
            return {
                "sessions": len(self._event_counts),
                "events": sum(self._event_counts.values()),
                "bytes": sum(self._byte_counts.values()),
                "alerts": sum(len(rows) for rows in self._alerts.values()),
                "batches": self._batch_count,
                "processing_errors": self._processing_errors,
                "stream": self.stream.stats(),
            }
