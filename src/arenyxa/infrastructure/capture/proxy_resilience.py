from __future__ import annotations

"""Phase-6 resilience helpers for the Proxy Suite.

This mixin keeps survivability, telemetry, and bounded persistence policy outside the network
protocol implementation so ``proxy.py`` remains below the architecture module-size ceiling.
"""

import logging
from typing import Any

from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.capture.proxy_models import ProxyFlow, ProxySettings
from arenyxa.infrastructure.capture.proxy_persistence import ProxyPersistencePipeline

LOGGER = logging.getLogger(__name__)


class ProxyResilienceMixin:
    """Bounded persistence, memory-pressure and telemetry integration for InterceptingProxy."""

    _performance_telemetry: Any
    settings: ProxySettings
    persistence: ProxyPersistencePipeline

    def _new_persistence_pipeline(self, capacity: int) -> ProxyPersistencePipeline:
        return ProxyPersistencePipeline(
            self.history_store,
            self.archive,
            capacity=capacity,
            error_callback=self._persistence_error,
        )

    def set_performance_telemetry(self, telemetry: Any) -> None:
        self._performance_telemetry = telemetry

    def _persistence_error(self, sink: str, flow: ProxyFlow, exc: BaseException) -> None:
        code = "PROXY_HISTORY_WRITE_FAILED" if sink == "history" else "PROXY_LEGACY_ARCHIVE_WRITE_FAILED"
        telemetry = self._performance_telemetry
        if telemetry is not None:
            telemetry.increment(f"proxy.persistence.{sink}_failures")
        self._emit(
            "error",
            {"code": code, "flow_id": flow.id, "sink": sink, "message": f"{type(exc).__name__}: {exc}"[:512]},
        )

    def _reconfigure_persistence(self, old_capacity: int, settings: ProxySettings) -> None:
        if int(old_capacity) == int(settings.persistence_queue_capacity):
            return
        if not self.persistence.close(float(settings.persistence_flush_timeout_seconds)):
            raise RuntimeError("Proxy persistence pipeline did not quiesce while applying settings")
        self.persistence = self._new_persistence_pipeline(settings.persistence_queue_capacity)

    def apply_memory_pressure(self, level: str) -> dict[str, Any]:
        """Trim only volatile history; durable forensic history is never deleted."""
        normalized = str(level or "normal").strip().casefold()
        target = (
            min(int(self.settings.history_limit), 250)
            if normalized == "critical"
            else min(int(self.settings.history_limit), 1000)
            if normalized in {"warning", "soft"}
            else int(self.settings.history_limit)
        )
        with self._lock:
            before = len(self._history)
            if before > target:
                del self._history[: before - target]
            after = len(self._history)
        return {
            "level": normalized,
            "memory_history_before": before,
            "memory_history_after": after,
            "memory_history_target": target,
            "durable_history_preserved": True,
        }

    def persistence_status(self) -> dict[str, Any]:
        return self.persistence.status()

    def flush_persistence(self, timeout: float | None = None) -> bool:
        budget = self.settings.persistence_flush_timeout_seconds if timeout is None else float(timeout)
        return self.persistence.flush(max(0.0, min(30.0, budget)))

    def _record_completed_proxy_metrics(self, flow: ProxyFlow) -> None:
        telemetry = self._performance_telemetry
        if telemetry is None:
            return
        telemetry.record_latency("proxy.flow", flow.duration_ms)
        telemetry.increment("proxy.flows")
        telemetry.gauge("proxy.request_bytes", float(flow.request_bytes))
        telemetry.gauge("proxy.response_bytes", float(flow.response_bytes))

    def _persist_completed_flow(self, session_id: str, flow: ProxyFlow) -> str:
        try:
            return self.persistence.enqueue(session_id, flow)
        except (RuntimeError, OSError, ArenyxaError) as exc:
            # Closing/failed pipeline: preserve the pre-Phase-6 durable evidence contract.
            LOGGER.exception("Proxy persistence admission failed for %s", flow.id)
            try:
                self.history_store.store(session_id, flow)
            except (OSError, ArenyxaError) as history_exc:
                self._persistence_error("history", flow, history_exc)
            try:
                self.archive.store(flow)
            except OSError as archive_exc:
                self._persistence_error("archive", flow, archive_exc)
            return "synchronous_emergency"

    def _record_persistence_backpressure(self, flow: ProxyFlow, mode: str) -> None:
        telemetry = self._performance_telemetry
        if telemetry is not None:
            state = self.persistence.status()
            telemetry.gauge("proxy.persistence_queue_depth", float(state["queue_depth"]))
        if mode == "queued":
            return
        if telemetry is not None:
            telemetry.increment("proxy.persistence_backpressure")
        self._emit("backpressure", {"flow_id": flow.id, "mode": mode})
