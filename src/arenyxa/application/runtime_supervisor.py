"""Process-local runtime supervision and bounded diagnostic capture."""

from __future__ import annotations

import faulthandler
import json
import logging
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from arenyxa.compat import dataclass
from arenyxa.infrastructure.atomic_io import atomic_write_json
from arenyxa.infrastructure.external_supervisor import ExternalSupervisorClient

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SupervisorIncident:
    component: str
    code: str
    detected_at: float
    blocked_seconds: float
    diagnostic_path: str
    state: dict[str, Any]


class ArenyxaRuntimeSupervisor:
    """Watch UI/async/worker/database/capture liveness without blocking those components."""

    def __init__(
        self,
        diagnostics_dir: Path,
        *,
        event_loop_block_seconds: float = 5.0,
        sample_interval_seconds: float = 0.5,
    ) -> None:
        self.diagnostics_dir = Path(diagnostics_dir)
        self.event_loop_block_seconds = max(1.0, float(event_loop_block_seconds))
        self.sample_interval_seconds = max(0.1, min(5.0, float(sample_interval_seconds)))
        self._heartbeats: dict[str, tuple[float, dict[str, Any]]] = {}
        self._probes: dict[str, Callable[[], Mapping[str, Any]]] = {}
        self._incident_listeners: list[Callable[[SupervisorIncident], None]] = []
        self._incidents: list[SupervisorIncident] = []
        self._reported_stalls: set[tuple[str, int]] = set()
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._external = ExternalSupervisorClient(
            self.diagnostics_dir / "external",
            stale_seconds=self.event_loop_block_seconds,
        )

    def register_probe(self, component: str, probe: Callable[[], Mapping[str, Any]]) -> None:
        with self._lock:
            self._probes[str(component)] = probe

    def register_incident_listener(self, listener: Callable[[SupervisorIncident], None]) -> None:
        with self._lock:
            if listener not in self._incident_listeners:
                self._incident_listeners.append(listener)
                if len(self._incident_listeners) > 16:
                    del self._incident_listeners[:-16]

    def heartbeat(self, component: str, state: Mapping[str, Any] | None = None) -> None:
        component_name = str(component)
        state_copy = dict(state or {})
        now = time.monotonic()
        with self._lock:
            self._heartbeats[component_name] = (now, state_copy)
            self._reported_stalls = {
                key for key in self._reported_stalls if key[0] != component_name
            }
        self._external.heartbeat(component_name, state_copy)

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="arenyxa-runtime-supervisor",
                daemon=True,
            )
            self._external.start()
            self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        with self._lock:
            thread = self._thread
            self._thread = None
        if thread is not None and thread is not threading.current_thread():
            thread.join(max(0.0, float(timeout)))
        self._external.stop(timeout=max(1.0, float(timeout)))

    def incidents(self) -> tuple[SupervisorIncident, ...]:
        with self._lock:
            return tuple(self._incidents)

    def snapshot(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            heartbeat_rows = {
                name: {"age_seconds": max(0.0, now - seen), "state": dict(state)}
                for name, (seen, state) in self._heartbeats.items()
            }
            incident_count = len(self._incidents)
        probes: dict[str, Any] = {}
        for name, probe in self._probe_snapshot():
            try:
                probes[name] = dict(probe())
            except (LookupError, OSError, RuntimeError, TypeError, ValueError) as exc:
                probes[name] = {"healthy": False, "error": f"{type(exc).__name__}: {exc}"[:256]}
        return {
            "running": bool(self._thread and self._thread.is_alive()),
            "event_loop_block_seconds": self.event_loop_block_seconds,
            "heartbeats": heartbeat_rows,
            "probes": probes,
            "incident_count": incident_count,
            "external": self._external.snapshot(),
        }

    def _probe_snapshot(self) -> tuple[tuple[str, Callable[[], Mapping[str, Any]]], ...]:
        with self._lock:
            return tuple(self._probes.items())

    def _run(self) -> None:
        while not self._stop.wait(self.sample_interval_seconds):
            now = time.monotonic()
            with self._lock:
                rows = tuple(self._heartbeats.items())
            for probe_name, probe in self._probe_snapshot():
                external_name = "worker_progress" if probe_name == "worker" else probe_name
                try:
                    probe_state = dict(probe())
                except (LookupError, OSError, RuntimeError, TypeError, ValueError) as exc:
                    probe_state = {
                        "healthy": False,
                        "error": f"{type(exc).__name__}: {exc}"[:256],
                    }
                self._external.heartbeat(external_name, probe_state)
            for component, (seen, state) in rows:
                blocked = now - seen
                if blocked <= self.event_loop_block_seconds:
                    continue
                bucket = int(blocked // self.event_loop_block_seconds)
                key = (component, bucket)
                with self._lock:
                    if key in self._reported_stalls:
                        continue
                    self._reported_stalls.add(key)
                self._record_incident(component, blocked, state)

    def _record_incident(
        self, component: str, blocked_seconds: float, state: Mapping[str, Any]
    ) -> None:
        self.diagnostics_dir.mkdir(parents=True, exist_ok=True)
        timestamp_ns = time.time_ns()
        stem = f"event-loop-block-{component}-{timestamp_ns}"
        stack_path = self.diagnostics_dir / f"{stem}.stacks.log"
        report_path = self.diagnostics_dir / f"{stem}.json"
        try:
            with stack_path.open("w", encoding="utf-8") as stream:
                stream.write(f"Arenyxa runtime incident: {component}\n")
                stream.write(f"blocked_seconds={blocked_seconds:.3f}\n")
                faulthandler.dump_traceback(file=stream, all_threads=True)
        except (OSError, RuntimeError):
            LOGGER.exception("Runtime Supervisor failed to capture thread stacks")
        payload = {
            "schema": "arenyxa.runtime-supervisor-incident/v1",
            "component": component,
            "code": "EVENT_LOOP_BLOCKED",
            "detected_at_unix_ns": timestamp_ns,
            "blocked_seconds": round(blocked_seconds, 3),
            "state": json.loads(json.dumps(dict(state), default=str)),
            "stack_path": str(stack_path),
        }
        try:
            atomic_write_json(report_path, payload)
        except OSError:
            LOGGER.exception("Runtime Supervisor failed to persist incident report")
        incident = SupervisorIncident(
            component=component,
            code="EVENT_LOOP_BLOCKED",
            detected_at=timestamp_ns / 1_000_000_000,
            blocked_seconds=blocked_seconds,
            diagnostic_path=str(report_path),
            state=dict(state),
        )
        with self._lock:
            self._incidents.append(incident)
            if len(self._incidents) > 128:
                del self._incidents[:-128]
            listeners = tuple(self._incident_listeners)
        for listener in listeners:
            try:
                listener(incident)
            except (OSError, RuntimeError, TypeError, ValueError):
                LOGGER.exception("Runtime Supervisor incident listener failed")
        LOGGER.error(
            "Runtime Supervisor detected %s blocked for %.3fs; diagnostics=%s",
            component,
            blocked_seconds,
            report_path,
        )
