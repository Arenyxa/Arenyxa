from __future__ import annotations

"""Always-on survivability state machine for Arenyxa Phase 6.

The manager converts resource pressure and component failure signals into explicit runtime
states.  It never silently converts a security or integrity failure into success: callers get a
state, a reason, admission policy and a bounded transition history suitable for diagnostics.
"""

import json
import threading
import time
from collections import deque
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping

from arenyxa.compat import dataclass
from arenyxa.domain.models import utc_now
from arenyxa.infrastructure.atomic_io import atomic_write_json, read_text_limited


class RuntimeSurvivabilityState(str, Enum):
    NORMAL = "normal"
    DEGRADED = "degraded"
    RESOURCE_PRESSURE = "resource_pressure"
    READ_ONLY = "read_only"
    RECOVERING = "recovering"
    SAFE_MODE = "safe_mode"


@dataclass(frozen=True, slots=True)
class SurvivabilityTransition:
    sequence: int
    timestamp: str
    previous: str
    current: str
    reason: str
    component: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "previous": self.previous,
            "current": self.current,
            "reason": self.reason,
            "component": self.component,
        }


class SurvivabilityManager:
    """Coordinate explicit degraded/read-only/recovery state with bounded persistence."""

    def __init__(
        self,
        data_root: Path,
        *,
        resource_governor: Any = None,
        resource_probe: Any = None,
        safe_mode: bool = False,
        sample_interval_seconds: float = 2.0,
        worker_count: Callable[[], int] | None = None,
        browser_count: Callable[[], int] | None = None,
    ) -> None:
        self.data_root = Path(data_root)
        self.resource_governor = resource_governor
        self.resource_probe = resource_probe
        self.safe_mode = bool(safe_mode)
        self.sample_interval_seconds = max(0.25, min(60.0, float(sample_interval_seconds)))
        self.worker_count = worker_count or (lambda: 0)
        self.browser_count = browser_count or (lambda: 0)
        self._state = RuntimeSurvivabilityState.SAFE_MODE if self.safe_mode else RuntimeSurvivabilityState.NORMAL
        self._reason = "explicit safe mode" if self.safe_mode else "runtime healthy"
        self._component = "bootstrap"
        self._resource: dict[str, Any] = {}
        self._components: dict[str, dict[str, Any]] = {}
        self._pressure_handlers: dict[str, Callable[[str], Mapping[str, Any] | None]] = {}
        self._pressure_actions: dict[str, dict[str, Any]] = {}
        self._history: deque[SurvivabilityTransition] = deque(maxlen=256)
        self._sequence = 0
        self._last_transition_at = utc_now()
        self._previous_persisted_state = self._load_previous_state()
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._transition_locked(self._state, self._reason, self._component, force=True)

    def _load_previous_state(self) -> dict[str, Any]:
        target = self.data_root / "repair" / "survivability_state.json"
        if not target.is_file():
            return {}
        try:
            raw = json.loads(read_text_limited(target, 256 * 1024))
            if not isinstance(raw, dict):
                return {"state": "invalid", "reason": "persisted state was not an object"}
            return {
                "state": str(raw.get("state", "unknown"))[:64],
                "reason": str(raw.get("reason", ""))[:512],
                "component": str(raw.get("component", ""))[:96],
                "updated_at": str(raw.get("updated_at", ""))[:64],
                "sequence": max(0, int(raw.get("sequence", 0) or 0)),
            }
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
            return {"state": "invalid", "reason": "persisted survivability state could not be read"}

    @property
    def state(self) -> RuntimeSurvivabilityState:
        with self._lock:
            return self._state

    def register_pressure_handler(
        self,
        name: str,
        handler: Callable[[str], Mapping[str, Any] | None],
    ) -> None:
        """Register a bounded cache/retention degradation hook for resource pressure."""
        if not callable(handler):
            raise TypeError("pressure handler must be callable")
        key = str(name or "handler")[:96]
        with self._lock:
            if key not in self._pressure_handlers and len(self._pressure_handlers) >= 32:
                raise ValueError("survivability pressure-handler limit reached")
            self._pressure_handlers[key] = handler

    def _apply_pressure_handlers(self, level: str) -> None:
        with self._lock:
            handlers = tuple(self._pressure_handlers.items())
        updates: dict[str, dict[str, Any]] = {}
        for name, handler in handlers:
            started = time.monotonic()
            try:
                result = handler(level)
                updates[name] = {
                    "ok": True,
                    "level": level,
                    "latency_ms": round((time.monotonic() - started) * 1000.0, 3),
                    "result": self._bounded_mapping(result or {}),
                }
            except (LookupError, OSError, RuntimeError, TypeError, ValueError) as exc:
                updates[name] = {
                    "ok": False,
                    "level": level,
                    "latency_ms": round((time.monotonic() - started) * 1000.0, 3),
                    "error": f"{type(exc).__name__}: {exc}"[:512],
                }
        if updates:
            with self._lock:
                self._pressure_actions = updates

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="arenyxa-survivability-monitor",
                daemon=True,
            )
            self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        with self._lock:
            thread = self._thread
            self._thread = None
        if thread is not None and thread is not threading.current_thread():
            thread.join(max(0.0, float(timeout)))

    def _run(self) -> None:
        while not self._stop.wait(self.sample_interval_seconds):
            try:
                self.refresh()
            except (OSError, RuntimeError, TypeError, ValueError):
                self.mark_component(
                    "survivability-monitor",
                    RuntimeSurvivabilityState.DEGRADED,
                    "resource sampling failed",
                )

    def refresh(self) -> dict[str, Any]:
        if self.safe_mode:
            self.transition(RuntimeSurvivabilityState.SAFE_MODE, "explicit safe mode", component="runtime")
            return self.snapshot()
        if self.resource_probe is None or self.resource_governor is None:
            self._derive_from_components()
            return self.snapshot()
        snapshot = self.resource_probe.sample(
            active_browser_instances=max(0, int(self.browser_count())),
            active_workers=max(0, int(self.worker_count())),
        )
        decision = self.resource_governor.evaluate(snapshot)
        resource_payload = {
            "sample": snapshot.to_dict() if hasattr(snapshot, "to_dict") else dict(snapshot),
            "decision": decision.to_dict() if hasattr(decision, "to_dict") else dict(decision),
        }
        with self._lock:
            self._resource = resource_payload
        reasons = set(getattr(decision, "reasons", ()) or ())
        pressure = str(getattr(decision, "pressure", "normal"))
        if "disk-critical" in reasons:
            self._apply_pressure_handlers("critical")
            self.transition(
                RuntimeSurvivabilityState.READ_ONLY,
                "critical free-disk threshold reached; noncritical writes must stop",
                component="resources",
            )
        elif pressure == "critical":
            self._apply_pressure_handlers("critical")
            self.transition(
                RuntimeSurvivabilityState.RESOURCE_PRESSURE,
                "critical CPU/memory/resource pressure; heavy work admission reduced",
                component="resources",
            )
        elif pressure in {"warning", "soft"}:
            self._apply_pressure_handlers("warning")
            self.transition(
                RuntimeSurvivabilityState.RESOURCE_PRESSURE,
                "resource pressure detected; adaptive ceilings reduced",
                component="resources",
            )
        else:
            self._apply_pressure_handlers("normal")
            self._derive_from_components()
        return self.snapshot()

    def mark_component(
        self,
        name: str,
        state: RuntimeSurvivabilityState | str,
        reason: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        component_state = RuntimeSurvivabilityState(str(getattr(state, "value", state)))
        component = str(name or "component")[:96]
        row = {
            "state": component_state.value,
            "reason": str(reason or "")[:512],
            "updated_at": utc_now(),
            "metadata": self._bounded_mapping(metadata or {}),
        }
        with self._lock:
            self._components[component] = row
            if len(self._components) > 128:
                oldest = next(iter(self._components))
                if oldest != component:
                    self._components.pop(oldest, None)
        self._derive_from_components()

    def clear_component(self, name: str) -> None:
        with self._lock:
            self._components.pop(str(name), None)
        self._derive_from_components()

    def begin_recovery(self, reason: str, *, component: str = "recovery") -> None:
        self.transition(RuntimeSurvivabilityState.RECOVERING, reason, component=component)

    def complete_recovery(self, *, component: str = "recovery") -> None:
        self.clear_component(component)
        self._derive_from_components()

    def transition(
        self,
        state: RuntimeSurvivabilityState | str,
        reason: str,
        *,
        component: str = "runtime",
    ) -> None:
        target = RuntimeSurvivabilityState(str(getattr(state, "value", state)))
        with self._lock:
            self._transition_locked(target, str(reason or "")[:512], str(component or "runtime")[:96])

    def _derive_from_components(self) -> None:
        with self._lock:
            if self.safe_mode:
                target = RuntimeSurvivabilityState.SAFE_MODE
                reason = "explicit safe mode"
                component = "runtime"
            else:
                rows = list(self._components.items())
                priority = {
                    RuntimeSurvivabilityState.READ_ONLY.value: 5,
                    RuntimeSurvivabilityState.RECOVERING.value: 4,
                    RuntimeSurvivabilityState.RESOURCE_PRESSURE.value: 3,
                    RuntimeSurvivabilityState.DEGRADED.value: 2,
                    RuntimeSurvivabilityState.NORMAL.value: 1,
                }
                selected = max(rows, key=lambda item: priority.get(str(item[1].get("state")), 1), default=None)
                if selected is None or str(selected[1].get("state")) == RuntimeSurvivabilityState.NORMAL.value:
                    target, reason, component = RuntimeSurvivabilityState.NORMAL, "runtime healthy", "runtime"
                else:
                    component, row = selected
                    target = RuntimeSurvivabilityState(str(row.get("state")))
                    reason = str(row.get("reason") or "component degraded")
            self._transition_locked(target, reason, component)

    def _transition_locked(
        self,
        target: RuntimeSurvivabilityState,
        reason: str,
        component: str,
        *,
        force: bool = False,
    ) -> None:
        previous = self._state
        if not force and previous is target and self._reason == reason and self._component == component:
            return
        self._state = target
        self._reason = reason
        self._component = component
        self._last_transition_at = utc_now()
        self._sequence += 1
        transition = SurvivabilityTransition(
            self._sequence,
            self._last_transition_at,
            previous.value,
            target.value,
            reason,
            component,
        )
        self._history.append(transition)
        self._persist_locked()

    def admission(self) -> dict[str, bool]:
        with self._lock:
            state = self._state
        return {
            "read": True,
            "diagnostics": True,
            "audit": True,
            "new_heavy_jobs": state not in {
                RuntimeSurvivabilityState.READ_ONLY,
                RuntimeSurvivabilityState.RESOURCE_PRESSURE,
                RuntimeSurvivabilityState.RECOVERING,
                RuntimeSurvivabilityState.SAFE_MODE,
            },
            "noncritical_writes": state is not RuntimeSurvivabilityState.READ_ONLY,
            "network_capture": state not in {RuntimeSurvivabilityState.RECOVERING},
        }

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "schema": "arenyxa.survivability/v1",
                "state": self._state.value,
                "reason": self._reason,
                "component": self._component,
                "safe_mode": self.safe_mode,
                "running": bool(self._thread and self._thread.is_alive()),
                "last_transition_at": self._last_transition_at,
                "previous_persisted_state": dict(self._previous_persisted_state),
                "admission": self.admission(),
                "resource": self._resource,
                "pressure_actions": {key: dict(value) for key, value in sorted(self._pressure_actions.items())},
                "components": {key: dict(value) for key, value in sorted(self._components.items())},
                "history": [item.to_dict() for item in self._history],
            }

    def _persist_locked(self) -> None:
        target = self.data_root / "repair" / "survivability_state.json"
        payload = {
            "schema": "arenyxa.survivability-state/v1",
            "state": self._state.value,
            "reason": self._reason,
            "component": self._component,
            "updated_at": self._last_transition_at,
            "sequence": self._sequence,
            "history": [item.to_dict() for item in list(self._history)[-64:]],
        }
        try:
            atomic_write_json(target, payload, ensure_ascii=False, indent=2)
        except OSError:
            # The in-memory state remains authoritative when disk is the failed resource.
            return

    @staticmethod
    def _bounded_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 32:
                break
            name = str(key)[:96]
            if item is None or isinstance(item, (bool, int, float)):
                result[name] = item
            else:
                result[name] = str(item)[:512]
        return result
