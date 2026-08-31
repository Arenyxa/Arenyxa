from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import fnmatch
import json
import logging
import os
import threading
import time
import uuid
from collections import deque
from dataclasses import asdict, field, replace
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping

from arenyxa.compat import dataclass
from arenyxa.domain.models import utc_now
from arenyxa.infrastructure.atomic_io import atomic_write_json


LOGGER = logging.getLogger(__name__)


class TrafficEvent(str, Enum):
    HTTP_REQUEST = "HTTP_REQUEST"
    HTTP_RESPONSE = "HTTP_RESPONSE"
    TLS_ESTABLISHED = "TLS_ESTABLISHED"
    WEBSOCKET_MESSAGE = "WEBSOCKET_MESSAGE"


class TrafficAction(str, Enum):
    RECORD = "RECORD"
    MODIFY = "MODIFY"
    EXPORT = "EXPORT"
    ALERT = "ALERT"
    ANALYZE = "ANALYZE"


@dataclass(frozen=True, slots=True)
class TrafficAutomationRule:
    id: str
    name: str
    event: TrafficEvent
    actions: tuple[TrafficAction, ...]
    enabled: bool = True
    host_pattern: str = "*"
    url_pattern: str = "*"
    method_pattern: str = "*"
    status_pattern: str = "*"
    parameters: dict[str, Any] = field(default_factory=dict)
    priority: int = 100
    stop_processing: bool = False
    cooldown_seconds: float = 0.0
    max_executions_per_minute: int = 0
    failure_policy: str = "continue"
    field_patterns: dict[str, str] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)

    def validate(self) -> None:
        if not self.id or len(self.id) > 96 or not self.name.strip() or len(self.name) > 160:
            raise ValueError("Traffic automation rule identity is invalid")
        if not self.actions or len(self.actions) > 8:
            raise ValueError("Traffic automation rule requires 1-8 actions")
        for pattern in (self.host_pattern, self.url_pattern, self.method_pattern, self.status_pattern):
            if len(str(pattern)) > 4096:
                raise ValueError("Traffic automation pattern exceeds its safety budget")
        if len(json.dumps(self.parameters, ensure_ascii=False, default=str).encode("utf-8")) > 256 * 1024:
            raise ValueError("Traffic automation parameters exceed the safety budget")
        if not -10_000 <= int(self.priority) <= 10_000:
            raise ValueError("Traffic automation priority is outside the supported range")
        if not 0.0 <= float(self.cooldown_seconds) <= 86_400.0:
            raise ValueError("Traffic automation cooldown is outside the supported range")
        if not 0 <= int(self.max_executions_per_minute) <= 60_000:
            raise ValueError("Traffic automation rate limit is outside the supported range")
        if str(self.failure_policy).casefold() not in {"continue", "stop_rule", "stop_event"}:
            raise ValueError("Traffic automation failure policy is invalid")
        if len(self.field_patterns) > 32:
            raise ValueError("Traffic automation field pattern count exceeds the safety budget")
        for key, pattern in self.field_patterns.items():
            if not str(key).strip() or len(str(key)) > 160 or len(str(pattern)) > 4096:
                raise ValueError("Traffic automation field pattern is invalid")

    def matches(self, event: TrafficEvent, payload: Mapping[str, Any]) -> bool:
        base = bool(
            self.enabled
            and self.event is event
            and fnmatch.fnmatchcase(str(payload.get("host") or "").casefold(), self.host_pattern.casefold())
            and fnmatch.fnmatchcase(str(payload.get("url") or "").casefold(), self.url_pattern.casefold())
            and fnmatch.fnmatchcase(str(payload.get("method") or "").upper(), self.method_pattern.upper())
            and fnmatch.fnmatchcase(str(payload.get("status") or ""), self.status_pattern)
        )
        if not base:
            return False
        for key, pattern in self.field_patterns.items():
            if not fnmatch.fnmatchcase(str(payload.get(str(key)) or ""), str(pattern)):
                return False
        return True

    def snapshot(self) -> dict[str, Any]:
        value = asdict(self)
        value["event"] = self.event.value
        value["actions"] = [item.value for item in self.actions]
        return value


class TrafficAutomationEngine:
    """Persistent traffic-event rule engine with explicit action callbacks."""

    MAX_RULES = 2_000

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._rules: list[TrafficAutomationRule] = []
        self._callbacks: dict[TrafficAction, Callable[[Mapping[str, Any], Mapping[str, Any]], Any]] = {}
        self._execution_windows: dict[str, deque[float]] = {}
        self._last_executed: dict[str, float] = {}
        self._success_count: dict[str, int] = {}
        self._failure_count: dict[str, int] = {}
        self._load()

    def register(
        self,
        action: TrafficAction,
        callback: Callable[[Mapping[str, Any], Mapping[str, Any]], Any],
    ) -> None:
        with self._lock:
            self._callbacks[action] = callback

    def _load(self) -> None:
        if not self.path.is_file():
            return
        value = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(value, list) or len(value) > self.MAX_RULES:
            raise ValueError("Traffic automation registry is invalid")
        rules: list[TrafficAutomationRule] = []
        for row in value:
            if not isinstance(row, Mapping):
                raise ValueError("Traffic automation rule is invalid")
            rule = TrafficAutomationRule(
                id=str(row.get("id") or ""),
                name=str(row.get("name") or ""),
                event=TrafficEvent(str(row.get("event") or "HTTP_REQUEST").upper()),
                actions=tuple(TrafficAction(str(item).upper()) for item in row.get("actions", [])),
                enabled=bool(row.get("enabled", True)),
                host_pattern=str(row.get("host_pattern") or "*"),
                url_pattern=str(row.get("url_pattern") or "*"),
                method_pattern=str(row.get("method_pattern") or "*"),
                status_pattern=str(row.get("status_pattern") or "*"),
                parameters=dict(row.get("parameters") or {}),
                priority=int(row.get("priority", 100)),
                stop_processing=bool(row.get("stop_processing", False)),
                cooldown_seconds=float(row.get("cooldown_seconds", 0.0)),
                max_executions_per_minute=int(row.get("max_executions_per_minute", 0)),
                failure_policy=str(row.get("failure_policy") or "continue").casefold(),
                field_patterns={str(key): str(value) for key, value in dict(row.get("field_patterns") or {}).items()},
                created_at=str(row.get("created_at") or utc_now()),
            )
            rule.validate()
            rules.append(rule)
        self._rules = rules

    def _save(self) -> None:
        atomic_write_json(self.path, [item.snapshot() for item in self._rules])

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            return [item.snapshot() for item in self._rules]

    def add(
        self,
        name: str,
        event: str,
        actions: list[str] | tuple[str, ...],
        **options: Any,
    ) -> dict[str, Any]:
        rule = TrafficAutomationRule(
            id=uuid.uuid4().hex,
            name=str(name).strip(),
            event=TrafficEvent(str(event).upper()),
            actions=tuple(TrafficAction(str(item).upper()) for item in actions),
            host_pattern=str(options.get("host_pattern") or "*"),
            url_pattern=str(options.get("url_pattern") or "*"),
            method_pattern=str(options.get("method_pattern") or "*"),
            status_pattern=str(options.get("status_pattern") or "*"),
            parameters=dict(options.get("parameters") or {}),
            priority=int(options.get("priority", 100)),
            stop_processing=bool(options.get("stop_processing", False)),
            cooldown_seconds=float(options.get("cooldown_seconds", 0.0)),
            max_executions_per_minute=int(options.get("max_executions_per_minute", 0)),
            failure_policy=str(options.get("failure_policy") or "continue").casefold(),
            field_patterns={str(key): str(value) for key, value in dict(options.get("field_patterns") or {}).items()},
        )
        rule.validate()
        with self._lock:
            if len(self._rules) >= self.MAX_RULES:
                raise ValueError("Traffic automation registry reached its safety limit")
            self._rules.append(rule)
            self._save()
        return rule.snapshot()

    def remove(self, rule_id: str) -> bool:
        with self._lock:
            key = str(rule_id)
            before = len(self._rules)
            self._rules = [rule for rule in self._rules if rule.id != key]
            changed = before != len(self._rules)
            if changed:
                self._clear_rule_state_locked(key)
                self._save()
            return changed

    def _clear_rule_state_locked(self, rule_id: str) -> None:
        key = str(rule_id)
        self._execution_windows.pop(key, None)
        self._last_executed.pop(key, None)
        self._success_count.pop(key, None)
        self._failure_count.pop(key, None)

    def set_enabled(self, rule_id: str, enabled: bool) -> bool:
        with self._lock:
            for index, rule in enumerate(self._rules):
                if rule.id == str(rule_id):
                    self._rules[index] = replace(rule, enabled=bool(enabled))
                    self._clear_rule_state_locked(rule.id)
                    self._save()
                    return True
        return False

    def update(self, rule_id: str, **changes: Any) -> dict[str, Any] | None:
        """Atomically update the supported mutable rule controls."""
        allowed = {
            "name", "enabled", "host_pattern", "url_pattern", "method_pattern", "status_pattern",
            "parameters", "priority", "stop_processing", "cooldown_seconds",
            "max_executions_per_minute", "failure_policy", "field_patterns",
        }
        unknown = set(changes) - allowed
        if unknown:
            raise ValueError("Unsupported traffic automation fields: " + ", ".join(sorted(unknown)))
        with self._lock:
            for index, rule in enumerate(self._rules):
                if rule.id != str(rule_id):
                    continue
                normalized = dict(changes)
                if "name" in normalized:
                    normalized["name"] = str(normalized["name"]).strip()
                if "parameters" in normalized:
                    normalized["parameters"] = dict(normalized["parameters"] or {})
                if "field_patterns" in normalized:
                    normalized["field_patterns"] = {
                        str(key): str(value) for key, value in dict(normalized["field_patterns"] or {}).items()
                    }
                if "priority" in normalized:
                    normalized["priority"] = int(normalized["priority"])
                if "cooldown_seconds" in normalized:
                    normalized["cooldown_seconds"] = float(normalized["cooldown_seconds"])
                if "max_executions_per_minute" in normalized:
                    normalized["max_executions_per_minute"] = int(normalized["max_executions_per_minute"])
                if "failure_policy" in normalized:
                    normalized["failure_policy"] = str(normalized["failure_policy"]).casefold()
                candidate = replace(rule, **normalized)
                candidate.validate()
                self._rules[index] = candidate
                self._clear_rule_state_locked(rule.id)
                self._save()
                return candidate.snapshot()
        return None

    def preview(self, event: TrafficEvent, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Return deterministic matching/ordering information without executing actions."""
        with self._lock:
            rules = sorted(self._rules, key=lambda item: (item.priority, item.created_at, item.id))
        result: list[dict[str, Any]] = []
        for rule in rules:
            if rule.matches(event, payload):
                result.append({
                    "rule_id": rule.id,
                    "name": rule.name,
                    "priority": rule.priority,
                    "actions": [action.value for action in rule.actions],
                    "stop_processing": rule.stop_processing,
                })
                if rule.stop_processing:
                    break
        return result

    def execution_stats(self) -> dict[str, dict[str, int | float | None]]:
        with self._lock:
            identifiers = {rule.id for rule in self._rules}
            return {
                rule_id: {
                    "success": int(self._success_count.get(rule_id, 0)),
                    "failure": int(self._failure_count.get(rule_id, 0)),
                    "last_executed_monotonic": self._last_executed.get(rule_id),
                    "executions_last_minute": len(self._execution_windows.get(rule_id, ())),
                }
                for rule_id in identifiers
            }

    def _rule_is_current_locked(self, rule: TrafficAutomationRule) -> bool:
        return any(candidate is rule for candidate in self._rules)

    def _increment_outcome_locked(self, rule: TrafficAutomationRule, *, success: bool) -> None:
        if not self._rule_is_current_locked(rule):
            return
        target = self._success_count if success else self._failure_count
        target[rule.id] = target.get(rule.id, 0) + 1

    def _reserve_execution(self, rule: TrafficAutomationRule, now: float) -> tuple[bool, str]:
        with self._lock:
            if not self._rule_is_current_locked(rule):
                return False, "stale"
            last = self._last_executed.get(rule.id)
            if last is not None and rule.cooldown_seconds > 0 and now - last < rule.cooldown_seconds:
                return False, "cooldown"
            window = self._execution_windows.setdefault(rule.id, deque())
            while window and now - window[0] >= 60.0:
                window.popleft()
            if rule.max_executions_per_minute > 0 and len(window) >= rule.max_executions_per_minute:
                return False, "rate_limit"
            window.append(now)
            self._last_executed[rule.id] = now
            return True, "ready"

    def process(self, event: TrafficEvent, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Run matching actions with ordering, throttling, and explicit failure policy."""
        with self._lock:
            rules = sorted(self._rules, key=lambda item: (item.priority, item.created_at, item.id))
            callbacks = dict(self._callbacks)
        results: list[dict[str, Any]] = []
        for rule in rules:
            if not rule.matches(event, payload):
                continue
            reserved, reason = self._reserve_execution(rule, time.monotonic())
            if not reserved:
                if reason == "stale":
                    continue
                results.append({
                    "rule_id": rule.id,
                    "action": "RULE",
                    "ok": False,
                    "error_code": "TRAFFIC_AUTOMATION_THROTTLED",
                    "reason": reason,
                })
                if rule.stop_processing:
                    break
                continue

            stop_event = False
            for action in rule.actions:
                callback = callbacks.get(action)
                if callback is None:
                    with self._lock:
                        self._increment_outcome_locked(rule, success=False)
                    results.append({
                        "rule_id": rule.id,
                        "action": action.value,
                        "ok": False,
                        "error_code": "TRAFFIC_AUTOMATION_HANDLER_MISSING",
                    })
                    if rule.failure_policy in {"stop_rule", "stop_event"}:
                        stop_event = rule.failure_policy == "stop_event"
                        break
                    continue
                try:
                    value = callback(payload, rule.parameters)
                    with self._lock:
                        self._increment_outcome_locked(rule, success=True)
                    results.append({
                        "rule_id": rule.id,
                        "action": action.value,
                        "ok": True,
                        "result": value,
                    })
                except Exception as exc:
                    with self._lock:
                        self._increment_outcome_locked(rule, success=False)
                    LOGGER.exception(
                        "Traffic automation action %s failed for rule %s",
                        action.value,
                        rule.id,
                    )
                    results.append({
                        "rule_id": rule.id,
                        "action": action.value,
                        "ok": False,
                        "error_code": "TRAFFIC_AUTOMATION_ACTION_FAILED",
                        "error_message": str(exc),
                    })
                    if rule.failure_policy in {"stop_rule", "stop_event"}:
                        stop_event = rule.failure_policy == "stop_event"
                        break
            if stop_event:
                break
            if rule.stop_processing:
                break
        return results


__all__ = [
    "TrafficAction",
    "TrafficAutomationEngine",
    "TrafficAutomationRule",
    "TrafficEvent",
    "configure_default_traffic_handlers",
]


def configure_default_traffic_handlers(engine: TrafficAutomationEngine, root: Path) -> None:
    """Install local, bounded handlers used by the desktop and unified CLI."""
    data_root = Path(root)
    data_root.mkdir(parents=True, exist_ok=True)
    event_log = data_root / "traffic-events.jsonl"
    export_root = data_root / "exports"
    export_root.mkdir(parents=True, exist_ok=True)
    write_lock = threading.RLock()

    def safe_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
        allowed = {
            "id", "flow_id", "event", "timestamp", "host", "url", "method", "status",
            "phase", "protocol", "size", "latency_ms", "tls_intercepted", "tunnel",
        }
        return {str(key): value for key, value in payload.items() if str(key) in allowed}

    def record(payload: Mapping[str, Any], _parameters: Mapping[str, Any]) -> dict[str, Any]:
        row = {"recorded_at": utc_now(), **safe_payload(payload)}
        encoded = (json.dumps(row, ensure_ascii=False, separators=(",", ":"), default=str) + "\n").encode("utf-8")
        with write_lock:
            descriptor = os.open(str(event_log), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(descriptor, "ab") as stream:
                stream.write(encoded)
                stream.flush()
                try:
                    os.fsync(stream.fileno())
                except OSError:
                    record_current_exception(__name__, 'configure_default_traffic_handlers.record:412')
        return {"recorded": True, "path": str(event_log)}

    def modify(_payload: Mapping[str, Any], parameters: Mapping[str, Any]) -> dict[str, Any]:
        changes = parameters.get("set", {})
        return {"modifications": dict(changes) if isinstance(changes, Mapping) else {}}

    def export(payload: Mapping[str, Any], _parameters: Mapping[str, Any]) -> dict[str, Any]:
        identifier = str(payload.get("id") or payload.get("flow_id") or uuid.uuid4().hex)
        safe_id = "".join(character for character in identifier if character.isalnum() or character in "-_")[:96]
        destination = export_root / f"{safe_id or uuid.uuid4().hex}.json"
        atomic_write_json(destination, {"exported_at": utc_now(), **safe_payload(payload)})
        return {"exported": True, "path": str(destination)}

    engine.register(TrafficAction.RECORD, record)
    engine.register(TrafficAction.MODIFY, modify)
    engine.register(TrafficAction.EXPORT, export)
    engine.register(
        TrafficAction.ALERT,
        lambda payload, parameters: {
            "alert": True,
            "severity": str(parameters.get("severity") or "info"),
            "flow_id": str(payload.get("id") or payload.get("flow_id") or ""),
        },
    )
    engine.register(
        TrafficAction.ANALYZE,
        lambda payload, _parameters: {
            "analysis_triggered": True,
            "flow_id": str(payload.get("id") or payload.get("flow_id") or ""),
        },
    )
