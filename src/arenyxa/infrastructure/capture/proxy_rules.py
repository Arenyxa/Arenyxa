from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import fnmatch
import json
import os
import threading
import uuid
from dataclasses import asdict, field
from enum import Enum
from pathlib import Path
from typing import Any

from arenyxa.compat import dataclass
from arenyxa.domain.models import utc_now
from arenyxa.infrastructure.atomic_io import atomic_write_json
from arenyxa.infrastructure.capture.proxy_transport import _assemble_message, _parse_raw_message


class InterceptAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    MODIFY = "MODIFY"
    PAUSE = "PAUSE"


@dataclass(frozen=True, slots=True)
class InterceptRule:
    id: str
    name: str
    action: InterceptAction
    phase: str = "both"
    enabled: bool = True
    priority: int = 100
    host_pattern: str = "*"
    url_pattern: str = "*"
    method_pattern: str = "*"
    header_pattern: str = "*"
    body_pattern: str = "*"
    replacement: str = ""
    created_at: str = field(default_factory=utc_now)

    def validate(self) -> None:
        if not self.id or len(self.id) > 96:
            raise ValueError("InterceptRule id is invalid")
        if not self.name.strip() or len(self.name) > 160:
            raise ValueError("InterceptRule name is invalid")
        if self.phase not in {"request", "response", "both"}:
            raise ValueError("InterceptRule phase must be request, response, or both")
        if not 0 <= int(self.priority) <= 100_000:
            raise ValueError("InterceptRule priority is outside the safe range")
        for value, label, limit in (
            (self.host_pattern, "host", 512),
            (self.url_pattern, "URL", 4096),
            (self.method_pattern, "method", 64),
            (self.header_pattern, "header", 4096),
            (self.body_pattern, "body", 8192),
            (self.replacement, "replacement", 1024 * 1024),
        ):
            if not isinstance(value, str) or len(value.encode("utf-8", errors="replace")) > limit:
                raise ValueError(f"InterceptRule {label} pattern exceeds its safety budget")

    def matches(self, phase: str, method: str, host: str, url: str, raw: bytes) -> bool:
        if not self.enabled or self.phase not in {phase, "both"}:
            return False
        if not fnmatch.fnmatchcase(str(host).casefold(), self.host_pattern.casefold()):
            return False
        if not fnmatch.fnmatchcase(str(url).casefold(), self.url_pattern.casefold()):
            return False
        if not fnmatch.fnmatchcase(str(method).upper(), self.method_pattern.upper()):
            return False
        try:
            _line, headers, body = _parse_raw_message(raw)
        except ValueError:
            headers, body = [], b""
        header_text = "\n".join(f"{name}: {value}" for name, value in headers)[:64 * 1024]
        if self.header_pattern != "*" and not fnmatch.fnmatchcase(header_text.casefold(), self.header_pattern.casefold()):
            return False
        if self.body_pattern != "*":
            body_text = body[:1024 * 1024].decode("utf-8", errors="replace")
            if not fnmatch.fnmatchcase(body_text.casefold(), self.body_pattern.casefold()):
                return False
        return True

    def snapshot(self) -> dict[str, Any]:
        value = asdict(self)
        value["action"] = self.action.value
        return value


@dataclass(frozen=True, slots=True)
class InterceptDecision:
    action: InterceptAction
    raw: bytes
    rule_id: str = ""
    rule_name: str = ""


class InterceptRuleEngine:
    """Ordered, bounded InterceptRule registry shared by GUI and CLI."""

    MAX_RULES = 1_000

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._rules: list[InterceptRule] = []
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(payload, list) or len(payload) > self.MAX_RULES:
                raise ValueError("InterceptRule registry is invalid")
            rules: list[InterceptRule] = []
            for row in payload:
                if not isinstance(row, dict):
                    raise ValueError("InterceptRule entry is invalid")
                rule = InterceptRule(
                    id=str(row.get("id") or ""),
                    name=str(row.get("name") or ""),
                    action=InterceptAction(str(row.get("action") or "PAUSE").upper()),
                    phase=str(row.get("phase") or "both").casefold(),
                    enabled=bool(row.get("enabled", True)),
                    priority=int(row.get("priority", 100)),
                    host_pattern=str(row.get("host_pattern") or "*"),
                    url_pattern=str(row.get("url_pattern") or "*"),
                    method_pattern=str(row.get("method_pattern") or "*"),
                    header_pattern=str(row.get("header_pattern") or "*"),
                    body_pattern=str(row.get("body_pattern") or "*"),
                    replacement=str(row.get("replacement") or ""),
                    created_at=str(row.get("created_at") or utc_now()),
                )
                rule.validate()
                rules.append(rule)
            self._rules = sorted(rules, key=lambda item: (item.priority, item.created_at, item.id))
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
            backup = self.path.with_suffix(self.path.suffix + f".corrupt-{uuid.uuid4().hex[:8]}")
            try:
                os.replace(self.path, backup)
            except OSError:
                record_current_exception(__name__, 'InterceptRuleEngine._load:143')
            self._rules = []

    def _save(self) -> None:
        atomic_write_json(self.path, [rule.snapshot() for rule in self._rules])

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            return [rule.snapshot() for rule in self._rules]

    def add(
        self,
        name: str,
        action: str,
        *,
        phase: str = "both",
        priority: int = 100,
        host_pattern: str = "*",
        url_pattern: str = "*",
        method_pattern: str = "*",
        header_pattern: str = "*",
        body_pattern: str = "*",
        replacement: str = "",
    ) -> dict[str, Any]:
        rule = InterceptRule(
            id=uuid.uuid4().hex,
            name=str(name).strip(),
            action=InterceptAction(str(action).upper()),
            phase=str(phase).casefold(),
            priority=int(priority),
            host_pattern=str(host_pattern) or "*",
            url_pattern=str(url_pattern) or "*",
            method_pattern=str(method_pattern) or "*",
            header_pattern=str(header_pattern) or "*",
            body_pattern=str(body_pattern) or "*",
            replacement=str(replacement),
        )
        rule.validate()
        with self._lock:
            if len(self._rules) >= self.MAX_RULES:
                raise ValueError("InterceptRule registry reached its safety limit")
            self._rules.append(rule)
            self._rules.sort(key=lambda item: (item.priority, item.created_at, item.id))
            self._save()
        return rule.snapshot()

    def remove(self, rule_id: str) -> bool:
        with self._lock:
            before = len(self._rules)
            self._rules = [rule for rule in self._rules if rule.id != str(rule_id)]
            changed = before != len(self._rules)
            if changed:
                self._save()
            return changed

    @staticmethod
    def _modify(rule: InterceptRule, raw: bytes) -> bytes:
        if not rule.replacement:
            return raw
        try:
            start_line, headers, body = _parse_raw_message(raw)
        except ValueError:
            return raw
        needle = rule.body_pattern.encode("utf-8") if rule.body_pattern not in {"", "*"} else b""
        replacement = rule.replacement.encode("utf-8")
        updated = body.replace(needle, replacement) if needle else replacement
        normalized: list[tuple[str, str]] = []
        length_written = False
        for name, value in headers:
            if name.casefold() == "content-length":
                if not length_written:
                    normalized.append(("Content-Length", str(len(updated))))
                    length_written = True
            else:
                normalized.append((name, value))
        if updated and not length_written:
            normalized.append(("Content-Length", str(len(updated))))
        return _assemble_message(start_line, normalized, updated)

    def evaluate(self, phase: str, method: str, host: str, url: str, raw: bytes) -> InterceptDecision | None:
        with self._lock:
            rules = list(self._rules)
        for rule in rules:
            if not rule.matches(phase, method, host, url, raw):
                continue
            output = self._modify(rule, raw) if rule.action is InterceptAction.MODIFY else raw
            return InterceptDecision(rule.action, output, rule.id, rule.name)
        return None


__all__ = ["InterceptAction", "InterceptDecision", "InterceptRule", "InterceptRuleEngine"]
