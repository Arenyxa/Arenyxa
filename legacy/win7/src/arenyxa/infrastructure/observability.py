from __future__ import annotations

import json
import logging
import logging.handlers
import re
from pathlib import Path
from typing import Any

from arenyxa.branding import LOG_FILENAME
from arenyxa.compat import dataclass
from arenyxa.domain.models import utc_now
from arenyxa.infrastructure.atomic_io import atomic_write_json

SENSITIVE_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "password",
    "secret",
}
MAX_REDACTION_DEPTH = 32
MAX_REDACTION_ITEMS = 10_000
_REDACTION_CYCLE = "[circular reference]"
_REDACTION_DEPTH_LIMIT = "[redaction depth limit]"
_REDACTION_ITEM_LIMIT = "[redaction item limit]"
_INLINE_PATTERNS = (
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(
        r"(?i)((?:access[_-]?token|refresh[_-]?token|token|secret|api[_-]?key|apikey|password)"
        r"\s*[=:]\s*)[^\s,;&]+"
    ),
    re.compile(
        r"(?i)((?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*)[^\r\n]+"
    ),
)


class Redactor:
    def __init__(self, replacement: str = "••••••••") -> None:
        self.replacement = replacement

    def redact(self, value: Any, key: str = "") -> Any:
        return self._redact(value, key, set(), 0)

    def _redact(self, value: Any, key: str, active: set[int], depth: int) -> Any:
        normalized_key = str(key).casefold()
        if (
            normalized_key in SENSITIVE_NAMES
            or "secret" in normalized_key
            or "token" in normalized_key
            or "password" in normalized_key
        ):
            return self.replacement
        if depth > MAX_REDACTION_DEPTH:
                                                                                           
                                                                       
            return _REDACTION_DEPTH_LIMIT
        if isinstance(value, dict):
            identity = id(value)
            if identity in active:
                return _REDACTION_CYCLE
            active.add(identity)
            try:
                if len(value) <= MAX_REDACTION_ITEMS:
                    result = {
                        name: self._redact(item, str(name), active, depth + 1)
                        for name, item in value.items()
                    }
                else:
                    result = {}
                    for index, (name, item) in enumerate(value.items()):
                        if index >= MAX_REDACTION_ITEMS:
                            result["_arenyxa_truncated"] = _REDACTION_ITEM_LIMIT
                            break
                        result[name] = self._redact(item, str(name), active, depth + 1)
                return result
            finally:
                active.discard(identity)
        if isinstance(value, list):
            identity = id(value)
            if identity in active:
                return _REDACTION_CYCLE
            active.add(identity)
            try:
                source = value if len(value) <= MAX_REDACTION_ITEMS else value[:MAX_REDACTION_ITEMS]
                result_list = [
                    self._redact(item, key, active, depth + 1)
                    for item in source
                ]
                if len(value) > MAX_REDACTION_ITEMS:
                    result_list.append(_REDACTION_ITEM_LIMIT)
                return result_list
            finally:
                active.discard(identity)
        if isinstance(value, tuple):
            identity = id(value)
            if identity in active:
                return _REDACTION_CYCLE
            active.add(identity)
            try:
                source_tuple = value if len(value) <= MAX_REDACTION_ITEMS else value[:MAX_REDACTION_ITEMS]
                result_tuple = tuple(
                    self._redact(item, key, active, depth + 1)
                    for item in source_tuple
                )
                if len(value) > MAX_REDACTION_ITEMS:
                    result_tuple += (_REDACTION_ITEM_LIMIT,)
                return result_tuple
            finally:
                active.discard(identity)
        if isinstance(value, str):
            redacted_text = value
            for pattern in _INLINE_PATTERNS:
                redacted_text = pattern.sub(
                    lambda match: match.group(1) + self.replacement,
                    redacted_text,
                )
            return redacted_text
        if value is None or isinstance(value, (bool, int, float)):
            return value
                                                                                                 
                                                                                                 
                                                                                                
        try:
            return self._redact(str(value), key, active, depth + 1)
        except Exception:                                                                   
            return "[unprintable redacted value]"


@dataclass(slots=True)
class LogEvent:
    level: str
    module: str
    message: str
    event: str = "event"
    task_id: str | None = None
    run_id: str | None = None
    capture_id: str | None = None
    correlation_id: str | None = None
    error_code: str | None = None
    context: dict[str, Any] | None = None
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = utc_now()


class JsonFormatter(logging.Formatter):
    def __init__(self, redactor: Redactor) -> None:
        super().__init__()
        self.redactor = redactor

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": utc_now(),
            "level": record.levelname.lower(),
            "module": record.name,
            "message": record.getMessage(),
        }
        context = getattr(record, "context", None)
        if context:
            payload["context"] = context
                                                                                               
                                                                                             
                                                                                      
        for field_name in (
            "correlation_id", "task_id", "run_id", "execution_id", "capture_id",
            "job_id", "worker_id", "schedule_id", "enterprise_id", "resource_id",
            "output_revision_id", "request_index", "phase",
        ):
            value = getattr(record, field_name, None)
            if value not in (None, ""):
                payload[field_name] = value
        error_code = getattr(record, "error_code", None)
        if error_code:
            payload["error_code"] = error_code
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
                                                                                               
                                                                                              
        return json.dumps(
            self.redactor.redact(payload),
            ensure_ascii=False,
            default=str,
            separators=(",", ":"),
        )


def configure_logging(log_dir: Path, level: int = logging.INFO) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger("arenyxa")
    root.setLevel(level)
    if root.handlers:
        return root
    handler = logging.handlers.RotatingFileHandler(
        log_dir / LOG_FILENAME,
        maxBytes=10 * 1024 * 1024,
        backupCount=8,
        encoding="utf-8",
        delay=True,
    )
    handler.setFormatter(JsonFormatter(Redactor()))
    root.addHandler(handler)
    return root


def export_diagnostic_summary(
    destination: Path,
    *,
    version: str,
    build: str,
    platform: str,
    settings: dict[str, Any],
    recent_errors: list[dict[str, Any]],
) -> Path:
    payload = Redactor().redact(
        {
            "generated_at": utc_now(),
            "version": version,
            "build": build,
            "platform": platform,
            "settings": settings,
            "recent_errors": recent_errors[-100:],
        }
    )
    atomic_write_json(destination, payload)
    return destination
