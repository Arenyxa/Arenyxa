from __future__ import annotations

import json
import logging
import logging.handlers
import queue
import re
import sys
import threading
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


class DropOldestQueueHandler(logging.handlers.QueueHandler):
    """Non-blocking business-log handler with explicit bounded overflow accounting."""

    def __init__(self, log_queue: queue.Queue[logging.LogRecord]) -> None:
        super().__init__(log_queue)
        self._lock = threading.Lock()
        self._dropped = 0

    def enqueue(self, record: logging.LogRecord) -> None:
        try:
            self.queue.put_nowait(record)
            return
        except queue.Full:
            with self._lock:
                self._dropped += 1
        try:
            self.queue.get_nowait()
        except queue.Empty:
            return
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            with self._lock:
                self._dropped += 1

    @property
    def dropped_records(self) -> int:
        with self._lock:
            return self._dropped




class LoggingSinkFailure(OSError):
    """Internal signal used to promote stdlib handler I/O failures to the resilient wrapper."""


class EscalatingRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """RotatingFileHandler that lets ResilientSinkHandler activate the fallback sink.

    Standard logging handlers call ``handleError`` and otherwise swallow emit failures. That is
    normally useful, but it makes disk-full/permission failures invisible to a supervisory
    wrapper. Raising here occurs only on the QueueListener thread, never the business caller.
    """

    def handleError(self, record: logging.LogRecord) -> None:  # noqa: N802 - logging API
        exc_type, exc_value, _traceback = sys.exc_info()
        detail = f"{getattr(exc_type, '__name__', 'Exception')}: {exc_value}"
        raise LoggingSinkFailure(detail) from exc_value


class ResilientSinkHandler(logging.Handler):
    """Isolate sink failures from QueueListener and fail over to structured stderr."""

    def __init__(self, primary: logging.Handler, fallback: logging.Handler) -> None:
        super().__init__(primary.level)
        self.primary = primary
        self.fallback = fallback
        self._lock = threading.Lock()
        self._primary_failures = 0
        self._last_error = ""

    def setFormatter(self, fmt: logging.Formatter | None) -> None:  # noqa: N802 - logging API
        super().setFormatter(fmt)
        self.primary.setFormatter(fmt)
        self.fallback.setFormatter(fmt)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.primary.handle(record)
        except (OSError, RuntimeError, ValueError) as exc:
            with self._lock:
                self._primary_failures += 1
                self._last_error = f"{type(exc).__name__}: {exc}"[:512]
            try:
                self.fallback.handle(record)
            except (OSError, RuntimeError, ValueError):
                # Logging must not re-enter application threads.  At this point both sinks
                # failed; the queue remains bounded and security audit uses a separate path.
                sys.__stderr__.write("Arenyxa logging sinks unavailable\n")

    def close(self) -> None:
        try:
            self.primary.close()
        finally:
            self.fallback.close()
            super().close()

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "primary_failures": self._primary_failures,
                "last_error": self._last_error,
                "primary": type(self.primary).__name__,
                "fallback": type(self.fallback).__name__,
            }


def configure_logging(log_dir: Path, level: int = logging.INFO) -> logging.Logger:
    """Configure bounded asynchronous business logging with fail-safe sink isolation.

    Security audit is deliberately not routed through this queue; audit durability and
    fail-closed/fail-operational semantics are implemented by ``security.audit.AuditLog``.
    """
    root = logging.getLogger("arenyxa")
    root.setLevel(level)
    existing_listener = getattr(root, "arenyxa_queue_listener", None)
    if existing_listener is not None:
        return root
    formatter = JsonFormatter(Redactor())
    fallback = logging.StreamHandler(sys.stderr)
    setattr(fallback, "arenyxa_sink", "stderr-fallback")
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        primary: logging.Handler = EscalatingRotatingFileHandler(
            log_dir / LOG_FILENAME,
            maxBytes=10 * 1024 * 1024,
            backupCount=8,
            encoding="utf-8",
            delay=True,
        )
        setattr(primary, "arenyxa_sink", "rotating-file")
    except OSError as exc:
        primary = logging.StreamHandler(sys.stderr)
        setattr(primary, "arenyxa_sink", "stderr-primary")
        setattr(primary, "arenyxa_file_error", f"{type(exc).__name__}: {exc}"[:512])
    sink = ResilientSinkHandler(primary, fallback)
    sink.setFormatter(formatter)
    log_queue: queue.Queue[logging.LogRecord] = queue.Queue(maxsize=8192)
    queue_handler = DropOldestQueueHandler(log_queue)
    queue_handler.setLevel(level)
    setattr(
        queue_handler,
        "arenyxa_sink",
        "stderr-fallback" if getattr(primary, "arenyxa_sink", "") == "stderr-primary" else "async-queue",
    )
    file_error = getattr(primary, "arenyxa_file_error", "")
    if file_error:
        setattr(queue_handler, "arenyxa_file_error", file_error)
    root.addHandler(queue_handler)
    listener = logging.handlers.QueueListener(log_queue, sink, respect_handler_level=True)
    listener.start()
    setattr(root, "arenyxa_queue_listener", listener)
    setattr(root, "arenyxa_queue_handler", queue_handler)
    setattr(root, "arenyxa_sink_handler", sink)
    if getattr(primary, "arenyxa_sink", "") == "stderr-primary":
        root.error(
            "Primary log file unavailable; asynchronous structured stderr logging is active",
            extra={"error_code": "LOG_SINK_FALLBACK", "context": {"log_dir": str(log_dir)}},
        )
    return root


def logging_status() -> dict[str, Any]:
    root = logging.getLogger("arenyxa")
    queue_handler = getattr(root, "arenyxa_queue_handler", None)
    sink = getattr(root, "arenyxa_sink_handler", None)
    listener = getattr(root, "arenyxa_queue_listener", None)
    return {
        "async": listener is not None,
        "listener_alive": bool(getattr(listener, "_thread", None) and listener._thread.is_alive()),
        "queue_depth": int(queue_handler.queue.qsize()) if queue_handler is not None else 0,
        "queue_capacity": int(queue_handler.queue.maxsize) if queue_handler is not None else 0,
        "dropped_records": int(queue_handler.dropped_records) if queue_handler is not None else 0,
        "sink": sink.status() if sink is not None else {},
    }


def shutdown_logging() -> None:
    root = logging.getLogger("arenyxa")
    listener = getattr(root, "arenyxa_queue_listener", None)
    if listener is not None:
        listener.stop()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    for name in ("arenyxa_queue_listener", "arenyxa_queue_handler", "arenyxa_sink_handler"):
        if hasattr(root, name):
            delattr(root, name)


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
