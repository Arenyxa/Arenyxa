from __future__ import annotations

import logging
import sys
import threading
import time
from dataclasses import dataclass


@dataclass(slots=True)
class _RecoveryState:
    last_emitted: float = 0.0
    suppressed: int = 0
    total: int = 0


_LOCK = threading.Lock()
_STATES: dict[tuple[str, str, str], _RecoveryState] = {}
_DEFAULT_INTERVAL_SECONDS = 30.0


def record_current_exception(
    module: str,
    operation: str,
    *,
    level: int = logging.DEBUG,
    min_interval_seconds: float = _DEFAULT_INTERVAL_SECONDS,
) -> None:
    """Record a deliberately recoverable exception without creating a log storm.

    This function must be invoked from an active ``except`` block. Repeated failures with the
    same module/operation/exception type are coalesced for ``min_interval_seconds`` and the next
    emitted record reports how many events were suppressed. The exception is therefore never
    silently discarded, while high-rate packet parsing and cleanup paths remain bounded.
    """
    exc = sys.exception()
    if exc is None:
        raise RuntimeError("record_current_exception() must be called from an except block")
    interval = max(0.0, float(min_interval_seconds))
    now = time.monotonic()
    key = (str(module), str(operation), type(exc).__name__)
    with _LOCK:
        state = _STATES.setdefault(key, _RecoveryState())
        state.total += 1
        if state.last_emitted and now - state.last_emitted < interval:
            state.suppressed += 1
            return
        suppressed = state.suppressed
        state.suppressed = 0
        state.last_emitted = now
        total = state.total
    logging.getLogger(module).log(
        level,
        "Recoverable exception in %s (type=%s total=%d suppressed_since_last=%d): %s",
        operation,
        type(exc).__name__,
        total,
        suppressed,
        exc,
        exc_info=True,
        extra={
            "error_code": "RECOVERABLE_EXCEPTION",
            "context": {
                "operation": operation,
                "exception_type": type(exc).__name__,
                "suppressed_since_last": suppressed,
                "total": total,
            },
        },
    )


def recoverable_exception_stats() -> dict[str, dict[str, int | float]]:
    """Return a snapshot suitable for diagnostics and health reports."""
    with _LOCK:
        return {
            "|".join(key): {
                "last_emitted_monotonic": state.last_emitted,
                "suppressed": state.suppressed,
                "total": state.total,
            }
            for key, state in _STATES.items()
        }
