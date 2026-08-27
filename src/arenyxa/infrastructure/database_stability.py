"""SQLite WAL/corruption monitoring and PostgreSQL health/retry policy models."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from arenyxa.compat import dataclass

LOGGER = logging.getLogger(__name__)
ResultT = TypeVar("ResultT")


@dataclass(frozen=True, slots=True)
class DatabaseRetryPolicy:
    max_attempts: int = 3
    initial_delay_seconds: float = 0.05
    maximum_delay_seconds: float = 1.0

    def delays(self) -> tuple[float, ...]:
        attempts = max(1, min(10, int(self.max_attempts)))
        delay = max(0.0, float(self.initial_delay_seconds))
        maximum = max(delay, float(self.maximum_delay_seconds))
        rows: list[float] = []
        for _index in range(attempts - 1):
            rows.append(min(maximum, delay))
            delay = max(0.001, delay * 2.0)
        return tuple(rows)


def retry_database_operation(
    operation: Callable[[], ResultT],
    *,
    retryable: tuple[type[BaseException], ...],
    policy: DatabaseRetryPolicy = DatabaseRetryPolicy(),
) -> ResultT:
    delays = policy.delays()
    for attempt in range(len(delays) + 1):
        try:
            return operation()
        except retryable:
            if attempt >= len(delays):
                raise
            time.sleep(delays[attempt])
    raise RuntimeError("unreachable database retry state")


class SQLiteStabilityMonitor:
    def __init__(
        self,
        store: Any,
        *,
        checkpoint_wal_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        self.store = store
        self.checkpoint_wal_bytes = max(1024 * 1024, int(checkpoint_wal_bytes))

    @property
    def wal_path(self) -> Path:
        return Path(str(self.store.path) + "-wal")

    def snapshot(self, *, check_integrity: bool = False) -> dict[str, Any]:
        wal_bytes = self.wal_path.stat().st_size if self.wal_path.is_file() else 0
        checkpoint: tuple[int, int, int] | None = None
        if wal_bytes >= self.checkpoint_wal_bytes:
            checkpoint = self.store.checkpoint("PASSIVE")
        quick_check = self.store.quick_check() if check_integrity else "not-run"
        return {
            "backend": "sqlite",
            "healthy": quick_check in {"not-run", "ok"} and bool(self.store.ping()),
            "wal_bytes": wal_bytes,
            "checkpoint": checkpoint,
            "quick_check": quick_check,
        }

    def corruption_detected(self) -> bool:
        try:
            return str(self.store.quick_check()).casefold() != "ok"
        except (OSError, RuntimeError, TypeError, ValueError):
            return True


class PostgreSQLHealthMonitor:
    def __init__(self, backend: Any) -> None:
        self.backend = backend

    def snapshot(self) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            with self.backend.connection() as connection:
                row = connection.execute("SELECT 1 AS healthy").fetchone()
            healthy = row is not None
            error = ""
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            healthy = False
            error = f"{type(exc).__name__}: {exc}"[:256]
        return {
            "backend": "postgresql",
            "healthy": healthy,
            "latency_ms": round((time.perf_counter() - started) * 1000.0, 3),
            "error": error,
        }
