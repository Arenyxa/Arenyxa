"""SQLite connection boundary with close-on-context and redacted slow-query telemetry."""

from __future__ import annotations

import hashlib
import logging
import sqlite3
import time
from typing import Any


LOGGER = logging.getLogger(__name__)


class SlowQueryConnection(sqlite3.Connection):
    SLOW_QUERY_SECONDS = 0.250

    @staticmethod
    def _query_identity(sql: str) -> str:
        normalized = " ".join(str(sql).split())
        operation = normalized.split(" ", 1)[0].upper() if normalized else "UNKNOWN"
        digest = hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:16]
        return f"{operation}:{digest}"

    def execute(self, sql: str, parameters: Any = (), /) -> sqlite3.Cursor:
        started = time.perf_counter()
        try:
            return super().execute(sql, parameters)
        finally:
            elapsed = time.perf_counter() - started
            if elapsed >= self.SLOW_QUERY_SECONDS:
                LOGGER.warning(
                    "SQLite slow query %.1fms identity=%s",
                    elapsed * 1000.0,
                    self._query_identity(sql),
                )

    def executemany(self, sql: str, seq_of_parameters: Any, /) -> sqlite3.Cursor:
        started = time.perf_counter()
        try:
            return super().executemany(sql, seq_of_parameters)
        finally:
            elapsed = time.perf_counter() - started
            if elapsed >= self.SLOW_QUERY_SECONDS:
                LOGGER.warning(
                    "SQLite slow batch %.1fms identity=%s",
                    elapsed * 1000.0,
                    self._query_identity(sql),
                )

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc, tb))
        finally:
            self.close()

