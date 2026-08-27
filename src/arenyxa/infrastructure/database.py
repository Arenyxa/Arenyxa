"""SQLite persistence facade and migration/runtime storage core."""
from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import logging
import sqlite3
import threading
import time
from collections import deque
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import (
    CaptureSession,
    DatasetRevision,
    FieldSpec,
    NetworkEvent,
    Project,
    ProjectSource,
    RequestSpec,
    ResultRecord,
    RetryPolicy,
    Run,
    Task,
    utc_now,
)
from arenyxa.domain.network import NetworkNormalizer
from arenyxa.infrastructure.atomic_io import fsync_existing_file
from arenyxa.infrastructure.database_jobs import PlatformJobStoreMixin
from arenyxa.infrastructure.sqlite_connection import SlowQueryConnection as _ClosingConnection
from arenyxa.security.sql_safety import sqlite_wal_checkpoint

LOGGER = logging.getLogger(__name__)


from arenyxa.infrastructure.database_migrations import MIGRATIONS
from arenyxa.infrastructure.database_maintenance import SQLiteMaintenanceMixin
from arenyxa.infrastructure.database_tasks import TaskRunStoreMixin
from arenyxa.infrastructure.database_network import NetworkStoreMixin
from arenyxa.infrastructure.database_datasets import DatasetStoreMixin
from arenyxa.infrastructure.database_workflows import WorkflowStoreMixin

class SQLiteStore(
    TaskRunStoreMixin,
    NetworkStoreMixin,
    DatasetStoreMixin,
    WorkflowStoreMixin,
    PlatformJobStoreMixin,
    SQLiteMaintenanceMixin,
):
    """Local durable store that composes task, network, dataset, and workflow persistence."""
    def __init__(self, path: Path) -> None:
        self.path = path
        self._migration_lock = threading.Lock()
        self._write_metrics_lock = threading.Lock()
        self._write_latency_ms = deque(maxlen=64)
        self._write_busy_events = 0
        self._write_failures = 0
        self._last_write_records = 0


    def _record_write_observation(self, elapsed_ms: float, *, records: int = 0, busy: bool = False, failed: bool = False) -> None:
        """Record bounded SQLite write telemetry for adaptive backpressure decisions."""
        with self._write_metrics_lock:
            self._write_latency_ms.append(max(0.0, float(elapsed_ms)))
            self._last_write_records = max(0, int(records))
            if busy:
                self._write_busy_events += 1
            if failed:
                self._write_failures += 1

    def write_pressure_snapshot(self) -> dict[str, float | int | bool]:
        """Return non-secret local persistence pressure without mutating the database."""
        with self._write_metrics_lock:
            samples = sorted(self._write_latency_ms)
            busy_events = int(self._write_busy_events)
            failures = int(self._write_failures)
            records = int(self._last_write_records)
        p95 = 0.0
        if samples:
            idx = min(len(samples) - 1, max(0, int((len(samples) - 1) * 0.95 + 0.999999)))
            p95 = float(samples[idx])
        wal_bytes = 0
        wal_pages = 0
        try:
            wal_path = Path(str(self.path) + "-wal")
            if wal_path.exists():
                wal_bytes = int(wal_path.stat().st_size)
            if wal_bytes:
                with self.connect() as connection:
                    page_size = int(connection.execute("PRAGMA page_size").fetchone()[0] or 4096)
                wal_pages = max(0, wal_bytes // max(512, page_size))
        except (OSError, sqlite3.Error, TypeError, ValueError):
            LOGGER.debug("SQLite write-pressure WAL probe failed", exc_info=True)
        pressured = bool(p95 >= 250.0 or wal_pages >= 8192 or busy_events > 0)
        return {
            "write_p95_ms": round(p95, 3),
            "wal_bytes": wal_bytes,
            "wal_pages_approx": wal_pages,
            "busy_events": busy_events,
            "write_failures": failures,
            "last_write_records": records,
            "pressured": pressured,
        }

    def connect(self) -> sqlite3.Connection:
        """Open a configured SQLite connection with Arenyxa durability and safety pragmas."""
        connection = sqlite3.connect(self.path, timeout=30.0, factory=_ClosingConnection)
        try:
            connection.row_factory = sqlite3.Row
                                                                                           
                                                                                             
                                                                                             
                                                                                           
                                                                                            
                                                                                             
            connection.executescript(
                """
                PRAGMA foreign_keys=ON;
                PRAGMA synchronous=NORMAL;
                PRAGMA wal_autocheckpoint=4096;
                PRAGMA cache_size=-8192;
                PRAGMA temp_store=MEMORY;
                """
            )
            return connection
        except Exception:
                                                                                           
                                                                                            
                                                                                            
                                                                                             
                                                                    
            connection.close()
            raise

    @staticmethod
    def validate_runtime() -> None:
        






        """Validate SQLite runtime capabilities required by the current schema."""
        if tuple(sqlite3.sqlite_version_info) < (3, 24, 0):
            raise ArenyxaError(
                "SQLITE_RUNTIME_UNSUPPORTED",
                f"SQLite {sqlite3.sqlite_version} 过旧；Arenyxa 需要 SQLite >= 3.24。",
                domain="DATABASE",
                context={"sqlite_version": sqlite3.sqlite_version},
            )
        try:
            probe = sqlite3.connect(":memory:")
            try:
                probe.execute("CREATE VIRTUAL TABLE __arenyxa_fts_probe USING fts5(value)")
            finally:
                probe.close()
        except sqlite3.DatabaseError as exc:
            raise ArenyxaError(
                "SQLITE_FTS5_UNAVAILABLE",
                "当前 SQLite 运行时未启用 FTS5；本地搜索索引无法安全初始化。",
                domain="DATABASE",
                context={"sqlite_version": sqlite3.sqlite_version},
            ) from exc

    def initialize(self) -> None:
        """Create or migrate the local schema and validate post-migration invariants."""
        self.validate_runtime()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._migration_lock:
            existed_before = self.path.exists() and self.path.stat().st_size > 0
            applied: set[int] = set()
            if existed_before:
                                                                                            
                                                                                           
                                                                                       
                                          
                probe = sqlite3.connect(self.path, timeout=30.0)
                try:
                    has_table = probe.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
                    ).fetchone()
                    if has_table is not None:
                        applied = {
                            int(row[0])
                            for row in probe.execute("SELECT version FROM schema_migrations")
                        }
                finally:
                    probe.close()
                pending = [
                    version for version in range(1, len(MIGRATIONS) + 1) if version not in applied
                ]
                if pending:
                    self.backup_to(self.path.with_name(f"{self.path.stem}.pre-migration.bak"))

            with self.connect() as connection:
                                                                                           
                                                                                           
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS schema_migrations "
                    "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
                )
                connection.commit()
                if not existed_before:
                    applied = {
                        int(row[0])
                        for row in connection.execute("SELECT version FROM schema_migrations")
                    }
                for version, script in enumerate(MIGRATIONS, start=1):
                    if version in applied:
                        continue
                    applied_at = utc_now()
                    try:
                        # executescript cannot bind values. Start the migration transaction inside
                        # the fixed script, then persist dynamic ledger values through DB-API parameters.
                        connection.executescript("BEGIN IMMEDIATE;\n" + script)
                        connection.execute(
                            "INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)",
                            (int(version), applied_at),
                        )
                        connection.commit()
                    except sqlite3.DatabaseError:
                        if connection.in_transaction:
                            connection.rollback()
                        raise

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run one explicit SQLite transaction with rollback on body or commit failure."""
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                # Roll back even for process-control exceptions, but never swallow them.
                if connection.in_transaction:
                    try:
                        connection.rollback()
                    except sqlite3.Error:
                        LOGGER.exception("SQLite rollback failed while unwinding transaction body")
                raise
            try:
                connection.commit()
            except BaseException:
                # A failed COMMIT leaves the connection unsuitable for reuse. Attempt a
                # rollback for deterministic cleanup, preserve the original failure, and
                # then close the connection in finally.
                if connection.in_transaction:
                    try:
                        connection.rollback()
                    except sqlite3.Error:
                        LOGGER.exception("SQLite rollback failed after COMMIT failure")
                raise
        finally:
            connection.close()

