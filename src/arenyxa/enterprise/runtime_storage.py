from __future__ import annotations

import hashlib
import logging
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any

from arenyxa.compat import dataclass
from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.database_stability import DatabaseRetryPolicy, retry_database_operation
from arenyxa.security.sql_safety import sql_identifier

LOGGER = logging.getLogger(__name__)

@dataclass(frozen=True, slots=True)
class RuntimeStorageCapabilities:
    backend: str
    multi_host_writers: bool
    row_lock_skip_locked: bool
    external_server: bool
    write_model: str = "concurrent"
    recommended_parallel_writers: int = 0
    recommended_worker_slots: int = 0
    recommended_total_worker_slots: int = 0
    high_concurrency_cutover_slots: int = 0
    high_concurrency_cutover_workers: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "multi_host_writers": self.multi_host_writers,
            "row_lock_skip_locked": self.row_lock_skip_locked,
            "external_server": self.external_server,
            "write_model": self.write_model,
            "recommended_parallel_writers": self.recommended_parallel_writers,
            "recommended_worker_slots": self.recommended_worker_slots,
            "recommended_total_worker_slots": self.recommended_total_worker_slots,
            "high_concurrency_cutover_slots": self.high_concurrency_cutover_slots,
            "high_concurrency_cutover_workers": self.high_concurrency_cutover_workers,
        }


def _storage_fail(code: str, message: str, **context: Any) -> ArenyxaError:
    return ArenyxaError(code, message, domain="ENTERPRISE_DISTRIBUTED_STORAGE", context=context)


_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS distributed_meta(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS distributed_workers(
    worker_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    identity_algorithm TEXT NOT NULL DEFAULT 'ED25519',
    identity_metadata_json TEXT NOT NULL DEFAULT '{}',
    protocol_min INTEGER NOT NULL,
    protocol_max INTEGER NOT NULL,
    negotiated_protocol INTEGER NOT NULL,
    app_compat_version TEXT NOT NULL,
    resources_json TEXT NOT NULL,
    max_slots INTEGER NOT NULL,
    active_leases INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    heartbeat_at REAL NOT NULL,
    revoked_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS distributed_jobs(
    job_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    traceparent TEXT NOT NULL DEFAULT '',
    tracestate TEXT NOT NULL DEFAULT '',
    resource_id TEXT NOT NULL,
    permission TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    side_effect_mode TEXT NOT NULL,
    side_effect_state TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    max_attempts INTEGER NOT NULL,
    protocol_version INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    lease_worker_id TEXT NOT NULL DEFAULT '',
    lease_token_sha256 TEXT NOT NULL DEFAULT '',
    lease_expires_at REAL NOT NULL DEFAULT 0,
    checkpoint_json TEXT NOT NULL DEFAULT '{}',
    checkpoint_seq INTEGER NOT NULL DEFAULT 0,
    result_json TEXT NOT NULL DEFAULT '{}',
    result_sha256 TEXT NOT NULL DEFAULT '',
    terminal_worker_id TEXT NOT NULL DEFAULT '',
    terminal_lease_token_sha256 TEXT NOT NULL DEFAULT '',
    terminal_at TEXT NOT NULL DEFAULT '',
    error_code TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS distributed_job_events(
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    worker_id TEXT NOT NULL DEFAULT '',
    code TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY(job_id) REFERENCES distributed_jobs(job_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_distributed_job_events_job
    ON distributed_job_events(job_id,event_id DESC);
CREATE INDEX IF NOT EXISTS idx_distributed_jobs_state_priority
    ON distributed_jobs(state, priority DESC, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_distributed_jobs_worker
    ON distributed_jobs(lease_worker_id, state);
CREATE TABLE IF NOT EXISTS distributed_job_idempotency(
    idempotency_key TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    permission TEXT NOT NULL,
    side_effect_mode TEXT NOT NULL,
    terminal_state TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    terminal_at TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_distributed_job_idempotency_mode_terminal
    ON distributed_job_idempotency(side_effect_mode, terminal_at);
"""

_POSTGRES_SCHEMA = (
    _SQLITE_SCHEMA.replace(
        "event_id INTEGER PRIMARY KEY AUTOINCREMENT", "event_id BIGSERIAL PRIMARY KEY"
    )
    # SQLite REAL is an 8-byte IEEE-754 value, while PostgreSQL REAL is only 4 bytes.
    # Epoch timestamps need float8 precision so short leases and heartbeats are not rounded
    # by roughly a minute at contemporary epoch values.
    .replace("heartbeat_at REAL", "heartbeat_at DOUBLE PRECISION")
    .replace("lease_expires_at REAL", "lease_expires_at DOUBLE PRECISION")
)

_POSTGRES_EPOCH_MIGRATIONS = (
    (
        "distributed_workers",
        "heartbeat_at",
        (
            "ALTER TABLE distributed_workers ALTER COLUMN heartbeat_at TYPE DOUBLE PRECISION "
            "USING heartbeat_at::DOUBLE PRECISION"
        ),
    ),
    (
        "distributed_jobs",
        "lease_expires_at",
        (
            "ALTER TABLE distributed_jobs ALTER COLUMN lease_expires_at TYPE DOUBLE PRECISION "
            "USING lease_expires_at::DOUBLE PRECISION"
        ),
    ),
)


class _MappingRow:
    






    __slots__ = ("_mapping", "_values")

    def __init__(self, mapping: Mapping[str, Any]) -> None:
        self._mapping = dict(mapping)
        self._values = tuple(self._mapping.values())

    def __getitem__(self, key: str | int) -> Any:
        if isinstance(key, int):
            return self._values[key]
        return self._mapping[key]

    def keys(self) -> Any:
        return self._mapping.keys()


class _CursorFacade:
    __slots__ = ("_cursor", "_mapping_rows")

    def __init__(self, cursor: Any, *, mapping_rows: bool) -> None:
        self._cursor = cursor
        self._mapping_rows = bool(mapping_rows)

    @property
    def rowcount(self) -> int:
        return int(self._cursor.rowcount)

    def _wrap(self, row: Any) -> Any:
        if row is None or not self._mapping_rows or not isinstance(row, Mapping):
            return row
        return _MappingRow(row)

    def fetchone(self) -> Any:
        return self._wrap(self._cursor.fetchone())

    def fetchall(self) -> list[Any]:
        return [self._wrap(row) for row in self._cursor.fetchall()]


class _ConnectionFacade:
    __slots__ = ("_statement_count", "_transaction_started", "backend", "raw")

    def __init__(self, raw: Any, backend: DistributedRuntimeStorageBackend) -> None:
        self.raw = raw
        self.backend = backend
        self._transaction_started: float | None = None
        self._statement_count = 0

    def execute(self, sql: str, params: Sequence[Any] = ()) -> _CursorFacade:
        translated = self.backend.translate_sql(sql)
        operation = str(sql).lstrip().partition(" ")[0].upper()
        if operation == "BEGIN":
            self._transaction_started = time.perf_counter()
            self._statement_count = 0
        else:
            self._statement_count += 1
        cursor = self.raw.execute(translated, tuple(params))
        return _CursorFacade(cursor, mapping_rows=self.backend.capabilities.backend == "postgresql")

    def executescript(self, sql: str) -> None:
        self.backend.execute_script(self.raw, sql)

    def commit(self) -> None:
        self.raw.commit()
        self._trace_transaction("commit")

    def rollback(self) -> None:
        self.raw.rollback()
        self._trace_transaction("rollback")

    def _trace_transaction(self, outcome: str) -> None:
        if self._transaction_started is None:
            return
        elapsed_ms = (time.perf_counter() - self._transaction_started) * 1000.0
        trace_identity = hashlib.sha256(
            f"{self.backend.capabilities.backend}:{self._statement_count}".encode("ascii")
        ).hexdigest()[:16]
        LOGGER.info(
            "database transaction outcome=%s backend=%s elapsed_ms=%.3f statements=%d trace=%s",
            outcome,
            self.backend.capabilities.backend,
            elapsed_ms,
            self._statement_count,
            trace_identity,
        )
        self._transaction_started = None
        self._statement_count = 0


class DistributedRuntimeStorageBackend(ABC):
    @property
    @abstractmethod
    def capabilities(self) -> RuntimeStorageCapabilities:
        """Describe the concrete runtime storage feature contract."""
        ...

    @contextmanager
    @abstractmethod
    def connection(self) -> Iterator[_ConnectionFacade]:
        """Yield a live transactional connection facade."""
        ...

    @abstractmethod
    def initialize_schema(self, schema: str, current_protocol: int, min_protocol: int) -> None:
        """Create or migrate the concrete runtime schema."""
        ...

    @abstractmethod
    def begin_write(self, connection: _ConnectionFacade) -> None:
        """Begin a write transaction with backend-appropriate locking."""
        ...

    @abstractmethod
    def integrity_check(self) -> tuple[bool, str]:
        """Run the concrete backend integrity/readiness check."""
        ...

    def authoritative_lease_epoch(self, connection: _ConnectionFacade, clock: Any) -> float:
        """Return the backend-authoritative epoch used for durable leases/heartbeats."""
        del connection
        return float(clock.stable_epoch())

    def fast_lease_expiry_parameter(self, now: float, duration: float) -> float:
        """Value bound to the fast lease SQL expiry slot."""
        return float(now) + max(0.0, float(duration))

    def fast_lease_expiry_from_row(self, row: Any, fallback: float) -> float:
        """Resolve the authoritative expiry returned by a backend fast lease path."""
        del row
        return float(fallback)

    def close(self) -> None:
        """Release persistent backend resources; SQLite has none between calls."""
        LOGGER.debug(
            "Runtime storage backend %s has no persistent pool to close",
            self.capabilities.backend,
        )

    def translate_sql(self, sql: str) -> str:
        return sql

    def execute_script(self, raw_connection: Any, sql: str) -> None:
        raw_connection.executescript(sql)

    def lease_candidate_sql(self) -> str:
        return (
            "SELECT * FROM distributed_jobs WHERE state='queued' "
            "AND protocol_version BETWEEN ? AND ? "
            "ORDER BY priority DESC, created_at ASC LIMIT 1"
        )

    def worker_for_lease_sql(self) -> str:
        return "SELECT * FROM distributed_workers WHERE worker_id=?"

    def lease_for_update_sql(self) -> str:
        return "SELECT * FROM distributed_jobs WHERE job_id=?"

    def claim_worker_slot_sql(self) -> str:
        return (
            "UPDATE distributed_workers SET active_leases=active_leases+1,heartbeat_at=?,updated_at=? "
            "WHERE worker_id=? AND state='active' AND active_leases<max_slots"
        )

    def claim_worker_slot_for_lease_sql(self) -> str | None:
        """Return a backend-specific atomic worker admission statement, when available."""
        return None

    def lease_next_fast_sql(self) -> str | None:
        """Return a backend-specific single-statement lease path, when available."""
        return None

    def start_job_fast_sql(self) -> str | None:
        """Return a backend-specific single-statement start path, when available."""
        return None

    def complete_fast_sql(self) -> str | None:
        """Return a backend-specific single-statement completion path, when available."""
        return None

    def lease_admission_guard(self):
        """Bound backend-specific lease admission without changing portable storage."""
        return nullcontext()

    def record_event(
        self, connection: _ConnectionFacade, values: Sequence[Any], max_events: int,
    ) -> None:
        """Persist an event and enforce the per-job journal bound."""
        connection.execute(
            """INSERT INTO distributed_job_events(
                job_id,event_type,from_state,to_state,worker_id,code,details_json,created_at
            ) VALUES(?,?,?,?,?,?,?,?)""",
            tuple(values),
        )
        job_id = str(values[0])
        connection.execute(
            """DELETE FROM distributed_job_events WHERE job_id=? AND event_id NOT IN (
                SELECT event_id FROM distributed_job_events WHERE job_id=? ORDER BY event_id DESC LIMIT ?
            )""",
            (job_id, job_id, max(1, int(max_events))),
        )

    def expired_lease_candidates_sql(self) -> str:
        return (
            "SELECT job_id,state,lease_worker_id,lease_token_sha256,lease_expires_at,side_effect_mode,side_effect_state,attempt,max_attempts "
            "FROM distributed_jobs WHERE state IN ('leased','running') "
            "AND lease_expires_at>0 AND lease_expires_at<=? "
            "ORDER BY lease_worker_id,job_id"
        )

    def invalid_lease_candidates_sql(self) -> str:
        return (
            "SELECT j.* FROM distributed_jobs j "
            "LEFT JOIN distributed_workers w ON w.worker_id=j.lease_worker_id "
            "WHERE j.state IN ('leased','running') AND ("
            "j.lease_worker_id='' OR j.lease_token_sha256='' OR j.lease_expires_at<=0 OR "
            "j.lease_expires_at>? OR w.worker_id IS NULL OR w.state='revoked')"
        )


class SQLiteDistributedRuntimeStorage(DistributedRuntimeStorageBackend):
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def capabilities(self) -> RuntimeStorageCapabilities:
        return RuntimeStorageCapabilities(
            backend="sqlite",
            multi_host_writers=False,
            row_lock_skip_locked=False,
            external_server=False,
            write_model="serialized-wal",
            recommended_parallel_writers=1,
            recommended_worker_slots=4,
            recommended_total_worker_slots=8,
            high_concurrency_cutover_slots=16,
            high_concurrency_cutover_workers=16,
        )

    @contextmanager
    def connection(self) -> Iterator[_ConnectionFacade]:
        raw = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        try:
            raw.row_factory = sqlite3.Row
            raw.executescript("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")
            yield _ConnectionFacade(raw, self)
        except (ArenyxaError, sqlite3.Error, OSError, ValueError, TypeError, RuntimeError, KeyError):
            try:
                raw.rollback()
            except sqlite3.Error as rollback_exc:
                LOGGER.warning("SQLite rollback failed while unwinding storage error: %s", rollback_exc)
            raise
        finally:
            raw.close()

    def initialize_schema(self, schema: str, current_protocol: int, min_protocol: int) -> None:
        with self.connection() as connection:
            journal = connection.execute("PRAGMA journal_mode=WAL").fetchone()
            if journal is None or str(journal[0]).casefold() != "wal":
                raise _storage_fail("DISTRIBUTED_WAL_UNAVAILABLE", "Distributed queue requires SQLite WAL mode")
            connection.executescript(_SQLITE_SCHEMA)
            schema_row = connection.execute("SELECT value FROM distributed_meta WHERE key='schema'").fetchone()
            if schema_row is None:
                connection.execute("INSERT INTO distributed_meta(key,value) VALUES('schema',?)", (schema,))
            elif str(schema_row[0]) != schema:
                raise _storage_fail("DISTRIBUTED_SCHEMA_UNSUPPORTED", "Distributed queue schema requires migration")
            existing_columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(distributed_jobs)").fetchall()
            }
            for column, declaration in (
                ("result_sha256", "TEXT NOT NULL DEFAULT ''"),
                ("terminal_worker_id", "TEXT NOT NULL DEFAULT ''"),
                ("terminal_lease_token_sha256", "TEXT NOT NULL DEFAULT ''"),
                ("terminal_at", "TEXT NOT NULL DEFAULT ''"),
                ("traceparent", "TEXT NOT NULL DEFAULT ''"),
                ("tracestate", "TEXT NOT NULL DEFAULT ''"),
            ):
                if column not in existing_columns:
                    connection.execute("ALTER TABLE distributed_jobs ADD COLUMN " + sql_identifier(column) + " " + declaration)
            worker_columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(distributed_workers)").fetchall()
            }
            for column, declaration in (
                ("identity_algorithm", "TEXT NOT NULL DEFAULT 'ED25519'"),
                ("identity_metadata_json", "TEXT NOT NULL DEFAULT '{}'"),
            ):
                if column not in worker_columns:
                    connection.execute("ALTER TABLE distributed_workers ADD COLUMN " + sql_identifier(column) + " " + declaration)
            connection.execute(
                "INSERT OR REPLACE INTO distributed_meta(key,value) VALUES('protocol_current',?)",
                (str(current_protocol),),
            )
            connection.execute(
                "INSERT OR REPLACE INTO distributed_meta(key,value) VALUES('protocol_min',?)",
                (str(min_protocol),),
            )

    def authoritative_lease_epoch(self, connection: _ConnectionFacade, clock: Any) -> float:
        # SQLite is a single-host backend.  Persist one epoch/monotonic anchor so every
        # process opening this queue interprets durable lease timestamps in the same
        # system-wide monotonic domain instead of projecting its own wall-clock anchor.
        key = "lease_clock_anchor_v1"
        current_mono = float(clock.monotonic())
        candidate_epoch = float(clock.stable_epoch())
        candidate = f"{candidate_epoch:.17g}|{current_mono:.17g}"
        row = connection.execute("SELECT value FROM distributed_meta WHERE key=?", (key,)).fetchone()
        if row is None:
            connection.execute(
                "INSERT OR IGNORE INTO distributed_meta(key,value) VALUES(?,?)",
                (key, candidate),
            )
            row = connection.execute("SELECT value FROM distributed_meta WHERE key=?", (key,)).fetchone()
        if row is None:
            raise _storage_fail("DISTRIBUTED_LEASE_CLOCK_UNAVAILABLE", "Durable SQLite lease clock anchor is unavailable")

        def parse(value: Any) -> tuple[float, float]:
            try:
                epoch_text, mono_text = str(value).split("|", 1)
                return float(epoch_text), float(mono_text)
            except (TypeError, ValueError) as exc:
                raise _storage_fail(
                    "DISTRIBUTED_LEASE_CLOCK_CORRUPT",
                    "Durable SQLite lease clock anchor is invalid",
                ) from exc

        epoch_anchor, mono_anchor = parse(row[0])
        # A monotonic rollback can only occur across a host reboot for the supported
        # single-host SQLite deployment. Re-anchor without moving logical time backward;
        # old leases then age out after at most their remaining lease duration.
        if current_mono + 1e-6 < mono_anchor:
            replacement_epoch = max(epoch_anchor, candidate_epoch)
            replacement = f"{replacement_epoch:.17g}|{current_mono:.17g}"
            connection.execute(
                "UPDATE distributed_meta SET value=? WHERE key=? AND value=?",
                (replacement, key, str(row[0])),
            )
            row = connection.execute("SELECT value FROM distributed_meta WHERE key=?", (key,)).fetchone()
            if row is None:
                raise _storage_fail("DISTRIBUTED_LEASE_CLOCK_UNAVAILABLE", "Durable SQLite lease clock anchor disappeared")
            epoch_anchor, mono_anchor = parse(row[0])
        return epoch_anchor + max(0.0, current_mono - mono_anchor)

    def begin_write(self, connection: _ConnectionFacade) -> None:
        connection.execute("BEGIN IMMEDIATE")

    def integrity_check(self) -> tuple[bool, str]:
        with self.connection() as connection:
            row = connection.execute("PRAGMA quick_check(1)").fetchone()
            result = "" if row is None else str(row[0])
            return result.casefold() == "ok", result


class PostgreSQLDistributedRuntimeStorage(DistributedRuntimeStorageBackend):
    






    _SCHEMA_ADVISORY_LOCK = 0x4152454E595841                                     
    _OPEN = "open"
    _CLOSING = "closing"
    _CLOSED = "closed"

    def __init__(self, dsn: str) -> None:
        text = str(dsn).strip()
        if not text.casefold().startswith(("postgresql://", "postgres://")):
            raise _storage_fail("DISTRIBUTED_STORAGE_DSN_INVALID", "PostgreSQL runtime DSN is invalid")
        self.dsn = text
        self._pool: Any | None = None
        self._pool_condition = threading.Condition()
        self._lifecycle_state = self._OPEN
        self._active_connections = 0
        self._close_owner = False
        self._pool_metrics_lock = threading.Lock()
        self._pool_acquisitions = 0
        self._pool_acquisition_failures = 0
        self._pool_reconnect_failures = 0
        self._last_pool_error = ""
        self.retry_policy = DatabaseRetryPolicy(max_attempts=3)

    @property
    def capabilities(self) -> RuntimeStorageCapabilities:
        return RuntimeStorageCapabilities(
            backend="postgresql",
            multi_host_writers=True,
            row_lock_skip_locked=True,
            external_server=True,
            write_model="row-lock-concurrent",
            recommended_parallel_writers=64,
            recommended_worker_slots=64,
            recommended_total_worker_slots=256,
            high_concurrency_cutover_slots=384,
            high_concurrency_cutover_workers=256,
        )

    def _driver(self) -> tuple[Any, Any, Any]:
        try:
            import psycopg
            from psycopg.rows import dict_row
            from psycopg_pool import ConnectionPool
        except ImportError as exc:
            raise _storage_fail(
                "DISTRIBUTED_POSTGRES_DRIVER_MISSING",
                "PostgreSQL Enterprise runtime requires Psycopg 3 and psycopg-pool",
            ) from exc
        return psycopg, dict_row, ConnectionPool

    def _pool_close_error_types(self) -> tuple[type[BaseException], ...]:
        errors: list[type[BaseException]] = [OSError, RuntimeError, TypeError, ValueError]
        try:
            driver_error = self._driver()[0].Error
        except (AttributeError, ImportError):
            return tuple(errors)
        if isinstance(driver_error, type) and issubclass(driver_error, BaseException):
            errors.append(driver_error)
        return tuple(errors)
    @staticmethod
    def _configure_pool_connection(connection: Any) -> None:
        """Configure PostgreSQL session limits once per physical pooled connection."""
        connection.execute("SET lock_timeout = '10s'")
        connection.execute("SET statement_timeout = '60s'")
        connection.execute("SET idle_in_transaction_session_timeout = '60s'")
    @staticmethod
    def _check_pool_connection(connection: Any) -> None:
        """Validate a checked-in/out PostgreSQL connection without relying on pool internals."""
        cursor = connection.execute("SELECT 1 AS arenyxa_pool_health")
        fetchone = getattr(cursor, "fetchone", None)
        if callable(fetchone):
            fetchone()
    def _on_reconnect_failed(self, pool: Any) -> None:
        with self._pool_metrics_lock:
            self._pool_reconnect_failures += 1
            self._last_pool_error = f"PostgreSQL pool reconnect failed: {getattr(pool, 'name', 'unknown')}"[:512]
        LOGGER.error("PostgreSQL distributed runtime pool reconnect failed")

    def pool_metrics(self) -> dict[str, Any]:
        with self._pool_condition:
            pool = self._pool
            lifecycle_state = self._lifecycle_state
            active_connections = self._active_connections
        with self._pool_metrics_lock:
            local = {
                "acquisitions": self._pool_acquisitions,
                "acquisition_failures": self._pool_acquisition_failures,
                "reconnect_failures": self._pool_reconnect_failures,
                "last_error": self._last_pool_error,
                "lifecycle_state": lifecycle_state,
                "active_connections": active_connections,
            }
        if pool is None:
            return {**local, "open": False, "backend": "postgresql"}
        try:
            stats = dict(pool.get_stats())
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            stats = {"stats_error": f"{type(exc).__name__}: {exc}"[:256]}
        return {
            **local,
            "open": lifecycle_state == self._OPEN and not bool(getattr(pool, "closed", False)),
            "backend": "postgresql",
            **stats,
        }
    def _ensure_open_locked(self) -> None:
        if self._lifecycle_state != self._OPEN:
            raise _storage_fail(
                "DISTRIBUTED_STORAGE_CLOSED",
                "PostgreSQL runtime storage is closing or closed",
                lifecycle_state=self._lifecycle_state,
            )
    def _connection_pool_locked(self) -> Any:
        self._ensure_open_locked()
        existing = self._pool
        if existing is not None:
            return existing
        _psycopg, dict_row, connection_pool = self._driver()
        pool = connection_pool(
            conninfo=self.dsn,
            kwargs={
                "autocommit": True,
                "row_factory": dict_row,
                "connect_timeout": 10,
            },
            # Warm the bounded client pool before high-concurrency work;
            # lazy connection expansion during the release gate inflates
            # tail latency even when every database operation succeeds.
            min_size=4,
            max_size=8,
            timeout=15.0,
            max_idle=300.0,
            max_lifetime=1800.0,
            reconnect_timeout=30.0,
            reconnect_failed=self._on_reconnect_failed,
            configure=self._configure_pool_connection,
            # A server-side termination of an idle socket is not observable
            # until I/O. Validate before handing the socket to a business
            # transaction so the pool can discard and replace it first.
            check=self._check_pool_connection,
            open=False,
            name="arenyxa-distributed-runtime",
        )
        opened = False
        try:
            retry_database_operation(
                lambda: pool.open(wait=True, timeout=15.0),
                retryable=(OSError, TimeoutError, RuntimeError, _psycopg.Error),
                policy=self.retry_policy,
            )
            opened = True
        finally:
            if not opened:
                try:
                    pool.close()
                except self._pool_close_error_types():
                    LOGGER.warning("PostgreSQL pool cleanup failed after open failure", exc_info=True)
        self._pool = pool
        return pool

    def _connection_pool(self) -> Any:
        with self._pool_condition:
            return self._connection_pool_locked()

    @contextmanager
    def connection(self) -> Iterator[_ConnectionFacade]:
        psycopg, _dict_row, _connection_pool = self._driver()
        with self._pool_condition:
            self._ensure_open_locked()
            self._active_connections += 1
            admission_ready = False
            try:
                pool = self._connection_pool_locked()
                admission_ready = True
            finally:
                if not admission_ready:
                    self._active_connections -= 1
                    self._pool_condition.notify_all()
        try:
            with pool.connection(timeout=15.0) as raw:
                with self._pool_metrics_lock:
                    self._pool_acquisitions += 1
                    self._last_pool_error = ""
                try:
                    yield _ConnectionFacade(raw, self)
                except (ArenyxaError, psycopg.Error, OSError, ValueError, TypeError, RuntimeError, KeyError):
                    try:
                        raw.rollback()
                    except psycopg.Error as rollback_exc:
                        LOGGER.warning("PostgreSQL rollback failed after runtime error: %s", rollback_exc)
                    raise
        except (psycopg.Error, OSError, TimeoutError, RuntimeError) as exc:
            with self._pool_metrics_lock:
                self._pool_acquisition_failures += 1
                self._last_pool_error = f"{type(exc).__name__}: {exc}"[:512]
            raise
        finally:
            with self._pool_condition:
                self._active_connections -= 1
                self._pool_condition.notify_all()

    def close(self) -> None:
        """Drain admitted connections and make this storage instance terminally closed."""
        with self._pool_condition:
            while True:
                if self._lifecycle_state == self._CLOSED:
                    return
                if self._lifecycle_state == self._OPEN:
                    self._lifecycle_state = self._CLOSING
                if not self._close_owner:
                    self._close_owner = True
                    break
                self._pool_condition.wait()
            while self._active_connections:
                self._pool_condition.wait()
            pool = self._pool

        try:
            if pool is not None:
                pool.close()
        except self._pool_close_error_types() as exc:
            with self._pool_metrics_lock:
                self._last_pool_error = f"{type(exc).__name__}: {exc}"[:512]
            with self._pool_condition:
                self._close_owner = False
                # CLOSING remains non-admitting, but a later close() owns a
                # well-defined retry instead of falsely reporting CLOSED.
                self._pool_condition.notify_all()
            raise

        with self._pool_condition:
            if self._pool is pool:
                self._pool = None
            self._lifecycle_state = self._CLOSED
            self._close_owner = False
            self._pool_condition.notify_all()

    def translate_sql(self, sql: str) -> str:
                                                                                                  
                                                                   
        translated = sql.replace("?", "%s")
        translated = translated.replace("max(0,active_leases-", "GREATEST(0,active_leases-")
        return translated

    def execute_script(self, raw_connection: Any, sql: str) -> None:
                                                                                               
                                                                                              
        for statement in sql.split(";"):
            statement = statement.strip()
            if statement:
                raw_connection.execute(statement)

    @staticmethod
    def _migrate_epoch_columns_to_float8(connection: _ConnectionFacade) -> None:
        """Upgrade legacy PostgreSQL float4 epoch columns without changing stored values."""
        rows = connection.execute(
            "SELECT table_name,column_name,data_type FROM information_schema.columns "
            "WHERE table_schema=current_schema() AND ((table_name='distributed_workers' "
            "AND column_name='heartbeat_at') OR (table_name='distributed_jobs' "
            "AND column_name='lease_expires_at'))"
        ).fetchall()
        types = {(str(row[0]), str(row[1])): str(row[2]).casefold() for row in rows}
        for table, column, migration_sql in _POSTGRES_EPOCH_MIGRATIONS:
            if types.get((table, column)) != "real":
                continue
            connection.execute(migration_sql)

    def initialize_schema(self, schema: str, current_protocol: int, min_protocol: int) -> None:
        with self.connection() as connection:
            connection.execute("BEGIN")
                                                                                                  
                                         
            connection.execute("SELECT pg_advisory_xact_lock(?)", (self._SCHEMA_ADVISORY_LOCK,))
            connection.executescript(_POSTGRES_SCHEMA)
            self._migrate_epoch_columns_to_float8(connection)
            schema_row = connection.execute("SELECT value FROM distributed_meta WHERE key='schema'").fetchone()
            if schema_row is None:
                connection.execute("INSERT INTO distributed_meta(key,value) VALUES('schema',?)", (schema,))
            elif str(schema_row[0]) != schema:
                connection.rollback()
                raise _storage_fail("DISTRIBUTED_SCHEMA_UNSUPPORTED", "Distributed queue schema requires migration")
            existing_columns = {
                str(row[0])
                for row in connection.execute(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema=current_schema() AND table_name='distributed_jobs'"
                ).fetchall()
            }
            for column, declaration in (
                ("result_sha256", "TEXT NOT NULL DEFAULT ''"),
                ("terminal_worker_id", "TEXT NOT NULL DEFAULT ''"),
                ("terminal_lease_token_sha256", "TEXT NOT NULL DEFAULT ''"),
                ("terminal_at", "TEXT NOT NULL DEFAULT ''"),
                ("traceparent", "TEXT NOT NULL DEFAULT ''"),
                ("tracestate", "TEXT NOT NULL DEFAULT ''"),
            ):
                if column not in existing_columns:
                    connection.execute("ALTER TABLE distributed_jobs ADD COLUMN " + sql_identifier(column) + " " + declaration)
            worker_columns = {
                str(row[0])
                for row in connection.execute(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema=current_schema() AND table_name='distributed_workers'"
                ).fetchall()
            }
            for column, declaration in (
                ("identity_algorithm", "TEXT NOT NULL DEFAULT 'ED25519'"),
                ("identity_metadata_json", "TEXT NOT NULL DEFAULT '{}'"),
            ):
                if column not in worker_columns:
                    connection.execute("ALTER TABLE distributed_workers ADD COLUMN " + sql_identifier(column) + " " + declaration)
            connection.execute(
                "INSERT INTO distributed_meta(key,value) VALUES('protocol_current',?) "
                "ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                (str(current_protocol),),
            )
            connection.execute(
                "INSERT INTO distributed_meta(key,value) VALUES('protocol_min',?) "
                "ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                (str(min_protocol),),
            )
            connection.commit()

    def authoritative_lease_epoch(self, connection: _ConnectionFacade, clock: Any) -> float:
        del clock
        row = connection.execute(
            "SELECT EXTRACT(EPOCH FROM clock_timestamp())::DOUBLE PRECISION AS lease_epoch"
        ).fetchone()
        if row is None:
            raise _storage_fail("DISTRIBUTED_LEASE_CLOCK_UNAVAILABLE", "PostgreSQL authoritative lease clock is unavailable")
        return float(row[0])

    def fast_lease_expiry_parameter(self, now: float, duration: float) -> float:
        del now
        return max(0.0, float(duration))

    def fast_lease_expiry_from_row(self, row: Any, fallback: float) -> float:
        del fallback
        return float(row["lease_expires_at"])

    def begin_write(self, connection: _ConnectionFacade) -> None:
        # Recovery and fencing statements deliberately re-check mutable rows in
        # their final UPDATE.  Pinning a server-configured REPEATABLE READ snapshot
        # would make that re-check observe the earlier candidate snapshot instead
        # of a heartbeat committed by another host in the meantime.
        connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")

    def integrity_check(self) -> tuple[bool, str]:
        try:
            psycopg, _dict_row, _pool = self._driver()
            with self.connection() as connection:
                row = connection.execute("SELECT 1 AS healthy").fetchone()
                return row is not None and int(row[0]) == 1, "ok"
        except (ArenyxaError, OSError, ValueError, TypeError, RuntimeError, psycopg.Error) as exc:
            return False, f"postgresql health check failed: {type(exc).__name__}"

    def lease_candidate_sql(self) -> str:
                                                                                           
                                                                                                 
        return (
            "SELECT * FROM distributed_jobs WHERE state='queued' "
            "AND protocol_version BETWEEN ? AND ? "
            "ORDER BY priority DESC, created_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED"
        )

    def worker_for_lease_sql(self) -> str:
        return "SELECT * FROM distributed_workers WHERE worker_id=? FOR UPDATE"

    def claim_worker_slot_for_lease_sql(self) -> str:
        return (
            "UPDATE distributed_workers SET active_leases=active_leases+1,"
            "heartbeat_at=GREATEST(heartbeat_at,?,EXTRACT(EPOCH FROM clock_timestamp())),updated_at=? "
            "WHERE worker_id=? AND state='active' AND active_leases<max_slots "
            "RETURNING protocol_min,protocol_max"
        )

    def lease_next_fast_sql(self) -> str:
        return """
            WITH eligible_worker AS (
                SELECT worker_id,protocol_min,protocol_max
                FROM distributed_workers
                WHERE worker_id=? AND state='active' AND active_leases<max_slots
            ), candidate AS (
                SELECT j.*
                FROM distributed_jobs AS j
                JOIN eligible_worker AS w
                  ON j.protocol_version BETWEEN w.protocol_min AND w.protocol_max
                WHERE j.state='queued'
                ORDER BY j.priority DESC,j.created_at ASC
                LIMIT 1
                FOR UPDATE OF j SKIP LOCKED
            ), claimed_worker AS (
                UPDATE distributed_workers AS w
                SET active_leases=w.active_leases+1,heartbeat_at=GREATEST(w.heartbeat_at,?,EXTRACT(EPOCH FROM clock_timestamp())),updated_at=?
                FROM candidate AS c
                WHERE w.worker_id=? AND w.state='active' AND w.active_leases<w.max_slots
                RETURNING w.worker_id
            ), leased AS (
                UPDATE distributed_jobs AS j
                SET state='leased',attempt=j.attempt+1,lease_worker_id=?,lease_token_sha256=?,
                    lease_expires_at=EXTRACT(EPOCH FROM clock_timestamp())+?,error_code='',updated_at=?
                FROM candidate AS c
                CROSS JOIN claimed_worker AS w
                WHERE j.job_id=c.job_id AND j.state='queued'
                RETURNING j.*
            ), event AS (
                INSERT INTO distributed_job_events(
                    job_id,event_type,from_state,to_state,worker_id,code,details_json,created_at
                )
                SELECT job_id,'leased','queued','leased',?,?,
                       json_build_object('attempt',attempt,'lease_seconds',?)::text,?
                FROM leased
                RETURNING job_id
            ), trimmed AS (
                DELETE FROM distributed_job_events
                WHERE job_id=(SELECT job_id FROM event)
                  AND event_id NOT IN (
                      SELECT event_id FROM distributed_job_events
                      WHERE job_id=(SELECT job_id FROM event)
                      ORDER BY event_id DESC LIMIT ?
                  )
            )
            SELECT * FROM leased
        """

    def start_job_fast_sql(self) -> str:
        return """
            WITH candidate AS (
                SELECT job_id,state
                FROM distributed_jobs
                WHERE job_id=? AND state='leased' AND lease_worker_id=?
                  AND lease_token_sha256=? AND lease_expires_at>GREATEST(?,EXTRACT(EPOCH FROM clock_timestamp()))
                FOR UPDATE
            ), updated AS (
                UPDATE distributed_jobs AS j
                SET state='running',updated_at=?
                FROM candidate AS c
                WHERE j.job_id=c.job_id
                RETURNING j.job_id
            ), event AS (
                INSERT INTO distributed_job_events(
                    job_id,event_type,from_state,to_state,worker_id,code,details_json,created_at
                )
                SELECT c.job_id,'started',c.state,'running',?,?,?,?
                FROM candidate AS c
                JOIN updated AS u ON u.job_id=c.job_id
                RETURNING job_id
            ), trimmed AS (
                DELETE FROM distributed_job_events
                WHERE job_id=(SELECT job_id FROM event)
                  AND event_id NOT IN (
                      SELECT event_id FROM distributed_job_events
                      WHERE job_id=(SELECT job_id FROM event)
                      ORDER BY event_id DESC LIMIT ?
                  )
            )
            SELECT * FROM updated
        """

    def complete_fast_sql(self) -> str:
        return """
            WITH candidate AS (
                SELECT job_id,state,side_effect_state,idempotency_key,kind,payload_sha256,
                       resource_id,permission,side_effect_mode,created_at
                FROM distributed_jobs
                WHERE job_id=? AND state IN ('leased','running')
                  AND lease_worker_id=? AND lease_token_sha256=? AND lease_expires_at>GREATEST(?,EXTRACT(EPOCH FROM clock_timestamp()))
                FOR UPDATE
            ), tombstone AS (
                INSERT INTO distributed_job_idempotency(
                    idempotency_key,job_id,kind,payload_sha256,resource_id,permission,
                    side_effect_mode,terminal_state,created_at,terminal_at,updated_at
                )
                SELECT c.idempotency_key,c.job_id,c.kind,c.payload_sha256,c.resource_id,c.permission,
                       c.side_effect_mode,'completed',c.created_at,?,?
                FROM candidate AS c
                ON CONFLICT (idempotency_key) DO UPDATE SET
                    terminal_state=EXCLUDED.terminal_state,
                    terminal_at=EXCLUDED.terminal_at,
                    updated_at=EXCLUDED.updated_at
                WHERE distributed_job_idempotency.job_id=EXCLUDED.job_id
                  AND distributed_job_idempotency.kind=EXCLUDED.kind
                  AND distributed_job_idempotency.payload_sha256=EXCLUDED.payload_sha256
                  AND distributed_job_idempotency.resource_id=EXCLUDED.resource_id
                  AND distributed_job_idempotency.permission=EXCLUDED.permission
                  AND distributed_job_idempotency.side_effect_mode=EXCLUDED.side_effect_mode
                RETURNING idempotency_key,terminal_at,updated_at
            ), updated AS (
                UPDATE distributed_jobs AS j
                SET state='completed',result_json=?,result_sha256=?,
                    side_effect_state=CASE WHEN c.side_effect_state='started' THEN 'completed'
                                           ELSE c.side_effect_state END,
                    terminal_worker_id=?,terminal_lease_token_sha256=?,terminal_at=t.terminal_at,
                    lease_worker_id='',lease_token_sha256='',lease_expires_at=0,
                    error_code='',updated_at=t.updated_at
                FROM candidate AS c
                JOIN tombstone AS t ON t.idempotency_key=c.idempotency_key
                WHERE j.job_id=c.job_id
                RETURNING j.job_id,j.terminal_at,j.updated_at
            ), worker_updated AS (
                UPDATE distributed_workers AS w
                SET active_leases=GREATEST(0,w.active_leases-1),heartbeat_at=GREATEST(w.heartbeat_at,?,EXTRACT(EPOCH FROM clock_timestamp())),updated_at=?
                WHERE w.worker_id=? AND EXISTS (SELECT 1 FROM updated)
                RETURNING w.worker_id
            ), event AS (
                INSERT INTO distributed_job_events(
                    job_id,event_type,from_state,to_state,worker_id,code,details_json,created_at
                )
                SELECT c.job_id,'completed',c.state,'completed',?,?,?,?
                FROM candidate AS c
                JOIN updated AS u ON u.job_id=c.job_id
                RETURNING job_id
            ), trimmed AS (
                DELETE FROM distributed_job_events
                WHERE job_id=(SELECT job_id FROM event)
                  AND event_id NOT IN (
                      SELECT event_id FROM distributed_job_events
                      WHERE job_id=(SELECT job_id FROM event)
                      ORDER BY event_id DESC LIMIT ?
                  )
            )
            SELECT c.state AS previous_state
            FROM candidate AS c
            JOIN updated AS u ON u.job_id=c.job_id
        """

    def record_event(
        self, connection: _ConnectionFacade, values: Sequence[Any], max_events: int,
    ) -> None:
        """Insert and trim one event in a single PostgreSQL round trip."""
        keep = max(1, int(max_events) - 1)
        connection.execute(
            """WITH inserted AS (
                INSERT INTO distributed_job_events(
                    job_id,event_type,from_state,to_state,worker_id,code,details_json,created_at
                ) VALUES(?,?,?,?,?,?,?,?)
                RETURNING job_id
            )
            DELETE FROM distributed_job_events
            WHERE job_id=(SELECT job_id FROM inserted)
              AND event_id NOT IN (
                  SELECT event_id FROM distributed_job_events
                  WHERE job_id=(SELECT job_id FROM inserted)
                  ORDER BY event_id DESC LIMIT ?
              )""",
            tuple(values) + (keep,),
        )

    def lease_for_update_sql(self) -> str:
        return "SELECT * FROM distributed_jobs WHERE job_id=? FOR UPDATE"

    def expired_lease_candidates_sql(self) -> str:
        return (
            "SELECT job_id,state,lease_worker_id,lease_token_sha256,lease_expires_at,side_effect_mode,side_effect_state,attempt,max_attempts "
            "FROM distributed_jobs WHERE state IN ('leased','running') "
            "AND lease_expires_at>0 AND lease_expires_at<=? "
            "ORDER BY lease_worker_id,job_id FOR UPDATE SKIP LOCKED"
        )

    def invalid_lease_candidates_sql(self) -> str:
        return (
            "SELECT j.* FROM distributed_jobs j "
            "LEFT JOIN distributed_workers w ON w.worker_id=j.lease_worker_id "
            "WHERE j.state IN ('leased','running') AND ("
            "j.lease_worker_id='' OR j.lease_token_sha256='' OR j.lease_expires_at<=0 OR "
            "j.lease_expires_at>? OR w.worker_id IS NULL OR w.state='revoked') "
            "FOR UPDATE OF j SKIP LOCKED"
        )


def storage_backend_for(target: Path | str) -> DistributedRuntimeStorageBackend:
    text = str(target).strip()
    if text.casefold().startswith(("postgresql://", "postgres://")):
        return PostgreSQLDistributedRuntimeStorage(text)
    return SQLiteDistributedRuntimeStorage(Path(target))
