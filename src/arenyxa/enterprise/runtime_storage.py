from __future__ import annotations

import hashlib
import logging
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
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

    def begin_write(self, connection: _ConnectionFacade) -> None:
        connection.execute("BEGIN IMMEDIATE")

    def integrity_check(self) -> tuple[bool, str]:
        with self.connection() as connection:
            row = connection.execute("PRAGMA quick_check(1)").fetchone()
            result = "" if row is None else str(row[0])
            return result.casefold() == "ok", result


class PostgreSQLDistributedRuntimeStorage(DistributedRuntimeStorageBackend):
    






    _SCHEMA_ADVISORY_LOCK = 0x4152454E595841                                     

    def __init__(self, dsn: str) -> None:
        text = str(dsn).strip()
        if not text.casefold().startswith(("postgresql://", "postgres://")):
            raise _storage_fail("DISTRIBUTED_STORAGE_DSN_INVALID", "PostgreSQL runtime DSN is invalid")
        self.dsn = text
        self._pool: Any | None = None
        self._pool_lock = threading.Lock()
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
        with self._pool_metrics_lock:
            local = {
                "acquisitions": self._pool_acquisitions,
                "acquisition_failures": self._pool_acquisition_failures,
                "reconnect_failures": self._pool_reconnect_failures,
                "last_error": self._last_pool_error,
            }
        pool = self._pool
        if pool is None:
            return {**local, "open": False, "backend": "postgresql"}
        try:
            stats = dict(pool.get_stats())
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            stats = {"stats_error": f"{type(exc).__name__}: {exc}"[:256]}
        return {**local, "open": not bool(getattr(pool, "closed", False)), "backend": "postgresql", **stats}

    def _connection_pool(self) -> Any:
        existing = self._pool
        if existing is not None:
            return existing
        _psycopg, dict_row, connection_pool = self._driver()
        with self._pool_lock:
            existing = self._pool
            if existing is not None:
                return existing
            pool = connection_pool(
                conninfo=self.dsn,
                kwargs={
                    "autocommit": True,
                    "row_factory": dict_row,
                    "connect_timeout": 10,
                },
                min_size=1,
                max_size=64,
                timeout=15.0,
                max_idle=300.0,
                max_lifetime=1800.0,
                reconnect_timeout=30.0,
                reconnect_failed=self._on_reconnect_failed,
                configure=self._configure_pool_connection,
                check=getattr(connection_pool, "check_connection", self._check_pool_connection),
                open=False,
                name="arenyxa-distributed-runtime",
            )
            retry_database_operation(
                lambda: pool.open(wait=True, timeout=15.0),
                retryable=(OSError, TimeoutError, RuntimeError, _psycopg.Error),
                policy=self.retry_policy,
            )
            self._pool = pool
            return pool

    @contextmanager
    def connection(self) -> Iterator[_ConnectionFacade]:
        psycopg, _dict_row, _connection_pool = self._driver()
        pool = self._connection_pool()
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

    def close(self) -> None:
        """Close the PostgreSQL connection pool during controlled shutdown and tests."""
        with self._pool_lock:
            pool = self._pool
            self._pool = None
        if pool is not None:
            pool.close()

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

    def begin_write(self, connection: _ConnectionFacade) -> None:
        connection.execute("BEGIN")

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
            "UPDATE distributed_workers SET active_leases=active_leases+1,heartbeat_at=?,updated_at=? "
            "WHERE worker_id=? AND state='active' AND active_leases<max_slots "
            "RETURNING protocol_min,protocol_max"
        )

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
