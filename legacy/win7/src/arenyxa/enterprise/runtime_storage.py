from __future__ import annotations

from arenyxa.security.sql_safety import sql_identifier
import sqlite3
from abc import ABC, abstractmethod
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from arenyxa.compat import dataclass
from arenyxa.domain.errors import ArenyxaError


@dataclass(frozen=True, slots=True)
class RuntimeStorageCapabilities:
    backend: str
    multi_host_writers: bool
    row_lock_skip_locked: bool
    external_server: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "multi_host_writers": self.multi_host_writers,
            "row_lock_skip_locked": self.row_lock_skip_locked,
            "external_server": self.external_server,
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

_POSTGRES_SCHEMA = _SQLITE_SCHEMA.replace(
    "event_id INTEGER PRIMARY KEY AUTOINCREMENT", "event_id BIGSERIAL PRIMARY KEY"
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

    def keys(self):
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
    __slots__ = ("raw", "backend")

    def __init__(self, raw: Any, backend: "DistributedRuntimeStorageBackend") -> None:
        self.raw = raw
        self.backend = backend

    def execute(self, sql: str, params: Sequence[Any] = ()) -> _CursorFacade:
        translated = self.backend.translate_sql(sql)
        cursor = self.raw.execute(translated, tuple(params))
        return _CursorFacade(cursor, mapping_rows=self.backend.capabilities.backend == "postgresql")

    def executescript(self, sql: str) -> None:
        self.backend.execute_script(self.raw, sql)

    def commit(self) -> None:
        self.raw.commit()

    def rollback(self) -> None:
        self.raw.rollback()


class DistributedRuntimeStorageBackend(ABC):
    @property
    @abstractmethod
    def capabilities(self) -> RuntimeStorageCapabilities:
        raise NotImplementedError

    @contextmanager
    @abstractmethod
    def connection(self) -> Iterator[_ConnectionFacade]:
        raise NotImplementedError

    @abstractmethod
    def initialize_schema(self, schema: str, current_protocol: int, min_protocol: int) -> None:
        raise NotImplementedError

    @abstractmethod
    def begin_write(self, connection: _ConnectionFacade) -> None:
        raise NotImplementedError

    @abstractmethod
    def integrity_check(self) -> tuple[bool, str]:
        raise NotImplementedError

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

    def claim_worker_slot_sql(self) -> str:
        return (
            "UPDATE distributed_workers SET active_leases=active_leases+1,heartbeat_at=?,updated_at=? "
            "WHERE worker_id=? AND state='active' AND active_leases<max_slots"
        )

    def expired_lease_candidates_sql(self) -> str:
        return (
            "SELECT job_id,state,lease_worker_id,side_effect_mode,side_effect_state,attempt,max_attempts "
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
        )

    @contextmanager
    def connection(self) -> Iterator[_ConnectionFacade]:
        raw = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        try:
            raw.row_factory = sqlite3.Row
            raw.executescript("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")
            yield _ConnectionFacade(raw, self)
        except Exception:
            try:
                raw.rollback()
            except sqlite3.Error:
                pass
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
            ):
                if column not in existing_columns:
                    connection.execute("ALTER TABLE distributed_jobs ADD COLUMN " + sql_identifier(column) + " " + declaration)
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

    @property
    def capabilities(self) -> RuntimeStorageCapabilities:
        return RuntimeStorageCapabilities(
            backend="postgresql",
            multi_host_writers=True,
            row_lock_skip_locked=True,
            external_server=True,
        )

    def _driver(self):
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise _storage_fail(
                "DISTRIBUTED_POSTGRES_DRIVER_MISSING",
                "PostgreSQL Enterprise runtime requires Psycopg 3",
            ) from exc
        return psycopg, dict_row

    @contextmanager
    def connection(self) -> Iterator[_ConnectionFacade]:
        psycopg, dict_row = self._driver()
        raw = psycopg.connect(
            self.dsn,
            autocommit=True,
            row_factory=dict_row,
            connect_timeout=10,
        )
        try:
            raw.execute("SET lock_timeout = '10s'")
            raw.execute("SET statement_timeout = '60s'")
            raw.execute("SET idle_in_transaction_session_timeout = '60s'")
            yield _ConnectionFacade(raw, self)
        except Exception:
            try:
                raw.rollback()
            except Exception:
                pass
            raise
        finally:
            raw.close()

    def translate_sql(self, sql: str) -> str:
                                                                                                  
                                                                   
        translated = sql.replace("?", "%s")
        translated = translated.replace("max(0,active_leases-", "GREATEST(0,active_leases-")
        return translated

    def execute_script(self, raw_connection: Any, sql: str) -> None:
                                                                                               
                                                                                              
        for statement in sql.split(";"):
            statement = statement.strip()
            if statement:
                raw_connection.execute(statement)

    def initialize_schema(self, schema: str, current_protocol: int, min_protocol: int) -> None:
        with self.connection() as connection:
            connection.execute("BEGIN")
                                                                                                  
                                         
            connection.execute("SELECT pg_advisory_xact_lock(?)", (self._SCHEMA_ADVISORY_LOCK,))
            connection.executescript(_POSTGRES_SCHEMA)
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
            ):
                if column not in existing_columns:
                    connection.execute("ALTER TABLE distributed_jobs ADD COLUMN " + sql_identifier(column) + " " + declaration)
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
            with self.connection() as connection:
                row = connection.execute("SELECT 1 AS healthy").fetchone()
                return row is not None and int(row[0]) == 1, "ok"
        except Exception as exc:
            return False, f"postgresql health check failed: {type(exc).__name__}"

    def lease_candidate_sql(self) -> str:
                                                                                           
                                                                                                 
        return (
            "SELECT * FROM distributed_jobs WHERE state='queued' "
            "AND protocol_version BETWEEN ? AND ? "
            "ORDER BY priority DESC, created_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED"
        )

    def worker_for_lease_sql(self) -> str:
        return "SELECT * FROM distributed_workers WHERE worker_id=?"

    def expired_lease_candidates_sql(self) -> str:
        return (
            "SELECT job_id,state,lease_worker_id,side_effect_mode,side_effect_state,attempt,max_attempts "
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
