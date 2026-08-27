from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Iterator, Mapping, Sequence
from arenyxa.compat import dataclass
from itertools import chain
from pathlib import Path
from typing import Any, Protocol

from arenyxa.security.sql_safety import sql_identifier


@dataclass(frozen=True, slots=True)
class AdapterCapabilities:
    transactions: bool
    bulk_insert: bool
    upsert: bool
    schema_management: bool
    query: bool
    streaming: bool
    full_text_search: bool = False


class DatabaseAdapter(Protocol):
    def open(self, config: Mapping[str, Any], secrets: Mapping[str, str]) -> None: ...

    def close(self) -> None: ...

    def describe_capabilities(self) -> AdapterCapabilities: ...

    def ensure_schema(self, table: str, columns: Mapping[str, str]) -> None: ...

    def bulk_write(self, table: str, rows: Iterable[Mapping[str, Any]], batch_size: int = 1000) -> int: ...

    def query(
        self, statement: str, parameters: Sequence[Any] | Mapping[str, Any] = ()
    ) -> Iterator[Mapping[str, Any]]: ...


class SQLiteDatabaseAdapter:
    def __init__(self) -> None:
        self.connection: sqlite3.Connection | None = None

    def open(self, config: Mapping[str, Any], secrets: Mapping[str, str]) -> None:
        del secrets
        path = Path(str(config["path"])).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA journal_mode=WAL")

    def close(self) -> None:
        if self.connection:
            self.connection.close()
            self.connection = None

    def describe_capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(True, True, True, True, True, True, True)

    def ensure_schema(self, table: str, columns: Mapping[str, str]) -> None:
        connection = self._require()
        if not columns:
            raise ValueError("schema must contain at least one column")
        safe_table = sql_identifier(table)
        definitions = ",".join(
            sql_identifier(name) + " " + self._column_type(kind)
            for name, kind in columns.items()
        )
        statement = "CREATE TABLE IF NOT EXISTS " + safe_table + " (" + definitions + ")"
        connection.execute(statement)
        connection.commit()

    def bulk_write(self, table: str, rows: Iterable[Mapping[str, Any]], batch_size: int = 1000) -> int:
        if not isinstance(batch_size, int) or isinstance(batch_size, bool) or batch_size <= 0:
            raise ValueError("batch_size must be a positive integer")
        connection = self._require()
        iterator = iter(rows)
        first = next(iterator, None)
        if first is None:
            return 0
        if not isinstance(first, Mapping):
            raise ValueError("rows must contain mapping objects")
        fields = list(first)
        if not fields:
            raise ValueError("rows must contain at least one column")
        expected_fields = set(fields)
        table_name = sql_identifier(table)
        column_sql = ",".join(sql_identifier(field) for field in fields)
        placeholders = ",".join("?" for _ in fields)
        statement = "INSERT INTO " + table_name + " (" + column_sql + ") VALUES (" + placeholders + ")"
        count = 0
        batch = []
        try:
            connection.execute("BEGIN")
            for row in chain((first,), iterator):
                if not isinstance(row, Mapping):
                    raise ValueError("rows must contain mapping objects")
                if set(row) != expected_fields:
                    raise ValueError("all rows in one bulk_write call must have identical columns")
                batch.append(tuple(row.get(field) for field in fields))
                if len(batch) >= batch_size:
                    connection.executemany(statement, batch)
                    count += len(batch)
                    batch.clear()
            if batch:
                connection.executemany(statement, batch)
                count += len(batch)
            connection.commit()
        except (sqlite3.Error, ValueError, TypeError, OverflowError):
            connection.rollback()
            raise
        return count

    def query(
        self, statement: str, parameters: Sequence[Any] | Mapping[str, Any] = ()
    ) -> Iterator[Mapping[str, Any]]:
        cursor = self._require().execute(statement, parameters)
        for row in cursor:
            yield dict(row)

    def _require(self) -> sqlite3.Connection:
        if not self.connection:
            raise RuntimeError("adapter is not open")
        return self.connection

    @staticmethod
    def _identifier(value: str) -> str:
        # Historical private helper now delegates to the shared strict validator.
        return sql_identifier(value)[1:-1]

    @staticmethod
    def _column_type(kind: str) -> str:
        if not isinstance(kind, str):
            raise ValueError("column type must be a string")
        mapped = {
            "string": "TEXT", "text": "TEXT", "integer": "INTEGER",
            "number": "REAL", "float": "REAL", "boolean": "INTEGER",
            "datetime": "TEXT", "json": "TEXT", "blob": "BLOB",
        }.get(kind.casefold())
        if mapped is None:
            raise ValueError(f"unsupported SQLite column type: {kind}")
        return mapped


class SQLAlchemyDatabaseAdapter:
    

    def __init__(self) -> None:
        self.engine: Any = None

    def open(self, config: Mapping[str, Any], secrets: Mapping[str, str]) -> None:
        try:
            import sqlalchemy
        except ImportError as exc:
            raise RuntimeError("install the database extra: pip install -e .[database]") from exc
        url = str(config["url"])
        for name, value in secrets.items():
            url = url.replace(f"${{{{secret.{name}}}}}", value)
        self.engine = sqlalchemy.create_engine(url, pool_pre_ping=True, future=True)

    def close(self) -> None:
        if self.engine:
            self.engine.dispose()
            self.engine = None

    def describe_capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(True, True, True, True, True, True, False)

    def ensure_schema(self, table: str, columns: Mapping[str, str]) -> None:
        import sqlalchemy

        if not isinstance(table, str) or not table or not columns:
            raise ValueError("table and schema must be non-empty")
        if any(not isinstance(name, str) or not name for name in columns):
            raise ValueError("column names must be non-empty strings")
        metadata = sqlalchemy.MetaData()
        sqlalchemy.Table(
            table,
            metadata,
            *(sqlalchemy.Column(name, self._type(kind)) for name, kind in columns.items()),
        )
        metadata.create_all(self.engine)

    def bulk_write(self, table: str, rows: Iterable[Mapping[str, Any]], batch_size: int = 1000) -> int:
        import sqlalchemy

        if not isinstance(batch_size, int) or isinstance(batch_size, bool) or batch_size <= 0:
            raise ValueError("batch_size must be a positive integer")
        metadata = sqlalchemy.MetaData()
        target = sqlalchemy.Table(table, metadata, autoload_with=self.engine)
        count = 0
        batch: list[Mapping[str, Any]] = []
        with self.engine.begin() as connection:
            expected_fields: set[str] | None = None
            for row in rows:
                if not isinstance(row, Mapping) or not row:
                    raise ValueError("rows must contain non-empty mapping objects")
                row_fields = set(row)
                if expected_fields is None:
                    expected_fields = row_fields
                elif row_fields != expected_fields:
                    raise ValueError("all rows in one bulk_write call must have identical columns")
                batch.append(dict(row))
                if len(batch) >= batch_size:
                    connection.execute(target.insert(), batch)
                    count += len(batch)
                    batch.clear()
            if batch:
                connection.execute(target.insert(), batch)
                count += len(batch)
        return count

    def query(
        self, statement: str, parameters: Sequence[Any] | Mapping[str, Any] = ()
    ) -> Iterator[Mapping[str, Any]]:
        import sqlalchemy

        with self.engine.connect() as connection:
            if isinstance(parameters, Mapping):
                result = connection.execute(sqlalchemy.text(statement), dict(parameters))
            else:
                                                                                          
                                                                                      
                                                                                     
                result = connection.exec_driver_sql(statement, tuple(parameters))
            yield from result.mappings()

    @staticmethod
    def _type(kind: str) -> Any:
        import sqlalchemy

        if not isinstance(kind, str):
            raise ValueError("column type must be a string")
        mapped = {
            "string": sqlalchemy.Text(),
            "text": sqlalchemy.Text(),
            "integer": sqlalchemy.Integer(),
            "number": sqlalchemy.Float(),
            "float": sqlalchemy.Float(),
            "boolean": sqlalchemy.Boolean(),
            "datetime": sqlalchemy.DateTime(timezone=True),
            "json": sqlalchemy.JSON(),
            "blob": sqlalchemy.LargeBinary(),
        }.get(kind.casefold())
        if mapped is None:
            raise ValueError(f"unsupported SQLAlchemy column type: {kind}")
        return mapped
