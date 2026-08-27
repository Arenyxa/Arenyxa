from __future__ import annotations

import re
from collections.abc import Collection, Iterable

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def sql_identifier(value: str, *, allowed: Collection[str] | None = None) -> str:
    """Return a strictly validated SQL identifier quoted for SQLite/PostgreSQL style SQL.

    Values are never accepted merely because quotes can be escaped: identifiers must use the
    conservative ASCII identifier grammar and may additionally be restricted to an allow-list.
    """
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"invalid SQL identifier: {value!r}")
    if allowed is not None and value not in allowed:
        raise ValueError(f"SQL identifier is not permitted: {value!r}")
    return '"' + value + '"'


def sql_placeholders(count: int) -> str:
    """Build a bounded DB-API placeholder list for an IN/VALUES clause."""
    if isinstance(count, bool) or not isinstance(count, int) or count <= 0 or count > 10_000:
        raise ValueError("placeholder count must be between 1 and 10000")
    return ",".join("?" for _ in range(count))


def sqlite_pragma_user_version(version: int) -> str:
    """Build the one SQLite PRAGMA that cannot use a DB-API value placeholder."""
    if isinstance(version, bool) or not isinstance(version, int) or not 0 <= version <= 2_147_483_647:
        raise ValueError("invalid SQLite user_version")
    return "PRAGMA user_version=" + str(version)


def sqlite_wal_checkpoint(mode: str) -> str:
    normalized = str(mode).upper()
    if normalized not in {"PASSIVE", "FULL", "RESTART", "TRUNCATE"}:
        raise ValueError("invalid WAL checkpoint mode")
    return "PRAGMA wal_checkpoint(" + normalized + ")"


def sql_column_definitions(columns: Iterable[tuple[str, str]], *, allowed_types: Collection[str]) -> str:
    definitions: list[str] = []
    for name, kind in columns:
        normalized = str(kind).strip().upper()
        if normalized not in allowed_types:
            raise ValueError(f"unsupported SQL column type: {kind!r}")
        definitions.append(sql_identifier(name) + " " + normalized)
    if not definitions:
        raise ValueError("at least one SQL column definition is required")
    return ",".join(definitions)
