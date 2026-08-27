"""Maintenance, recovery, and enterprise binding helpers for SQLiteStore."""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from arenyxa.recoverable import record_current_exception
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import utc_now
from arenyxa.infrastructure.atomic_io import fsync_existing_file
from arenyxa.security.sql_safety import sqlite_wal_checkpoint

LOGGER = logging.getLogger(__name__)


class SQLiteMaintenanceMixin:
    """Operational helpers separated from schema bootstrapping for maintainability."""

    def integrity_check(self) -> str:
        """Run SQLite integrity_check and return the engine response."""
        with self.connect() as connection:
            return str(connection.execute("PRAGMA integrity_check").fetchone()[0])

    def quick_check(self) -> str:
        
        """Run SQLite quick_check and return bounded diagnostic rows."""
        with self.connect() as connection:
            return str(connection.execute("PRAGMA quick_check(1)").fetchone()[0])

    def ping(self) -> bool:
        
        """Verify that the local database can execute a trivial bounded query."""
        try:
            with self.connect() as connection:
                row = connection.execute("SELECT 1").fetchone()
            return bool(row and int(row[0]) == 1)
        except (sqlite3.DatabaseError, OSError, ValueError):
            return False

    def checkpoint(self, mode: str = "PASSIVE") -> tuple[int, int, int]:
        
        """Checkpoint the WAL using an allowlisted SQLite checkpoint mode."""
        statement = sqlite_wal_checkpoint(mode)
        with self.connect() as connection:
            row = connection.execute(statement).fetchone()
        return (int(row[0]), int(row[1]), int(row[2]))

    def optimize(self) -> None:
        
        """Run bounded SQLite optimization for the local embedded store."""
        with self.connect() as connection:
            connection.execute("PRAGMA optimize")

    def stability_snapshot(self, *, check_integrity: bool = False) -> dict[str, Any]:
        from arenyxa.infrastructure.database_stability import SQLiteStabilityMonitor

        return SQLiteStabilityMonitor(self).snapshot(check_integrity=check_integrity)

    def backup_to(self, destination: Path) -> Path:
        





        """Create a consistent SQLite backup at the requested destination."""
        target = Path(destination).expanduser().resolve()
        source_path = self.path.expanduser().resolve()
        if target == source_path:
            raise ValueError("备份目标不能覆盖正在使用的 Arenyxa 数据库。")
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
        os.close(fd)
        temporary = Path(temporary_name)
        try:
            with self.connect() as source:
                backup = sqlite3.connect(temporary)
                try:
                    source.backup(backup, pages=256, sleep=0.01)
                    backup.commit()
                    row = backup.execute("PRAGMA quick_check(1)").fetchone()
                    if row is None or str(row[0]).casefold() != "ok":
                        raise ArenyxaError(
                            "DATABASE_BACKUP_VERIFY_FAILED",
                            "SQLite 备份完整性检查失败，未替换现有备份。",
                            domain="DATABASE",
                        )
                finally:
                    backup.close()
            fsync_existing_file(temporary)
            os.replace(temporary, target)
            return target
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                record_current_exception(__name__, 'SQLiteStore.backup_to:829')

    def recover_interrupted_state(self) -> dict[str, int]:
        







        """Reconcile stale run and capture lifecycle rows after an interrupted process."""
        finished_at = utc_now()
        with self.transaction() as connection:
            run_cursor = connection.execute(
                "UPDATE runs SET status='failed',stage='failed',"
                "error_code=COALESCE(error_code,'RUN_INTERRUPTED'),"
                "finished_at=COALESCE(finished_at,?) "
                "WHERE status IN ('queued','running','paused')",
                (finished_at,),
            )
            capture_cursor = connection.execute(
                "UPDATE capture_sessions SET state='failed',finished_at=COALESCE(finished_at,?),"
                "event_count=(SELECT count(*) FROM network_events e WHERE e.session_id=capture_sessions.id),"
                "bytes_captured=COALESCE((SELECT sum(e.size) FROM network_events e "
                "WHERE e.session_id=capture_sessions.id),0) "
                "WHERE state IN ('preparing','capturing','paused','finalizing')",
                (finished_at,),
            )
        return {
            "runs": max(0, int(run_cursor.rowcount)),
            "captures": max(0, int(capture_cursor.rowcount)),
        }

    def recover_interrupted_pipeline_state(self) -> dict[str, int]:
        







        """Reconcile stale workflow and dataset pipeline state after interruption."""
        recovered_at = utc_now()
        with self.transaction() as connection:
            completed_cursor = connection.execute(
                """
                UPDATE workflow_executions
                SET state=CASE WHEN error_count>0 THEN 'completed_with_errors' ELSE 'completed' END,
                    updated_at=?,finished_at=COALESCE(finished_at,?),error_code=NULL,error_message=NULL
                WHERE state IN ('queued','running','interrupted')
                  AND EXISTS (
                      SELECT 1 FROM dataset_revisions r
                      WHERE r.id=workflow_executions.output_revision_id AND r.build_state='ready'
                  )
                """,
                (recovered_at, recovered_at),
            )
            workflow_cursor = connection.execute(
                "UPDATE workflow_executions SET state='interrupted',updated_at=?,"
                "error_code=COALESCE(error_code,'WORKFLOW_INTERRUPTED') "
                "WHERE state IN ('queued','running')",
                (recovered_at,),
            )
            revision_cursor = connection.execute(
                "UPDATE dataset_revisions SET build_state='interrupted' "
                "WHERE build_state='building'"
            )
        return {
            "completed_workflows": max(0, int(completed_cursor.rowcount)),
            "workflows": max(0, int(workflow_cursor.rowcount)),
            "revisions": max(0, int(revision_cursor.rowcount)),
        }

    def set_setting(self, key: str, value: Any) -> None:
        """Persist one bounded application setting value."""
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO settings(key,value_json,updated_at) VALUES(?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at",
                (key, json.dumps(value, ensure_ascii=False), utc_now()),
            )

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Read one application setting and return a caller-provided default when absent."""
        with self.connect() as connection:
            row = connection.execute("SELECT value_json FROM settings WHERE key=?", (key,)).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row[0])
        except (json.JSONDecodeError, TypeError, UnicodeError) as exc:
                                                                                           
                                                                                      
            LOGGER.error("Ignoring corrupt setting %s: %s", key, exc)
            return default

    def bind_enterprise_resource(
        self, kind: str, external_id: str, resource_id: str, enterprise_id: str
    ) -> None:
        
        """Bind a local resource to enterprise governance metadata."""
        values = tuple(str(value).strip() for value in (kind, external_id, resource_id, enterprise_id))
        if any(not value or len(value) > 160 for value in values):
            raise ValueError("enterprise resource binding fields must contain 1-160 characters")
        resource_kind, local_id, governed_id, domain_id = values
        now = utc_now()
        with self.transaction() as connection:
            existing = connection.execute(
                "SELECT enterprise_id,resource_id FROM enterprise_resource_bindings WHERE kind=? AND external_id=?",
                (resource_kind, local_id),
            ).fetchone()
            if existing is not None and (
                str(existing["enterprise_id"]) != domain_id or str(existing["resource_id"]) != governed_id
            ):
                raise ArenyxaError(
                    "ENTERPRISE_BINDING_CONFLICT",
                    "Local resource is already bound to a different Enterprise resource.",
                    domain="ENTERPRISE",
                    context={"kind": resource_kind, "external_id": local_id},
                )
            connection.execute(
                """
                INSERT INTO enterprise_resource_bindings(kind,external_id,resource_id,enterprise_id,bound_at,updated_at)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(kind,external_id) DO UPDATE SET
                    resource_id=excluded.resource_id, enterprise_id=excluded.enterprise_id, updated_at=excluded.updated_at
                """,
                (resource_kind, local_id, governed_id, domain_id, now, now),
            )

    def enterprise_resource_binding(self, kind: str, external_id: str) -> dict[str, Any] | None:
        """Return enterprise governance metadata for one local resource."""
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM enterprise_resource_bindings WHERE kind=? AND external_id=?",
                (str(kind).strip(), str(external_id).strip()),
            ).fetchone()
        return None if row is None else dict(row)

    def unbind_enterprise_resource(
        self, kind: str, external_id: str, *, enterprise_id: str | None = None
    ) -> bool:
        """Remove an enterprise resource binding atomically."""
        with self.transaction() as connection:
            if enterprise_id is None:
                cursor = connection.execute(
                    "DELETE FROM enterprise_resource_bindings WHERE kind=? AND external_id=?",
                    (str(kind).strip(), str(external_id).strip()),
                )
            else:
                cursor = connection.execute(
                    "DELETE FROM enterprise_resource_bindings WHERE kind=? AND external_id=? AND enterprise_id=?",
                    (str(kind).strip(), str(external_id).strip(), str(enterprise_id).strip()),
                )
            return int(cursor.rowcount) > 0

    def list_enterprise_resource_bindings(self, *, enterprise_id: str = "", limit: int = 1000) -> list[dict[str, Any]]:
        """List bounded enterprise resource bindings for governance inspection."""
        cap = max(1, min(20_000, int(limit)))
        sql = "SELECT * FROM enterprise_resource_bindings"
        values: list[Any] = []
        if enterprise_id:
            sql += " WHERE enterprise_id=?"
            values.append(str(enterprise_id))
        sql += " ORDER BY kind,external_id LIMIT ?"
        values.append(cap)
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(sql, values)]
