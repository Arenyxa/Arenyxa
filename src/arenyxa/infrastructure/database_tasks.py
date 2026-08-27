from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import time
import tempfile
import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from arenyxa.domain.enums import CaptureSource, RunStatus, TaskStatus
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
from arenyxa.security.sql_safety import sqlite_wal_checkpoint

LOGGER = logging.getLogger(__name__)

class TaskRunStoreMixin:
    def save_task(self, task: Task) -> None:
        task.updated_at = utc_now()
                                                                                               
                                                                                                 
                                                                                            
        payload = task.to_dict()
        definition = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        snapshot_hash = hashlib.sha256(definition.encode("utf-8")).hexdigest()
                                                                                       
                                                                                    
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO tasks(id,name,status,tags_json,parser_hint,definition_json,snapshot_hash,
                                  created_at,updated_at,schema_version,deleted_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,NULL)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,status=excluded.status,tags_json=excluded.tags_json,
                    parser_hint=excluded.parser_hint,definition_json=excluded.definition_json,
                    snapshot_hash=excluded.snapshot_hash,updated_at=excluded.updated_at,
                    schema_version=excluded.schema_version,
                    deleted_at=CASE WHEN excluded.status='deleted' THEN excluded.updated_at ELSE NULL END
                """,
                (
                    task.id, task.name, task.status.value, json.dumps(task.tags, ensure_ascii=False),
                    task.parser_hint, definition, snapshot_hash, task.created_at,
                    task.updated_at, task.schema_version,
                ),
            )
            connection.execute(
                "DELETE FROM local_search WHERE object_type=? AND object_id=?", ("task", task.id)
            )
            if task.status != TaskStatus.DELETED:
                connection.execute(
                    "INSERT INTO local_search(object_type,object_id,title,url,content) VALUES(?,?,?,?,?)",
                    (
                        "task", task.id, task.name,
                        task.requests[0].url if task.requests else "",
                        " ".join(task.tags),
                    ),
                )

    def get_task(self, task_id: str) -> Task | None:
        with self.connect() as connection:
            row = connection.execute("SELECT definition_json FROM tasks WHERE id=?", (task_id,)).fetchone()
        if row is None:
            return None
        try:
            raw = json.loads(row[0])
            return self._task_from_dict(raw)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ArenyxaError(
                "TASK_DEFINITION_CORRUPT",
                "任务定义已损坏，无法安全加载。请在日志与诊断中查看详情。",
                domain="TASK",
                context={"task_id": task_id},
            ) from exc

    def list_tasks(self, include_archived: bool = False, query: str = "", limit: int = 500) -> list[Task]:
        values: list[Any] = []
        has_query = bool(query)
        if has_query:
            wildcard = "%" + str(query) + "%"
            values.extend([wildcard, wildcard, wildcard])
        values.append(max(1, min(5_000, int(limit))))

        # Four fixed statements avoid constructing a WHERE clause from runtime strings.
        if include_archived and has_query:
            sql = (
                "SELECT id,definition_json FROM tasks "
                "WHERE status <> 'deleted' AND (name LIKE ? OR tags_json LIKE ? OR definition_json LIKE ?) "
                "ORDER BY updated_at DESC LIMIT ?"
            )
        elif include_archived:
            sql = "SELECT id,definition_json FROM tasks WHERE status <> 'deleted' ORDER BY updated_at DESC LIMIT ?"
        elif has_query:
            sql = (
                "SELECT id,definition_json FROM tasks "
                "WHERE status <> 'deleted' AND status <> 'archived' "
                "AND (name LIKE ? OR tags_json LIKE ? OR definition_json LIKE ?) "
                "ORDER BY updated_at DESC LIMIT ?"
            )
        else:
            sql = (
                "SELECT id,definition_json FROM tasks "
                "WHERE status <> 'deleted' AND status <> 'archived' ORDER BY updated_at DESC LIMIT ?"
            )
        with self.connect() as connection:
            rows = connection.execute(sql, values).fetchall()
        tasks: list[Task] = []
        for row in rows:
            try:
                tasks.append(self._task_from_dict(json.loads(row["definition_json"])))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                LOGGER.error("Skipping corrupt task definition %s: %s", row["id"], exc)
        return tasks

    def save_run(self, run: Run) -> None:
        with self.connect() as connection:
                                                                                            
                                                                                             
                                                                                              
                                                                                               
            status = run.status.value
            updated = connection.execute(
                """
                UPDATE runs SET
                    status=CASE
                        -- Pause/resume is written through update_run_control_status(). A stale
                        -- progress snapshot must never reverse the latest control transition.
                        WHEN status IN ('running','paused') AND ? IN ('running','paused')
                        THEN status
                        -- Once a Run is terminal, delayed active/queued snapshots must not
                        -- resurrect it. Terminal-to-terminal writes remain allowed for explicit
                        -- recovery/reconciliation code paths.
                        WHEN status IN ('completed','partial','failed','cancelled')
                         AND ? IN ('queued','running','paused')
                        THEN status
                        ELSE ?
                    END,
                    stage=?,completed_units=?,total_units=?,request_count=?,success_count=?,
                    failure_count=?,result_count=?,retry_count=?,error_code=?,started_at=?,finished_at=?
                WHERE id=?
                """,
                (
                    status,
                    status,
                    status,
                    run.stage,
                    run.completed_units,
                    run.total_units,
                    run.request_count,
                    run.success_count,
                    run.failure_count,
                    run.result_count,
                    run.retry_count,
                    run.error_code,
                    run.started_at,
                    run.finished_at,
                    run.id,
                ),
            )
            if updated.rowcount:
                return
            connection.execute(
                """
                INSERT INTO runs(id,task_id,status,snapshot_json,stage,completed_units,total_units,
                    request_count,success_count,failure_count,result_count,retry_count,error_code,
                    created_at,started_at,finished_at,schema_version)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    run.id,
                    run.task_id,
                    status,
                    json.dumps(run.task_snapshot, ensure_ascii=False, default=str),
                    run.stage,
                    run.completed_units,
                    run.total_units,
                    run.request_count,
                    run.success_count,
                    run.failure_count,
                    run.result_count,
                    run.retry_count,
                    run.error_code,
                    run.created_at,
                    run.started_at,
                    run.finished_at,
                    run.schema_version,
                ),
            )

    def update_run_control_status(self, run_id: str, status: RunStatus) -> bool:
        





        if status == RunStatus.PAUSED:
            allowed = (RunStatus.QUEUED.value, RunStatus.RUNNING.value, RunStatus.PAUSED.value)
        elif status == RunStatus.RUNNING:
            allowed = (RunStatus.PAUSED.value, RunStatus.RUNNING.value)
        else:
            raise ValueError("control status must be paused or running")
        placeholders = ",".join("?" for _ in allowed)
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE runs SET status=? WHERE id=? AND status IN (" + placeholders + ")",
                (status.value, run_id, *allowed),
            )
            return cursor.rowcount == 1

    def list_runs(self, task_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        sql = "SELECT * FROM runs"
        values: list[Any] = []
        if task_id:
            sql += " WHERE task_id=?"
            values.append(task_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        values.append(max(1, min(5_000, int(limit))))
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(sql, values)]

    def append_results(self, records: Iterable[ResultRecord], batch_size: int = 500) -> int:
        if not isinstance(batch_size, int) or isinstance(batch_size, bool) or batch_size <= 0:
            raise ValueError("batch_size must be a positive integer")
        write_started = time.perf_counter()
        target_batch_size = min(5_000, batch_size)
        batch: list[tuple[Any, ...]] = []
        total = 0
        try:
            with self.transaction() as connection:
                for record in records:
                    marker = connection.execute(
                        "INSERT OR IGNORE INTO run_result_hashes(run_id,content_hash) VALUES(?,?)",
                        (record.run_id, record.content_hash),
                    )
                    if marker.rowcount != 1:
                        continue
                    batch.append(
                        (
                            record.id,
                            record.task_id,
                            record.run_id,
                            record.source_url,
                            record.fetched_at,
                            json.dumps(record.data, ensure_ascii=False, default=str),
                            record.content_hash,
                            json.dumps(record.quality_flags, ensure_ascii=False),
                        )
                    )
                    if len(batch) >= target_batch_size:
                        connection.executemany("INSERT INTO result_records VALUES(?,?,?,?,?,?,?,?)", batch)
                        total += len(batch)
                        batch.clear()
                if batch:
                    connection.executemany("INSERT INTO result_records VALUES(?,?,?,?,?,?,?,?)", batch)
                    total += len(batch)
        except sqlite3.OperationalError as exc:
            if hasattr(self, "_record_write_observation"):
                text = str(exc).casefold()
                self._record_write_observation(
                    (time.perf_counter() - write_started) * 1000.0, records=total,
                    busy=("locked" in text or "busy" in text), failed=True,
                )
            raise
        except (sqlite3.DatabaseError, OSError) as exc:
            if hasattr(self, "_record_write_observation"):
                self._record_write_observation(
                    (time.perf_counter() - write_started) * 1000.0, records=total, failed=True
                )
            raise
        if hasattr(self, "_record_write_observation"):
            self._record_write_observation((time.perf_counter() - write_started) * 1000.0, records=total)
        return total

    def iter_results(self, run_id: str, page_size: int = 1000) -> Iterator[dict[str, Any]]:
        last_id = ""
        while True:
            with self.connect() as connection:
                rows = connection.execute(
                    "SELECT id,source_url,fetched_at,data_json,quality_flags_json FROM result_records "
                    "WHERE run_id=? AND id>? ORDER BY id LIMIT ?",
                    (run_id, last_id, page_size),
                ).fetchall()
            if not rows:
                break
            for row in rows:
                last_id = str(row["id"])
                yield {
                    "id": last_id,
                    "source_url": row["source_url"],
                    "fetched_at": row["fetched_at"],
                    **json.loads(row["data_json"]),
                    "_quality_flags": json.loads(row["quality_flags_json"]),
                }

    def count_results(self, run_id: str | None = None) -> int:
        with self.connect() as connection:
            if run_id:
                row = connection.execute(
                    "SELECT count(*) FROM result_records WHERE run_id=?", (run_id,)
                ).fetchone()
            else:
                row = connection.execute("SELECT count(*) FROM result_records").fetchone()
        return int(row[0])

    def result_page(self, run_id: str, offset: int, limit: int) -> list[dict[str, Any]]:
        safe_offset = max(0, int(offset))
        safe_limit = max(1, min(5_000, int(limit)))
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id,source_url,fetched_at,data_json,quality_flags_json FROM result_records "
                "WHERE run_id=? ORDER BY id LIMIT ? OFFSET ?",
                (run_id, safe_limit, safe_offset),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "source_url": row["source_url"],
                "fetched_at": row["fetched_at"],
                **json.loads(row["data_json"]),
                "_quality_flags": json.loads(row["quality_flags_json"]),
            }
            for row in rows
        ]

    def save_project(self, project: Project) -> None:
        errors = project.validate()
        if errors:
            raise ArenyxaError("PROJECT_INVALID", "; ".join(errors), domain="PROJECT")
        project.updated_at = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO projects(id,workspace_id,name,description,tags_json,created_at,updated_at,schema_version)
                VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET workspace_id=excluded.workspace_id,name=excluded.name,
                    description=excluded.description,tags_json=excluded.tags_json,
                    updated_at=excluded.updated_at,schema_version=excluded.schema_version
                """,
                (
                    project.id, project.workspace_id, project.name, project.description,
                    json.dumps(project.tags, ensure_ascii=False), project.created_at,
                    project.updated_at, project.schema_version,
                ),
            )

    def get_project(self, project_id: str) -> Project | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        if row is None:
            return None
        return self._project_from_row(row)

    @staticmethod
    def _project_from_row(row: sqlite3.Row) -> Project:
        return Project(
            id=str(row["id"]), workspace_id=row["workspace_id"], name=str(row["name"]),
            description=str(row["description"]), tags=json.loads(row["tags_json"]),
            created_at=str(row["created_at"]), updated_at=str(row["updated_at"]),
            schema_version=int(row["schema_version"]),
        )

    def list_projects(self, workspace_id: str | None = None, limit: int = 200) -> list[Project]:
                                                                                                 
                                                                                             
                                                                                             
        sql = "SELECT * FROM projects"
        values: list[Any] = []
        if workspace_id is not None:
            sql += " WHERE workspace_id=?"
            values.append(workspace_id)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        values.append(max(1, min(int(limit), 5000)))
        with self.connect() as connection:
            rows = connection.execute(sql, values).fetchall()
        return [self._project_from_row(row) for row in rows]

    def save_project_source(self, source: ProjectSource) -> None:
        errors = source.validate()
        if errors:
            raise ArenyxaError("PROJECT_SOURCE_INVALID", "; ".join(errors), domain="PROJECT")
        source.updated_at = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO project_sources(id,project_id,name,kind,config_json,created_at,updated_at,schema_version)
                VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET project_id=excluded.project_id,name=excluded.name,
                    kind=excluded.kind,config_json=excluded.config_json,
                    updated_at=excluded.updated_at,schema_version=excluded.schema_version
                """,
                (
                    source.id, source.project_id, source.name, source.kind.value,
                    json.dumps(source.config, ensure_ascii=False, default=str), source.created_at,
                    source.updated_at, source.schema_version,
                ),
            )

    def list_project_sources(self, project_id: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM project_sources WHERE project_id=? ORDER BY created_at,id", (project_id,)
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["config"] = json.loads(item.pop("config_json"))
            result.append(item)
        return result

    @staticmethod
    def _bind_capture_connection(
        connection: sqlite3.Connection, session_id: str, project_id: str | None, source_id: str | None
    ) -> None:
        session_exists = connection.execute(
            "SELECT 1 FROM capture_sessions WHERE id=?", (session_id,)
        ).fetchone()
        if session_exists is None:
            raise ArenyxaError("CAPTURE_NOT_FOUND", "无法绑定不存在的捕获会话。", domain="PROJECT")
        resolved_project = project_id
        if source_id is not None:
            row = connection.execute("SELECT project_id FROM project_sources WHERE id=?", (source_id,)).fetchone()
            if row is None:
                raise ArenyxaError("PROJECT_SOURCE_NOT_FOUND", "捕获绑定的数据源不存在。", domain="PROJECT")
            source_project = str(row[0])
            if resolved_project is None:
                resolved_project = source_project
            elif resolved_project != source_project:
                raise ArenyxaError(
                    "PROJECT_SOURCE_MISMATCH", "捕获数据源不属于指定项目。", domain="PROJECT",
                    context={"project_id": resolved_project, "source_id": source_id},
                )
        if resolved_project is not None:
            exists = connection.execute("SELECT 1 FROM projects WHERE id=?", (resolved_project,)).fetchone()
            if exists is None:
                raise ArenyxaError("PROJECT_NOT_FOUND", "捕获绑定的项目不存在。", domain="PROJECT")
        if resolved_project is None and source_id is None:
            return
        connection.execute(
            """
            INSERT INTO capture_bindings(session_id,project_id,source_id) VALUES(?,?,?)
            ON CONFLICT(session_id) DO UPDATE SET project_id=excluded.project_id,source_id=excluded.source_id
            """,
            (session_id, resolved_project, source_id),
        )

    def bind_capture(self, session_id: str, project_id: str | None, source_id: str | None) -> None:
        with self.transaction() as connection:
            self._bind_capture_connection(connection, session_id, project_id, source_id)

