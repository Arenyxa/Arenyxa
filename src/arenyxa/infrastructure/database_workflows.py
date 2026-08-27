from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
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

class WorkflowStoreMixin:
    def save_schedule(self, schedule: dict[str, Any]) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO schedules(id,task_id,rule_json,timezone,enabled,next_run_at,last_run_at,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET rule_json=excluded.rule_json,timezone=excluded.timezone,
                    enabled=excluded.enabled,next_run_at=excluded.next_run_at,last_run_at=excluded.last_run_at,
                    updated_at=excluded.updated_at
                """,
                (
                    schedule["id"],
                    schedule["task_id"],
                    json.dumps(schedule["rule"], ensure_ascii=False),
                    schedule["timezone"],
                    int(schedule.get("enabled", True)),
                    schedule.get("next_run_at"),
                    schedule.get("last_run_at"),
                    schedule.get("created_at", utc_now()),
                    utc_now(),
                ),
            )

    def list_schedules(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT s.*,t.name AS task_name FROM schedules s JOIN tasks t ON t.id=s.task_id ORDER BY s.updated_at DESC"
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            raw_rule = item.pop("rule_json", "{}")
            try:
                parsed_rule = json.loads(raw_rule)
                if not isinstance(parsed_rule, dict):
                    raise ValueError("rule_json root is not an object")
                item["rule"] = parsed_rule
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                                                                                            
                                                                                          
                item["rule"] = {}
                item["rule_error"] = f"Invalid persisted schedule rule: {exc}"
                LOGGER.error("Invalid schedule rule for %s: %s", item.get("id"), exc)
            item["enabled"] = bool(item.get("enabled"))
            result.append(item)
        return result

    def update_schedule_enabled(self, schedule_id: str, enabled: bool) -> None:
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE schedules SET enabled=?,updated_at=? WHERE id=?",
                (int(bool(enabled)), utc_now(), schedule_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(schedule_id)

    def delete_schedule(self, schedule_id: str) -> bool:
        with self.connect() as connection:
            cursor = connection.execute("DELETE FROM schedules WHERE id=?", (schedule_id,))
            return cursor.rowcount == 1

    def update_schedule_next_run(self, schedule_id: str, next_run_at: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE schedules SET next_run_at=?,updated_at=? WHERE id=?",
                (next_run_at, utc_now(), schedule_id),
            )

    def mark_schedule_executed(self, schedule_id: str, last_run_at: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE schedules SET last_run_at=?,updated_at=? WHERE id=?",
                (last_run_at, utc_now(), schedule_id),
            )

    def mark_schedule_fired(self, schedule_id: str, next_run_at: str, last_run_at: str) -> None:
        
        with self.connect() as connection:
            connection.execute(
                "UPDATE schedules SET next_run_at=?,last_run_at=?,updated_at=? WHERE id=?",
                (next_run_at, last_run_at, utc_now(), schedule_id),
            )

    def save_workflow(self, workflow: dict[str, Any]) -> None:
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO workflows(id,name,version,definition_json,created_at,updated_at,schema_version)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET name=excluded.name,version=excluded.version,
                    definition_json=excluded.definition_json,updated_at=excluded.updated_at,
                    schema_version=excluded.schema_version
                """,
                (
                    workflow["id"],
                    workflow["name"],
                    workflow.get("version", "1.0.0"),
                    json.dumps(workflow, ensure_ascii=False, default=str),
                    workflow.get("created_at", now),
                    now,
                    workflow.get("schema_version", 6),
                ),
            )

    def list_workflows(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            return [
                json.loads(row[0])
                for row in connection.execute(
                    "SELECT definition_json FROM workflows ORDER BY updated_at DESC"
                )
            ]

    def get_workflow(self, workflow_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT definition_json FROM workflows WHERE id=?", (workflow_id,)
            ).fetchone()
        if row is None:
            return None
        try:
            payload = json.loads(str(row[0]))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ArenyxaError(
                "WORKFLOW_DEFINITION_CORRUPT",
                "持久化的工作流定义损坏。",
                domain="WORKFLOW",
                context={"workflow_id": workflow_id},
            ) from exc
        if not isinstance(payload, dict):
            raise ArenyxaError(
                "WORKFLOW_DEFINITION_CORRUPT",
                "持久化的工作流定义根节点必须是对象。",
                domain="WORKFLOW",
                context={"workflow_id": workflow_id},
            )
        return payload

    def begin_workflow_execution(
        self,
        execution: dict[str, Any],
        node_ids: Iterable[str],
    ) -> None:
        required = {
            "id", "workflow_id", "source_revision_id", "output_dataset_id",
            "output_revision_id", "definition_hash", "started_at",
        }
        missing = sorted(required - set(execution))
        if missing:
            raise ValueError(f"missing workflow execution fields: {', '.join(missing)}")
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO workflow_executions(
                    id,workflow_id,source_revision_id,output_dataset_id,output_revision_id,
                    state,definition_hash,started_at,updated_at,finished_at,last_input_identity,
                    processed_inputs,staged_outputs,error_count,checkpoint_json,error_code,error_message,
                    definition_json
                ) VALUES(?,?,?,?,?,'running',?,?,?,NULL,NULL,0,0,0,'{}',NULL,NULL,?)
                """,
                (
                    execution["id"], execution["workflow_id"], execution["source_revision_id"],
                    execution["output_dataset_id"], execution["output_revision_id"],
                    execution["definition_hash"], execution["started_at"], execution["started_at"],
                    str(execution.get("definition_json") or "{}"),
                ),
            )
            rows = [(execution["id"], str(node_id)) for node_id in node_ids]
            if rows:
                connection.executemany(
                    "INSERT INTO workflow_node_executions(execution_id,node_id) VALUES(?,?)",
                    rows,
                )

    def get_workflow_execution(self, execution_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM workflow_executions WHERE id=?", (execution_id,)
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        try:
            item["checkpoint"] = json.loads(str(item.pop("checkpoint_json")))
        except (json.JSONDecodeError, TypeError, ValueError):
            item["checkpoint"] = {}
        return item

    def claim_workflow_execution_for_resume(self, execution_id: str) -> bool:
        






        now = utc_now()
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT state,output_revision_id FROM workflow_executions WHERE id=?",
                (execution_id,),
            ).fetchone()
            if row is None:
                raise ArenyxaError(
                    "WORKFLOW_EXECUTION_NOT_FOUND", "找不到工作流执行记录。", domain="WORKFLOW",
                    context={"execution_id": execution_id},
                )
            state = str(row[0])
            output_revision_id = str(row[1] or "")
            if state not in {"interrupted", "cancelled"}:
                return False
            revision = connection.execute(
                "SELECT build_state FROM dataset_revisions WHERE id=?",
                (output_revision_id,),
            ).fetchone()
            if revision is None or str(revision[0]) == "ready":
                raise ArenyxaError(
                    "WORKFLOW_RESUME_OUTPUT_INVALID",
                    "工作流输出 Revision 不存在或已经完成，无法恢复。",
                    domain="WORKFLOW",
                    context={"execution_id": execution_id, "revision_id": output_revision_id},
                )
            cursor = connection.execute(
                "UPDATE workflow_executions SET state='running',updated_at=?,finished_at=NULL,"
                "error_code=NULL,error_message=NULL WHERE id=? AND state=?",
                (now, execution_id, state),
            )
            if cursor.rowcount != 1:
                return False
            revision_cursor = connection.execute(
                "UPDATE dataset_revisions SET build_state='building' WHERE id=? AND build_state<>'ready'",
                (output_revision_id,),
            )
            if revision_cursor.rowcount != 1:
                raise ArenyxaError(
                    "WORKFLOW_RESUME_OUTPUT_CONFLICT",
                    "工作流输出 Revision 状态发生并发变化，已取消恢复。",
                    domain="WORKFLOW",
                    context={"execution_id": execution_id, "revision_id": output_revision_id},
                )
        return True

    def list_workflow_executions(
        self, workflow_id: str | None = None, *, limit: int = 200
    ) -> list[dict[str, Any]]:
        cap = max(1, min(5000, int(limit)))
        sql = "SELECT * FROM workflow_executions"
        values: list[Any] = []
        if workflow_id is not None:
            sql += " WHERE workflow_id=?"
            values.append(workflow_id)
        sql += " ORDER BY started_at DESC,id LIMIT ?"
        values.append(cap)
        with self.connect() as connection:
            rows = connection.execute(sql, values).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                item["checkpoint"] = json.loads(str(item.pop("checkpoint_json")))
            except (json.JSONDecodeError, TypeError, ValueError):
                item["checkpoint"] = {}
            output.append(item)
        return output

    def list_completed_workflow_executions_missing_lineage(
        self, *, limit: int = 5000
    ) -> list[dict[str, Any]]:
        





        cap = max(1, min(20_000, int(limit)))
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT e.*
                FROM workflow_executions e
                JOIN dataset_revisions r ON r.id=e.output_revision_id AND r.build_state='ready'
                LEFT JOIN lineage_nodes source_node
                  ON source_node.kind='workflow_execution' AND source_node.object_id=e.id
                LEFT JOIN lineage_nodes target_node
                  ON target_node.kind='revision' AND target_node.object_id=e.output_revision_id
                LEFT JOIN lineage_edges edge
                  ON edge.from_node_id=source_node.id
                 AND edge.to_node_id=target_node.id
                 AND edge.relation='produced'
                WHERE e.state IN ('completed','completed_with_errors')
                  AND edge.id IS NULL
                ORDER BY e.started_at DESC,e.id
                LIMIT ?
                """,
                (cap,),
            ).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                item["checkpoint"] = json.loads(str(item.pop("checkpoint_json")))
            except (json.JSONDecodeError, TypeError, ValueError):
                item["checkpoint"] = {}
            output.append(item)
        return output

    def list_ready_dataset_revisions_missing_lineage(
        self, *, limit: int = 5000
    ) -> list[dict[str, Any]]:
        
        cap = max(1, min(20_000, int(limit)))
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT r.*
                FROM dataset_revisions r
                LEFT JOIN lineage_nodes revision_node
                  ON revision_node.kind='revision' AND revision_node.object_id=r.id
                LEFT JOIN lineage_nodes dataset_node
                  ON dataset_node.kind='dataset' AND dataset_node.object_id=r.dataset_id
                LEFT JOIN lineage_edges edge
                  ON edge.from_node_id=revision_node.id
                 AND edge.to_node_id=dataset_node.id
                 AND edge.relation='version_of'
                WHERE r.build_state='ready' AND edge.id IS NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM workflow_executions execution
                      WHERE execution.output_revision_id=r.id
                  )
                ORDER BY r.created_at DESC,r.id
                LIMIT ?
                """,
                (cap,),
            ).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                item["source_run_ids"] = json.loads(str(item.pop("source_run_ids_json")))
                item["schema"] = json.loads(str(item.pop("schema_json")))
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                LOGGER.error("Skipping corrupt ready revision during lineage scan: %s", exc)
                continue
            output.append(item)
        return output

    def get_workflow_node_executions(self, execution_id: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            return [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM workflow_node_executions WHERE execution_id=? ORDER BY node_id",
                    (execution_id,),
                )
            ]

    def checkpoint_workflow_execution(
        self,
        execution_id: str,
        *,
        last_input_identity: str,
        processed_delta: int,
        output_delta: int,
        error_delta: int,
        node_deltas: dict[str, dict[str, int | str]],
        checkpoint: dict[str, Any] | None = None,
    ) -> None:
        if processed_delta < 0 or output_delta < 0 or error_delta < 0:
            raise ValueError("workflow checkpoint deltas must be non-negative")
        now = utc_now()
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT state FROM workflow_executions WHERE id=?", (execution_id,)
            ).fetchone()
            if row is None:
                raise ArenyxaError(
                    "WORKFLOW_EXECUTION_NOT_FOUND", "找不到工作流执行记录。", domain="WORKFLOW",
                    context={"execution_id": execution_id},
                )
            if str(row[0]) != "running":
                raise ArenyxaError(
                    "WORKFLOW_EXECUTION_STATE_CONFLICT",
                    "当前工作流执行状态不能写入检查点。",
                    domain="WORKFLOW",
                    context={"execution_id": execution_id, "state": str(row[0])},
                )
            connection.execute(
                """
                UPDATE workflow_executions SET
                    state='running',updated_at=?,last_input_identity=?,
                    processed_inputs=processed_inputs+?,staged_outputs=staged_outputs+?,
                    error_count=error_count+?,checkpoint_json=?,error_code=NULL,error_message=NULL
                WHERE id=?
                """,
                (
                    now, last_input_identity, int(processed_delta), int(output_delta), int(error_delta),
                    json.dumps(checkpoint or {}, ensure_ascii=False, sort_keys=True, default=str), execution_id,
                ),
            )
            for node_id, delta in node_deltas.items():
                connection.execute(
                    """
                    INSERT INTO workflow_node_executions(
                        execution_id,node_id,input_count,output_count,error_count,state
                    ) VALUES(?,?,?,?,?,?)
                    ON CONFLICT(execution_id,node_id) DO UPDATE SET
                        input_count=workflow_node_executions.input_count+excluded.input_count,
                        output_count=workflow_node_executions.output_count+excluded.output_count,
                        error_count=workflow_node_executions.error_count+excluded.error_count,
                        state=excluded.state
                    """,
                    (
                        execution_id, str(node_id), int(delta.get("input_count", 0)),
                        int(delta.get("output_count", 0)), int(delta.get("error_count", 0)),
                        str(delta.get("state", "completed"))[:32],
                    ),
                )

    def finish_workflow_execution(
        self,
        execution_id: str,
        *,
        state: str,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> None:
        if state not in {"completed", "completed_with_errors", "failed", "cancelled", "interrupted"}:
            raise ValueError("unsupported workflow execution state")
        now = utc_now()
        finished = now if state in {"completed", "completed_with_errors", "failed", "cancelled"} else None
        with self.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE workflow_executions SET state=?,updated_at=?,finished_at=?,error_code=?,error_message=?
                WHERE id=?
                """,
                (
                    state, now, finished, error_code,
                    None if error_message is None else str(error_message)[:500], execution_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ArenyxaError(
                    "WORKFLOW_EXECUTION_NOT_FOUND", "找不到工作流执行记录。", domain="WORKFLOW",
                    context={"execution_id": execution_id},
                )

    def save_visualization(self, visualization: dict[str, Any]) -> None:
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO visualizations(id,name,dataset_ref,chart_type,config_json,created_at,updated_at,schema_version)
                VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET name=excluded.name,dataset_ref=excluded.dataset_ref,
                    chart_type=excluded.chart_type,config_json=excluded.config_json,updated_at=excluded.updated_at,
                    schema_version=excluded.schema_version
                """,
                (
                    visualization["id"],
                    visualization["name"],
                    visualization["dataset_ref"],
                    visualization["chart_type"],
                    json.dumps(visualization["config"], ensure_ascii=False),
                    visualization.get("created_at", now),
                    now,
                    visualization.get("schema_version", 6),
                ),
            )

    def list_visualizations(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM visualizations ORDER BY updated_at DESC").fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["config"] = json.loads(item.pop("config_json"))
            result.append(item)
        return result

    def index_object(self, object_type: str, object_id: str, title: str, url: str, content: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "DELETE FROM local_search WHERE object_type=? AND object_id=?", (object_type, object_id)
            )
            connection.execute(
                "INSERT INTO local_search(object_type,object_id,title,url,content) VALUES(?,?,?,?,?)",
                (object_type, object_id, title, url, content),
            )

    def search(self, query: str, limit: int = 100) -> list[dict[str, Any]]:
        import re

        sanitized = " ".join(f'"{token}"*' for token in re.findall(r"[\w]+", query, flags=re.UNICODE))
        if not sanitized:
            return []
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT object_type,object_id,title,url,snippet(local_search,4,'<b>','</b>','…',18) AS snippet "
                "FROM local_search WHERE local_search MATCH ? ORDER BY rank LIMIT ?",
                (sanitized, max(1, min(1_000, int(limit)))),
            ).fetchall()
        return [dict(row) for row in rows]

    def dashboard_metrics(self) -> dict[str, Any]:
        with self.connect() as connection:
                                                                                                
                                                                                             
                                                  
            row = connection.execute(
                """SELECT
                   (SELECT count(*) FROM tasks WHERE status NOT IN ('deleted','archived')) AS tasks,
                   (SELECT count(*) FROM runs) AS runs,
                   (SELECT count(*) FROM result_records) AS records,
                   (SELECT count(*) FROM runs WHERE status IN ('queued','running','paused')) AS active,
                   (SELECT count(*) FROM capture_sessions) AS captures,
                   (SELECT count(*) FROM runs WHERE status='failed') AS errors"""
            ).fetchone()
        assert row is not None
        return {
            "tasks": int(row["tasks"]),
            "runs": int(row["runs"]),
            "records": int(row["records"]),
            "active": int(row["active"]),
            "captures": int(row["captures"]),
            "errors": int(row["errors"]),
            "database_bytes": self.path.stat().st_size if self.path.exists() else 0,
        }

    @staticmethod
    def _task_from_dict(data: dict[str, Any]) -> Task:
        if not isinstance(data, dict):
            raise TypeError("task definition root must be an object")
        request_items = data.get("requests", [])
        field_items = data.get("fields", [])
        if not isinstance(request_items, list) or not isinstance(field_items, list):
            raise TypeError("task requests/fields must be arrays")

        requests: list[RequestSpec] = []
        for item in request_items:
            if not isinstance(item, dict):
                raise TypeError("task request must be an object")
            raw = dict(item)
            retry_value = raw.pop("retry", {})
            if not isinstance(retry_value, dict):
                raise TypeError("retry policy must be an object")
            requests.append(RequestSpec(**raw, retry=RetryPolicy(**dict(retry_value))))

        fields: list[FieldSpec] = []
        from arenyxa.domain.models import CleanerStep, ValidationRule

        for item in field_items:
            if not isinstance(item, dict):
                raise TypeError("task field must be an object")
            raw = dict(item)
            cleaner_items = raw.pop("cleaners", [])
            validator_items = raw.pop("validators", [])
            if not isinstance(cleaner_items, list) or not isinstance(validator_items, list):
                raise TypeError("field cleaners/validators must be arrays")
            cleaners = []
            for cleaner in cleaner_items:
                if not isinstance(cleaner, dict):
                    raise TypeError("cleaner must be an object")
                cleaners.append(CleanerStep(**dict(cleaner)))
            validators = []
            for validator in validator_items:
                if not isinstance(validator, dict):
                    raise TypeError("validator must be an object")
                validators.append(ValidationRule(**dict(validator)))
            fields.append(FieldSpec(**raw, cleaners=cleaners, validators=validators))

        if not isinstance(data.get("name"), str) or not isinstance(data.get("id"), str):
            raise TypeError("task name/id must be strings")
        return Task(
            name=data["name"],
            requests=requests,
            fields=fields,
            id=data["id"],
            status=TaskStatus(str(data.get("status", "draft"))),
            tags=list(data.get("tags", [])) if isinstance(data.get("tags", []), list) else [],
            parser_hint=str(data.get("parser_hint", "auto")),
            created_at=str(data.get("created_at", utc_now())),
            updated_at=str(data.get("updated_at", utc_now())),
            schema_version=int(data.get("schema_version", 1)),
        )

