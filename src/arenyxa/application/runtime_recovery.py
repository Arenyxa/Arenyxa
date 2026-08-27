from __future__ import annotations

import json
from dataclasses import asdict, field
from arenyxa.compat import dataclass
from typing import Any

from arenyxa.application.scheduler import ScheduleRule
from arenyxa.application.reliability import FailureDiagnosis, RecoveryTaxonomy
from arenyxa.domain.models import utc_now
from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.security.sql_safety import sql_placeholders


@dataclass(slots=True)
class RuntimeStateAudit:
    """Summarize stale, invalid, and resumable persisted runtime state before recovery."""
    active_runs: list[str] = field(default_factory=list)
    active_captures: list[str] = field(default_factory=list)
    active_workflows: list[str] = field(default_factory=list)
    building_revisions: list[str] = field(default_factory=list)
    invalid_schedules: list[str] = field(default_factory=list)
    invalid_revision_states: list[str] = field(default_factory=list)
    invalid_workflow_states: list[str] = field(default_factory=list)
    broken_interrupted_revisions: list[str] = field(default_factory=list)
    broken_interrupted_workflows: list[str] = field(default_factory=list)
    resumable_revisions: list[str] = field(default_factory=list)
    resumable_workflows: list[str] = field(default_factory=list)

    @property
    def has_stale_active_state(self) -> bool:
        return bool(self.active_runs or self.active_captures or self.active_workflows or self.building_revisions)

    @property
    def has_invalid_state(self) -> bool:
        return bool(
            self.invalid_schedules
            or self.invalid_revision_states
            or self.invalid_workflow_states
            or self.broken_interrupted_revisions
            or self.broken_interrupted_workflows
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RuntimeRecoveryResult:
    """Record deterministic actions taken while reconciling interrupted runtime state."""
    recovered_runs: int = 0
    recovered_captures: int = 0
    reconciled_completed_workflows: int = 0
    interrupted_workflows: int = 0
    interrupted_revisions: int = 0
    disabled_invalid_schedules: int = 0
    failed_invalid_revisions: int = 0
    failed_invalid_workflows: int = 0
    failed_broken_revisions: int = 0
    failed_broken_workflows: int = 0
    resumable_revisions: int = 0
    resumable_workflows: int = 0
    recovered_at: str = field(default_factory=utc_now)

    @property
    def changed(self) -> bool:
        return any(
            value
            for key, value in asdict(self).items()
            if key != "recovered_at" and isinstance(value, int)
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RuntimeRecoveryService:
    """Audit and reconcile interrupted run, capture, workflow, and schedule state."""
    







    RUN_ACTIVE = {"queued", "running", "paused"}
    CAPTURE_ACTIVE = {"preparing", "capturing", "paused", "finalizing"}
    REVISION_ALLOWED = {"building", "ready", "interrupted", "failed", "cancelled"}
    WORKFLOW_ALLOWED = {
        "queued", "running", "interrupted", "cancelled", "failed", "completed", "completed_with_errors"
    }

    def __init__(self, store: SQLiteStore) -> None:
        self.store = store

    @staticmethod
    def diagnose_failure(
        error: BaseException | None = None,
        *,
        error_code: str | None = None,
        status: int | None = None,
        persisted_data: bool = False,
    ) -> FailureDiagnosis:
        
        return RecoveryTaxonomy.classify(
            error, error_code=error_code, status=status, persisted_data=persisted_data
        )

    @staticmethod
    def _table_exists(connection: Any, name: str) -> bool:
        return connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone() is not None

    @staticmethod
    def _schedule_valid(raw_rule: Any) -> bool:
        try:
            payload = json.loads(str(raw_rule))
            if not isinstance(payload, dict):
                return False
            if isinstance(payload.get("weekdays"), list):
                payload["weekdays"] = tuple(payload["weekdays"])
            rule = ScheduleRule(**payload)
            rule.validate()
            return True
        except (TypeError, ValueError, json.JSONDecodeError, OverflowError):
            return False

    @staticmethod
    def _source_ids_valid(raw: Any) -> bool:
        try:
            payload = json.loads(str(raw))
        except (TypeError, ValueError, json.JSONDecodeError):
            return False
        return isinstance(payload, list) and all(isinstance(item, str) and item.strip() for item in payload)

    @staticmethod
    def _workflow_definition_valid(raw_snapshot: Any, raw_current: Any, expected_hash: Any) -> bool:
        
        from arenyxa.application.workflow_runtime import WorkflowDatasetService

        for raw in (raw_snapshot, raw_current):
            if raw in (None, "", "{}"):
                continue
            try:
                payload = json.loads(str(raw)) if isinstance(raw, str) else raw
                if not isinstance(payload, dict):
                    continue
                workflow = WorkflowDatasetService.workflow_from_payload(payload)
                if WorkflowDatasetService.definition_hash(workflow) == str(expected_hash):
                    return True
            except (TypeError, ValueError, json.JSONDecodeError, KeyError):
                continue
            except Exception:
                                                                                           
                                                                               
                continue
        return False

    def audit(self) -> RuntimeStateAudit:
        result = RuntimeStateAudit()
        with self.store.connect() as connection:
            if self._table_exists(connection, "runs"):
                result.active_runs = [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT id FROM runs WHERE status IN ('queued','running','paused') ORDER BY created_at,id LIMIT 500"
                    )
                ]
            if self._table_exists(connection, "capture_sessions"):
                result.active_captures = [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT id FROM capture_sessions WHERE state IN ('preparing','capturing','paused','finalizing') "
                        "ORDER BY created_at,id LIMIT 500"
                    )
                ]
            if self._table_exists(connection, "workflow_executions"):
                result.active_workflows = [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT id FROM workflow_executions WHERE state IN ('queued','running') ORDER BY started_at,id LIMIT 500"
                    )
                ]
                result.invalid_workflow_states = [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT id FROM workflow_executions WHERE state NOT IN "
                        "('queued','running','interrupted','cancelled','failed','completed','completed_with_errors') "
                        "ORDER BY started_at,id LIMIT 500"
                    )
                ]
                interrupted = connection.execute(
                    "SELECT e.id,e.workflow_id,e.source_revision_id,e.output_revision_id,"
                    "e.definition_hash,e.definition_json,w.definition_json AS current_definition,"
                    "src.build_state AS source_state,out.build_state AS output_state "
                    "FROM workflow_executions e "
                    "LEFT JOIN workflows w ON w.id=e.workflow_id "
                    "LEFT JOIN dataset_revisions src ON src.id=e.source_revision_id "
                    "LEFT JOIN dataset_revisions out ON out.id=e.output_revision_id "
                    "WHERE e.state='interrupted' ORDER BY e.updated_at,e.id LIMIT 1000"
                ).fetchall()
                for row in interrupted:
                    definition_valid = self._workflow_definition_valid(row[5], row[6], row[4])
                    broken = (
                        not definition_valid
                        or row[7] != "ready"
                        or row[8] is None
                        or row[8] == "ready"
                    )
                    (result.broken_interrupted_workflows if broken else result.resumable_workflows).append(str(row[0]))
            if self._table_exists(connection, "dataset_revisions"):
                result.building_revisions = [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT id FROM dataset_revisions WHERE build_state='building' ORDER BY created_at,id LIMIT 500"
                    )
                ]
                result.invalid_revision_states = [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT id FROM dataset_revisions WHERE build_state NOT IN "
                        "('building','ready','interrupted','failed','cancelled') ORDER BY created_at,id LIMIT 500"
                    )
                ]
                for row in connection.execute(
                    "SELECT id,source_run_ids_json FROM dataset_revisions WHERE build_state='interrupted' "
                    "ORDER BY created_at,id LIMIT 1000"
                ):
                    revision_id = str(row[0])
                    if not self._source_ids_valid(row[1]):
                        result.broken_interrupted_revisions.append(revision_id)
                    else:
                        result.resumable_revisions.append(revision_id)
            if self._table_exists(connection, "schedules"):
                for row in connection.execute(
                    "SELECT id,rule_json,enabled FROM schedules ORDER BY updated_at,id LIMIT 2000"
                ):
                    if int(row[2] or 0) and not self._schedule_valid(row[1]):
                        result.invalid_schedules.append(str(row[0]))
        return result

    def recover(self) -> RuntimeRecoveryResult:
        before = self.audit()
        legacy = self.store.recover_interrupted_state()
        pipeline = self.store.recover_interrupted_pipeline_state()
        result = RuntimeRecoveryResult(
            recovered_runs=int(legacy.get("runs", 0)),
            recovered_captures=int(legacy.get("captures", 0)),
            reconciled_completed_workflows=int(pipeline.get("completed_workflows", 0)),
            interrupted_workflows=int(pipeline.get("workflows", 0)),
            interrupted_revisions=int(pipeline.get("revisions", 0)),
        )
                                                                                              
                                                                                            
                                                                                            
        normalized = self.audit()

        with self.store.transaction() as connection:
            if normalized.invalid_schedules:
                placeholders = sql_placeholders(len(normalized.invalid_schedules))
                cursor = connection.execute(
                    "UPDATE schedules SET enabled=0,updated_at=? WHERE id IN (" + placeholders + ")",
                    (utc_now(), *normalized.invalid_schedules),
                )
                result.disabled_invalid_schedules = max(0, int(cursor.rowcount))
            if normalized.invalid_revision_states:
                placeholders = sql_placeholders(len(normalized.invalid_revision_states))
                cursor = connection.execute(
                    "UPDATE dataset_revisions SET build_state='failed' WHERE id IN (" + placeholders + ")",
                    tuple(normalized.invalid_revision_states),
                )
                result.failed_invalid_revisions = max(0, int(cursor.rowcount))
            if normalized.broken_interrupted_revisions:
                placeholders = sql_placeholders(len(normalized.broken_interrupted_revisions))
                cursor = connection.execute(
                    "UPDATE dataset_revisions SET build_state='failed' WHERE id IN (" + placeholders + ")",
                    tuple(normalized.broken_interrupted_revisions),
                )
                result.failed_broken_revisions = max(0, int(cursor.rowcount))
            invalid_workflows = list(dict.fromkeys(normalized.invalid_workflow_states))
            if invalid_workflows:
                placeholders = sql_placeholders(len(invalid_workflows))
                cursor = connection.execute(
                    ("UPDATE workflow_executions SET state='failed',updated_at=?,finished_at=?,"
                     "error_code='WORKFLOW_STATE_INVALID',error_message='Repair Center normalized invalid persisted state' "
                     "WHERE id IN (" + placeholders + ")"),
                    (utc_now(), utc_now(), *invalid_workflows),
                )
                result.failed_invalid_workflows = max(0, int(cursor.rowcount))
            broken_workflows = [item for item in normalized.broken_interrupted_workflows if item not in invalid_workflows]
            if broken_workflows:
                placeholders = sql_placeholders(len(broken_workflows))
                now = utc_now()
                cursor = connection.execute(
                    ("UPDATE workflow_executions SET state='failed',updated_at=?,finished_at=?,"
                     "error_code='WORKFLOW_RESUME_INVALID',error_message='Required resume metadata is missing or inconsistent' "
                     "WHERE id IN (" + placeholders + ") AND state='interrupted'"),
                    (now, now, *broken_workflows),
                )
                result.failed_broken_workflows = max(0, int(cursor.rowcount))
                output_rows = connection.execute(
                    "SELECT output_revision_id FROM workflow_executions WHERE id IN (" + placeholders + ")",
                    tuple(broken_workflows),
                ).fetchall()
                output_ids = [str(row[0]) for row in output_rows if row[0]]
                if output_ids:
                    out_placeholders = sql_placeholders(len(output_ids))
                    connection.execute(
                        ("UPDATE dataset_revisions SET build_state='failed' "
                         "WHERE id IN (" + out_placeholders + ") AND build_state<>'ready'"),
                        tuple(output_ids),
                    )

        after = self.audit()
        result.resumable_revisions = len(after.resumable_revisions)
        result.resumable_workflows = len(after.resumable_workflows)
        return result
