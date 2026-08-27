from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
from dataclasses import asdict
from arenyxa.compat import dataclass
from typing import Any, Callable, Mapping

from arenyxa.application.data_lineage import DataLineageService, _SchemaAccumulator
from arenyxa.application.workflows import WorkflowEngine, WorkflowResult
from arenyxa.application.workflow_contract import serialize_workflow, validate_workflow_contract
from arenyxa.application.workflow_test_lab import WorkflowTestLab
from arenyxa.application.workflow_resume import WorkflowResumeValidation, checkpoint_digest
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import DatasetRevision, Workflow, WorkflowNode, new_id, utc_now
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.http_client import CancellationToken
from arenyxa.application.workflow_runtime_models import WorkflowExecutionResult

LOGGER = logging.getLogger(__name__)


class WorkflowResumeMixin:
    def validate_resume_checkpoint(
        self,
        execution_id: str,
        workflow: Workflow | None = None,
        *,
        scopes: Mapping[str, Mapping[str, Any]] | None = None,
        secret_resolver: Callable[[str], str | None] | None = None,
    ) -> WorkflowResumeValidation:
        """Validate a durable checkpoint and safely replay one deterministic input in memory."""
        execution = self.store.get_workflow_execution(execution_id)
        if execution is None:
            raise ArenyxaError(
                "WORKFLOW_EXECUTION_NOT_FOUND",
                "找不到工作流执行记录。",
                domain="WORKFLOW",
                context={"execution_id": execution_id},
            )
        if workflow is None:
            workflow = self._workflow_for_execution(execution)
        digest = self.definition_hash(workflow)
        if digest != str(execution.get("definition_hash", "")):
            return WorkflowResumeValidation(
                execution_id, False, False, digest, warnings=("workflow-definition-changed",)
            )
        checkpoint = execution.get("checkpoint")
        if not isinstance(checkpoint, Mapping):
            checkpoint = {}
        cp_hash = str(checkpoint.get("definition_hash", digest))
        if cp_hash and cp_hash != digest:
            return WorkflowResumeValidation(
                execution_id, False, False, digest, warnings=("checkpoint-definition-hash-mismatch",)
            )
        generation = max(0, int(checkpoint.get("generation", 0) or 0))
        stored_checkpoint_digest = str(checkpoint.get("checkpoint_sha256", ""))
        integrity_verified = bool(stored_checkpoint_digest) and hmac.compare_digest(
            stored_checkpoint_digest, checkpoint_digest(checkpoint)
        )
        if stored_checkpoint_digest and not integrity_verified:
            return WorkflowResumeValidation(
                execution_id, False, False, digest, warnings=("checkpoint-integrity-mismatch",),
                checkpoint_generation=generation, integrity_verified=False,
            )
        source_revision_id = str(execution.get("source_revision_id", ""))
        output_revision_id = str(execution.get("output_revision_id", ""))
        if self.store.get_revision_metadata(source_revision_id) is None:
            return WorkflowResumeValidation(
                execution_id, False, False, digest, warnings=("source-revision-missing",)
            )
        output = self.store.get_revision_metadata(output_revision_id, include_incomplete=True)
        if output is None or str(output.get("build_state", "")) == "ready":
            return WorkflowResumeValidation(
                execution_id, False, False, digest, warnings=("output-revision-invalid",)
            )
        lab = WorkflowTestLab(self.engine)
        dry = lab.dry_run(workflow, scopes=scopes, secret_resolver=secret_resolver)
        warnings = list(dry.warnings)
        warnings.extend(dry.missing_handlers)
        warnings.extend(dry.unresolved_variable_refs)
        if not dry.valid:
            return WorkflowResumeValidation(
                execution_id, False, False, digest, warnings=tuple(sorted(set(warnings)))
            )
        safe_kinds = {"source", "filter", "map", "validate", "sink"}
        non_deterministic = sorted({node.kind for node in workflow.nodes if node.kind not in safe_kinds})
        after_identity = str(execution.get("last_input_identity") or "")
        next_record = None
        for identity, record in self.store.iter_revision_records(
            source_revision_id, after_identity=after_identity, page_size=1
        ):
            next_record = (str(identity), dict(record))
            break
        if next_record is None:
            return WorkflowResumeValidation(
                execution_id, True, True, digest, warnings=tuple(sorted(set(warnings))),
                checkpoint_generation=generation, integrity_verified=integrity_verified or not stored_checkpoint_digest,
            )
        if non_deterministic:
            warnings.append("sandbox-replay-skipped-non-deterministic:" + ",".join(non_deterministic))
            return WorkflowResumeValidation(
                execution_id, True, False, digest, next_input_identity=next_record[0],
                warnings=tuple(sorted(set(warnings))), checkpoint_generation=generation,
                integrity_verified=integrity_verified or not stored_checkpoint_digest,
            )
        test_engine = WorkflowEngine(buffer_size=self.engine.buffer_size)
        test_engine.handlers = dict(self.engine.handlers)
        result = test_engine.execute(
            workflow, [next_record[1]], scopes=scopes, secret_resolver=secret_resolver
        )
        return WorkflowResumeValidation(
            execution_id,
            True,
            True,
            digest,
            next_input_identity=next_record[0],
            output_count=len(result.outputs),
            error_count=len(result.errors),
            warnings=tuple(sorted(set(warnings))),
            checkpoint_generation=generation,
            integrity_verified=integrity_verified or not stored_checkpoint_digest,
        )

    def resume_execution(
        self,
        execution_id: str,
        workflow: Workflow | None = None,
        *,
        token: CancellationToken | None = None,
        scopes: Mapping[str, Mapping[str, Any]] | None = None,
        secret_resolver: Callable[[str], str | None] | None = None,
        max_outputs: int | None = None,
        validate_checkpoint: bool = True,
    ) -> WorkflowExecutionResult:
        if validate_checkpoint:
            validation = self.validate_resume_checkpoint(
                execution_id, workflow, scopes=scopes, secret_resolver=secret_resolver
            )
            if not validation.valid:
                raise ArenyxaError(
                    "WORKFLOW_RESUME_PREFLIGHT_FAILED",
                    "工作流检查点未通过隔离恢复预检。",
                    domain="WORKFLOW",
                    context=validation.to_dict(),
                )
        active_token = token or CancellationToken()
        operation_key = self._register_operation(active_token)
        try:
            return self._resume_execution_registered(
                execution_id,
                workflow,
                token=active_token,
                scopes=scopes,
                secret_resolver=secret_resolver,
                max_outputs=max_outputs,
            )
        finally:
            self._unregister_operation(operation_key)

    def _resume_execution_registered(
        self,
        execution_id: str,
        workflow: Workflow | None,
        *,
        token: CancellationToken,
        scopes: Mapping[str, Mapping[str, Any]] | None,
        secret_resolver: Callable[[str], str | None] | None,
        max_outputs: int | None,
    ) -> WorkflowExecutionResult:
        execution = self.store.get_workflow_execution(execution_id)
        if execution is None:
            raise ArenyxaError(
                "WORKFLOW_EXECUTION_NOT_FOUND",
                "找不到工作流执行记录。",
                domain="WORKFLOW",
                context={"execution_id": execution_id},
            )
        state = str(execution["state"])
        if state in {"completed", "completed_with_errors"}:
            return self._result_from_row(execution, resumed=True)
        if state not in {"interrupted", "cancelled"}:
            raise ArenyxaError(
                "WORKFLOW_RESUME_NOT_ALLOWED",
                "当前工作流执行状态不允许恢复。",
                domain="WORKFLOW",
                context={"execution_id": execution_id, "state": state},
            )
        if workflow is None:
            workflow = self._workflow_for_execution(execution)
        else:
            digest = self.definition_hash(workflow)
            if digest != str(execution["definition_hash"]):
                raise ArenyxaError(
                    "WORKFLOW_RESUME_DEFINITION_CHANGED",
                    "工作流定义已变化，拒绝在旧检查点上继续执行。",
                    domain="WORKFLOW",
                    context={"execution_id": execution_id},
                )
        output_revision = self.store.get_revision_metadata(
            str(execution["output_revision_id"]), include_incomplete=True
        )
        if output_revision is None or str(output_revision["build_state"]) == "ready":
            raise ArenyxaError(
                "WORKFLOW_RESUME_OUTPUT_INVALID",
                "工作流输出 Revision 不存在或已经完成，无法恢复。",
                domain="WORKFLOW",
            )
        source_revision = self.store.get_revision_metadata(str(execution["source_revision_id"]))
        if source_revision is None:
            raise ArenyxaError(
                "DATASET_REVISION_NOT_FOUND",
                "恢复执行所需的输入 Revision 不存在。",
                domain="WORKFLOW",
                context={"execution_id": execution_id},
            )
        self._authorize_execution_resources(
            workflow.id,
            str(source_revision["dataset_id"]),
            str(execution["output_dataset_id"]),
            correlation_id=f"workflow-resume:{execution_id}",
        )
        if not self.store.claim_workflow_execution_for_resume(execution_id):

            current = self.store.get_workflow_execution(execution_id)
            if current is not None and str(current.get("state")) in {"completed", "completed_with_errors"}:
                return self._result_from_row(current, resumed=True)
            raise ArenyxaError(
                "WORKFLOW_RESUME_CONFLICT",
                "该工作流执行已被另一个恢复操作占用或状态已变化。",
                domain="WORKFLOW",
                context={"execution_id": execution_id, "state": None if current is None else current.get("state")},
            )
        dataset = self.store.get_dataset(str(execution["output_dataset_id"]))
        dataset_name = str(dataset.get("name")) if dataset else str(execution["output_dataset_id"])
        return self._run(
            workflow,
            execution_id,
            str(execution["source_revision_id"]),
            str(execution["output_revision_id"]),
            str(execution["output_dataset_id"]),
            dataset_name,
            token=token,
            scopes=scopes,
            secret_resolver=secret_resolver,
            max_outputs=max_outputs,
            resumed=True,
        )

    def reconcile_completed_lineage(self, *, limit: int = 5000) -> int:

        repaired = 0
        for execution in self.store.list_completed_workflow_executions_missing_lineage(
            limit=max(1, min(20_000, int(limit)))
        ):
            output_revision_id = str(execution.get("output_revision_id") or "")
            try:
                workflow = self._workflow_for_execution(execution)
            except ArenyxaError:

                continue
            try:
                self._record_lineage(
                    workflow,
                    str(execution["id"]),
                    str(execution["source_revision_id"]),
                    output_revision_id,
                    str(execution["output_dataset_id"]),
                    self.store.count_revision_records(output_revision_id),
                )
            except Exception:
                LOGGER.exception("Lineage reconciliation failed for Workflow %s", execution.get("id"))
                continue
            repaired += 1
        return repaired
