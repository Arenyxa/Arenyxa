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


class WorkflowExecutionMixin:
    def execute_saved_workflow(
        self,
        workflow_id: str,
        source_revision_id: str,
        output_dataset_id: str,
        **kwargs: Any,
    ) -> WorkflowExecutionResult:
        payload = self.store.get_workflow(workflow_id)
        if payload is None:
            raise ArenyxaError(
                "WORKFLOW_NOT_FOUND",
                "找不到指定工作流。",
                domain="WORKFLOW",
                context={"workflow_id": workflow_id},
            )
        return self.execute_revision(
            self.workflow_from_payload(payload),
            source_revision_id,
            output_dataset_id,
            **kwargs,
        )

    def execute_revision(
        self,
        workflow: Workflow,
        source_revision_id: str,
        output_dataset_id: str,
        *,
        output_dataset_name: str | None = None,
        output_label: str | None = None,
        project_id: str | None = None,
        token: CancellationToken | None = None,
        scopes: Mapping[str, Mapping[str, Any]] | None = None,
        secret_resolver: Callable[[str], str | None] | None = None,
        max_outputs: int | None = None,
    ) -> WorkflowExecutionResult:

        active_token = token or CancellationToken()
        operation_key = self._register_operation(active_token)
        try:
            return self._execute_revision_registered(
                workflow,
                source_revision_id,
                output_dataset_id,
                output_dataset_name=output_dataset_name,
                output_label=output_label,
                project_id=project_id,
                token=active_token,
                scopes=scopes,
                secret_resolver=secret_resolver,
                max_outputs=max_outputs,
            )
        finally:
            self._unregister_operation(operation_key)

    def _execute_revision_registered(
        self,
        workflow: Workflow,
        source_revision_id: str,
        output_dataset_id: str,
        *,
        output_dataset_name: str | None,
        output_label: str | None,
        project_id: str | None,
        token: CancellationToken,
        scopes: Mapping[str, Mapping[str, Any]] | None,
        secret_resolver: Callable[[str], str | None] | None,
        max_outputs: int | None,
    ) -> WorkflowExecutionResult:
        source = self.store.get_revision_metadata(source_revision_id)
        if source is None:
            raise ArenyxaError(
                "DATASET_REVISION_NOT_FOUND",
                "工作流输入 Revision 不存在或尚未完成。",
                domain="WORKFLOW",
                context={"revision_id": source_revision_id},
            )
        if not workflow.nodes:
            raise ArenyxaError("WORKFLOW_EMPTY", "工作流至少需要一个节点。", domain="WORKFLOW")

        self._authorize_execution_resources(
            workflow.id,
            str(source["dataset_id"]),
            str(output_dataset_id),
            correlation_id=f"workflow-run:{workflow.id}:{source_revision_id}",
        )

        self.store.save_workflow(serialize_workflow(workflow))
        digest = self.definition_hash(workflow)
        output_dataset = self.store.get_dataset(output_dataset_id)
        dataset_name = (
            str(output_dataset_name).strip()
            if output_dataset_name is not None and str(output_dataset_name).strip()
            else str(output_dataset.get("name")) if output_dataset else str(output_dataset_id)
        )

        parent_revision = None
        if output_dataset_id == str(source["dataset_id"]):
            parent_revision = str(source_revision_id)
        elif output_dataset is not None and output_dataset.get("current_revision_id"):
            parent_revision = str(output_dataset["current_revision_id"])

        output_revision = DatasetRevision(
            dataset_id=str(output_dataset_id),
            source_run_ids=[str(value) for value in source.get("source_run_ids", [])],
            records={},
            parent_revision=parent_revision,
            label=output_label or f"Workflow {workflow.name} {workflow.version}",
            schema={},
        )
        execution_id = self._begin_execution_build(
            workflow, source_revision_id, output_dataset_id, output_revision, digest
        )

        return self._run(
            workflow,
            execution_id,
            source_revision_id,
            output_revision.id,
            str(output_dataset_id),
            dataset_name,
            project_id=project_id,
            token=token,
            scopes=scopes,
            secret_resolver=secret_resolver,
            max_outputs=max_outputs,
            resumed=False,
        )

    def _begin_execution_build(
        self,
        workflow: Workflow,
        source_revision_id: str,
        output_dataset_id: str,
        output_revision: DatasetRevision,
        definition_hash: str,
    ) -> str:
        execution_id = new_id("workflowexec")
        self.store.begin_revision_build(output_revision)
        initialized = False
        try:
            self.store.begin_workflow_execution(
                {
                    "id": execution_id,
                    "workflow_id": workflow.id,
                    "source_revision_id": source_revision_id,
                    "output_dataset_id": output_dataset_id,
                    "output_revision_id": output_revision.id,
                    "definition_hash": definition_hash,
                    "definition_json": json.dumps(
                        asdict(workflow), ensure_ascii=False, sort_keys=True, default=str
                    ),
                    "started_at": utc_now(),
                },
                [node.id for node in workflow.nodes],
            )
            initialized = True
        finally:
            if not initialized:
                try:
                    self.store.set_revision_build_state(output_revision.id, "failed")
                except (ArenyxaError, OSError, RuntimeError, ValueError, TypeError, KeyError):
                    LOGGER.exception(
                        "Failed to mark output revision failed after workflow execution initialization error",
                        extra={"output_revision_id": output_revision.id, "execution_id": execution_id},
                    )
        return execution_id
