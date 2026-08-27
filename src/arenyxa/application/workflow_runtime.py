from __future__ import annotations
from arenyxa.application.workflow_runtime_execution import WorkflowExecutionMixin
from arenyxa.application.workflow_runtime_resume import WorkflowResumeMixin
from arenyxa.application.workflow_runtime_engine import WorkflowRuntimeEngineMixin

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


class WorkflowDatasetService(WorkflowExecutionMixin, WorkflowResumeMixin, WorkflowRuntimeEngineMixin):

    def __init__(
        self,
        store: SQLiteStore,
        engine: WorkflowEngine,
        lineage: DataLineageService,
        *,
        checkpoint_every: int = 100,
        write_batch_size: int = 500,
        max_outputs: int = 2_000_000,
        max_pending_output_bytes: int = 32 * 1024 * 1024,
        checkpoint_max_interval_seconds: float = 2.0,
        enterprise_operations: object | None = None,
    ) -> None:
        self.store = store
        self.engine = engine
        self.lineage = lineage
        self.checkpoint_every = max(1, min(5000, int(checkpoint_every)))
        self.write_batch_size = max(50, min(5000, int(write_batch_size)))
        self.max_outputs = max(1_000, min(20_000_000, int(max_outputs)))
        self.max_pending_output_bytes = max(
            1 * 1024 * 1024, min(256 * 1024 * 1024, int(max_pending_output_bytes))
        )
        self.checkpoint_max_interval_seconds = max(
            0.25, min(30.0, float(checkpoint_max_interval_seconds))
        )
        self._enterprise_operations = enterprise_operations
        self._operation_condition = threading.Condition()
        self._active_tokens: dict[int, CancellationToken] = {}
        self._operation_serial = 0
        self._closing = False

    def _register_operation(self, token: CancellationToken) -> int:
        with self._operation_condition:
            if self._closing:
                raise ArenyxaError(
                    "WORKFLOW_RUNTIME_SHUTDOWN",
                    "工作流运行时正在关闭，不能启动新的执行。",
                    domain="WORKFLOW",
                )

            self._operation_serial += 1
            operation_key = self._operation_serial
            self._active_tokens[operation_key] = token
            return operation_key

    def _unregister_operation(self, operation_key: int) -> None:
        with self._operation_condition:
            self._active_tokens.pop(operation_key, None)
            self._operation_condition.notify_all()

    def shutdown(self, *, wait: bool = True, timeout: float = 10.0) -> bool:

        with self._operation_condition:
            self._closing = True
            tokens = list(self._active_tokens.values())
        for token in tokens:
            token.cancel()
        if not wait:
            return not tokens
        deadline = time.monotonic() + max(0.0, float(timeout))
        with self._operation_condition:
            while self._active_tokens:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._operation_condition.wait(timeout=min(0.1, remaining))
            return True

    @staticmethod
    def definition_hash(workflow: Workflow) -> str:

        payload = {
            "id": workflow.id,
            "name": workflow.name,
            "version": workflow.version,
            "schema_version": workflow.schema_version,
            "nodes": [asdict(node) for node in workflow.nodes],
        }
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def _output_identity(source_identity: str, workflow_id: str, ordinal: int) -> str:
        digest = hashlib.sha256(
            f"{source_identity}\0{workflow_id}\0{int(ordinal)}".encode("utf-8")
        ).hexdigest()
        return f"wf_{digest}"

    @staticmethod
    def workflow_from_payload(payload: Mapping[str, Any]) -> Workflow:
        try:
            raw_nodes = payload.get("nodes", [])
            if not isinstance(raw_nodes, list):
                raise TypeError("nodes must be a list")
            nodes = [
                WorkflowNode(
                    kind=str(item["kind"]),
                    config=dict(item.get("config", {})),
                    id=str(item["id"]),
                    next_ids=[str(value) for value in item.get("next_ids", [])],
                    failure_ids=[str(value) for value in item.get("failure_ids", [])],
                )
                for item in raw_nodes
                if isinstance(item, Mapping)
            ]
            workflow = Workflow(
                name=str(payload["name"]),
                nodes=nodes,
                id=str(payload["id"]),
                version=str(payload.get("version", "1.0.0")),
                created_at=str(payload.get("created_at", utc_now())),
                schema_version=int(payload.get("schema_version", 6)),
            )
            validate_workflow_contract(workflow)
            return workflow
        except (KeyError, TypeError, ValueError) as exc:
            raise ArenyxaError(
                "WORKFLOW_DEFINITION_INVALID",
                "工作流定义无法加载。",
                domain="WORKFLOW",
            ) from exc

    def _workflow_for_execution(self, execution: Mapping[str, Any]) -> Workflow:

        snapshot = execution.get("definition_json")
        payload: Mapping[str, Any] | None = None
        if isinstance(snapshot, str) and snapshot.strip() not in {"", "{}"}:
            try:
                decoded = json.loads(snapshot)
                if isinstance(decoded, Mapping):
                    payload = decoded
            except (json.JSONDecodeError, TypeError, ValueError):
                payload = None
        elif isinstance(snapshot, Mapping):
            payload = snapshot
        if payload is None:
            stored = self.store.get_workflow(str(execution["workflow_id"]))
            if isinstance(stored, Mapping):
                payload = stored
        if payload is None:
            raise ArenyxaError(
                "WORKFLOW_NOT_FOUND",
                "恢复执行所需的工作流定义不存在。",
                domain="WORKFLOW",
            )
        workflow = self.workflow_from_payload(payload)
        if self.definition_hash(workflow) != str(execution["definition_hash"]):
            raise ArenyxaError(
                "WORKFLOW_RESUME_DEFINITION_CHANGED",
                "工作流定义已变化，拒绝在旧检查点上继续执行。",
                domain="WORKFLOW",
                context={"execution_id": str(execution.get("id", ""))},
            )
        return workflow

    def _authorize_execution_resources(
        self, workflow_id: str, source_dataset_id: str, output_dataset_id: str, *, correlation_id: str
    ) -> None:
        if self._enterprise_operations is None:
            return

        self._enterprise_operations.authorize_if_bound(
            "workflow", workflow_id, "workflow.execute", correlation_id=correlation_id
        )
        self._enterprise_operations.authorize_if_bound(
            "dataset", source_dataset_id, "dataset.read", correlation_id=correlation_id
        )
        self._enterprise_operations.authorize_if_bound(
            "dataset", output_dataset_id, "dataset.write", correlation_id=correlation_id
        )












