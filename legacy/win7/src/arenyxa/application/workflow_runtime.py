from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from dataclasses import asdict
from arenyxa.compat import dataclass
from typing import Any, Callable, Mapping

from arenyxa.application.data_lineage import DataLineageService, _SchemaAccumulator
from arenyxa.application.workflows import WorkflowEngine, WorkflowResult
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import DatasetRevision, Workflow, WorkflowNode, new_id, utc_now
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.http_client import CancellationToken

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class WorkflowExecutionResult:
    execution_id: str
    workflow_id: str
    source_revision_id: str
    output_revision_id: str
    output_dataset_id: str
    state: str
    processed_inputs: int
    output_count: int
    error_count: int
    resumed: bool = False


class WorkflowDatasetService:
    







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
            return Workflow(
                name=str(payload["name"]),
                nodes=nodes,
                id=str(payload["id"]),
                version=str(payload.get("version", "1.0.0")),
                created_at=str(payload.get("created_at", utc_now())),
                schema_version=int(payload.get("schema_version", 6)),
            )
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

                                                                                            
                                                        
        self.store.save_workflow(asdict(workflow))
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
        execution_id = new_id("workflowexec")
        self.store.begin_revision_build(output_revision)
        try:
            self.store.begin_workflow_execution(
                {
                    "id": execution_id,
                    "workflow_id": workflow.id,
                    "source_revision_id": source_revision_id,
                    "output_dataset_id": output_dataset_id,
                    "output_revision_id": output_revision.id,
                    "definition_hash": digest,
                    "definition_json": json.dumps(
                        asdict(workflow), ensure_ascii=False, sort_keys=True, default=str
                    ),
                    "started_at": utc_now(),
                },
                [node.id for node in workflow.nodes],
            )
        except Exception:
            try:
                self.store.set_revision_build_state(output_revision.id, "failed")
            except Exception:
                LOGGER.exception(
                    "Failed to mark output revision failed after workflow execution initialization error",
                    extra={"output_revision_id": output_revision.id, "execution_id": execution_id},
                )
            raise

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

    def resume_execution(
        self,
        execution_id: str,
        workflow: Workflow | None = None,
        *,
        token: CancellationToken | None = None,
        scopes: Mapping[str, Mapping[str, Any]] | None = None,
        secret_resolver: Callable[[str], str | None] | None = None,
        max_outputs: int | None = None,
    ) -> WorkflowExecutionResult:
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

    def _run(
        self,
        workflow: Workflow,
        execution_id: str,
        source_revision_id: str,
        output_revision_id: str,
        output_dataset_id: str,
        dataset_name: str,
        *,
        project_id: str | None = None,
        token: CancellationToken,
        scopes: Mapping[str, Mapping[str, Any]] | None,
        secret_resolver: Callable[[str], str | None] | None,
        max_outputs: int | None,
        resumed: bool,
    ) -> WorkflowExecutionResult:
        return self._run_inner(
            workflow,
            execution_id,
            source_revision_id,
            output_revision_id,
            output_dataset_id,
            dataset_name,
            project_id=project_id,
            token=token,
            scopes=scopes,
            secret_resolver=secret_resolver,
            max_outputs=max_outputs,
            resumed=resumed,
        )

    def _run_inner(
        self,
        workflow: Workflow,
        execution_id: str,
        source_revision_id: str,
        output_revision_id: str,
        output_dataset_id: str,
        dataset_name: str,
        *,
        project_id: str | None = None,
        token: CancellationToken,
        scopes: Mapping[str, Mapping[str, Any]] | None,
        secret_resolver: Callable[[str], str | None] | None,
        max_outputs: int | None,
        resumed: bool,
    ) -> WorkflowExecutionResult:
        execution = self.store.get_workflow_execution(execution_id)
        if execution is None:
            raise ArenyxaError("WORKFLOW_EXECUTION_NOT_FOUND", "找不到工作流执行记录。", domain="WORKFLOW")
        after_identity = str(execution.get("last_input_identity") or "")
        output_cap = self.max_outputs if max_outputs is None else max(1, min(self.max_outputs, int(max_outputs)))
        already_outputs = int(execution.get("staged_outputs", 0))

        schema = _SchemaAccumulator()
        if resumed:
            for _, existing in self.store.iter_revision_records(
                output_revision_id, include_incomplete=True, page_size=2000
            ):
                schema.observe(existing)

        pending_outputs: list[tuple[str, dict[str, Any]]] = []
        pending_processed = 0
        pending_errors = 0
        pending_node_deltas: dict[str, dict[str, int | str]] = {}
        pending_output_bytes = 0
        checkpoint_started_at = time.monotonic()
        last_completed_identity = after_identity
        total_output_observed = already_outputs

        def merge_node_metrics(result: WorkflowResult) -> None:
            for node_id, metrics in result.nodes.items():
                target = pending_node_deltas.setdefault(
                    node_id,
                    {"input_count": 0, "output_count": 0, "error_count": 0, "state": "completed"},
                )
                target["input_count"] = int(target["input_count"]) + int(metrics.input_count)
                target["output_count"] = int(target["output_count"]) + int(metrics.output_count)
                target["error_count"] = int(target["error_count"]) + int(metrics.error_count)
                if metrics.state == "partial" or int(target["error_count"]) > 0:
                    target["state"] = "partial"

        def flush_checkpoint() -> None:
            nonlocal pending_processed, pending_errors, pending_outputs, pending_node_deltas
            nonlocal pending_output_bytes, checkpoint_started_at
            if pending_processed <= 0:
                return
            if pending_outputs:
                self.store.append_revision_records(
                    output_revision_id,
                    pending_outputs,
                    replace=True,
                    batch_size=self.write_batch_size,
                )
            self.store.checkpoint_workflow_execution(
                execution_id,
                last_input_identity=last_completed_identity,
                processed_delta=pending_processed,
                output_delta=len(pending_outputs),
                error_delta=pending_errors,
                node_deltas=pending_node_deltas,
                checkpoint={
                    "workflow_version": workflow.version,
                    "output_schema": schema.as_dict(),
                },
            )
            pending_processed = 0
            pending_errors = 0
            pending_outputs = []
            pending_node_deltas = {}
            pending_output_bytes = 0
            checkpoint_started_at = time.monotonic()

        try:
            for source_identity, source_record in self.store.iter_revision_records(
                source_revision_id,
                after_identity=after_identity,
                page_size=1000,
            ):
                token.checkpoint()
                result = self.engine.execute(
                    workflow,
                    [dict(source_record)],
                    token,
                    scopes=scopes,
                    secret_resolver=secret_resolver,
                )
                merge_node_metrics(result)
                pending_errors += len(result.errors)
                for ordinal, output in enumerate(result.outputs):
                    total_output_observed += 1
                    if total_output_observed > output_cap:
                        raise ArenyxaError(
                            "WORKFLOW_OUTPUT_LIMIT",
                            "工作流输出超过本次执行的安全上限。",
                            domain="WORKFLOW",
                            context={"limit": output_cap},
                        )
                    clean_output = dict(output)
                    encoded_size = len(
                        json.dumps(
                            clean_output, ensure_ascii=False, default=str, separators=(",", ":")
                        ).encode("utf-8")
                    )
                    if encoded_size > self.max_pending_output_bytes:
                        raise ArenyxaError(
                            "WORKFLOW_RECORD_TOO_LARGE",
                            "单条工作流输出超过内存缓冲安全上限。",
                            domain="WORKFLOW",
                            context={"bytes": encoded_size, "limit": self.max_pending_output_bytes},
                        )
                    schema.observe(clean_output)
                    pending_outputs.append(
                        (
                            self._output_identity(source_identity, workflow.id, ordinal),
                            clean_output,
                        )
                    )
                    pending_output_bytes += encoded_size
                pending_processed += 1
                last_completed_identity = source_identity
                if (
                    pending_processed >= self.checkpoint_every
                    or len(pending_outputs) >= self.write_batch_size
                    or pending_output_bytes >= self.max_pending_output_bytes
                    or time.monotonic() - checkpoint_started_at >= self.checkpoint_max_interval_seconds
                ):
                    flush_checkpoint()
            flush_checkpoint()

            record_count = self.store.finalize_revision_build(
                output_revision_id,
                schema=schema.as_dict(),
                dataset_name=dataset_name,
                project_id=project_id,
            )
            final_row = self.store.get_workflow_execution(execution_id)
            if final_row is None:
                raise ArenyxaError("WORKFLOW_EXECUTION_NOT_FOUND", "找不到工作流执行记录。", domain="WORKFLOW")
            final_state = "completed_with_errors" if int(final_row.get("error_count", 0)) > 0 else "completed"
            self.store.finish_workflow_execution(execution_id, state=final_state)
                                                                                             
                                                                                          
                                                                                           
            try:
                self._record_lineage(
                    workflow,
                    execution_id,
                    source_revision_id,
                    output_revision_id,
                    output_dataset_id,
                    record_count,
                )
            except Exception:
                LOGGER.exception("Workflow %s completed but lineage recording failed", execution_id)
            final_row = self.store.get_workflow_execution(execution_id)
            assert final_row is not None
            return self._result_from_row(final_row, resumed=resumed)
        except ArenyxaError as exc:
            if exc.code == "RUN_CANCELLED":
                try:
                    flush_checkpoint()
                except Exception:
                    LOGGER.exception(
                        "Failed to flush workflow checkpoint during cancellation",
                        extra={"execution_id": execution_id},
                    )
                try:
                    self.store.set_revision_build_state(output_revision_id, "cancelled")
                except Exception:
                    LOGGER.exception(
                        "Failed to mark output revision cancelled",
                        extra={"execution_id": execution_id, "output_revision_id": output_revision_id},
                    )
                self.store.finish_workflow_execution(
                    execution_id,
                    state="cancelled",
                    error_code="WORKFLOW_CANCELLED",
                    error_message="Execution cancelled cooperatively",
                )
            else:
                try:
                    flush_checkpoint()
                except Exception:
                    LOGGER.exception(
                        "Failed to flush workflow checkpoint after domain failure",
                        extra={"execution_id": execution_id, "error_code": exc.code},
                    )
                try:
                    self.store.set_revision_build_state(output_revision_id, "failed")
                except Exception:
                    LOGGER.exception(
                        "Failed to mark output revision failed after domain failure",
                        extra={"execution_id": execution_id, "output_revision_id": output_revision_id},
                    )
                self.store.finish_workflow_execution(
                    execution_id,
                    state="failed",
                    error_code=exc.code,
                    error_message=exc.message,
                )
            raise
        except Exception as exc:
            try:
                flush_checkpoint()
            except Exception:
                LOGGER.exception(
                    "Failed to flush workflow checkpoint after unexpected failure",
                    extra={"execution_id": execution_id},
                )
            try:
                self.store.set_revision_build_state(output_revision_id, "failed")
            except Exception:
                LOGGER.exception(
                    "Failed to mark output revision failed after unexpected workflow failure",
                    extra={"execution_id": execution_id, "output_revision_id": output_revision_id},
                )
            self.store.finish_workflow_execution(
                execution_id,
                state="failed",
                error_code="WORKFLOW_RUNTIME_FAILED",
                error_message=type(exc).__name__,
            )
            raise

    def _record_lineage(
        self,
        workflow: Workflow,
        execution_id: str,
        source_revision_id: str,
        output_revision_id: str,
        output_dataset_id: str,
        record_count: int,
    ) -> None:
        self.lineage.record_derivation(
            "revision", source_revision_id,
            "workflow_execution", execution_id,
            "input_to",
        )
        self.lineage.record_derivation(
            "workflow", workflow.id,
            "workflow_execution", execution_id,
            "executed_as",
            from_label=workflow.name,
            evidence={"version": workflow.version},
        )
        self.lineage.record_derivation(
            "workflow_execution", execution_id,
            "revision", output_revision_id,
            "produced",
            evidence={"record_count": record_count},
        )
        self.lineage.record_derivation(
            "revision", output_revision_id,
            "dataset", output_dataset_id,
            "version_of",
        )
        output = self.store.get_revision_metadata(output_revision_id)
        if output is not None and output.get("parent_revision"):
            self.lineage.record_derivation(
                "revision", str(output["parent_revision"]),
                "revision", output_revision_id,
                "parent_of",
            )

    @staticmethod
    def _result_from_row(row: Mapping[str, Any], *, resumed: bool) -> WorkflowExecutionResult:
        return WorkflowExecutionResult(
            execution_id=str(row["id"]),
            workflow_id=str(row["workflow_id"]),
            source_revision_id=str(row["source_revision_id"]),
            output_revision_id=str(row["output_revision_id"]),
            output_dataset_id=str(row["output_dataset_id"]),
            state=str(row["state"]),
            processed_inputs=int(row.get("processed_inputs", 0)),
            output_count=int(row.get("staged_outputs", 0)),
            error_count=int(row.get("error_count", 0)),
            resumed=resumed,
        )
