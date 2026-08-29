from __future__ import annotations

import hashlib
import hmac
import json
import logging
import sqlite3
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


class WorkflowRuntimeEngineMixin:
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
        previous_checkpoint = execution.get("checkpoint")
        if not isinstance(previous_checkpoint, Mapping):
            previous_checkpoint = {}
        checkpoint_generation = max(0, int(previous_checkpoint.get("generation", 0) or 0))
        previous_checkpoint_hash = str(previous_checkpoint.get("checkpoint_sha256", ""))

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
        checkpoint_write_failed = False

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
            nonlocal pending_output_bytes, checkpoint_started_at, checkpoint_generation, previous_checkpoint_hash
            nonlocal checkpoint_write_failed
            if pending_processed <= 0:
                return
            if pending_outputs:
                self.store.append_revision_records(
                    output_revision_id,
                    pending_outputs,
                    replace=True,
                    batch_size=self.write_batch_size,
                )
            checkpoint_generation += 1
            checkpoint_payload = {
                "schema": "arenyxa.workflow-checkpoint/v3",
                "generation": checkpoint_generation,
                "previous_checkpoint_sha256": previous_checkpoint_hash,
                "workflow_id": workflow.id,
                "workflow_version": workflow.version,
                "definition_hash": self.definition_hash(workflow),
                "source_revision_id": source_revision_id,
                "output_revision_id": output_revision_id,
                "last_input_identity": last_completed_identity,
                "output_schema": schema.as_dict(),
            }
            checkpoint_payload["checkpoint_sha256"] = checkpoint_digest(checkpoint_payload)

            def checkpoint_is_durable() -> bool:
                try:
                    durable = self.store.get_workflow_execution(execution_id)
                except Exception:
                    return False
                stored = durable.get("checkpoint") if durable is not None else None
                return isinstance(stored, Mapping) and hmac.compare_digest(
                    str(stored.get("checkpoint_sha256", "")),
                    str(checkpoint_payload["checkpoint_sha256"]),
                )

            for attempt in range(2):
                try:
                    self.store.checkpoint_workflow_execution(
                        execution_id,
                        last_input_identity=last_completed_identity,
                        processed_delta=pending_processed,
                        output_delta=len(pending_outputs),
                        error_delta=pending_errors,
                        node_deltas=pending_node_deltas,
                        checkpoint=checkpoint_payload,
                    )
                    break
                except sqlite3.OperationalError:
                    # Confirm an ambiguous commit before retrying additive deltas.  A retry is
                    # safe only when the intended checkpoint is not already durable.
                    if checkpoint_is_durable():
                        break
                    if attempt == 0:
                        continue
                    checkpoint_write_failed = True
                    raise
                except Exception:
                    if checkpoint_is_durable():
                        break
                    checkpoint_write_failed = True
                    raise
            previous_checkpoint_hash = str(checkpoint_payload["checkpoint_sha256"])
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
                if not checkpoint_write_failed:
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
                if not checkpoint_write_failed:
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
            if not checkpoint_write_failed:
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
