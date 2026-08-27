from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import field
from arenyxa.compat import dataclass
from typing import Any, Iterable, Sequence

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import DatasetRevision, new_id
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.http_client import CancellationToken

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class DatasetBuildResult:
    dataset_id: str
    revision_id: str
    record_count: int
    source_run_ids: list[str]
    schema: dict[str, str]
    parent_revision: str | None = None


@dataclass(slots=True)
class LineageGraph:
    root: dict[str, Any]
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    truncated: bool = False


class _SchemaAccumulator:
    def __init__(self) -> None:
        self._types: dict[str, str] = {}

    @staticmethod
    def _type_of(value: Any) -> str:
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, int):
            return "integer"
        if isinstance(value, float):
            return "number"
        if isinstance(value, str):
            return "string"
        if isinstance(value, dict):
            return "object"
        if isinstance(value, (list, tuple)):
            return "array"
        return "string"

    @staticmethod
    def _merge(before: str | None, after: str) -> str:
        if before is None:
            return after
        if before == after:
            return before
        if before == "null":
            return after
        if after == "null":
            return before
        if {before, after} <= {"integer", "number"}:
            return "number"
        return "mixed"

    def observe(self, record: dict[str, Any]) -> None:
        for key, value in record.items():
            name = str(key)
            self._types[name] = self._merge(self._types.get(name), self._type_of(value))

    def as_dict(self) -> dict[str, str]:
        return dict(sorted(self._types.items()))


class DataLineageService:
    






    def __init__(
        self,
        store: SQLiteStore,
        *,
        write_batch_size: int = 500,
        max_records: int = 1_000_000,
    ) -> None:
        self.store = store
        self.write_batch_size = max(50, min(5000, int(write_batch_size)))
        self.max_records = max(1_000, min(10_000_000, int(max_records)))

    def create_dataset(
        self,
        name: str,
        *,
        dataset_id: str | None = None,
        project_id: str | None = None,
    ) -> str:
        clean_name = str(name).strip()
        if not clean_name:
            raise ArenyxaError("DATASET_NAME_REQUIRED", "数据集名称不能为空。", domain="DATASET")
        identifier = str(dataset_id or new_id("dataset"))
        self.store.upsert_dataset(identifier, clean_name, project_id=project_id)
        self._ensure_node("dataset", identifier, label=clean_name, metadata={"project_id": project_id})
        return identifier

    @staticmethod
    def _identity_for_record(
        data: dict[str, Any],
        *,
        source_content_hash: str,
        identity_fields: Sequence[str],
    ) -> str:
        if identity_fields:
            identity_payload = {
                str(field): data.get(str(field))
                for field in identity_fields
            }
            canonical = json.dumps(
                identity_payload,
                ensure_ascii=False,
                sort_keys=True,
                default=str,
                separators=(",", ":"),
            )
            digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            return f"key_{digest}"
        digest = str(source_content_hash).strip().casefold()
        if len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest):
            return f"hash_{digest}"
        canonical = json.dumps(data, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
        return f"hash_{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"

    def materialize_from_runs(
        self,
        dataset_id: str,
        run_ids: Sequence[str],
        *,
        dataset_name: str | None = None,
        identity_fields: Sequence[str] = (),
        label: str | None = None,
        parent_revision: str | None = None,
        project_id: str | None = None,
        token: CancellationToken | None = None,
        max_records: int | None = None,
    ) -> DatasetBuildResult:
        token = token or CancellationToken()
        clean_run_ids = [str(value).strip() for value in run_ids if str(value).strip()]
        if not clean_run_ids:
            raise ArenyxaError("DATASET_SOURCE_REQUIRED", "至少需要一个 Run 作为数据集来源。", domain="DATASET")
        if len(clean_run_ids) != len(set(clean_run_ids)):
            raise ArenyxaError("DATASET_SOURCE_DUPLICATE", "数据集来源 Run 不能重复。", domain="DATASET")

        source_runs: list[dict[str, Any]] = []
        for run_id in clean_run_ids:
            run = self.store.get_run(run_id)
            if run is None:
                raise ArenyxaError(
                    "DATASET_SOURCE_RUN_MISSING",
                    "数据集来源 Run 不存在。",
                    domain="DATASET",
                    context={"run_id": run_id},
                )
            status = str(run.get("status", ""))
            if status in {"queued", "running", "paused"}:
                raise ArenyxaError(
                    "DATASET_SOURCE_RUN_ACTIVE",
                    "仍在执行的 Run 不能作为不可变 Dataset Revision 的来源。",
                    domain="DATASET",
                    context={"run_id": run_id, "status": status},
                )
            source_runs.append(run)

        existing_dataset = self.store.get_dataset(dataset_id)
        resolved_name = (
            str(dataset_name).strip()
            if dataset_name is not None and str(dataset_name).strip()
            else str(existing_dataset.get("name")) if existing_dataset else str(dataset_id)
        )
        if existing_dataset is None:
            self.store.upsert_dataset(dataset_id, resolved_name, project_id=project_id)

        if parent_revision is None and existing_dataset is not None:
            current = existing_dataset.get("current_revision_id")
            parent_revision = str(current) if current else None
        if parent_revision is not None:
            parent = self.store.get_revision_metadata(parent_revision)
            if parent is None:
                raise ArenyxaError(
                    "DATASET_PARENT_REVISION_MISSING",
                    "指定的父 Revision 不存在或未完成。",
                    domain="DATASET",
                    context={"revision_id": parent_revision},
                )
            if str(parent["dataset_id"]) != str(dataset_id):
                raise ArenyxaError(
                    "DATASET_PARENT_MISMATCH",
                    "父 Revision 必须属于同一个 Dataset。",
                    domain="DATASET",
                )

        revision = DatasetRevision(
            dataset_id=str(dataset_id),
            source_run_ids=list(clean_run_ids),
            records={},
            parent_revision=parent_revision,
            label=label,
            schema={},
        )
        self.store.begin_revision_build(revision)

        cap = self.max_records if max_records is None else max(1, min(self.max_records, int(max_records)))
        schema = _SchemaAccumulator()
        pending: list[tuple[str, dict[str, Any]]] = []
        processed = 0
        try:
            for run in source_runs:
                token.checkpoint()
                run_id = str(run["id"])
                for raw_record in self.store.iter_result_records_raw(run_id):
                    token.checkpoint()
                    processed += 1
                    if processed > cap:
                        raise ArenyxaError(
                            "DATASET_RECORD_LIMIT",
                            "本次 Dataset Revision 构建超过安全记录上限。",
                            domain="DATASET",
                            context={"limit": cap},
                        )
                    data = dict(raw_record["data"])
                    schema.observe(data)
                    identity = self._identity_for_record(
                        data,
                        source_content_hash=str(raw_record["content_hash"]),
                        identity_fields=identity_fields,
                    )
                    pending.append((identity, data))
                    if len(pending) >= self.write_batch_size:
                        self.store.append_revision_records(
                            revision.id, pending, replace=True, batch_size=self.write_batch_size
                        )
                        pending.clear()
            if pending:
                self.store.append_revision_records(
                    revision.id, pending, replace=True, batch_size=self.write_batch_size
                )
                pending.clear()
            record_count = self.store.finalize_revision_build(
                revision.id,
                schema=schema.as_dict(),
                dataset_name=resolved_name,
                project_id=project_id,
            )
        except ArenyxaError as exc:
            state = "cancelled" if exc.code == "RUN_CANCELLED" else "failed"
            try:
                self.store.set_revision_build_state(revision.id, state)
            except Exception:
                LOGGER.exception(
                    "Failed to persist Dataset revision %s terminal state %s after domain failure",
                    revision.id,
                    state,
                )
            raise
        except Exception:
            try:
                self.store.set_revision_build_state(revision.id, "failed")
            except Exception:
                LOGGER.exception(
                    "Failed to persist Dataset revision %s failed state after unexpected build error",
                    revision.id,
                )
            raise

                                                                                              
                                                                                              
                                                                          
        try:
            self._record_run_revision_lineage(source_runs, revision, resolved_name, record_count)
        except Exception:
            LOGGER.exception("Dataset %s revision %s committed but lineage recording failed", dataset_id, revision.id)
        return DatasetBuildResult(
            dataset_id=str(dataset_id),
            revision_id=revision.id,
            record_count=record_count,
            source_run_ids=list(clean_run_ids),
            schema=schema.as_dict(),
            parent_revision=parent_revision,
        )

    def reconcile_ready_revision_lineage(self, *, limit: int = 5000) -> int:
        
        repaired = 0
        for metadata in self.store.list_ready_dataset_revisions_missing_lineage(
            limit=max(1, min(20_000, int(limit)))
        ):
            revision = DatasetRevision(
                dataset_id=str(metadata["dataset_id"]),
                source_run_ids=[str(value) for value in metadata.get("source_run_ids", [])],
                records={},
                id=str(metadata["id"]),
                parent_revision=None if metadata.get("parent_revision") is None else str(metadata["parent_revision"]),
                label=None if metadata.get("label") is None else str(metadata["label"]),
                schema=dict(metadata.get("schema") or {}),
                created_at=str(metadata.get("created_at") or ""),
                schema_version=int(metadata.get("schema_version", 6)),
            )
            dataset = self.store.get_dataset(revision.dataset_id)
            dataset_name = str(dataset.get("name")) if dataset else revision.dataset_id
            source_runs = []
            for run_id in revision.source_run_ids:
                run = self.store.get_run(run_id)
                if run is not None:
                    source_runs.append(run)
            try:
                self._record_run_revision_lineage(
                    source_runs,
                    revision,
                    dataset_name,
                    self.store.count_revision_records(revision.id),
                )
            except Exception:
                LOGGER.exception("Lineage reconciliation failed for Dataset Revision %s", revision.id)
                continue
            repaired += 1
        return repaired

    def _record_run_revision_lineage(
        self,
        source_runs: Sequence[dict[str, Any]],
        revision: DatasetRevision,
        dataset_name: str,
        record_count: int,
    ) -> None:
        dataset_node = self._ensure_node("dataset", revision.dataset_id, label=dataset_name)
        revision_node = self._ensure_node(
            "revision",
            revision.id,
            label=revision.label or revision.id,
            metadata={"record_count": record_count},
        )
        self.store.add_lineage_edge(revision_node, dataset_node, "version_of")
        if revision.parent_revision:
            parent_node = self._ensure_node("revision", revision.parent_revision)
            self.store.add_lineage_edge(parent_node, revision_node, "parent_of")
        for run in source_runs:
            run_id = str(run["id"])
            task_id = str(run.get("task_id", ""))
            run_node = self._ensure_node(
                "run",
                run_id,
                metadata={"status": str(run.get("status", "")), "task_id": task_id},
            )
            self.store.add_lineage_edge(run_node, revision_node, "materialized_into")
            if task_id:
                task_node = self._ensure_node("task", task_id)
                self.store.add_lineage_edge(task_node, run_node, "executed_as")

    def record_derivation(
        self,
        from_kind: str,
        from_id: str,
        to_kind: str,
        to_id: str,
        relation: str,
        *,
        evidence: dict[str, Any] | None = None,
        from_label: str = "",
        to_label: str = "",
    ) -> str:
        source = self._ensure_node(from_kind, from_id, label=from_label)
        target = self._ensure_node(to_kind, to_id, label=to_label)
        return self.store.add_lineage_edge(source, target, relation, evidence=evidence)

    def _ensure_node(
        self,
        kind: str,
        object_id: str,
        *,
        label: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> str:
                                                                                          
                                                                                            
        bounded: dict[str, Any] = {}
        for key, value in (metadata or {}).items():
            safe_key = str(key)[:64]
            if isinstance(value, (str, int, float, bool)) or value is None:
                bounded[safe_key] = str(value)[:240] if isinstance(value, str) else value
        return self.store.ensure_lineage_node(kind, object_id, label=label, metadata=bounded)

    def graph(
        self,
        kind: str,
        object_id: str,
        *,
        direction: str = "both",
        max_depth: int = 4,
        max_nodes: int = 500,
    ) -> LineageGraph:
        root = self.store.get_lineage_node(kind, object_id)
        if root is None:
            raise ArenyxaError(
                "LINEAGE_NODE_NOT_FOUND",
                "找不到指定的血缘对象。",
                domain="DATASET",
                context={"kind": kind, "object_id": object_id},
            )
        depth_cap = max(0, min(32, int(max_depth)))
        node_cap = max(1, min(10_000, int(max_nodes)))
        queue: list[tuple[str, int]] = [(str(root["id"]), 0)]
        seen_nodes = {str(root["id"])}
        nodes: dict[str, dict[str, Any]] = {str(root["id"]): root}
        edges: dict[str, dict[str, Any]] = {}
        truncated = False
        cursor = 0
        while cursor < len(queue):
            node_id, depth = queue[cursor]
            cursor += 1
            if depth >= depth_cap:
                continue
            neighbors = self.store.lineage_neighbors(node_id, direction=direction, limit=node_cap)
            for edge in neighbors:
                edge_id = str(edge["id"])
                edges[edge_id] = {
                    "id": edge_id,
                    "from_node_id": str(edge["from_node_id"]),
                    "to_node_id": str(edge["to_node_id"]),
                    "relation": str(edge["relation"]),
                    "direction": str(edge["direction"]),
                    "evidence": edge.get("evidence", {}),
                }
                neighbor_id = (
                    str(edge["to_node_id"])
                    if str(edge["direction"]) == "downstream"
                    else str(edge["from_node_id"])
                )
                if neighbor_id in seen_nodes:
                    continue
                if len(seen_nodes) >= node_cap:
                    truncated = True
                    continue
                seen_nodes.add(neighbor_id)
                node = {
                    "id": neighbor_id,
                    "kind": str(edge["kind"]),
                    "object_id": str(edge["object_id"]),
                    "label": str(edge["label"]),
                    "metadata": edge.get("metadata", {}),
                }
                nodes[neighbor_id] = node
                queue.append((neighbor_id, depth + 1))
        return LineageGraph(
            root=root,
            nodes=list(nodes.values()),
            edges=list(edges.values()),
            truncated=truncated,
        )
