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

class DatasetStoreMixin:
    def save_revision(self, revision: DatasetRevision) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO dataset_revisions
                (id,dataset_id,parent_revision,label,source_run_ids_json,schema_json,created_at,schema_version,build_state)
                VALUES(?,?,?,?,?,?,?,?, 'ready')
                """,
                (
                    revision.id,
                    revision.dataset_id,
                    revision.parent_revision,
                    revision.label,
                    json.dumps(revision.source_run_ids),
                    json.dumps(revision.schema, ensure_ascii=False),
                    revision.created_at,
                    revision.schema_version,
                ),
            )

            batch: list[tuple[str, str, str, str]] = []
            for identity, data in revision.records.items():
                raw = json.dumps(data, ensure_ascii=False, sort_keys=True, default=str)
                batch.append((revision.id, identity, raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()))
                if len(batch) >= 500:
                    connection.executemany("INSERT INTO revision_records VALUES(?,?,?,?)", batch)
                    batch.clear()
            if batch:
                connection.executemany("INSERT INTO revision_records VALUES(?,?,?,?)", batch)

    def count_revision_records(self, revision_id: str) -> int:
        with self.connect() as connection:
            return int(connection.execute(
                "SELECT count(*) FROM revision_records WHERE revision_id=?", (revision_id,)
            ).fetchone()[0])

    def load_revision_records(self, revision_id: str) -> dict[str, dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT record_identity,data_json FROM revision_records WHERE revision_id=?", (revision_id,)
            ).fetchall()
        return {str(row[0]): json.loads(row[1]) for row in rows}

    def list_revisions(
        self, dataset_id: str | None = None, *, include_incomplete: bool = False
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        values: list[Any] = []
        if dataset_id:
            clauses.append("dataset_id=?")
            values.append(dataset_id)
        if not include_incomplete:
            clauses.append("build_state='ready'")
        sql = "SELECT * FROM dataset_revisions"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at DESC"
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(sql, values)]

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return None if row is None else dict(row)

    def iter_result_records_raw(
        self, run_id: str, *, after_id: str = "", page_size: int = 1000
    ) -> Iterator[dict[str, Any]]:
        
        if not isinstance(page_size, int) or isinstance(page_size, bool) or page_size <= 0:
            raise ValueError("page_size must be a positive integer")
        page_size = min(page_size, 10_000)
        last_id = str(after_id or "")
        while True:
            with self.connect() as connection:
                rows = connection.execute(
                    "SELECT id,task_id,run_id,source_url,fetched_at,data_json,content_hash,quality_flags_json "
                    "FROM result_records WHERE run_id=? AND id>? ORDER BY id LIMIT ?",
                    (run_id, last_id, page_size),
                ).fetchall()
            if not rows:
                return
            for row in rows:
                last_id = str(row["id"])
                try:
                    data = json.loads(str(row["data_json"]))
                    flags = json.loads(str(row["quality_flags_json"]))
                except (json.JSONDecodeError, TypeError, ValueError) as exc:
                    raise ArenyxaError(
                        "DATASET_SOURCE_CORRUPT",
                        "结果记录包含损坏的 JSON，无法安全构建数据集修订。",
                        domain="DATASET",
                        context={"run_id": run_id, "record_id": last_id},
                    ) from exc
                if not isinstance(data, dict) or not isinstance(flags, list):
                    raise ArenyxaError(
                        "DATASET_SOURCE_CORRUPT",
                        "结果记录结构无效，无法安全构建数据集修订。",
                        domain="DATASET",
                        context={"run_id": run_id, "record_id": last_id},
                    )
                yield {
                    "id": last_id,
                    "task_id": str(row["task_id"]),
                    "run_id": str(row["run_id"]),
                    "source_url": str(row["source_url"]),
                    "fetched_at": str(row["fetched_at"]),
                    "data": data,
                    "content_hash": str(row["content_hash"]),
                    "quality_flags": [str(item) for item in flags],
                }

    def upsert_dataset(
        self,
        dataset_id: str,
        name: str,
        *,
        project_id: str | None = None,
        current_revision_id: str | None = None,
        schema_version: int = 6,
    ) -> None:
        dataset_id = str(dataset_id).strip()
        name = str(name).strip()
        if not dataset_id or not name:
            raise ValueError("dataset_id and name must be non-empty")
        now = utc_now()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO datasets(id,name,project_id,current_revision_id,created_at,updated_at,schema_version)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    project_id=COALESCE(excluded.project_id,datasets.project_id),
                    current_revision_id=COALESCE(excluded.current_revision_id,datasets.current_revision_id),
                    updated_at=excluded.updated_at,
                    schema_version=excluded.schema_version
                """,
                (dataset_id, name, project_id, current_revision_id, now, now, int(schema_version)),
            )

    def get_dataset(self, dataset_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM datasets WHERE id=?", (dataset_id,)).fetchone()
        return None if row is None else dict(row)

    def list_datasets(self, project_id: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        cap = max(1, min(10_000, int(limit)))
        sql = "SELECT * FROM datasets"
        values: list[Any] = []
        if project_id is not None:
            sql += " WHERE project_id=?"
            values.append(project_id)
        sql += " ORDER BY updated_at DESC,id LIMIT ?"
        values.append(cap)
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(sql, values)]

    def get_revision_metadata(
        self, revision_id: str, *, include_incomplete: bool = False
    ) -> dict[str, Any] | None:
        sql = "SELECT * FROM dataset_revisions WHERE id=?"
        values: list[Any] = [revision_id]
        if not include_incomplete:
            sql += " AND build_state='ready'"
        with self.connect() as connection:
            row = connection.execute(sql, values).fetchone()
        if row is None:
            return None
        item = dict(row)
        for raw_name, out_name, default in (
            ("source_run_ids_json", "source_run_ids", []),
            ("schema_json", "schema", {}),
        ):
            raw = item.pop(raw_name, None)
            try:
                parsed = json.loads(str(raw)) if raw is not None else default
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise ArenyxaError(
                    "DATASET_REVISION_CORRUPT",
                    "数据集修订元数据损坏。",
                    domain="DATASET",
                    context={"revision_id": revision_id, "field": raw_name},
                ) from exc
            item[out_name] = parsed
        return item

    def iter_revision_records(
        self,
        revision_id: str,
        *,
        after_identity: str = "",
        page_size: int = 1000,
        include_incomplete: bool = False,
    ) -> Iterator[tuple[str, dict[str, Any]]]:
        if not isinstance(page_size, int) or isinstance(page_size, bool) or page_size <= 0:
            raise ValueError("page_size must be a positive integer")
        page_size = min(page_size, 10_000)
        metadata = self.get_revision_metadata(revision_id, include_incomplete=include_incomplete)
        if metadata is None:
            raise ArenyxaError(
                "DATASET_REVISION_NOT_FOUND",
                "找不到可读取的数据集修订。",
                domain="DATASET",
                context={"revision_id": revision_id},
            )
        last_identity = str(after_identity or "")
        while True:
            with self.connect() as connection:
                rows = connection.execute(
                    "SELECT record_identity,data_json FROM revision_records "
                    "WHERE revision_id=? AND record_identity>? ORDER BY record_identity LIMIT ?",
                    (revision_id, last_identity, page_size),
                ).fetchall()
            if not rows:
                return
            for row in rows:
                last_identity = str(row["record_identity"])
                try:
                    data = json.loads(str(row["data_json"]))
                except (json.JSONDecodeError, TypeError, ValueError) as exc:
                    raise ArenyxaError(
                        "DATASET_REVISION_CORRUPT",
                        "数据集修订记录损坏。",
                        domain="DATASET",
                        context={"revision_id": revision_id, "record_identity": last_identity},
                    ) from exc
                if not isinstance(data, dict):
                    raise ArenyxaError(
                        "DATASET_REVISION_CORRUPT",
                        "数据集修订记录必须是对象。",
                        domain="DATASET",
                        context={"revision_id": revision_id, "record_identity": last_identity},
                    )
                yield last_identity, data

    def begin_revision_build(self, revision: DatasetRevision) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO dataset_revisions
                (id,dataset_id,parent_revision,label,source_run_ids_json,schema_json,created_at,schema_version,build_state)
                VALUES(?,?,?,?,?,?,?,?, 'building')
                """,
                (
                    revision.id,
                    revision.dataset_id,
                    revision.parent_revision,
                    revision.label,
                    json.dumps(revision.source_run_ids, ensure_ascii=False),
                    json.dumps(revision.schema, ensure_ascii=False),
                    revision.created_at,
                    revision.schema_version,
                ),
            )

    def append_revision_records(
        self,
        revision_id: str,
        records: Iterable[tuple[str, dict[str, Any]]],
        *,
        replace: bool = True,
        batch_size: int = 500,
    ) -> int:
        if not isinstance(batch_size, int) or isinstance(batch_size, bool) or batch_size <= 0:
            raise ValueError("batch_size must be a positive integer")
        batch_size = min(batch_size, 5000)
        sql = (
            "INSERT INTO revision_records(revision_id,record_identity,data_json,data_hash) VALUES(?,?,?,?) "
            "ON CONFLICT(revision_id,record_identity) DO UPDATE SET "
            "data_json=excluded.data_json,data_hash=excluded.data_hash"
            if replace
            else "INSERT INTO revision_records(revision_id,record_identity,data_json,data_hash) VALUES(?,?,?,?)"
        )
        total = 0
        batch: list[tuple[str, str, str, str]] = []
        with self.transaction() as connection:
            state_row = connection.execute(
                "SELECT build_state FROM dataset_revisions WHERE id=?", (revision_id,)
            ).fetchone()
            if state_row is None:
                raise ArenyxaError(
                    "DATASET_REVISION_NOT_FOUND", "找不到数据集修订。", domain="DATASET",
                    context={"revision_id": revision_id},
                )
            if str(state_row[0]) not in {"building", "interrupted"}:
                raise ArenyxaError(
                    "DATASET_REVISION_IMMUTABLE",
                    "已完成的数据集修订不可原地修改。",
                    domain="DATASET",
                    context={"revision_id": revision_id, "state": str(state_row[0])},
                )
            for identity, data in records:
                identity = str(identity)
                if not identity or len(identity) > 256 or not isinstance(data, dict):
                    raise ArenyxaError(
                        "DATASET_RECORD_INVALID",
                        "数据集记录标识或内容无效。",
                        domain="DATASET",
                        context={"revision_id": revision_id},
                    )
                raw = json.dumps(data, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
                batch.append((revision_id, identity, raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()))
                if len(batch) >= batch_size:
                    connection.executemany(sql, batch)
                    total += len(batch)
                    batch.clear()
            if batch:
                connection.executemany(sql, batch)
                total += len(batch)
        return total

    def set_revision_build_state(self, revision_id: str, state: str) -> None:
        if state not in {"building", "interrupted", "failed", "cancelled"}:
            raise ValueError("unsupported revision build state")
        with self.transaction() as connection:
            cursor = connection.execute(
                "UPDATE dataset_revisions SET build_state=? WHERE id=? AND build_state<>'ready'",
                (state, revision_id),
            )
            if cursor.rowcount != 1:
                raise ArenyxaError(
                    "DATASET_REVISION_STATE_CONFLICT",
                    "数据集修订状态已发生变化。",
                    domain="DATASET",
                    context={"revision_id": revision_id},
                )

    def finalize_revision_build(
        self,
        revision_id: str,
        *,
        schema: dict[str, str],
        dataset_name: str,
        project_id: str | None = None,
    ) -> int:
        now = utc_now()
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT dataset_id,build_state FROM dataset_revisions WHERE id=?", (revision_id,)
            ).fetchone()
            if row is None:
                raise ArenyxaError(
                    "DATASET_REVISION_NOT_FOUND", "找不到数据集修订。", domain="DATASET",
                    context={"revision_id": revision_id},
                )
            state = str(row["build_state"])
            if state not in {"building", "interrupted"}:
                raise ArenyxaError(
                    "DATASET_REVISION_STATE_CONFLICT",
                    "当前修订不能完成构建。",
                    domain="DATASET",
                    context={"revision_id": revision_id, "state": state},
                )
            dataset_id = str(row["dataset_id"])
            count = int(connection.execute(
                "SELECT count(*) FROM revision_records WHERE revision_id=?", (revision_id,)
            ).fetchone()[0])
            connection.execute(
                "UPDATE dataset_revisions SET schema_json=?,build_state='ready' WHERE id=?",
                (json.dumps(schema, ensure_ascii=False, sort_keys=True), revision_id),
            )
            connection.execute(
                """
                INSERT INTO datasets(id,name,project_id,current_revision_id,created_at,updated_at,schema_version)
                VALUES(?,?,?,?,?,?,6)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    project_id=COALESCE(excluded.project_id,datasets.project_id),
                    current_revision_id=excluded.current_revision_id,
                    updated_at=excluded.updated_at
                """,
                (dataset_id, dataset_name, project_id, revision_id, now, now),
            )
        return count

    @staticmethod
    def _lineage_node_id(kind: str, object_id: str) -> str:
        digest = hashlib.sha256(f"{kind}\0{object_id}".encode("utf-8")).hexdigest()[:32]
        return f"lineage_{digest}"

    @staticmethod
    def _lineage_edge_id(from_node_id: str, to_node_id: str, relation: str) -> str:
        digest = hashlib.sha256(
            f"{from_node_id}\0{to_node_id}\0{relation}".encode("utf-8")
        ).hexdigest()[:32]
        return f"edge_{digest}"

    def ensure_lineage_node(
        self,
        kind: str,
        object_id: str,
        *,
        label: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        kind = str(kind).strip().casefold()
        object_id = str(object_id).strip()
        if not kind or not object_id or len(kind) > 64 or len(object_id) > 256:
            raise ValueError("invalid lineage node identity")
        safe_metadata = metadata if isinstance(metadata, dict) else {}
        raw_metadata = json.dumps(safe_metadata, ensure_ascii=False, sort_keys=True, default=str)
        node_id = self._lineage_node_id(kind, object_id)
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO lineage_nodes(id,kind,object_id,label,metadata_json,created_at)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(kind,object_id) DO UPDATE SET
                    label=CASE WHEN excluded.label<>'' THEN excluded.label ELSE lineage_nodes.label END,
                    metadata_json=CASE WHEN excluded.metadata_json<>'{}' THEN excluded.metadata_json ELSE lineage_nodes.metadata_json END
                """,
                (node_id, kind, object_id, str(label)[:240], raw_metadata, utc_now()),
            )
        return node_id

    def add_lineage_edge(
        self,
        from_node_id: str,
        to_node_id: str,
        relation: str,
        *,
        evidence: dict[str, Any] | None = None,
    ) -> str:
        relation = str(relation).strip().casefold()
        if not relation or len(relation) > 80:
            raise ValueError("invalid lineage relation")
        edge_id = self._lineage_edge_id(from_node_id, to_node_id, relation)
        raw_evidence = json.dumps(
            evidence if isinstance(evidence, dict) else {},
            ensure_ascii=False,
            sort_keys=True,
            default=str,
        )
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO lineage_edges(id,from_node_id,to_node_id,relation,evidence_json,created_at)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(from_node_id,to_node_id,relation) DO UPDATE SET
                    evidence_json=CASE WHEN excluded.evidence_json<>'{}' THEN excluded.evidence_json ELSE lineage_edges.evidence_json END
                """,
                (edge_id, from_node_id, to_node_id, relation, raw_evidence, utc_now()),
            )
        return edge_id

    def get_lineage_node(self, kind: str, object_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM lineage_nodes WHERE kind=? AND object_id=?",
                (str(kind).casefold(), str(object_id)),
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        try:
            item["metadata"] = json.loads(str(item.pop("metadata_json")))
        except (json.JSONDecodeError, TypeError, ValueError):
            item["metadata"] = {}
        return item

    def lineage_neighbors(
        self, node_id: str, *, direction: str = "both", limit: int = 500
    ) -> list[dict[str, Any]]:
        if direction not in {"upstream", "downstream", "both"}:
            raise ValueError("direction must be upstream/downstream/both")
        cap = max(1, min(5000, int(limit)))
        queries: list[tuple[str, str]] = []
        if direction in {"downstream", "both"}:
            queries.append((
                "downstream",
                "SELECT e.*,n.kind,n.object_id,n.label,n.metadata_json "
                "FROM lineage_edges e JOIN lineage_nodes n ON n.id=e.to_node_id "
                "WHERE e.from_node_id=? ORDER BY e.id LIMIT ?",
            ))
        if direction in {"upstream", "both"}:
            queries.append((
                "upstream",
                "SELECT e.*,n.kind,n.object_id,n.label,n.metadata_json "
                "FROM lineage_edges e JOIN lineage_nodes n ON n.id=e.from_node_id "
                "WHERE e.to_node_id=? ORDER BY e.id LIMIT ?",
            ))
        output: list[dict[str, Any]] = []
        with self.connect() as connection:
            for edge_direction, sql in queries:
                for row in connection.execute(sql, (node_id, cap)).fetchall():
                    item = dict(row)
                    item["direction"] = edge_direction
                    try:
                        item["evidence"] = json.loads(str(item.pop("evidence_json")))
                    except (json.JSONDecodeError, TypeError, ValueError):
                        item["evidence"] = {}
                    try:
                        item["metadata"] = json.loads(str(item.pop("metadata_json")))
                    except (json.JSONDecodeError, TypeError, ValueError):
                        item["metadata"] = {}
                    output.append(item)
                    if len(output) >= cap:
                        return output
        return output

