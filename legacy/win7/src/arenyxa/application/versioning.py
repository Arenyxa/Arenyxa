from __future__ import annotations

from dataclasses import field
from arenyxa.compat import dataclass
from typing import Any

from arenyxa.domain.models import DatasetRevision


@dataclass(slots=True)
class FieldChange:
    field: str
    before: Any
    after: Any


@dataclass(slots=True)
class RevisionDiff:
    added: dict[str, dict[str, Any]] = field(default_factory=dict)
    removed: dict[str, dict[str, Any]] = field(default_factory=dict)
    modified: dict[str, list[FieldChange]] = field(default_factory=dict)
    schema_added: dict[str, str] = field(default_factory=dict)
    schema_removed: dict[str, str] = field(default_factory=dict)
    schema_changed: dict[str, tuple[str, str]] = field(default_factory=dict)


class DatasetVersionService:
    @staticmethod
    def compare(before: DatasetRevision, after: DatasetRevision) -> RevisionDiff:
        result = RevisionDiff()
        before_keys = set(before.records)
        after_keys = set(after.records)
        result.added = {key: after.records[key] for key in after_keys - before_keys}
        result.removed = {key: before.records[key] for key in before_keys - after_keys}
        for key in before_keys & after_keys:
            old_record = before.records[key]
            new_record = after.records[key]
            changes = []
            for field_name in sorted(set(old_record) | set(new_record)):
                if old_record.get(field_name) != new_record.get(field_name):
                    changes.append(
                        FieldChange(field_name, old_record.get(field_name), new_record.get(field_name))
                    )
            if changes:
                result.modified[key] = changes
        old_fields = set(before.schema)
        new_fields = set(after.schema)
        result.schema_added = {field: after.schema[field] for field in new_fields - old_fields}
        result.schema_removed = {field: before.schema[field] for field in old_fields - new_fields}
        result.schema_changed = {
            field: (before.schema[field], after.schema[field])
            for field in old_fields & new_fields
            if before.schema[field] != after.schema[field]
        }
        return result

    @staticmethod
    def rollback(current: DatasetRevision, target: DatasetRevision) -> DatasetRevision:
        return DatasetRevision(
            dataset_id=current.dataset_id,
            source_run_ids=current.source_run_ids,
            records={key: dict(value) for key, value in target.records.items()},
            parent_revision=current.id,
            label=f"Rollback to {target.id}",
            schema=dict(target.schema),
        )
