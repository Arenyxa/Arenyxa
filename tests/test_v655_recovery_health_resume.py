from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from arenyxa.application.nextgen import DistributedWorker, DistributedWorkerService
from arenyxa.application.scheduler import ScheduleRule, SchedulerService
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import DatasetRevision, utc_now


def _interrupted_execution(store) -> tuple[str, str]:
    source = DatasetRevision(
        "source_dataset_v655",
        [],
        {"row-1": {"id": 1}},
        schema={"id": "integer"},
        id="source_revision_v655",
    )
    store.save_revision(source)
    output = DatasetRevision(
        "output_dataset_v655",
        [],
        {},
        schema={"id": "integer"},
        id="output_revision_v655",
    )
    store.begin_revision_build(output)
    execution_id = "execution_v655"
    store.begin_workflow_execution(
        {
            "id": execution_id,
            "workflow_id": "workflow_v655",
            "source_revision_id": source.id,
            "output_dataset_id": "output_dataset_v655",
            "output_revision_id": output.id,
            "definition_hash": "a" * 64,
            "started_at": utc_now(),
        },
        ["source", "sink"],
    )
    store.finish_workflow_execution(execution_id, state="interrupted")
    store.set_revision_build_state(output.id, "interrupted")
    return execution_id, output.id


def test_v655_resume_claim_is_atomic_across_competing_callers(store) -> None:
    execution_id, output_revision_id = _interrupted_execution(store)

    def claim(_: int) -> bool:
        return store.claim_workflow_execution_for_resume(execution_id)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(claim, range(16)))

    assert results.count(True) == 1
    assert results.count(False) == 15
    execution = store.get_workflow_execution(execution_id)
    assert execution is not None and execution["state"] == "running"
    revision = store.get_revision_metadata(output_revision_id, include_incomplete=True)
    assert revision is not None and revision["build_state"] == "building"


def test_v655_checkpoint_requires_owned_running_execution(store) -> None:
    execution_id, _ = _interrupted_execution(store)
    with pytest.raises(ArenyxaError) as caught:
        store.checkpoint_workflow_execution(
            execution_id,
            last_input_identity="row-1",
            processed_delta=1,
            output_delta=1,
            error_delta=0,
            node_deltas={},
            checkpoint={"after": "row-1"},
        )
    assert caught.value.code == "WORKFLOW_EXECUTION_STATE_CONFLICT"


def test_v655_scheduler_snapshot_is_locked_bounded_and_callback_free() -> None:
    scheduler = SchedulerService(max_callback_workers=1)
    try:
        rule = ScheduleRule(kind="interval", interval_minutes=30, timezone="UTC")
        scheduler.add(
            "schedule-v655",
            rule,
            lambda: None,
            enabled=True,
            next_run=datetime.now(UTC) + timedelta(minutes=30),
        )
        rows = scheduler.snapshot()
        assert len(rows) == 1
        row = rows[0]
        assert row["id"] == "schedule-v655"
        assert row["kind"] == "interval"
        assert row["enabled"] is True
        assert row["running"] is False
        assert row["callback_pending"] is False
        assert "callback" not in row
        assert set(row) == {
            "id", "kind", "timezone", "enabled", "next_run_at", "running", "callback_pending"
        }
    finally:
        scheduler.stop()


class _Vault:
    def get(self, _name: str):
        return None


def test_v655_worker_health_all_normalizes_partial_outage(monkeypatch, tmp_path: Path) -> None:
    service = DistributedWorkerService(tmp_path / "workers", _Vault())
    workers = [
        DistributedWorker("ok", "OK", "http://127.0.0.1:9011", "worker.ok", enabled=True),
        DistributedWorker("bad", "Bad", "http://127.0.0.1:9012", "worker.bad", enabled=True),
        DistributedWorker("off", "Off", "http://127.0.0.1:9013", "worker.off", enabled=False),
    ]
    monkeypatch.setattr(service, "list", lambda: workers)

    def health(worker_id: str):
        if worker_id == "bad":
            raise TimeoutError("simulated timeout")
        worker = next(item for item in workers if item.id == worker_id)
        return {"worker": {
            "id": worker.id, "name": worker.name, "base_url": worker.base_url,
            "token_secret": worker.token_secret, "enabled": worker.enabled, "weight": worker.weight,
        }, "latency_ms": 1.25, "health": {"status": "ok"}}

    monkeypatch.setattr(service, "health", health)
    rows = service.health_all(max_workers=8)
    by_id = {row["worker"]["id"]: row for row in rows}
    assert set(by_id) == {"ok", "bad", "off"}
    assert by_id["ok"]["online"] is True and by_id["ok"]["error"] is None
    assert by_id["bad"]["online"] is False and "TimeoutError" in str(by_id["bad"]["error"])
    assert by_id["off"]["online"] is False and by_id["off"]["error"] == "disabled"


def test_v655_recovery_page_and_locale_contracts_are_registered() -> None:
    root = Path(__file__).resolve().parents[1]
    main_window = (root / "src/arenyxa/presentation/main_window.py").read_text(encoding="utf-8")
    registry = (root / "src/arenyxa/presentation/main_window_registry.py").read_text(encoding="utf-8")
    recovery_page = (root / "src/arenyxa/presentation/pages/recovery.py").read_text(encoding="utf-8")
    catalog = (root / "src/arenyxa/presentation/i18n_catalog.py").read_text(encoding="utf-8")
    language = (root / "src/arenyxa/presentation/language.py").read_text(encoding="utf-8")
    assert "RecoveryCenterPage" in main_window
    assert '"nav.recovery"' in registry
    assert "SelectionMode.SingleSelection" in recovery_page
    assert "claim_workflow_execution_for_resume" in (root / "src/arenyxa/infrastructure/database_workflows.py").read_text(encoding="utf-8")
    for phrase in (
        "Recovery & Health Center",
        "Resume Selected",
        "Resumable workflows",
        "Workflow resume completed",
        "Recovery history is unavailable",
    ):
        assert phrase in catalog
        assert phrase in language
