from __future__ import annotations

import base64
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.models import CaptureSession, NetworkEvent, RequestSpec, Task
from arenyxa.application import runtime_supervisor as runtime_supervisor_module
from arenyxa.application.resilience_scheduler import ResilienceDrillScheduler
from arenyxa.application.runtime_supervisor import ArenyxaRuntimeSupervisor
from arenyxa.application.traffic_automation import (
    TrafficAction,
    TrafficAutomationEngine,
    TrafficEvent,
)
from arenyxa.enterprise.distributed import DurableDistributedQueue
from arenyxa.enterprise import distributed_queue as distributed_queue_module
from arenyxa.enterprise.distributed_runtime import EnterpriseServerRuntime
from arenyxa.enterprise.runtime_storage import PostgreSQLDistributedRuntimeStorage
from arenyxa.enterprise import worker_agent as worker_agent_module
from arenyxa.enterprise.worker_agent import EnterpriseWorkerAgent
from arenyxa.infrastructure.timebase import StableEpochClock
from arenyxa.infrastructure.capture.controller import CaptureController
from arenyxa.infrastructure.capture.live_intelligence import LiveIntelligencePipeline


def _public_key() -> str:
    return base64.urlsafe_b64encode(bytes(range(32))).decode("ascii").rstrip("=")


def _enqueue(
    queue: DurableDistributedQueue,
    key: str,
    *,
    payload: dict[str, object] | None = None,
    side_effect_mode: str = "idempotent",
    max_attempts: int = 3,
) -> str:
    return queue.enqueue(
        "task.run",
        payload or {"task": key},
        resource_id="resource-long-horizon",
        permission="workflow.execute",
        idempotency_key=key,
        side_effect_mode=side_effect_mode,
        max_attempts=max_attempts,
    )


def _register_worker(queue: DurableDistributedQueue) -> None:
    queue.register_worker("worker-a", _public_key(), {"slots": 1}, max_slots=1)


def _complete(queue: DurableDistributedQueue, key: str, *, side_effect_mode: str = "idempotent") -> str:
    job_id = _enqueue(queue, key, side_effect_mode=side_effect_mode)
    lease = queue.lease_next("worker-a", lease_seconds=15)
    assert lease is not None and lease.job_id == job_id
    queue.start_job(job_id, "worker-a", lease.lease_token)
    queue.complete(job_id, "worker-a", lease.lease_token, {"key": key})
    return job_id


def test_sqlite_lease_time_survives_reopen_with_process_wall_clock_skew(tmp_path: Path) -> None:
    monotonic = [50.0]
    first_clock = StableEpochClock(wall=lambda: 1_000.0, monotonic=lambda: monotonic[0])
    database = tmp_path / "lease-time-domain.sqlite"
    first = DurableDistributedQueue(database, clock=first_clock, lease_grace_seconds=0.0)
    first.register_worker("worker-a", _public_key(), {"slots": 1}, max_slots=1)
    job_id = _enqueue(first, "restart-skew")
    lease = first.lease_next("worker-a", lease_seconds=15)
    assert lease is not None
    first.start_job(job_id, "worker-a", lease.lease_token)

    monotonic[0] = 51.0
    second_clock = StableEpochClock(wall=lambda: 1_300.0, monotonic=lambda: monotonic[0])
    second = DurableDistributedQueue(database, clock=second_clock, lease_grace_seconds=0.0)
    assert second.recover_expired_leases() == 0
    assert second.job(job_id)["state"] == "running"

    monotonic[0] = 70.0
    assert second.recover_expired_leases() == 1
    assert second.job(job_id)["state"] == "queued"


def test_postgresql_lease_fencing_sql_uses_database_wall_clock() -> None:
    storage = PostgreSQLDistributedRuntimeStorage("postgresql://clock-contract.invalid/arenyxa")
    statements = {
        "claim_worker_slot": storage.claim_worker_slot_for_lease_sql(),
        "lease_next": storage.lease_next_fast_sql(),
        "start_job": storage.start_job_fast_sql(),
        "complete": storage.complete_fast_sql(),
    }
    for operation, sql in statements.items():
        normalized = sql.casefold()
        assert "clock_timestamp()" in normalized, operation
        assert "transaction_timestamp()" not in normalized, operation
        assert "statement_timestamp()" not in normalized, operation


def test_terminal_history_recycles_before_max_jobs_without_losing_idempotency(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(distributed_queue_module, "MAX_JOBS", 4)
    queue = DurableDistributedQueue(tmp_path / "terminal-retention.sqlite")
    _register_worker(queue)
    original_ids = [_complete(queue, f"retention-{index}") for index in range(4)]

    fifth_id = _enqueue(queue, "retention-4")
    assert fifth_id not in original_ids
    historical = queue.job_for_idempotency("retention-0")
    assert historical is not None
    assert historical["job_id"] == original_ids[0]
    with queue._connection() as connection:
        assert int(connection.execute("SELECT count(*) FROM distributed_jobs").fetchone()[0]) < 4


def test_retention_preserves_review_required_and_non_idempotent_fences(tmp_path: Path) -> None:
    queue = DurableDistributedQueue(tmp_path / "non-idempotent-retention.sqlite")
    _register_worker(queue)
    failed_id = _enqueue(queue, "non-idempotent-failed", side_effect_mode="non_idempotent", max_attempts=1)
    failed_lease = queue.lease_next("worker-a", lease_seconds=15)
    assert failed_lease is not None and failed_lease.job_id == failed_id
    queue.start_job(failed_id, "worker-a", failed_lease.lease_token)
    assert queue.fail(failed_id, "worker-a", failed_lease.lease_token, "EXPECTED", retryable=False) == "failed"

    review_id = _enqueue(queue, "non-idempotent-review", side_effect_mode="non_idempotent")
    review_lease = queue.lease_next("worker-a", lease_seconds=15)
    assert review_lease is not None and review_lease.job_id == review_id
    queue.start_job(review_id, "worker-a", review_lease.lease_token)
    queue.mark_side_effect_started(review_id, "worker-a", review_lease.lease_token)
    assert queue.handover_lease(review_id, "worker-a", review_lease.lease_token) == "review_required"

    report = queue.retain_terminal_jobs(max_terminal=0, max_idempotent_tombstones=0)
    assert report["jobs_pruned"] == 1
    assert report["idempotent_tombstones_pruned"] == 0
    assert queue.job(review_id) is not None
    assert queue.job_for_idempotency("non-idempotent-failed")["job_id"] == failed_id


def test_legacy_terminal_history_backfills_fence_before_pruning(tmp_path: Path) -> None:
    database = tmp_path / "legacy-terminal.sqlite"
    first = DurableDistributedQueue(database)
    _register_worker(first)
    job_id = _complete(first, "legacy-terminal")
    with first._lock, first._connection() as connection:
        first._begin(connection)
        connection.execute(
            "DELETE FROM distributed_job_idempotency WHERE idempotency_key=?",
            ("legacy-terminal",),
        )
        connection.commit()
    first.close()

    reopened = DurableDistributedQueue(database)
    report = reopened.retain_terminal_jobs(max_terminal=0)
    assert report["jobs_pruned"] == 1
    assert reopened.job_for_idempotency("legacy-terminal")["job_id"] == job_id


def test_incomplete_backfill_disables_destructive_terminal_pruning(tmp_path: Path) -> None:
    queue = DurableDistributedQueue(tmp_path / "failed-backfill.sqlite")
    _register_worker(queue)
    job_id = _complete(queue, "failed-backfill")
    queue._idempotency_backfill_complete = False

    report = queue.retain_terminal_jobs(max_terminal=0)
    assert report["pruning_disabled"] is True
    assert report["jobs_pruned"] == 0
    assert queue.job(job_id) is not None


def test_idempotency_collision_fingerprint_includes_side_effect_mode(tmp_path: Path) -> None:
    queue = DurableDistributedQueue(tmp_path / "mode-fingerprint.sqlite")
    job_id = _enqueue(queue, "mode-fingerprint", side_effect_mode="idempotent")

    with pytest.raises(ArenyxaError) as captured:
        _enqueue(queue, "mode-fingerprint", side_effect_mode="non_idempotent")
    assert captured.value.code == "DISTRIBUTED_IDEMPOTENCY_COLLISION"
    assert queue.job(job_id) is not None


def test_runtime_idempotency_lookup_uses_tombstone_payload_after_history_prune(tmp_path: Path) -> None:
    queue = DurableDistributedQueue(tmp_path / "runtime-tombstone.sqlite")
    _register_worker(queue)
    task = Task("retained-task", [RequestSpec("https://example.test/")])
    payload = {"task": task.to_dict(), "task_snapshot_sha256": task.snapshot_hash()}
    job_id = _enqueue(queue, "runtime-retained", payload=payload)
    lease = queue.lease_next("worker-a", lease_seconds=15)
    assert lease is not None and lease.job_id == job_id
    queue.start_job(job_id, "worker-a", lease.lease_token)
    queue.complete(job_id, "worker-a", lease.lease_token, {"ok": True})
    assert queue.retain_terminal_jobs(max_terminal=0)["jobs_pruned"] == 1

    runtime = object.__new__(EnterpriseServerRuntime)
    runtime.queue = queue
    replayed = runtime.submit_task(
        task,
        resource_id="resource-long-horizon",
        permission="workflow.execute",
        idempotency_key="runtime-retained",
    )
    assert replayed == job_id


def test_postgresql_completion_fast_path_writes_tombstone_without_extra_binds() -> None:
    storage = PostgreSQLDistributedRuntimeStorage("postgresql://retention-contract.invalid/arenyxa")
    sql = storage.complete_fast_sql()
    assert "distributed_job_idempotency" in sql
    assert sql.count("?") == 18


def test_idempotent_retention_remains_bounded_over_many_capacity_cycles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(distributed_queue_module, "MAX_JOBS", 8)
    queue = DurableDistributedQueue(tmp_path / "long-idempotent-retention.sqlite")
    _register_worker(queue)

    for index in range(160):
        _complete(queue, f"long-idempotent-{index}")

    report = queue.retain_terminal_jobs(max_terminal=4, max_idempotent_tombstones=8)
    assert report["jobs_remaining"] <= 4
    assert report["idempotent_tombstones_remaining"] <= 8
    assert report["non_idempotent_tombstones_remaining"] == 0
    assert queue.job_for_idempotency("long-idempotent-159") is not None


def test_non_idempotent_fence_ledger_does_not_consume_job_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(distributed_queue_module, "MAX_JOBS", 8)
    queue = DurableDistributedQueue(tmp_path / "long-non-idempotent-retention.sqlite")
    _register_worker(queue)

    job_ids = [
        _complete(queue, f"long-non-idempotent-{index}", side_effect_mode="non_idempotent")
        for index in range(40)
    ]
    report = queue.retain_terminal_jobs(max_terminal=2, max_idempotent_tombstones=0)
    assert report["jobs_remaining"] <= 2
    assert report["non_idempotent_tombstones_remaining"] == 40
    assert queue.job_for_idempotency("long-non-idempotent-0")["job_id"] == job_ids[0]
    assert (
        _enqueue(queue, "long-non-idempotent-0", side_effect_mode="non_idempotent")
        == job_ids[0]
    )


def test_conflicting_existing_tombstone_fails_terminal_transition_closed(tmp_path: Path) -> None:
    queue = DurableDistributedQueue(tmp_path / "conflicting-tombstone.sqlite")
    _register_worker(queue)
    job_id = _enqueue(queue, "conflicting-tombstone")
    lease = queue.lease_next("worker-a", lease_seconds=15)
    assert lease is not None and lease.job_id == job_id
    queue.start_job(job_id, "worker-a", lease.lease_token)
    with queue._lock, queue._connection() as connection:
        queue._begin(connection)
        connection.execute(
            """INSERT INTO distributed_job_idempotency(
                   idempotency_key,job_id,kind,payload_sha256,resource_id,permission,
                   side_effect_mode,terminal_state,created_at,terminal_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "conflicting-tombstone",
                "job-corrupt-binding",
                "task.run",
                "0" * 64,
                "resource-long-horizon",
                "workflow.execute",
                "idempotent",
                "failed",
                "2026-01-01T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00",
            ),
        )
        connection.commit()

    with pytest.raises(ArenyxaError) as captured:
        queue.complete(job_id, "worker-a", lease.lease_token, {"ok": True})
    assert captured.value.code == "DISTRIBUTED_IDEMPOTENCY_COLLISION"
    assert queue.job(job_id)["state"] == "running"


def test_worker_reconnect_jitter_is_deterministic_desynchronized_and_hard_bounded() -> None:
    delays: list[float] = []
    for worker_index in range(10_000):
        agent = object.__new__(EnterpriseWorkerAgent)
        agent.worker_id = f"worker-{worker_index}"
        delay = agent._reconnect_delay(30.0, worker_index % 32)
        delays.append(delay)
        assert worker_agent_module.MIN_RECONNECT_BACKOFF_SECONDS <= delay
        assert delay <= worker_agent_module.MAX_RECONNECT_BACKOFF_SECONDS
        assert delay == agent._reconnect_delay(30.0, worker_index % 32)

    first_retry_delays = []
    for worker_index in range(32):
        agent = object.__new__(EnterpriseWorkerAgent)
        agent.worker_id = f"simultaneous-worker-{worker_index}"
        first_retry_delays.append(round(agent._reconnect_delay(1.0, 0), 9))
    assert len(set(first_retry_delays)) >= 30
    assert max(delays) <= 30.0


def test_worker_reconnect_jitter_preserves_exponential_base_tendency() -> None:
    agent = object.__new__(EnterpriseWorkerAgent)
    agent.worker_id = "exponential-worker"
    bases = [1.0, 2.0, 4.0, 8.0, 16.0, 25.0, 30.0]
    delays = [agent._reconnect_delay(base, attempt) for attempt, base in enumerate(bases)]
    assert all(delay >= min(base, 25.0) for base, delay in zip(bases, delays))
    assert all(delay <= min(base, 25.0) * 1.2 for base, delay in zip(bases, delays))
    assert min(delays[3:4]) > max(delays[:2])
    assert all(delay <= worker_agent_module.MAX_RECONNECT_BACKOFF_SECONDS for delay in delays)


class _LoopIterations:
    def __init__(self, count: int) -> None:
        self.remaining = count

    def wait(self, _timeout: float) -> bool:
        if self.remaining <= 0:
            return True
        self.remaining -= 1
        return False


def test_runtime_supervisor_reports_once_per_continuous_stall_episode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = ArenyxaRuntimeSupervisor(
        tmp_path / "supervisor", event_loop_block_seconds=1.0
    )
    supervisor._external.heartbeat = lambda *_args, **_kwargs: None
    incidents: list[tuple[str, float]] = []
    supervisor._record_incident = lambda component, blocked, _state: incidents.append((component, blocked))
    supervisor._heartbeats["event-loop"] = (0.0, {"phase": "first"})
    monotonic_values = iter((2.0, 4.0, 8.0))
    monkeypatch.setattr(runtime_supervisor_module.time, "monotonic", lambda: next(monotonic_values))
    supervisor._stop = _LoopIterations(3)  # type: ignore[assignment]
    supervisor._run()

    assert len(incidents) == 1
    assert supervisor._reported_stalls == {"event-loop"}

    monkeypatch.setattr(runtime_supervisor_module.time, "monotonic", lambda: 10.0)
    supervisor.heartbeat("event-loop", {"phase": "recovered"})
    assert supervisor._reported_stalls == set()
    supervisor._heartbeats["event-loop"] = (10.0, {"phase": "second"})
    monkeypatch.setattr(runtime_supervisor_module.time, "monotonic", lambda: 12.0)
    supervisor._stop = _LoopIterations(1)  # type: ignore[assignment]
    supervisor._run()
    assert len(incidents) == 2


def test_runtime_supervisor_bounds_incident_families_including_orphan_stacks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    diagnostics = tmp_path / "supervisor-families"
    diagnostics.mkdir()
    for index in range(40):
        (diagnostics / f"event-loop-block-worker-{index}.stacks.log").write_text("stack", encoding="utf-8")
    supervisor = ArenyxaRuntimeSupervisor(diagnostics)
    monkeypatch.setattr(runtime_supervisor_module, "atomic_write_json", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk")))
    monkeypatch.setattr(runtime_supervisor_module.faulthandler, "dump_traceback", lambda **_kwargs: None)

    supervisor._record_incident("worker", 5.0, {})

    families = {
        path.name.removesuffix(".stacks.log").removesuffix(".json")
        for path in diagnostics.glob("event-loop-block-*")
    }
    assert len(families) <= 32


def test_resilience_scheduler_survives_repeated_failures_and_recovers(
    tmp_path: Path
) -> None:
    scheduler = ResilienceDrillScheduler(SimpleNamespace(paths=SimpleNamespace(root=tmp_path)))
    scheduler._enabled = True
    scheduler._stop = _LoopIterations(3)  # type: ignore[assignment]
    calls = 0

    def run_once() -> dict[str, object]:
        nonlocal calls
        calls += 1
        if calls <= 2:
            raise RuntimeError(f"injected-{calls}")
        return {"state": "healthy"}

    scheduler.run_once = run_once  # type: ignore[method-assign]
    scheduler._loop()
    snapshot = scheduler.snapshot()
    assert calls == 3
    assert snapshot["failure_count"] == 2
    assert snapshot["last_error"] == ""


@pytest.mark.parametrize("callback_fails", (False, True))
def test_traffic_callback_cannot_resurrect_removed_rule_state(
    tmp_path: Path, callback_fails: bool
) -> None:
    engine = TrafficAutomationEngine(tmp_path / f"traffic-race-{callback_fails}.json")
    started = threading.Event()
    release = threading.Event()

    def callback(_payload: object, _parameters: object) -> dict[str, bool]:
        started.set()
        assert release.wait(2.0)
        if callback_fails:
            raise RuntimeError("injected callback failure")
        return {"ok": True}

    engine.register(TrafficAction.ALERT, callback)
    rule_id = engine.add("race", "HTTP_REQUEST", ["ALERT"])["id"]
    worker = threading.Thread(
        target=engine.process,
        args=(TrafficEvent.HTTP_REQUEST, {"host": "example.test"}),
    )
    worker.start()
    assert started.wait(2.0)
    assert engine.remove(rule_id) is True
    release.set()
    worker.join(2.0)
    assert not worker.is_alive()
    with engine._lock:
        assert engine._rules == []
        assert engine._execution_windows == {}
        assert engine._last_executed == {}
        assert engine._success_count == {}
        assert engine._failure_count == {}


def test_traffic_rule_replacement_clears_old_identity_state(tmp_path: Path) -> None:
    engine = TrafficAutomationEngine(tmp_path / "traffic-replacement.json")
    started = threading.Event()
    release = threading.Event()
    calls = 0

    def callback(_payload: object, _parameters: object) -> dict[str, bool]:
        nonlocal calls
        calls += 1
        if calls == 1:
            started.set()
            assert release.wait(2.0)
        return {"ok": True}

    engine.register(TrafficAction.ALERT, callback)
    rule_id = engine.add("before", "HTTP_REQUEST", ["ALERT"], cooldown_seconds=60)["id"]
    worker = threading.Thread(
        target=engine.process,
        args=(TrafficEvent.HTTP_REQUEST, {"host": "example.test"}),
    )
    worker.start()
    assert started.wait(2.0)
    assert engine.update(rule_id, name="after") is not None
    release.set()
    worker.join(2.0)
    assert not worker.is_alive()
    assert engine.execution_stats()[rule_id] == {
        "success": 0,
        "failure": 0,
        "last_executed_monotonic": None,
        "executions_last_minute": 0,
    }
    engine.process(TrafficEvent.HTTP_REQUEST, {"host": "example.test"})
    assert engine.execution_stats()[rule_id]["success"] == 1


def test_traffic_automation_10000_add_execute_remove_cycles_leave_no_state(
    tmp_path: Path
) -> None:
    engine = TrafficAutomationEngine(tmp_path / "traffic-churn.json")
    engine._save = lambda: None  # type: ignore[method-assign]
    engine.register(TrafficAction.ALERT, lambda _payload, _parameters: {"ok": True})
    for index in range(10_000):
        rule_id = engine.add(f"rule-{index}", "HTTP_REQUEST", ["ALERT"])["id"]
        engine.process(TrafficEvent.HTTP_REQUEST, {"host": "example.test"})
        assert engine.remove(rule_id) is True
    with engine._lock:
        assert engine._rules == []
        assert engine._execution_windows == {}
        assert engine._last_executed == {}
        assert engine._success_count == {}
        assert engine._failure_count == {}


class _CaptureAdapter:
    def __init__(self, *, fail_start: bool = False, fail_stop: bool = False) -> None:
        self.fail_start = fail_start
        self.fail_stop = fail_stop

    def start(self, _session: CaptureSession, _emit: object) -> None:
        if self.fail_start:
            raise RuntimeError("injected capture start failure")

    def stop(self) -> None:
        if self.fail_stop:
            raise RuntimeError("injected capture stop failure")

    def pause(self) -> None:
        return None

    def resume(self) -> None:
        return None


def test_capture_finalization_notifies_exactly_once_across_terminal_paths(store) -> None:
    cases = (
        ("normal", _CaptureAdapter(), False, None),
        ("cancel", _CaptureAdapter(), True, None),
        ("start-failure", _CaptureAdapter(fail_start=True), False, "start"),
        ("finalize-failure", _CaptureAdapter(fail_stop=True), False, "stop"),
    )
    for name, adapter, cancelled, failure_phase in cases:
        controller = CaptureController(store, queue_capacity=8, flush_size=1)
        session = CaptureSession(name, CaptureSource.SYSTEM)
        notifications: list[str] = []
        controller.add_finalization_listener(lambda finalized: notifications.append(finalized.id))
        controller.add_finalization_listener(lambda _finalized: (_ for _ in ()).throw(RuntimeError("listener")))
        controller.prepare(session, adapter)
        if failure_phase == "start":
            with pytest.raises(RuntimeError):
                controller.start()
            controller.stop()
        else:
            controller.start()
            if failure_phase == "stop":
                with pytest.raises(ArenyxaError):
                    controller.stop(cancelled=cancelled)
            else:
                controller.stop(cancelled=cancelled)
                controller.stop(cancelled=cancelled)
        assert notifications == [session.id], name


def test_live_intelligence_1000_finalized_sessions_leave_no_retained_state() -> None:
    pipeline = LiveIntelligencePipeline()
    for index in range(1_000):
        session_id = f"retired-session-{index}"
        pipeline.on_capture_batch(
            [
                NetworkEvent(
                    session_id,
                    CaptureSource.SYSTEM,
                    "https",
                    "bidirectional",
                    64,
                    host="example.test",
                )
            ]
        )
        pipeline.retire_session(session_id)
        snapshot = pipeline.live_snapshot(session_id)
        assert snapshot["events"] == 0
        assert snapshot["protocols"] == {}
    with pipeline._lock:
        assert pipeline._alerts == {}
        assert pipeline._event_counts == {}
        assert pipeline._protocol_counts == {}
        assert pipeline._host_counts == {}
        assert pipeline._byte_counts == {}
