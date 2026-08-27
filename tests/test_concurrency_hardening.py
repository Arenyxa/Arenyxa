from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from arenyxa.application.runner import RunOrchestrator, _AdaptiveRequestController, _DynamicRequestGate
from arenyxa.domain.enums import TaskStatus
from arenyxa.domain.models import RequestSpec, Task
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.http_client import FetchResponse
from arenyxa.performance import DeviceCapability, PerformancePolicy


def test_global_request_admission_bounds_multi_run_futures(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "admission.db")
    store.initialize()
    release = threading.Event()
    orchestrator = RunOrchestrator(
        store,
        max_workers=4,
        request_workers=4,
        per_host_workers=4,
        progress_interval_ms=500,
        result_write_batch_size=16,
    )

    def fetch(spec, token, on_attempt=None):
        del token, on_attempt
        release.wait(timeout=5.0)
        index = int(spec.url.rsplit("/", 1)[1])
        payload = json.dumps({"value": index}).encode("utf-8")
        return FetchResponse(spec.url, spec.url, 200, {}, payload, 0.1, "utf-8", "application/json")

    orchestrator.fetcher.fetch = fetch
    handles = []
    try:
        for run_index in range(4):
            task = Task(
                f"admission-{run_index}",
                [RequestSpec(f"http://host-{run_index}.test/{i}") for i in range(20)],
                status=TaskStatus.READY,
            )
            store.save_task(task)
            handles.append(orchestrator.submit(task))

        deadline = time.monotonic() + 3.0
        observed = 0
        while time.monotonic() < deadline:
            snapshot = orchestrator.concurrency_snapshot()
            observed = max(observed, snapshot["active_requests"])
            if observed >= 4:
                break
            time.sleep(0.01)
        snapshot = orchestrator.concurrency_snapshot()
        assert observed == 4
        assert snapshot["active_requests"] <= snapshot["request_queue_bound"] == 4
    finally:
        release.set()
        for handle in handles:
            handle.future.result(timeout=10.0)
        orchestrator.shutdown(wait_for_runs=True)


def test_high_policy_batches_more_results_without_exceeding_bound(monkeypatch) -> None:
    monkeypatch.setattr(
        "arenyxa.performance.detect_device_capability",
        lambda: DeviceCapability(logical_cpus=32, memory_gb=32.0, recommended_mode="high"),
    )
    policy = PerformancePolicy.resolve(
        "quality", configured_workers=8, configured_request_workers=20, configured_per_host_workers=6
    )
    assert policy.result_write_batch_size == 192
    assert 96 <= policy.result_write_batch_size <= 192
    assert policy.runner_progress_interval_ms >= 150


def test_sqlite_connection_uses_burst_friendly_wal_settings(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "wal.db")
    store.initialize()
    with store.connect() as connection:
        assert int(connection.execute("PRAGMA wal_autocheckpoint").fetchone()[0]) == 4096
        assert int(connection.execute("PRAGMA cache_size").fetchone()[0]) == -8192
        assert int(connection.execute("PRAGMA temp_store").fetchone()[0]) == 2


def test_live_request_budget_is_process_wide_across_runs(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "live-budget.db")
    store.initialize()
    release = threading.Event()
    orchestrator = RunOrchestrator(
        store,
        max_workers=4,
        request_workers=4,
        per_host_workers=4,
        progress_interval_ms=500,
        result_write_batch_size=16,
    )
    assert orchestrator.set_request_limit(2) == 2

    def fetch(spec, token, on_attempt=None):
        del token, on_attempt
        release.wait(timeout=5.0)
        payload = json.dumps({"url": spec.url}).encode("utf-8")
        return FetchResponse(spec.url, spec.url, 200, {}, payload, 0.1, "utf-8", "application/json")

    orchestrator.fetcher.fetch = fetch
    handles = []
    try:
        for run_index in range(4):
            task = Task(
                f"budget-{run_index}",
                [RequestSpec(f"http://budget-{run_index}.test/{i}") for i in range(8)],
                status=TaskStatus.READY,
            )
            store.save_task(task)
            handles.append(orchestrator.submit(task))

        deadline = time.monotonic() + 3.0
        observed = 0
        while time.monotonic() < deadline:
            snapshot = orchestrator.concurrency_snapshot()
            observed = max(observed, snapshot["active_requests"])
            if observed >= 2:
                break
            time.sleep(0.01)
        snapshot = orchestrator.concurrency_snapshot()
        assert observed == 2
        assert snapshot["active_requests"] <= 2
        assert snapshot["request_limit"] == 2

                                                                                   
        assert orchestrator.set_request_limit(4) == 4
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if orchestrator.concurrency_snapshot()["active_requests"] >= 4:
                break
            time.sleep(0.01)
        assert orchestrator.concurrency_snapshot()["active_requests"] == 4
    finally:
        release.set()
        for handle in handles:
            handle.future.result(timeout=10.0)
        orchestrator.shutdown(wait_for_runs=True)


def test_lowering_live_budget_drains_without_rebound(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "budget-drain.db")
    store.initialize()
    permits = threading.Semaphore(0)
    active_lock = threading.Lock()
    active = 0
    orchestrator = RunOrchestrator(
        store,
        max_workers=2,
        request_workers=4,
        per_host_workers=4,
        progress_interval_ms=500,
        result_write_batch_size=16,
    )

    def fetch(spec, token, on_attempt=None):
        nonlocal active
        del token, on_attempt
        with active_lock:
            active += 1
        try:
            permits.acquire(timeout=5.0)
            payload = json.dumps({"url": spec.url}).encode("utf-8")
            return FetchResponse(spec.url, spec.url, 200, {}, payload, 0.1, "utf-8", "application/json")
        finally:
            with active_lock:
                active -= 1

    orchestrator.fetcher.fetch = fetch
    handles = []
    try:
        for run_index in range(2):
            task = Task(
                f"drain-{run_index}",
                [RequestSpec(f"http://drain-{run_index}.test/{i}") for i in range(8)],
                status=TaskStatus.READY,
            )
            store.save_task(task)
            handles.append(orchestrator.submit(task))

        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if orchestrator.concurrency_snapshot()["active_requests"] == 4:
                break
            time.sleep(0.01)
        assert orchestrator.concurrency_snapshot()["active_requests"] == 4

        assert orchestrator.set_request_limit(2) == 2
                                                                                           
                                                                            
        permits.release()
        permits.release()
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if orchestrator.concurrency_snapshot()["active_requests"] <= 2:
                break
            time.sleep(0.01)
        assert orchestrator.concurrency_snapshot()["active_requests"] <= 2
        for _ in range(30):
            assert orchestrator.concurrency_snapshot()["active_requests"] <= 2
            time.sleep(0.01)
    finally:
                                                                                                
        for _ in range(32):
            permits.release()
        for handle in handles:
            handle.future.result(timeout=10.0)
        orchestrator.shutdown(wait_for_runs=True)


def test_low_global_budget_is_fair_between_runs(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "fair-budget.db")
    store.initialize()
    permits = threading.Semaphore(0)
    order: list[str] = []
    order_lock = threading.Lock()
    orchestrator = RunOrchestrator(
        store,
        max_workers=2,
        request_workers=4,
        per_host_workers=4,
        progress_interval_ms=500,
        result_write_batch_size=16,
    )
    orchestrator.set_request_limit(1)

    def fetch(spec, token, on_attempt=None):
        del token, on_attempt
        with order_lock:
            order.append(spec.url)
        permits.acquire(timeout=5.0)
        payload = json.dumps({"url": spec.url}).encode("utf-8")
        return FetchResponse(spec.url, spec.url, 200, {}, payload, 0.1, "utf-8", "application/json")

    orchestrator.fetcher.fetch = fetch
    tasks = []
    handles = []
    try:
        for run_index in range(2):
            task = Task(
                f"fair-{run_index}",
                [RequestSpec(f"http://fair-{run_index}.test/{i}") for i in range(6)],
                status=TaskStatus.READY,
            )
            store.save_task(task)
            tasks.append(task)
            handles.append(orchestrator.submit(task))

        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            snapshot = orchestrator.concurrency_snapshot()
            if snapshot["active_requests"] == 1 and snapshot["request_waiting_runs"] >= 1:
                break
            time.sleep(0.01)
        assert orchestrator.concurrency_snapshot()["request_waiting_runs"] >= 1

                                                                                           
                                                                             
        permits.release()
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            with order_lock:
                if len(order) >= 2:
                    break
            time.sleep(0.01)
        with order_lock:
            assert len(order) >= 2
            first_host = order[0].split("/")[2]
            second_host = order[1].split("/")[2]
        assert first_host != second_host
    finally:
        for _ in range(32):
            permits.release()
        for handle in handles:
            handle.future.result(timeout=10.0)
        orchestrator.shutdown(wait_for_runs=True)


def test_v68_adaptive_request_controller_grows_then_backs_off() -> None:
    gate = _DynamicRequestGate(8)
    controller = _AdaptiveRequestController(gate, 8, enabled=True)
    assert gate.limit() == 4
    assert controller.snapshot()["mode"] == "adaptive"

    for _ in range(24):
        controller.observe(1.0, saturated=True)
    assert gate.limit() == 5

    for _ in range(24):
        controller.observe(1.0, saturated=True)
    assert gate.limit() == 6

    for _ in range(24):
        controller.observe(20.0, saturated=True)
    assert gate.limit() < 6
    assert gate.limit() >= 4
    assert controller.snapshot()["last_decision"] == "backoff"


def test_v68_manual_request_budget_suspends_auto_until_reenabled() -> None:
    gate = _DynamicRequestGate(8)
    controller = _AdaptiveRequestController(gate, 8, enabled=True)
    assert controller.set_manual(7) == 7
    assert controller.snapshot()["mode"] == "manual"
    for _ in range(96):
        controller.observe(100.0, saturated=True)
    assert gate.limit() == 7

    assert controller.enable_auto() == 4
    assert controller.snapshot()["mode"] == "adaptive"


def test_v68_runner_starts_adaptive_request_budget_at_four(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "adaptive-start.db")
    store.initialize()
    runner = RunOrchestrator(
        store,
        max_workers=4,
        request_workers=8,
        per_host_workers=4,
        adaptive_request_concurrency=True,
    )
    try:
        snapshot = runner.concurrency_snapshot()
        assert snapshot["request_workers"] == 8
        assert snapshot["request_limit"] == 4
        assert snapshot["request_limit_mode"] == "adaptive"
        assert snapshot["request_adaptive_floor"] == 4
        assert snapshot["request_adaptive_ceiling"] == 8
    finally:
        runner.shutdown(wait_for_runs=True)


def test_v68_disabled_adaptive_request_budget_preserves_configured_limit(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "adaptive-disabled.db")
    store.initialize()
    runner = RunOrchestrator(
        store,
        max_workers=4,
        request_workers=8,
        per_host_workers=4,
        adaptive_request_concurrency=False,
    )
    try:
        snapshot = runner.concurrency_snapshot()
        assert snapshot["request_limit"] == 8
        assert snapshot["request_limit_mode"] == "manual"
    finally:
        runner.shutdown(wait_for_runs=True)


def test_adaptive_request_controller_backs_off_failed_outcome_without_timing() -> None:
    gate = _DynamicRequestGate(8)
    controller = _AdaptiveRequestController(gate, 8, enabled=True)
    for _ in range(24):
        controller.observe(1.0, saturated=True)
    assert gate.limit() == 5

    controller.observe(None, saturated=True, failed=True)

    assert gate.limit() == 4
    assert controller.snapshot()["last_decision"] == "failure-backoff"
