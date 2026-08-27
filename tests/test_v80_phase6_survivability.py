from __future__ import annotations

from pathlib import Path
import logging

from arenyxa.application.performance_telemetry import PerformanceTelemetry
from arenyxa.application.reliability import ResourceGovernor, ResourceLimits, ResourceSnapshot
from arenyxa.application.resilience_drills import ResilienceDrillService
from arenyxa.application.survivability import RuntimeSurvivabilityState, SurvivabilityManager
from arenyxa.bootstrap import bootstrap
from arenyxa.infrastructure.observability import configure_logging


class _Probe:
    def __init__(self, samples: list[ResourceSnapshot]) -> None:
        self.samples = list(samples)

    def sample(self, **_kwargs):
        if len(self.samples) > 1:
            return self.samples.pop(0)
        return self.samples[0]


def _resource_sample(*, cpu=10.0, memory=20.0, disk=8 * 1024**3) -> ResourceSnapshot:
    return ResourceSnapshot(
        sampled_at=1.0,
        cpu_percent=cpu,
        memory_percent=memory,
        process_rss_bytes=256 * 1024**2,
        available_memory_bytes=8 * 1024**3,
        disk_free_bytes=disk,
        active_browser_instances=0,
        active_workers=0,
    )


def test_performance_telemetry_reports_bounded_percentiles() -> None:
    telemetry = PerformanceTelemetry(max_metrics=16, max_samples_per_metric=32)
    for value in range(1, 101):
        telemetry.record_latency("proxy.hot_path", value)
    telemetry.increment("proxy.requests", 5)
    telemetry.gauge("proxy.queue_depth", 3)

    snapshot = telemetry.snapshot()
    summary = snapshot["latencies"]["proxy.hot_path"]
    assert summary["count"] == 32
    assert 84 <= summary["p50_ms"] <= 85
    assert 98 <= summary["p95_ms"] <= 99
    assert summary["p99_ms"] >= summary["p95_ms"]
    assert snapshot["counters"]["proxy.requests"] == 5
    assert snapshot["gauges"]["proxy.queue_depth"] == 3.0


def test_survivability_enters_read_only_on_disk_critical_and_recovers(tmp_path: Path) -> None:
    limits = ResourceLimits(
        max_request_concurrency=8,
        max_worker_count=4,
        critical_free_disk_bytes=128 * 1024**2,
        min_free_disk_bytes=512 * 1024**2,
    )
    probe = _Probe([
        _resource_sample(disk=64 * 1024**2),
        _resource_sample(),
    ])
    manager = SurvivabilityManager(
        tmp_path,
        resource_governor=ResourceGovernor(limits),
        resource_probe=probe,
        sample_interval_seconds=60,
    )

    first = manager.refresh()
    assert first["state"] == RuntimeSurvivabilityState.READ_ONLY.value
    assert first["admission"]["noncritical_writes"] is False
    assert first["admission"]["diagnostics"] is True

    second = manager.refresh()
    assert second["state"] == RuntimeSurvivabilityState.NORMAL.value
    assert second["admission"]["noncritical_writes"] is True
    assert (tmp_path / "repair" / "survivability_state.json").is_file()


def test_survivability_component_failure_is_explicit_and_clearable(tmp_path: Path) -> None:
    manager = SurvivabilityManager(tmp_path)
    manager.mark_component("proxy-writer", "degraded", "archive sink failed", {"queue": 12})
    snapshot = manager.snapshot()
    assert snapshot["state"] == "degraded"
    assert snapshot["components"]["proxy-writer"]["metadata"]["queue"] == 12
    manager.clear_component("proxy-writer")
    assert manager.snapshot()["state"] == "normal"


def test_phase6_isolated_drills_cover_contention_config_and_pressure() -> None:
    for operation in (
        ResilienceDrillService._sqlite_lock_backpressure,
        ResilienceDrillService._corrupt_config_fallback,
        ResilienceDrillService._resource_pressure_degradation,
    ):
        passed, detail, metrics = operation()
        assert passed, (detail, metrics)



def test_logging_falls_back_when_primary_log_path_is_unwritable(tmp_path: Path) -> None:
    root = logging.getLogger("arenyxa")
    previous = list(root.handlers)
    for handler in list(root.handlers):
        root.removeHandler(handler)
    blocked = tmp_path / "not-a-directory"
    blocked.write_text("x", encoding="utf-8")
    try:
        configured = configure_logging(blocked / "logs")
        assert configured.handlers
        assert getattr(configured.handlers[0], "arenyxa_sink", "") == "stderr-fallback"
        assert "NotADirectoryError" in getattr(configured.handlers[0], "arenyxa_file_error", "")
    finally:
        for handler in list(root.handlers):
            root.removeHandler(handler)
            try:
                handler.close()
            except Exception:
                pass
        for handler in previous:
            root.addHandler(handler)

def test_phase6_control_plane_wires_survivability_performance_and_drills(tmp_path: Path) -> None:
    context = bootstrap(tmp_path, start_scheduler=False)
    try:
        control = context.control_plane
        session = context.local_control_session
        assert control is not None
        assert session is not None

        survivability = control.survivability_status(session=session, surface="test", refresh=True)
        assert survivability["schema"] == "arenyxa.survivability/v1"
        assert survivability["state"] in {"normal", "resource_pressure", "read_only", "safe_mode", "degraded"}

        performance = control.performance_status(session=session, surface="test")
        assert performance["schema"] == "arenyxa.performance-telemetry/v1"
        assert performance["bounded"] is True

        job = control.submit_resilience_drills(session=session, surface="test", timeout_seconds=30)
        completed = control.wait_job(str(job["id"]), session=session, surface="test", timeout_seconds=40)
        assert completed["state"] == "succeeded"
        result = completed.get("result") or {}
        assert result.get("passed") is True
        assert int(result.get("count", 0)) >= 7
    finally:
        context.shutdown()


def test_survivability_invokes_pressure_handlers(tmp_path: Path) -> None:
    limits = ResourceLimits(
        max_request_concurrency=8,
        max_worker_count=4,
        critical_free_disk_bytes=128 * 1024**2,
        min_free_disk_bytes=512 * 1024**2,
    )
    probe = _Probe([_resource_sample(memory=95.0), _resource_sample()])
    manager = SurvivabilityManager(
        tmp_path,
        resource_governor=ResourceGovernor(limits),
        resource_probe=probe,
        sample_interval_seconds=60,
    )
    seen: list[str] = []
    manager.register_pressure_handler("cache", lambda level: seen.append(level) or {"trimmed": level != "normal"})

    pressured = manager.refresh()
    recovered = manager.refresh()
    assert seen == ["critical", "normal"]
    assert pressured["pressure_actions"]["cache"]["ok"] is True
    assert recovered["state"] == "normal"


def test_job_system_rejects_heavy_work_during_resource_pressure(tmp_path: Path) -> None:
    from arenyxa.domain.errors import ArenyxaError

    context = bootstrap(tmp_path, start_scheduler=False)
    try:
        context.survivability.transition(
            RuntimeSurvivabilityState.RESOURCE_PRESSURE,
            "test pressure",
            component="test",
        )
        try:
            context.job_system.submit(
                "pressure-test",
                lambda execution: {"ok": True},
                session=context.local_control_session,
                capability="logs.read",
                resource="diagnostics:pressure-test",
                surface="test",
                timeout_seconds=5,
                workload="heavy",
            )
        except ArenyxaError as exc:
            assert exc.code == "JOB_ADMISSION_DEGRADED"
        else:
            raise AssertionError("heavy job was admitted under resource pressure")

        accepted = context.job_system.submit(
            "diagnostic-test",
            lambda execution: {"ok": True},
            session=context.local_control_session,
            capability="logs.read",
            resource="diagnostics:pressure-test",
            surface="test",
            timeout_seconds=5,
            workload="diagnostics",
        )
        completed = context.job_system.wait(str(accepted["id"]), 10)
        assert completed["state"] == "succeeded"
        telemetry = context.performance_telemetry.snapshot()
        assert telemetry["counters"]["job.admission_rejected"] >= 1
        assert telemetry["counters"]["job.submitted"] >= 1
    finally:
        context.shutdown()


def test_proxy_persistence_pipeline_is_bounded_and_drains() -> None:
    import time

    from arenyxa.domain.models import utc_now
    from arenyxa.infrastructure.capture.proxy_models import ProxyFlow
    from arenyxa.infrastructure.capture.proxy_persistence import ProxyPersistencePipeline

    class _SlowSink:
        def __init__(self) -> None:
            self.rows: list[str] = []
            self._lock = __import__("threading").Lock()

        def store(self, *args) -> None:
            flow = args[-1]
            time.sleep(0.002)
            with self._lock:
                self.rows.append(flow.id)

    history = _SlowSink()
    archive = _SlowSink()
    pipeline = ProxyPersistencePipeline(history, archive, capacity=16)
    try:
        for sequence in range(80):
            flow = ProxyFlow(
                id=f"flow-{sequence}",
                sequence=sequence,
                started_at=utc_now(),
                client="127.0.0.1",
                scheme="http",
                method="GET",
                host="example.test",
                port=80,
                target="/",
                completed_at=utc_now(),
            )
            pipeline.enqueue("session", flow)
        assert pipeline.flush(10.0) is True
        status = pipeline.status()
        assert status["bounded"] is True
        assert status["max_queue_depth"] <= 16
        assert status["sync_fallbacks"] > 0
        assert len(history.rows) == 80
        assert len(archive.rows) == 80
    finally:
        assert pipeline.close(10.0) is True
