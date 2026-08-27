from pathlib import Path

import pytest

from arenyxa.application.reliability import (
    BoundedPerformanceHistory,
    FailureCategory,
    PerformanceIntelligence,
    PerformanceSample,
    PreflightEstimator,
    PreflightRequest,
    RecoveryTaxonomy,
    ResourceGovernor,
    ResourceLeasePool,
    ResourceLimits,
    ResourceSnapshot,
)
from arenyxa.application.runner import RunOrchestrator, _AdaptiveRequestController, _DynamicRequestGate
from arenyxa.application.workflow_test_lab import WorkflowFixture, WorkflowTestLab
from arenyxa.application.workflows import WorkflowEngine
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import RequestSpec, Task, Workflow, WorkflowNode
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.plugins import PluginHealthRegistry, SandboxBudget


def snap(*, cpu=20.0, memory=30.0, disk=4 * 1024**3, browsers=0, workers=0):
    return ResourceSnapshot(
        sampled_at=1.0,
        cpu_percent=cpu,
        memory_percent=memory,
        process_rss_bytes=128 * 1024**2,
        available_memory_bytes=8 * 1024**3,
        disk_free_bytes=disk,
        active_browser_instances=browsers,
        active_workers=workers,
    )


def test_recovery_taxonomy_has_all_six_fail_closed_families() -> None:
    cases = {
        FailureCategory.TRANSIENT: RecoveryTaxonomy.classify(TimeoutError("timeout")),
        FailureCategory.RECOVERABLE: RecoveryTaxonomy.classify(error_code="RESOURCE_PRESSURE"),
        FailureCategory.CONFIGURATION: RecoveryTaxonomy.classify(ValueError("bad config")),
        FailureCategory.PERMISSION: RecoveryTaxonomy.classify(PermissionError("denied")),
        FailureCategory.CORRUPTION: RecoveryTaxonomy.classify(RuntimeError("checksum mismatch")),
        FailureCategory.FATAL: RecoveryTaxonomy.classify(RuntimeError("unexpected invariant")),
    }
    assert set(cases) == set(FailureCategory)
    for expected, diagnosis in cases.items():
        assert diagnosis.category is expected
    assert RecoveryTaxonomy.may_retry(cases[FailureCategory.TRANSIENT], attempt=0, max_attempts=2, idempotent=True)
    assert not RecoveryTaxonomy.may_retry(cases[FailureCategory.TRANSIENT], attempt=0, max_attempts=2, idempotent=False)
    assert not RecoveryTaxonomy.may_retry(cases[FailureCategory.FATAL], attempt=0, max_attempts=2, idempotent=True)


def test_resource_governor_backoff_is_downward_and_recovery_has_hysteresis() -> None:
    limits = ResourceLimits(max_request_concurrency=12, max_worker_count=6, max_browser_instances=4)
    governor = ResourceGovernor(limits)
    warning = governor.evaluate(snap(cpu=91.0))
    assert warning.pressure == "warning"
    assert 1 <= warning.request_ceiling <= 6
    assert 1 <= warning.worker_ceiling <= 3
    backed_off = warning.request_ceiling
    assert governor.evaluate(snap()).request_ceiling == backed_off
    assert governor.evaluate(snap()).request_ceiling == backed_off
    recovered = governor.evaluate(snap())
    assert recovered.request_ceiling == min(12, backed_off + 1)


def test_disk_critical_stops_new_runs_and_browser_admission() -> None:
    governor = ResourceGovernor(
        ResourceLimits(min_free_disk_bytes=512 * 1024**2, critical_free_disk_bytes=128 * 1024**2)
    )
    decision = governor.evaluate(snap(disk=64 * 1024**2))
    assert decision.pressure == "critical"
    assert decision.admit_new_runs is False
    assert decision.admit_new_browser is False
    assert decision.browser_ceiling == 0
    assert "disk-critical" in decision.reasons



def test_run_orchestrator_blocks_before_persisting_when_disk_is_critical(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "phase3.sqlite3")
    store.initialize()
    governor = ResourceGovernor(ResourceLimits(critical_free_disk_bytes=128 * 1024**2))

    class CriticalProbe:
        def sample(self, **_kwargs):
            return snap(disk=64 * 1024**2)

    runner = RunOrchestrator(
        store,
        max_workers=1,
        request_workers=2,
        per_host_workers=1,
        resource_governor=governor,
        resource_probe=CriticalProbe(),
    )
    task = Task("blocked", [RequestSpec("https://example.com")])
    try:
        with pytest.raises(ArenyxaError) as exc_info:
            runner.submit(task)
        assert exc_info.value.code == "RESOURCE_PREFLIGHT_BLOCKED"
        assert store.list_runs(limit=10) == []
    finally:
        runner.shutdown(wait=True)


def test_manual_and_adaptive_request_limits_never_raise_resource_ceiling() -> None:
    gate = _DynamicRequestGate(16)
    controller = _AdaptiveRequestController(gate, 16, enabled=True)
    controller.set_resource_ceiling(3)
    assert gate.limit() <= 3
    assert controller.set_manual(12) == 3
    assert gate.limit() == 3
    controller.set_resource_ceiling(10)
                                                                                                   
    assert gate.limit() <= 10
    assert controller.set_manual(4) == 4
    controller.set_resource_ceiling(2)
    assert gate.limit() == 2
    assert controller.enable_auto() <= 2


def test_browser_lease_pool_never_exceeds_dynamic_limit() -> None:
    pool = ResourceLeasePool(3)
    a = pool.acquire()
    b = pool.acquire()
    assert pool.active_count() == 2
    pool.set_limit(2)
    assert pool.try_acquire() is None
    a.release()
    lease = pool.try_acquire()
    assert lease is not None
    lease.release()
    b.release()
    assert pool.active_count() == 0


def test_preflight_estimator_reports_capacity_risk_before_execution() -> None:
    estimator = PreflightEstimator(ResourceLimits())
    request = PreflightRequest(
        target_count=5_000,
        average_response_bytes=2 * 1024**2,
        browser_ratio=0.5,
        request_concurrency=16,
        expected_latency_ms=1000,
    )
    estimate = estimator.estimate(
        request,
        resource_snapshot=ResourceSnapshot(
            sampled_at=1.0,
            cpu_percent=20,
            memory_percent=30,
            process_rss_bytes=100 * 1024**2,
            available_memory_bytes=2 * 1024**3,
            disk_free_bytes=3 * 1024**3,
        ),
    )
    assert estimate.risk_level == "high"
    assert "large-target-set" in estimate.risks
    assert "browser-heavy" in estimate.risks
    assert "disk-capacity" in estimate.risks or "memory-capacity" in estimate.risks
    assert estimate.estimated_disk_bytes_high >= estimate.estimated_disk_bytes_low
    assert estimate.estimated_seconds_high >= estimate.estimated_seconds_low


def test_performance_intelligence_explains_rate_cpu_disk_and_browser_pressure() -> None:
    samples = [
        PerformanceSample(
            timestamp=float(i), completed=1, retries=1, http_429=1,
            latency_ms=2200, local_processing_ms=40, cpu_percent=94, memory_percent=84,
            disk_free_bytes=200 * 1024**2, request_limit=4, request_active=4,
            browser_active=2, browser_limit=2,
        )
        for i in range(1, 8)
    ]
    explanation = PerformanceIntelligence().explain(samples)
    observed = {explanation.primary, *explanation.contributors}
    assert explanation.primary != "healthy-or-unexplained"
    assert observed & {"rate-limit", "cpu-pressure", "disk-pressure", "browser-saturation"}
    assert explanation.throughput_per_second > 0


def test_performance_history_is_strictly_bounded_for_long_runs() -> None:
    history = BoundedPerformanceHistory(32)
    for i in range(10_000):
        history.append(PerformanceSample(timestamp=float(i), completed=1))
    assert len(history.snapshot()) == 32
    assert history.snapshot()[0].timestamp == 9968.0


def test_workflow_test_lab_dry_run_mock_http_and_golden_regression_are_reproducible() -> None:
    engine = WorkflowEngine()
    lab = WorkflowTestLab(engine)
    source = WorkflowNode("source", {}, id="source", next_ids=["http"])
    http = WorkflowNode("http", {"mock_key": "profile"}, id="http", next_ids=["sink"])
    sink = WorkflowNode("sink", {}, id="sink")
    workflow = Workflow("fixture", [source, http, sink])
    assert lab.dry_run(workflow).valid

    expected = ({"id": 1, "name": "Arenyxa"},)
    fixture = WorkflowFixture(
        "mocked",
        inputs=({"id": 1},),
        mock_http={"profile": {"name": "Arenyxa"}},
        expected_outputs=expected,
    )
    first = lab.run_fixture(workflow, fixture)
    second = lab.run_fixture(workflow, fixture)
    assert first.passed and second.passed
    assert first.output_hash == second.output_hash == lab.golden_hash(expected)

    no_network = lab.run_fixture(workflow, WorkflowFixture("no-real-network", inputs=({"id": 1},)))
    assert not no_network.passed
    assert no_network.error_count == 1


def test_workflow_test_lab_detects_golden_output_drift() -> None:
    lab = WorkflowTestLab(WorkflowEngine())
    workflow = Workflow("simple", [WorkflowNode("map", {"constants": {"value": 2}}, id="map")])
    result = lab.run_fixture(
        workflow,
        WorkflowFixture("golden", inputs=({"value": 1},), expected_outputs=({"value": 1},)),
    )
    assert result.passed is False
    assert any(item.startswith("golden-output-mismatch") for item in result.differences)


def test_plugin_health_circuit_breaker_and_budgets_are_explicit() -> None:
    registry = PluginHealthRegistry(failure_threshold=3, cooldown_seconds=5)
    for _ in range(3):
        registry.failure("demo", "PLUGIN_TIMEOUT")
    with pytest.raises(ArenyxaError) as exc_info:
        registry.allow("demo")
    assert exc_info.value.code == "PLUGIN_HEALTH_QUARANTINED"
    health = registry.snapshot()[0]
    assert health.state == "quarantined"
    assert health.failure_count == 3
    budget = SandboxBudget()
    assert budget.timeout_seconds > 0
    assert budget.max_memory_mb > 0
    assert budget.max_input_bytes > 0
    assert budget.max_output_bytes > 0
    assert budget.max_processes == 1


def test_settings_and_personalization_are_separate_navigation_surfaces() -> None:
    root = Path(__file__).resolve().parents[1]
    settings_source = (root / "src/arenyxa/presentation/pages/settings.py").read_text(encoding="utf-8")
    personalization_source = (root / "src/arenyxa/presentation/pages/personalization.py").read_text(encoding="utf-8")
    registry_source = (root / "src/arenyxa/presentation/main_window_registry.py").read_text(encoding="utf-8")
    settings_class = settings_source.split("class SettingsPage", 1)[1].split("class AboutPage", 1)[0]
    assert "ThemePreviewCard(" not in settings_class
    assert 'PageHeader("设置"' in settings_class
    assert 'PageHeader("个性化"' in personalization_source
    assert "ThemePreviewCard(" in personalization_source
    assert '("personalization", "✧", "nav.personalization"' in registry_source


def test_startup_visual_implementation_matches_current_approved_baseline() -> None:
    import hashlib

    root = Path(__file__).resolve().parents[1]
    expected = {
        "src/arenyxa/presentation/startup_splash.py": "46141636071f7adedabbb8ddacc7faaa9381bfdbc059712a72a85ab6ebea0b33",
        "src/arenyxa/presentation/startup_motion_math.py": "04488fec32a69741b93dcf5b5806108acc3f265f1ea7cdf2930552190bca77ae",
    }
    for relative, digest in expected.items():
        assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == digest
