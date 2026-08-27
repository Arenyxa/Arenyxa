from __future__ import annotations

import inspect
import tracemalloc
from pathlib import Path
from types import SimpleNamespace

import pytest

from arenyxa.application.developer_safety import DEVELOPER_TERMS_VERSION, authorization_from_settings
from arenyxa.application.developer_validation import (
    STRESS_PROFILES,
    DeveloperStressSuite,
    DeveloperValidationSuite,
)
from arenyxa.bootstrap import bootstrap


def test_developer_authorization_requires_mode_version_and_acceptance_time() -> None:
    assert not authorization_from_settings(SimpleNamespace()).valid
    assert not authorization_from_settings(
        SimpleNamespace(developer_mode=True, developer_terms_version=0, developer_terms_accepted_at="2026-08-10")
    ).valid
    assert not authorization_from_settings(
        SimpleNamespace(developer_mode=True, developer_terms_version=DEVELOPER_TERMS_VERSION, developer_terms_accepted_at="")
    ).valid
    assert authorization_from_settings(
        SimpleNamespace(
            developer_mode=True,
            developer_terms_version=DEVELOPER_TERMS_VERSION,
            developer_terms_accepted_at="2026-08-10T12:00:00+00:00",
        )
    ).valid


def test_stress_profiles_are_bounded_and_monotonic() -> None:
    assert set(STRESS_PROFILES) == {"quick", "standard", "extreme"}
    for profile in STRESS_PROFILES.values():
        assert profile.worker_levels == tuple(sorted(set(profile.worker_levels)))
        assert profile.worker_levels[0] == 1
        assert profile.worker_levels[-1] <= 64
        assert 1 <= profile.operations_per_level <= 1000
        assert 1.0 <= profile.max_duration_seconds <= 300.0


def test_stress_timing_does_not_run_under_global_tracemalloc() -> None:
    run_source = inspect.getsource(DeveloperStressSuite.run)
    level_source = inspect.getsource(DeveloperStressSuite._run_level)
    assert "tracemalloc.start" not in run_source
    assert level_source.index("tracemalloc.start(1)") < level_source.index("started = time.monotonic()")
    assert level_source.index("tracemalloc.stop()") < level_source.index("started = time.monotonic()")


def test_stress_level_keeps_memory_probe_but_leaves_tracing_disabled(tmp_path: Path) -> None:
    from arenyxa.application.nextgen import SelectorStudio
    from arenyxa.infrastructure.database import SQLiteStore

    store = SQLiteStore(tmp_path / "stress-probe.db")
    store.initialize()
    context = SimpleNamespace(nextgen=SimpleNamespace(selector=SelectorStudio()))
    result = DeveloperStressSuite(context)._run_level(store, tmp_path, workers=2, operations=12)
    assert result.stable
    assert result.operations == 12
    assert result.first_error == ""
    assert result.peak_python_memory_mib > 0
    assert result.to_dict()["memory_probe_peak_mib"] > 0
    assert not tracemalloc.is_tracing()


def test_stress_level_rejects_an_externally_owned_tracemalloc_session(tmp_path: Path) -> None:
    from arenyxa.application.nextgen import SelectorStudio
    from arenyxa.infrastructure.database import SQLiteStore

    store = SQLiteStore(tmp_path / "external-tracer.db")
    store.initialize()
    context = SimpleNamespace(nextgen=SimpleNamespace(selector=SelectorStudio()))
    tracemalloc.start(1)
    try:
        with pytest.raises(RuntimeError, match="tracemalloc to be disabled"):
            DeveloperStressSuite(context)._run_level(store, tmp_path, workers=2, operations=8)
        assert tracemalloc.is_tracing()
    finally:
        tracemalloc.stop()


def test_developer_validation_suite_exercises_isolated_major_subsystems(tmp_path: Path) -> None:
    context = bootstrap(tmp_path / "data")
    try:
        report = DeveloperValidationSuite(context).run_all()
        assert report.healthy, report.to_dict()
        assert report.failed == 0
        assert report.passed >= 14
    finally:
        context.shutdown()


def test_quick_stress_suite_reports_stable_local_ramp(tmp_path: Path) -> None:
    context = bootstrap(tmp_path / "data")
    try:
        report = DeveloperStressSuite(context).run("quick")
        assert report.levels
        assert report.observed_stable_workers >= 1
        assert report.first_unstable_workers is None
        assert all(level.errors == 0 for level in report.levels)
    finally:
        context.shutdown()


def test_terminal_source_contains_both_protected_developer_commands() -> None:
    root = Path(__file__).resolve().parents[1]
    source = "\n".join((root / "src" / "arenyxa" / "presentation" / "pages" / name).read_text(encoding="utf-8") for name in ("tools.py", "tools_terminal_workspace.py", "tools_terminal_execution.py"))
    assert '"test-all"' in source
    assert '"stress-test"' in source
    assert "authorization_from_settings" in source
    assert "_developer_validation_authorized" in source


def test_v68_stress_report_recommends_throughput_sweet_spot() -> None:
    from arenyxa.application.developer_validation import StressLevelResult, StressReport

    levels = [
        StressLevelResult(1, 100, 0, 1.0, 100.0, 10.0, 1.0),
        StressLevelResult(2, 100, 0, 0.6, 166.0, 13.0, 1.1),
        StressLevelResult(4, 100, 0, 0.4, 250.0, 20.0, 1.2),
        StressLevelResult(8, 100, 0, 0.42, 238.0, 60.0, 1.3),
    ]
    report = StressReport("standard", "now", 2.0, levels, "done")
    payload = report.to_dict()
    assert payload["workload"] == "local-persistence-mixed-v2"
    assert payload["peak_throughput_workers"] == 4
    assert payload["recommended_local_workers"] == 4
    assert payload["max_p95_ms"] == 60.0
