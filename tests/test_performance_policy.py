from __future__ import annotations

from arenyxa.config import AppSettings
from arenyxa.performance import DeviceCapability, PerformancePolicy


def test_default_settings_use_auto_performance_mode() -> None:
    settings = AppSettings()
    assert settings.performance_mode == "auto"
    assert settings.adaptive_request_concurrency is True


def test_auto_mode_uses_device_recommendation(monkeypatch) -> None:
    monkeypatch.setattr(
        "arenyxa.performance.detect_device_capability",
        lambda: DeviceCapability(logical_cpus=4, memory_gb=8.0, recommended_mode="efficiency"),
    )
    policy = PerformancePolicy.resolve("auto", configured_workers=8)
    assert policy.mode == "efficiency"
    assert policy.runner_workers == 2
    assert policy.request_workers == 4
    assert policy.per_host_workers == 2
    assert policy.animation_hz_cap == 30
    assert policy.network_event_limit == 5_000
    assert policy.glass_specular is False


def test_explicit_quality_preserves_visual_budget(monkeypatch) -> None:
    monkeypatch.setattr(
        "arenyxa.performance.detect_device_capability",
        lambda: DeviceCapability(logical_cpus=4, memory_gb=8.0, recommended_mode="efficiency"),
    )
    policy = PerformancePolicy.resolve(
        "quality", configured_workers=6, configured_request_workers=20, configured_per_host_workers=7
    )
    assert policy.mode == "high"
    assert policy.runner_workers == 6
    assert policy.request_workers == 20
    assert policy.per_host_workers == 7
    assert policy.animation_hz_cap >= 120
    assert policy.glass_specular is True


def test_efficiency_keeps_features_but_bounds_memory_and_background_work(monkeypatch) -> None:
    monkeypatch.setattr(
        "arenyxa.performance.detect_device_capability",
        lambda: DeviceCapability(logical_cpus=16, memory_gb=32.0, recommended_mode="high"),
    )
    policy = PerformancePolicy.resolve("efficiency", configured_workers=64)
    assert policy.runner_workers == 2
    assert policy.request_workers <= 4
    assert policy.per_host_workers <= 2
    assert policy.background_workers == 2
    assert policy.capture_queue_capacity <= 10_000
    assert policy.result_page_size <= 150
    assert policy.network_history_limit <= 5_000


def test_legacy_balanced_setting_downshifts_on_constrained_device(monkeypatch) -> None:
    monkeypatch.setattr(
        "arenyxa.performance.detect_device_capability",
        lambda: DeviceCapability(logical_cpus=4, memory_gb=8.0, recommended_mode="efficiency"),
    )
    policy = PerformancePolicy.resolve("balanced", configured_workers=4)
    assert policy.mode == "efficiency"
    assert policy.runner_workers == 2


def test_concurrency_settings_are_clamped_and_per_host_never_exceeds_global(tmp_path) -> None:
    import json

    path = tmp_path / "settings.json"
    path.write_text(
        json.dumps({"request_concurrency": 3, "per_host_concurrency": 99}),
        encoding="utf-8",
    )
    settings = AppSettings.load(path)
    assert settings.request_concurrency == 3
    assert settings.per_host_concurrency == 3

    path.write_text(
        json.dumps({"request_concurrency": 999, "per_host_concurrency": -5}),
        encoding="utf-8",
    )
    settings = AppSettings.load(path)
    assert settings.request_concurrency == 64
    assert settings.per_host_concurrency == 1


def test_adaptive_request_concurrency_setting_is_type_safe(tmp_path) -> None:
    import json

    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"adaptive_request_concurrency": False}), encoding="utf-8")
    assert AppSettings.load(path).adaptive_request_concurrency is False

    path.write_text(json.dumps({"adaptive_request_concurrency": "yes"}), encoding="utf-8")
    assert AppSettings.load(path).adaptive_request_concurrency is True
