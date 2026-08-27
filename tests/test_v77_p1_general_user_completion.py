from __future__ import annotations

from pathlib import Path

import pytest

from arenyxa.application.experience import apply_experience_profile
from arenyxa.application.general_user import (
    GeneralUserIntentRouter,
    RuntimeCapabilityService,
    WORKFLOWS,
    is_general_user,
    summarize_network_events,
)
from arenyxa.config import AppSettings
from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine
from arenyxa.infrastructure.capture.packet_lab import OfflinePacketLab


def test_simple_mode_is_only_personal_profile() -> None:
    settings = AppSettings()
    apply_experience_profile(settings, "personal")
    assert is_general_user(settings) is True
    apply_experience_profile(settings, "power")
    assert is_general_user(settings) is False
    apply_experience_profile(settings, "professional")
    assert is_general_user(settings) is False
    apply_experience_profile(settings, "developer")
    assert is_general_user(settings) is False


def test_general_user_has_eight_task_oriented_workflows() -> None:
    assert {row.id for row in WORKFLOWS} == {
        "live_network", "capture_traffic", "analyze_pcap", "security_check",
        "debug_api", "inspect_website", "diagnose_network", "open_project",
    }
    assert all(row.steps for row in WORKFLOWS)


@pytest.mark.parametrize(
    ("query", "workflow_id"),
    [
        ("帮我分析这个 PCAP", "analyze_pcap"),
        ("开始抓包", "capture_traffic"),
        ("看看电脑连接了哪些服务器", "live_network"),
        ("检查 DNS 隧道和异常连接", "security_check"),
        ("我需要调试 API", "debug_api"),
        ("分析这个网站的页面结构", "inspect_website"),
        ("网络连不上帮我诊断", "diagnose_network"),
        ("打开 Arenyxa project", "open_project"),
    ],
)
def test_local_intent_router(query: str, workflow_id: str) -> None:
    resolved = GeneralUserIntentRouter().resolve(query)
    assert resolved is not None
    assert resolved.id == workflow_id


def test_general_user_summary_is_conservative_and_risk_ranked() -> None:
    rows = [
        {
            "protocol": "http", "host": "example.test", "url": "http://example.test/login",
            "request_headers": {"Authorization": "redacted"}, "sensitivity_flags": ["credential"],
            "status": 200, "metadata": {},
        },
        {
            "protocol": "tls", "host": "legacy.test", "url": "https://legacy.test/",
            "request_headers": {}, "status": 200, "metadata": {"tls_version": "TLSv1.0"},
        },
    ]
    summary = summarize_network_events(rows)
    assert summary.risk in {"Medium", "High"}
    assert summary.score >= 45
    assert summary.event_count == 2
    assert any("明文" in finding.title for finding in summary.findings)


def test_runtime_capability_service_exposes_explicit_fallbacks() -> None:
    caps = RuntimeCapabilityService().snapshot()
    assert caps["packet.native"].state == "native"
    assert caps["packet.native"].backend == "arenyxa-native"
    assert caps["packet.deep"].fallback == "arenyxa-native"
    assert caps["mitm.external"].fallback == "proxy+builtin-analysis"
    assert caps["browser.automation"].fallback == "http+har"


def test_broken_external_tshark_falls_back_to_native_for_unfiltered_pcap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    artifact = OfflinePacketLab.dns_query(
        src_ip="10.0.0.1", dst_ip="8.8.8.8", name="example.com", src_port=53000, dst_port=53,
    )
    capture = OfflinePacketLab.write_pcap(tmp_path / "sample.pcap", artifact, linktype=101, timestamp=1.0)
    engine = PacketAnalysisEngine(executable="/fake/tshark")

    def fail(*_args, **_kwargs):
        engine._external_runtime_failed = True
        raise ArenyxaError("PACKET_ANALYSIS_COMMAND_FAILED", "simulated incompatible tshark", domain="CAPTURE")

    monkeypatch.setattr(engine, "_run_tshark", fail)
    rows = engine.packet_summaries(capture, limit=10)
    assert len(rows) == 1
    assert rows[0].metadata.get("native_decode") is True
    assert engine.available is False


def test_simple_mode_ui_is_wired_without_changing_professional_command_runtime() -> None:
    root = Path(__file__).resolve().parents[1]
    task_center = (root / "src/arenyxa/presentation/pages/task_center.py").read_text(encoding="utf-8")
    navigation = (root / "src/arenyxa/presentation/main_window_navigation.py").read_text(encoding="utf-8")
    operations = (root / "src/arenyxa/presentation/main_window_operations.py").read_text(encoding="utf-8")
    command_runtime = (root / "src/arenyxa/application/command_runtime_core.py").read_text(encoding="utf-8")
    assert "class TaskCenterPage" in task_center
    assert "workflowRequested" in task_center and "assistantRequested" in task_center
    assert "is_general_user(self.context.settings)" in navigation
    assert "run_general_user_workflow" in operations
    assert "simple." in operations
    assert "GeneralUserIntentRouter" not in command_runtime


def test_general_user_network_page_uses_progressive_disclosure_and_auto_summary() -> None:
    root = Path(__file__).resolve().parents[1]
    source = "\n".join((root / rel).read_text(encoding="utf-8") for rel in (
        "src/arenyxa/presentation/pages/network.py",
        "src/arenyxa/presentation/pages/network_capture_actions.py",
        "src/arenyxa/presentation/pages/network_analysis_actions.py",
    ))
    assert "self.simple_mode = is_general_user(context.settings)" in source
    assert "self.simple_advanced_button" in source
    assert "_set_simple_advanced_visible(False)" in source
    assert "summarize_network_events" in source
    assert "PCAP 分析完成 · Risk" in source


def test_simple_navigation_hides_disallowed_system_and_advanced_surfaces() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/arenyxa/presentation/main_window_navigation.py").read_text(encoding="utf-8")
    assert "if simple:\n                button.setVisible(self._page_allowed(page_id))" in source
    assert 'advanced_header.setVisible(not simple)' in source
    assert '"server_ops"' not in source[source.index("simple_visible = {"):source.index("return page_id not in DEVELOPER_PAGE_IDS")]
    assert '"enterprise"' not in source[source.index("simple_visible = {"):source.index("return page_id not in DEVELOPER_PAGE_IDS")]


def test_simple_command_palette_returns_before_professional_shortcuts() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/arenyxa/presentation/main_window_operations.py").read_text(encoding="utf-8")
    simple_branch = source[source.index("if is_general_user(self.context.settings):", source.index("def show_command_palette")):]
    assert "palette.exec()\n            return" in simple_branch
    assert simple_branch.index("palette.exec()\n            return") < simple_branch.index("studio.smartpath")


def test_runtime_capability_probe_marks_present_but_broken_tools_degraded(monkeypatch: pytest.MonkeyPatch) -> None:
    import arenyxa.application.general_user as general_user

    monkeypatch.setattr(general_user.shutil, "which", lambda name: f"/fake/{name}")

    def broken(*_args, **_kwargs):
        raise OSError("blocked")

    monkeypatch.setattr(general_user.subprocess, "run", broken)
    caps = RuntimeCapabilityService().snapshot()
    assert caps["packet.deep"].state == "degraded"
    assert caps["packet.deep"].backend == "arenyxa-native"
    assert caps["capture.system"].state == "unavailable"
    assert caps["mitm.external"].state == "unavailable"
