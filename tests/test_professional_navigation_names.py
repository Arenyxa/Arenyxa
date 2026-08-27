from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_professional_navigation_uses_unique_final_product_names() -> None:
    language = (ROOT / "src/arenyxa/presentation/language.py").read_text(encoding="utf-8")
    expected = {
        "nav.network": "Network Analysis",
        "nav.proxy": "Proxy Suite",
        "nav.mitm_proxy": "MITM Proxy",
        "nav.extraction": "Extraction Lab",
        "nav.studio": "Web Intelligence",
        "nav.workflow": "Flow Designer",
        "nav.automation": "Automation Center",
        "nav.server_ops": "Fleet Control",
    }
    for key, value in expected.items():
        assert f'"{key}": "{value}"' in language
    assert len(set(expected.values())) == len(expected)
    assert "EN.update(PROFESSIONAL_NAV_NAMES)" in language
    assert "ZH_CN.update(PROFESSIONAL_NAV_NAMES)" in language
    assert "NATIVE_OVERRIDES[_locale].update(PROFESSIONAL_NAV_NAMES)" in language


def test_packet_intelligence_replaces_packet_analysis_workbench_label() -> None:
    network = (ROOT / "src/arenyxa/presentation/pages/network.py").read_text(encoding="utf-8")
    packet_analysis = (ROOT / "src/arenyxa/presentation/packet_intelligence_workbench.py").read_text(encoding="utf-8")
    assert 'QPushButton("Packet Intelligence")' in network
    assert '"Packet Intelligence Workbench"' not in network
    assert '"Packet Intelligence Workbench"' not in packet_analysis


def test_final_names_reach_page_headers_and_shell_entry_points() -> None:
    expected_by_file = {
        "src/arenyxa/presentation/pages/mitm_proxy.py": "MITM Proxy",
        "src/arenyxa/presentation/pages/extraction.py": "Extraction Lab",
        "src/arenyxa/presentation/pages/studio.py": "Web Intelligence",
        "src/arenyxa/presentation/pages/tools_automation.py": "Flow Designer",
        "src/arenyxa/presentation/pages/server_ops.py": "Fleet Control",
        "src/arenyxa/presentation/main_window.py": "Web Intelligence",
    }
    for rel, label in expected_by_file.items():
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert label in text
