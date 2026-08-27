from pathlib import Path


def test_professional_tools_use_independent_top_level_workbenches():
    root = Path(__file__).parents[1]
    main = (root / "src" / "arenyxa" / "presentation" / "main_window_registry.py").read_text(encoding="utf-8")
    expected = (
        '("network", "◫", "nav.network", NetworkPage, "core")',
        '("proxy", "⇄", "nav.proxy", ProxyPage, "core")',
        '("mitm", "⇌", "nav.mitm_proxy", MitmInterceptionPage, "core")',
        '("studio", "⌬", "nav.studio", IntelligenceStudioPage, "core")',
        '("workflow", "◇", "nav.workflow", WorkflowPage, "core")',
        '("automation", "◷", "nav.automation", AutomationEnginePage, "core")',
    )
    for definition in expected:
        assert definition in main
    assert '("professional", "⌬", "nav.professional", ProfessionalSuitePage, "core")' not in main
