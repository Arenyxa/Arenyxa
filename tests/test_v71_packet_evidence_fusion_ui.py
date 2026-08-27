from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKBENCH = ROOT / "src/arenyxa/presentation/packet_intelligence_workbench.py"


def test_passive_evidence_fusion_has_dedicated_workbench_surface_and_wiring() -> None:
    text = WORKBENCH.read_text(encoding="utf-8")
    assert 'QPushButton("Passive Evidence Fusion")' in text
    assert 'self.tabs.addTab(self.evidence_fusion_view, "Passive Evidence Fusion")' in text
    assert "self.evidence_fusion_button.clicked.connect(self.load_passive_evidence_fusion)" in text
    assert "self.engine.fuse_passive_evidence(" in text
    assert "zeek_json_paths=" in text
    assert "suricata_eve_path=" in text


def test_passive_evidence_fusion_ui_keeps_external_findings_attributed() -> None:
    evidence = (ROOT / "src/arenyxa/infrastructure/capture/passive_evidence.py").read_text(encoding="utf-8")
    assert "external alerts/notices remain attributed" in evidence
    assert "not promoted to Arenyxa-native findings without packet evidence" in evidence
