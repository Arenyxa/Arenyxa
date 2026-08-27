from __future__ import annotations

import json
from pathlib import Path

from arenyxa.config import AppSettings
from arenyxa.domain.models import MotionProfile


def test_animation_mode_defaults_and_persists(tmp_path: Path) -> None:
    settings = AppSettings()
    assert settings.animation_mode == "auto"
    settings.animation_mode = "always"
    path = tmp_path / "settings.json"
    settings.save(path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["animation_mode"] == "always"
    assert AppSettings.load(path).animation_mode == "always"


def test_invalid_animation_mode_falls_back_to_auto(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text('{"animation_mode":"unsupported"}', encoding="utf-8")
    assert AppSettings.load(path).animation_mode == "auto"


def test_motion_profile_exposes_animation_mode() -> None:
    assert MotionProfile().animation_mode == "auto"
    assert MotionProfile(animation_mode="minimal").animation_mode == "minimal"


def test_dashboard_uses_numeric_motion_for_key_metrics() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/arenyxa/presentation/pages/dashboard.py").read_text(encoding="utf-8")
    assert source.count("self.motion.animate_number(") >= 6


def test_personalization_exposes_three_animation_modes() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/arenyxa/presentation/pages/personalization.py").read_text(encoding="utf-8")
    for mode in ('"auto"', '"always"', '"minimal"'):
        assert mode in source
    assert 'settings.animation_mode = profile.animation_mode' in source
