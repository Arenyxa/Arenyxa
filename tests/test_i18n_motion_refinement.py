from __future__ import annotations

import re

import pytest

from arenyxa.qt_compat import binding_available
if not binding_available():
    pytest.skip("No supported Qt binding is installed", allow_module_level=True)

from arenyxa.qt_compat.QtCore import Qt
from arenyxa.qt_compat.QtWidgets import QLabel, QLineEdit

from arenyxa.domain.models import MotionProfile
from arenyxa.presentation.language import LOCALES, LanguageManager
from arenyxa.presentation.motion import MotionOrchestrator


def test_all_supported_locales_and_non_chinese_fallback(qapp) -> None:
    manager = LanguageManager(qapp, "zh_CN")
    assert set(LOCALES) == {
        "system",
        "zh_CN",
        "zh_TW",
        "en_US",
        "fr_FR",
        "ru_RU",
        "de_DE",
        "ja_JP",
        "ko_KR",
        "ar_SA",
        "la_VA",
    }
    for locale in ("en_US", "fr_FR", "ru_RU", "de_DE", "ko_KR", "ar_SA", "la_VA"):
        manager.apply(locale)
        rendered = manager.literal("抓取任务")
        assert rendered
        assert not re.search(r"[\u3400-\u9fff]", rendered)


def test_arabic_keeps_technical_fields_ltr(qapp) -> None:
    manager = LanguageManager(qapp, "ar_SA")
    manager.apply("ar_SA")
    human = QLabel("仪表盘")
    technical = QLineEdit()
    technical.setObjectName("request_url")
    technical.setPlaceholderText("https://example.com")
    manager.translate_tree(human)
    manager.translate_tree(technical)
    assert human.layoutDirection() == Qt.LayoutDirection.LeftToRight
    assert human.alignment() & Qt.AlignmentFlag.AlignRight
    assert technical.layoutDirection() == Qt.LayoutDirection.LeftToRight


def test_user_quality_caps_adaptive_quality(qapp) -> None:
    profile = MotionProfile(quality="efficiency")
    motion = MotionOrchestrator(profile, refresh_hz=60)
    motion.adaptive_quality = "high"
    assert motion.effective_quality() == "efficiency"
    motion.set_profile(MotionProfile(quality="high"))
    motion.adaptive_quality = "balanced"
    assert motion.effective_quality() == "balanced"
