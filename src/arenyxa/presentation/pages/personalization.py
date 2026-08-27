from __future__ import annotations

"""Dedicated visual-personalization surface.

Settings intentionally does not own theme cards or visual tuning.  Keeping this page separate
prevents operational/enterprise configuration from being buried under large visual presets.
"""

from arenyxa.qt_compat.QtCore import QTimer, Qt, Signal
from arenyxa.qt_compat.QtWidgets import QApplication, QCheckBox, QFormLayout, QGridLayout, QLabel, QScrollArea, QVBoxLayout, QWidget

from arenyxa.compat import strict_zip
from arenyxa.domain.models import MotionProfile
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.pages.settings import ThemePreviewCard
from arenyxa.presentation.themes import THEMES
from arenyxa.presentation.widgets import PageHeader, SectionCard, ScrollSafeComboBox, ScrollSafeSlider, ScrollSafeSpinBox


class PersonalizationPage(WorkspacePage):
    themeRequested = Signal(str)
    motionRequested = Signal(object)
    uiScaleRequested = Signal(object)

    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        layout = page_layout(self)
        self._settings_save_dirty = False
        self._settings_save_timer = QTimer(self)
        self._settings_save_timer.setSingleShot(True)
        self._settings_save_timer.setInterval(180)
        self._settings_save_timer.timeout.connect(self._flush_settings_save)
        app = QApplication.instance()
        if app is not None:
            app.aboutToQuit.connect(self._flush_settings_save)

        layout.addWidget(PageHeader("个性化", "主题、界面材质、动效与缩放；系统和企业配置请前往“设置”"))
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        container = QWidget()
        body = QVBoxLayout(container)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(12)
        scroll.setWidget(container)
        layout.addWidget(scroll, 1)

        themes_card = SectionCard(theme, "视觉预设")
        theme_hint = QLabel("Arenyxa 视觉预设只影响外观，不改变运行、权限、存储或企业策略。")
        theme_hint.setProperty("muted", True)
        theme_hint.setWordWrap(True)
        themes_card.body.addWidget(theme_hint)
        themes_grid = QGridLayout()
        themes_grid.setHorizontalSpacing(10)
        themes_grid.setVerticalSpacing(10)
        self.theme_buttons: dict[str, ThemePreviewCard] = {}
        ordered = ["modern_dark", "aurora_glass", "clean_light", "terminal_green", "professional_graphite", "blue_productivity"]
        for index, theme_id in enumerate(ordered):
            card = ThemePreviewCard(theme_id, THEMES[theme_id])
            card.clicked.connect(self.select_theme)
            self.theme_buttons[theme_id] = card
            themes_grid.addWidget(card, index // 2, index % 2)
        themes_grid.setColumnStretch(0, 1)
        themes_grid.setColumnStretch(1, 1)
        themes_card.body.addLayout(themes_grid)
        body.addWidget(themes_card)

        motion_card = SectionCard(theme, "材质与动效")
        form = QFormLayout()
        self.glass = ScrollSafeSlider(Qt.Orientation.Horizontal)
        self.glass.setRange(0, 100)
        self.motion_slider = ScrollSafeSlider(Qt.Orientation.Horizontal)
        self.motion_slider.setRange(0, 100)
        self.blur = ScrollSafeSlider(Qt.Orientation.Horizontal)
        self.blur.setRange(12, 36)
        self.animation_mode = ScrollSafeComboBox()
        self.animation_mode.addItem("自动（根据性能动态调整）", "auto")
        self.animation_mode.addItem("始终开启", "always")
        self.animation_mode.addItem("最小动效 / 省电", "minimal")
        self.reduce_motion = QCheckBox("减少大幅位移、折射、粒子和连续光效")
        self.live_motion = QCheckBox("启用实时数据流动态")
        self.high_contrast = QCheckBox("高对比度玻璃回退")
        form.addRow("材质强度", self.glass)
        form.addRow("背景模糊", self.blur)
        form.addRow("动态强度", self.motion_slider)
        form.addRow("动画模式", self.animation_mode)
        form.addRow(self.reduce_motion)
        form.addRow(self.live_motion)
        form.addRow(self.high_contrast)
        motion_card.body.addLayout(form)
        body.addWidget(motion_card)

        scale_card = SectionCard(theme, "界面缩放与字体")
        scale_form = QFormLayout()
        self.ui_scale_mode = ScrollSafeComboBox()
        self.ui_scale_mode.addItem("自动（随窗口大小）", "auto")
        self.ui_scale_mode.addItem("手动", "manual")
        self.ui_scale_percent = ScrollSafeSpinBox()
        self.ui_scale_percent.setRange(85, 160)
        self.ui_scale_percent.setSingleStep(5)
        self.ui_scale_percent.setSuffix("%")
        scale_hint = QLabel(
            "自动模式会根据 Arenyxa 窗口可用面积调整文字与常用控件尺寸，同时保留 Qt/Windows DPI 缩放；"
            "手动模式可固定 85%–160%。"
        )
        scale_hint.setProperty("muted", True)
        scale_hint.setWordWrap(True)
        scale_form.addRow("缩放模式", self.ui_scale_mode)
        scale_form.addRow("手动缩放", self.ui_scale_percent)
        scale_form.addRow("说明", scale_hint)
        scale_card.body.addLayout(scale_form)
        body.addWidget(scale_card)
        body.addStretch()

        self._sync_controls_from_settings()
        for slider in (self.glass, self.blur, self.motion_slider):
            slider.valueChanged.connect(self.apply_motion)
        for checkbox in (self.reduce_motion, self.live_motion, self.high_contrast):
            checkbox.toggled.connect(self.apply_motion)
        self.animation_mode.activated.connect(self.apply_motion)
        self.ui_scale_mode.activated.connect(self._ui_scale_changed)
        self.ui_scale_percent.valueChanged.connect(self._ui_scale_changed)

    def _sync_controls_from_settings(self) -> None:
        settings = self.context.settings
        widgets = [
            self.glass, self.motion_slider, self.blur, self.animation_mode, self.reduce_motion, self.live_motion,
            self.high_contrast, self.ui_scale_mode, self.ui_scale_percent,
        ]
        previous = [widget.blockSignals(True) for widget in widgets]
        try:
            self.glass.setValue(round(settings.glass_strength * 100))
            self.motion_slider.setValue(round(settings.motion_strength * 100))
            self.blur.setValue(round(settings.blur_strength))
            mode_index = self.animation_mode.findData(settings.animation_mode)
            self.animation_mode.setCurrentIndex(max(0, mode_index))
            self.reduce_motion.setChecked(settings.reduce_motion)
            self.live_motion.setChecked(settings.live_data_motion)
            self.high_contrast.setChecked(settings.high_contrast)
            scale_index = self.ui_scale_mode.findData(settings.ui_scale_mode)
            self.ui_scale_mode.setCurrentIndex(max(0, scale_index))
            self.ui_scale_percent.setValue(settings.ui_scale_percent)
            self.ui_scale_percent.setEnabled(settings.ui_scale_mode == "manual")
        finally:
            for widget, old in strict_zip(widgets, previous, strict=False):
                widget.blockSignals(old)

    def activated(self) -> None:
        self._sync_controls_from_settings()
        for theme_id, card in self.theme_buttons.items():
            card.set_selected(theme_id == self.context.settings.theme)
        self.inspectorChanged.emit(
            "Personalization",
            {
                "theme": self.context.settings.theme,
                "animation_mode": self.context.settings.animation_mode,
                "reduce_motion": self.context.settings.reduce_motion,
                "high_contrast": self.context.settings.high_contrast,
                "ui_scale_mode": self.context.settings.ui_scale_mode,
                "ui_scale_percent": self.context.settings.ui_scale_percent,
            },
        )

    def refresh_localized_previews(self) -> None:
        for card in self.theme_buttons.values():
            card.refresh_locale()

    def select_theme(self, theme_id: str) -> None:
        if theme_id not in THEMES:
            return
        self.context.settings.theme = theme_id
        for key, card in self.theme_buttons.items():
            card.set_selected(key == theme_id)
        self.themeRequested.emit(theme_id)
        self._schedule_settings_save()

    def apply_motion(self, *_args) -> None:
        profile = MotionProfile(
            glass_strength=self.glass.value() / 100,
            transparency=max(0.18, min(0.52, 0.58 - self.glass.value() / 200)),
            blur=float(self.blur.value()),
            motion_strength=self.motion_slider.value() / 100,
            edge_flow=False,
            live_data_motion=self.live_motion.isChecked(),
            reduce_motion=self.reduce_motion.isChecked(),
            animation_mode=str(self.animation_mode.currentData() or "auto"),
            quality=self.context.performance.mode,
        )
        settings = self.context.settings
        settings.glass_strength = profile.glass_strength
        settings.motion_strength = profile.motion_strength
        settings.blur_strength = profile.blur
        settings.edge_flow = False
        settings.live_data_motion = profile.live_data_motion
        settings.reduce_motion = profile.reduce_motion
        settings.animation_mode = profile.animation_mode
        settings.high_contrast = self.high_contrast.isChecked()
        app = QApplication.instance()
        if app is not None:
            app.setProperty("arenyxa_high_contrast", bool(settings.high_contrast))
            for widget in app.allWidgets():
                if bool(widget.property("glass")):
                    widget.update()
        self._schedule_settings_save()
        self.motionRequested.emit(profile)

    def _ui_scale_changed(self, *_args) -> None:
        mode = str(self.ui_scale_mode.currentData() or "auto")
        percent = max(85, min(160, int(self.ui_scale_percent.value())))
        self.ui_scale_percent.setEnabled(mode == "manual")
        settings = self.context.settings
        settings.ui_scale_mode = mode if mode in {"auto", "manual"} else "auto"
        settings.ui_scale_percent = percent
        self._schedule_settings_save()
        self.uiScaleRequested.emit((settings.ui_scale_mode, settings.ui_scale_percent))
        self.statusMessage.emit(
            "界面缩放已更新：自动随窗口调整" if settings.ui_scale_mode == "auto"
            else f"界面缩放已固定为 {settings.ui_scale_percent}%"
        )

    def _schedule_settings_save(self) -> None:
        self._settings_save_dirty = True
        self._settings_save_timer.start()

    def _flush_settings_save(self) -> None:
        if self._settings_save_timer.isActive():
            self._settings_save_timer.stop()
        if not self._settings_save_dirty:
            return
        self.context.settings.save(self.context.paths.root / "settings.json")
        self._settings_save_dirty = False

    def deactivated(self) -> None:
        self._flush_settings_save()
