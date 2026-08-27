from __future__ import annotations

import json
import logging
import os
import platform
import time
import shutil
import tempfile
import zipfile
from collections import deque
from dataclasses import asdict, fields
from datetime import datetime, timezone
from pathlib import Path

from arenyxa.qt_compat.QtCore import QRectF, QTimer, Qt, Signal
from arenyxa.branding import application_icon_png_path
from arenyxa.qt_compat.QtGui import QColor, QPainter, QPainterPath, QPen, QPixmap
from arenyxa.qt_compat.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from arenyxa import __version__
from arenyxa.compat import strict_zip
from arenyxa.config import AppSettings
from arenyxa.application.developer_safety import (
    DEVELOPER_TERMS_VERSION,
    RISK_AGREEMENT_TEXT,
    RISK_AGREEMENT_TITLE,
    WAIVER_TEXT,
    WAIVER_TITLE,
)
from arenyxa.domain.models import MotionProfile
from arenyxa.provenance import build_identity_summary, commercialization_notice, verify_release_attestation
from arenyxa.repair import StartupHealthScanner, installation_root
from arenyxa.infrastructure.atomic_io import fsync_existing_file
from arenyxa.infrastructure.observability import Redactor
from arenyxa.presentation.background import run_background
from arenyxa.presentation.language import LOCALES, LanguageManager, literal_for_locale
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.themes import ThemeTokens
from arenyxa.presentation.widgets import (
    PageHeader,
    SectionCard,
    ScrollSafeComboBox,
    ScrollSafeSpinBox,
)


THEME_META = {
    "modern_dark": ("正式预设 · 默认", "现代深色 / 高信息密度 / 专业工作台"),
    "aurora_glass": ("正式预设", "极光液态玻璃 / 青绿光晕 / 深海渐变"),
    "clean_light": ("正式预设", "明亮浅色 / 清洁留白 / 绿色强调"),
    "terminal_green": ("正式预设", "复古终端 / 荧光绿 / 低圆角科技感"),
    "professional_graphite": ("扩展预设", "石墨灰 / 克制玻璃 / 企业专业感"),
    "blue_productivity": ("扩展预设", "蓝色生产力 / 明亮商务 / 高可读性"),
}


LOGGER = logging.getLogger(__name__)

class ThemePreviewCard(QFrame):
    

    clicked = Signal(str)

    def __init__(self, theme_id: str, tokens: ThemeTokens, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme_id = theme_id
        self.tokens = tokens
        self.selected = False
        self.setMinimumSize(280, 210)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(tokens.name)

    def set_selected(self, selected: bool) -> None:
        if self.selected != selected:
            self.selected = selected
            self.update()

    def refresh_locale(self) -> None:
        app = QApplication.instance()
        locale = str(app.property("arenyxa_locale") or "zh_CN") if app is not None else "zh_CN"
        self.setToolTip(literal_for_locale(self.tokens.name, locale))
        self.update()

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.theme_id)
        super().mouseReleaseEvent(event)

    def paintEvent(self, event) -> None:
        del event
        t = self.tokens
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        outer = QRectF(self.rect()).adjusted(1.0, 1.0, -1.0, -1.0)
        card_bg = QColor(t.surface)
        if card_bg.alpha() < 210:
            card_bg.setAlpha(232 if t.dark else 248)
        painter.setBrush(card_bg)
        border = QColor(t.accent if self.selected else t.border)
        painter.setPen(QPen(border, 2.2 if self.selected else 1.0))
        painter.drawRoundedRect(outer, 15, 15)

        preview = QRectF(12, 12, outer.width() - 24, 122)
        path = QPainterPath()
        path.addRoundedRect(preview, 11, 11)
        painter.save()
        painter.setClipPath(path)
        painter.fillRect(preview, QColor(t.background))

                                                                            
        from arenyxa.qt_compat.QtGui import QLinearGradient
        gradient = QLinearGradient(preview.topLeft(), preview.bottomRight())
        gradient.setColorAt(0.0, QColor(t.gradient_start))
        gradient.setColorAt(0.52, QColor(t.gradient_mid))
        gradient.setColorAt(1.0, QColor(t.gradient_end))
        painter.fillRect(preview, gradient)

                                      
        sidebar = QRectF(preview.left() + 7, preview.top() + 7, 42, preview.height() - 14)
        painter.setPen(QPen(QColor(t.border), 0.8))
        painter.setBrush(QColor(t.glass_elevated))
        painter.drawRoundedRect(sidebar, 7, 7)
        topbar = QRectF(sidebar.right() + 6, preview.top() + 7, preview.width() - sidebar.width() - 20, 19)
        painter.setBrush(QColor(t.glass_elevated))
        painter.drawRoundedRect(topbar, 6, 6)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(t.accent))
        painter.drawRoundedRect(QRectF(sidebar.left() + 7, sidebar.top() + 11, 27, 4), 2, 2)
        for i in range(4):
            painter.setBrush(QColor(t.accent_soft if i == 0 else t.border))
            painter.drawRoundedRect(QRectF(sidebar.left() + 7, sidebar.top() + 28 + i * 15, 27, 7), 3, 3)

        content_left = topbar.left()
        content_top = topbar.bottom() + 6
        content_width = topbar.width()
        gap = 5
        metric_w = (content_width - gap * 2) / 3
        for i in range(3):
            metric = QRectF(content_left + i * (metric_w + gap), content_top, metric_w, 30)
            painter.setBrush(QColor(t.glass))
            painter.setPen(QPen(QColor(t.border), 0.7))
            painter.drawRoundedRect(metric, 5, 5)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(t.accent if i == 0 else t.text_muted))
            painter.drawRoundedRect(QRectF(metric.left() + 5, metric.top() + 7, metric.width() * .45, 3), 1.5, 1.5)
            painter.setBrush(QColor(t.text))
            painter.drawRoundedRect(QRectF(metric.left() + 5, metric.top() + 15, metric.width() * .62, 5), 2, 2)

        lower_y = content_top + 36
        panel1 = QRectF(content_left, lower_y, content_width * .61, preview.bottom() - lower_y - 7)
        panel2 = QRectF(panel1.right() + 5, lower_y, content_width - panel1.width() - 5, panel1.height())
        for panel in (panel1, panel2):
            painter.setBrush(QColor(t.glass))
            painter.setPen(QPen(QColor(t.border), 0.7))
            painter.drawRoundedRect(panel, 5, 5)
        painter.setPen(Qt.PenStyle.NoPen)
        for i, scale in enumerate((.42, .78, .57, .9, .66)):
            x = panel1.left() + 7 + i * max(7, (panel1.width() - 18) / 5)
            h = (panel1.height() - 16) * scale
            painter.setBrush(QColor(t.accent if i in (1, 3) else t.text_muted))
            painter.drawRoundedRect(QRectF(x, panel1.bottom() - 6 - h, 5, h), 2, 2)
        painter.setBrush(QColor(t.accent))
        painter.drawEllipse(QRectF(panel2.center().x() - 12, panel2.center().y() - 12, 24, 24))
        painter.setBrush(QColor(t.background_alt))
        painter.drawEllipse(QRectF(panel2.center().x() - 7, panel2.center().y() - 7, 14, 14))
        painter.restore()

                                                                                   
                                                                                           
        app = QApplication.instance()
        locale = str(app.property("arenyxa_locale") or "zh_CN") if app is not None else "zh_CN"
        meta_source, description_source = THEME_META.get(self.theme_id, ("视觉预设", "Arenyxa visual profile"))
        meta = literal_for_locale(meta_source, locale)
        description = literal_for_locale(description_source, locale)
        display_name = literal_for_locale(t.name, locale)
        text_align = Qt.AlignmentFlag.AlignRight if locale.startswith("ar") else Qt.AlignmentFlag.AlignLeft
        painter.setPen(QColor(t.text))
        font = painter.font()
        font.setBold(True)
        font.setPointSize(10)
        painter.setFont(font)
        painter.drawText(QRectF(14, 143, outer.width() - 28, 22), text_align | Qt.AlignmentFlag.AlignVCenter, display_name)
        font.setBold(False)
        font.setPointSize(8)
        painter.setFont(font)
        painter.setPen(QColor(t.accent if self.selected else t.text_muted))
        painter.drawText(QRectF(14, 165, outer.width() - 28, 18), text_align | Qt.AlignmentFlag.AlignVCenter, meta)
        painter.setPen(QColor(t.text_muted))
        painter.drawText(QRectF(14, 183, outer.width() - 28, 18), text_align | Qt.AlignmentFlag.AlignVCenter, description)

        if self.selected:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(t.accent))
            painter.drawEllipse(QRectF(outer.right() - 34, outer.top() + 12, 22, 22))
            painter.setPen(QColor("#06120c" if not t.dark else "#03130b"))
            check_font = painter.font()
            check_font.setBold(True)
            check_font.setPointSize(10)
            painter.setFont(check_font)
            painter.drawText(QRectF(outer.right() - 34, outer.top() + 12, 22, 22), Qt.AlignmentFlag.AlignCenter, "✓")
        painter.end()


class _DeveloperTermsDialog(QDialog):
    

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("启用 Developer Mode")
        self.setModal(True)
        self.setMinimumWidth(620)
        layout = QVBoxLayout(self)

        risk_title = QLabel(RISK_AGREEMENT_TITLE)
        risk_title.setStyleSheet("font-weight: 700;")
        risk_text = QLabel(RISK_AGREEMENT_TEXT)
        risk_text.setWordWrap(True)
        risk_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(risk_title)
        layout.addWidget(risk_text)

        waiver_title = QLabel(WAIVER_TITLE)
        waiver_title.setStyleSheet("font-weight: 700; margin-top: 8px;")
        waiver_text = QLabel(WAIVER_TEXT)
        waiver_text.setWordWrap(True)
        waiver_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(waiver_title)
        layout.addWidget(waiver_text)

        self.risk_accept = QCheckBox("我已阅读并同意开发者风险协议")
        self.waiver_accept = QCheckBox("我已阅读并同意测试免责协议")
        layout.addWidget(self.risk_accept)
        layout.addWidget(self.waiver_accept)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        self.risk_accept.toggled.connect(self._refresh_accept)
        self.waiver_accept.toggled.connect(self._refresh_accept)
        self._refresh_accept()

    def _refresh_accept(self) -> None:
        button = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        if button is not None:
            button.setEnabled(self.risk_accept.isChecked() and self.waiver_accept.isChecked())


class SettingsPage(WorkspacePage):
                                                                                          
                                                                                               
                                           
    themeRequested = Signal(str)
    localeRequested = Signal(str)
    motionRequested = Signal(object)
    developerModeChanged = Signal(bool)
    uiScaleRequested = Signal(object)
    repairRequested = Signal()
    welcomeRequested = Signal()

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

        layout.addWidget(PageHeader("设置", "系统、语言、性能、资源治理、诊断与高级维护"))
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        container = QWidget()
        body = QVBoxLayout(container)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(12)
        scroll.setWidget(container)
        layout.addWidget(scroll, 1)

        experience_card = SectionCard(theme, "使用模式")
        experience_form = QFormLayout()
        self.experience_status = QLabel()
        self.experience_status.setWordWrap(True)
        self.experience_status.setProperty("muted", True)
        self.reopen_welcome_button = QPushButton("重新选择使用模式")
        experience_form.addRow("当前模式", self.experience_status)
        experience_form.addRow("", self.reopen_welcome_button)
        experience_hint = QLabel(
            "使用模式只调整工作区呈现与默认导航，不是权限等级。Developer / Enterprise 权限始终由后端安全策略决定；主题和预设仍在独立“个性化”页面。"
        )
        experience_hint.setWordWrap(True)
        experience_hint.setProperty("muted", True)
        experience_form.addRow("说明", experience_hint)
        experience_card.body.addLayout(experience_form)
        body.addWidget(experience_card)

        performance_card = SectionCard(theme, "性能与资源治理")
        performance_form = QFormLayout()
        self.performance = ScrollSafeComboBox()
        self.performance.addItems(["auto", "quality", "balanced", "efficiency"])
        self.resource_governor_enabled = QCheckBox("启用 Resource Governor（推荐）")
        self.resource_cpu_soft = ScrollSafeSpinBox()
        self.resource_cpu_soft.setRange(40, 98)
        self.resource_cpu_soft.setSuffix("%")
        self.resource_memory_soft = ScrollSafeSpinBox()
        self.resource_memory_soft.setRange(40, 95)
        self.resource_memory_soft.setSuffix("%")
        self.resource_min_disk = ScrollSafeSpinBox()
        self.resource_min_disk.setRange(128, 1048576)
        self.resource_min_disk.setSuffix(" MB")
        self.resource_browser_limit = ScrollSafeSpinBox()
        self.resource_browser_limit.setRange(1, 32)
        self.resource_status = QLabel()
        self.resource_status.setProperty("muted", True)
        self.resource_status.setWordWrap(True)
        performance_form.addRow("性能模式", self.performance)
        performance_form.addRow(self.resource_governor_enabled)
        performance_form.addRow("CPU 软阈值", self.resource_cpu_soft)
        performance_form.addRow("内存软阈值", self.resource_memory_soft)
        performance_form.addRow("磁盘安全余量", self.resource_min_disk)
        performance_form.addRow("浏览器实例上限", self.resource_browser_limit)
        performance_form.addRow("当前状态", self.resource_status)
        performance_card.body.addLayout(performance_form)
        body.addWidget(performance_card)

        concurrency_card = SectionCard(theme, "网页抓取并发")
        concurrency_form = QFormLayout()
        self.request_concurrency = ScrollSafeSpinBox()
        self.request_concurrency.setRange(1, 64)
        self.per_host_concurrency = ScrollSafeSpinBox()
        self.per_host_concurrency.setRange(1, 32)
        self.adaptive_request_concurrency = QCheckBox("自动调节全局请求并发（推荐）")
        concurrency_form.addRow("全局请求并发硬上限", self.request_concurrency)
        concurrency_form.addRow("单域名并发上限", self.per_host_concurrency)
        concurrency_form.addRow(self.adaptive_request_concurrency)
        concurrency_hint = QLabel(
            "Resource Governor 只能向下收紧并发，不能突破这里的用户硬上限。CPU、RAM、磁盘或浏览器压力上升时会退避；"
            "恢复必须经过连续健康采样，避免并发振荡。"
        )
        concurrency_hint.setProperty("muted", True)
        concurrency_hint.setWordWrap(True)
        concurrency_form.addRow("调度策略", concurrency_hint)
        concurrency_card.body.addLayout(concurrency_form)
        body.addWidget(concurrency_card)

        locale_card = SectionCard(theme, "语言")
        locale_form = QFormLayout()
        self.locale_box = ScrollSafeComboBox()
        for code, name in LOCALES.items():
            self.locale_box.addItem(name, code)
        locale_form.addRow("界面语言", self.locale_box)
        locale_card.body.addLayout(locale_form)
        body.addWidget(locale_card)

        self.advanced_card = SectionCard(theme, "高级设置与维护")
        advanced_hint = QLabel(
            "诊断、Repair Center 与 Developer Mode 集中在这里。个性化主题、动效和界面缩放位于独立“个性化”页面。"
        )
        advanced_hint.setProperty("muted", True)
        advanced_hint.setWordWrap(True)
        self.advanced_card.body.addWidget(advanced_hint)
        self.developer = QCheckBox("Developer Mode（显示开发者工具；系统命令仍需逐次确认）")
        self.advanced_card.body.addWidget(self.developer)

        maintenance_row = QHBoxLayout()
        self.diagnostics_button = QPushButton("运行诊断")
        self.repair_button = QPushButton("打开 Repair Center")
        self.export_diagnostics_button = QPushButton("导出诊断包")
        maintenance_row.addWidget(self.diagnostics_button)
        maintenance_row.addWidget(self.repair_button)
        maintenance_row.addWidget(self.export_diagnostics_button)
        maintenance_row.addStretch()
        self.advanced_card.body.addLayout(maintenance_row)
        self.diagnostic_status = QLabel("尚未在本次会话中运行诊断。")
        self.diagnostic_status.setWordWrap(True)
        self.diagnostic_status.setProperty("muted", True)
        self.advanced_card.body.addWidget(self.diagnostic_status)
        privacy_form = QFormLayout()
        self.include_paths = QCheckBox("诊断包包含本机路径（默认关闭）")
        privacy_form.addRow(self.include_paths)
        self.advanced_card.body.addLayout(privacy_form)
        reset_row = QHBoxLayout()
        self.reset_settings_button = QPushButton("恢复全部默认设置")
        self.reset_settings_button.setToolTip("重置应用设置与个性化偏好；不会删除 Projects、Captures、Exports 或正式结果数据")
        reset_row.addWidget(self.reset_settings_button)
        reset_row.addStretch()
        self.advanced_card.body.addLayout(reset_row)
        body.addWidget(self.advanced_card)

        self.official_developer_card = SectionCard(theme, "Official Arenyxa Developer Access")
        official_hint = QLabel(
            "Official Developer 与公开 Developer Profile 完全分离：必须验证 Developer Certificate 信任链，"
            "再用对应设备私钥完成一次性挑战。Root Owner 使用独立 Owner/Authority credential；"
            "Developer Root Private Key 不参与日常登录并应始终保持离线。邮箱不是安全根；Enterprise 管理员也不会自动获得这些能力。"
        )
        official_hint.setProperty("muted", True)
        official_hint.setWordWrap(True)
        self.official_developer_card.body.addWidget(official_hint)
        self.official_developer_status = QLabel()
        self.official_developer_status.setWordWrap(True)
        self.official_developer_status.setProperty("muted", True)
        self.official_developer_card.body.addWidget(self.official_developer_status)
        official_row = QHBoxLayout()
        self.official_developer_login_button = QPushButton("登录 Official Developer")
        self.root_owner_login_button = QPushButton("登录 Root Owner / Authority")
        self.official_developer_logout_button = QPushButton("退出 Official Developer")
        for button in (self.official_developer_login_button, self.root_owner_login_button, self.official_developer_logout_button):
            official_row.addWidget(button)
        official_row.addStretch()
        self.official_developer_card.body.addLayout(official_row)
        body.addWidget(self.official_developer_card)
        body.addStretch()

        self._sync_controls_from_settings()
        self.locale_box.activated.connect(self._locale_activated)
        self.performance.activated.connect(self._performance_activated)
        self.resource_governor_enabled.toggled.connect(self._save_resource_settings)
        for control in (self.resource_cpu_soft, self.resource_memory_soft, self.resource_min_disk, self.resource_browser_limit):
            control.valueChanged.connect(self._save_resource_settings)
        self.request_concurrency.valueChanged.connect(self._save_concurrency)
        self.per_host_concurrency.valueChanged.connect(self._save_concurrency)
        self.adaptive_request_concurrency.toggled.connect(self._save_concurrency)
        self.developer.toggled.connect(self._developer_toggled)
        self.include_paths.toggled.connect(self._include_paths_toggled)
        self.diagnostics_button.clicked.connect(self.run_diagnostics)
        self.repair_button.clicked.connect(self.repairRequested.emit)
        self.export_diagnostics_button.clicked.connect(self.export_diagnostics)
        self.reset_settings_button.clicked.connect(self.reset_settings)
        self.reopen_welcome_button.clicked.connect(self.welcomeRequested.emit)
        self.official_developer_login_button.clicked.connect(self._official_developer_login)
        self.root_owner_login_button.clicked.connect(self._root_owner_login)
        self.official_developer_logout_button.clicked.connect(self._official_developer_logout)

    def _locale_activated(self, *_args) -> None:
        locale = self.locale_box.currentData()
        if locale and str(locale) != self.context.settings.locale:
            self.localeRequested.emit(str(locale))

    def _performance_activated(self, *_args) -> None:
        mode = self.performance.currentText()
        if mode not in {"auto", "quality", "balanced", "efficiency"}:
            return
        self.context.settings.performance_mode = mode
        self._schedule_settings_save()
        self.statusMessage.emit("性能模式已保存；线程池与完整缓存预算将在下次启动时应用。")

    def _save_resource_settings(self, *_args) -> None:
        settings = self.context.settings
        settings.resource_governor_enabled = bool(self.resource_governor_enabled.isChecked())
        settings.resource_cpu_soft_percent = int(self.resource_cpu_soft.value())
        settings.resource_memory_soft_percent = int(self.resource_memory_soft.value())
        settings.resource_min_free_disk_mb = int(self.resource_min_disk.value())
        settings.resource_max_browser_instances = int(self.resource_browser_limit.value())
        self._schedule_settings_save()
                                                                                           
                                                                                                    
        if hasattr(self.context, "browser_pool"):
            self.context.browser_pool.set_limit(settings.resource_max_browser_instances)
        self._refresh_resource_status()
        self.statusMessage.emit("资源治理阈值已保存；完整 Governor 阈值与启停状态将在下次启动时应用。")

    def _save_concurrency(self, *_args) -> None:
        request_workers = max(1, min(64, self.request_concurrency.value()))
        previous = self.per_host_concurrency.blockSignals(True)
        try:
            self.per_host_concurrency.setMaximum(max(1, min(32, request_workers)))
            if self.per_host_concurrency.value() > request_workers:
                self.per_host_concurrency.setValue(request_workers)
        finally:
            self.per_host_concurrency.blockSignals(previous)
        settings = self.context.settings
        settings.request_concurrency = request_workers
        settings.per_host_concurrency = max(1, min(self.per_host_concurrency.value(), request_workers))
        settings.adaptive_request_concurrency = self.adaptive_request_concurrency.isChecked()
        self._schedule_settings_save()
        if settings.adaptive_request_concurrency:
            self.context.runner.enable_adaptive_request_limit()
        else:
            self.context.runner.set_request_limit(min(self.context.runner.request_workers, settings.request_concurrency))
        self._refresh_resource_status()
        self.statusMessage.emit(
            f"抓取并发已保存：请求硬上限 {settings.request_concurrency} / 单域名 {settings.per_host_concurrency} / "
            + ("自适应" if settings.adaptive_request_concurrency else "手动固定")
        )

    def _sync_controls_from_settings(self) -> None:
        settings = self.context.settings
        widgets = [
            self.performance, self.resource_governor_enabled, self.resource_cpu_soft,
            self.resource_memory_soft, self.resource_min_disk, self.resource_browser_limit,
            self.request_concurrency, self.per_host_concurrency, self.adaptive_request_concurrency,
            self.locale_box, self.developer, self.include_paths,
        ]
        previous = [widget.blockSignals(True) for widget in widgets]
        try:
            self.performance.setCurrentText(settings.performance_mode)
            self.resource_governor_enabled.setChecked(settings.resource_governor_enabled)
            self.resource_cpu_soft.setValue(settings.resource_cpu_soft_percent)
            self.resource_memory_soft.setValue(settings.resource_memory_soft_percent)
            self.resource_min_disk.setValue(settings.resource_min_free_disk_mb)
            self.resource_browser_limit.setValue(settings.resource_max_browser_instances)
            self.request_concurrency.setValue(settings.request_concurrency)
            self.per_host_concurrency.setMaximum(max(1, min(32, settings.request_concurrency)))
            self.per_host_concurrency.setValue(min(settings.per_host_concurrency, settings.request_concurrency))
            self.adaptive_request_concurrency.setChecked(settings.adaptive_request_concurrency)
            locale_index = self.locale_box.findData(settings.locale)
            self.locale_box.setCurrentIndex(max(0, locale_index))
            self.developer.setChecked(settings.developer_mode)
            self.include_paths.setChecked(settings.diagnostics_include_paths)
        finally:
            for widget, old in strict_zip(widgets, previous, strict=False):
                widget.blockSignals(old)
        profile_labels = {
            "personal": "个人工作",
            "power": "高级用户",
            "professional": "专业工作",
            "developer": "Developer Profile",
        }
        profile_id = str(getattr(settings, "experience_profile", "") or "")
        self.experience_status.setText(profile_labels.get(profile_id, "尚未选择；下次启动将显示 Welcome Center"))
        self._refresh_resource_status()

    def _refresh_resource_status(self) -> None:
        try:
            snapshot = self.context.runner.resource_snapshot()
            decision = snapshot.get("decision") if isinstance(snapshot, dict) else None
        except Exception:
            decision = None
        if not self.context.settings.resource_governor_enabled:
            self.resource_status.setText("Resource Governor 已配置为关闭；重启后生效。硬并发与浏览器租约上限仍保留。")
        elif isinstance(decision, dict):
            reasons = ", ".join(str(x) for x in decision.get("reasons", [])) or "none"
            self.resource_status.setText(
                f"{decision.get('pressure', 'unknown')} · 请求动态上限 {decision.get('request_ceiling', '?')} · "
                f"运行上限 {decision.get('worker_ceiling', '?')} · 浏览器上限 {decision.get('browser_ceiling', '?')} · {reasons}"
            )
        else:
            self.resource_status.setText("等待 Resource Governor 首次采样；阈值修改会持久化并在下次启动完整应用。")

    def activated(self) -> None:
        self._sync_controls_from_settings()
        self._refresh_official_developer_status()
        self.inspectorChanged.emit(
            "Settings",
            {
                "locale": self.context.settings.locale,
                "performance_mode": self.context.settings.performance_mode,
                "resource_governor": self.context.settings.resource_governor_enabled,
                "request_concurrency": self.context.settings.request_concurrency,
                "developer_mode": self.context.settings.developer_mode,
            },
        )

    def refresh_localized_previews(self) -> None:
        self._refresh_resource_status()

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

    def _developer_toggled(self, enabled: bool) -> None:
        settings = self.context.settings
        if enabled and settings.developer_terms_version < DEVELOPER_TERMS_VERSION:
            dialog = _DeveloperTermsDialog(self)
            if dialog.exec() != QDialog.DialogCode.Accepted:
                previous = self.developer.blockSignals(True)
                try:
                    self.developer.setChecked(False)
                finally:
                    self.developer.blockSignals(previous)
                settings.developer_mode = False
                settings.developer_nav_expanded = False
                settings.save(self.context.paths.root / "settings.json")
                self.developerModeChanged.emit(False)
                self.statusMessage.emit("Developer Mode 未启用：必须先同意风险协议与免责协议。")
                return
            settings.developer_terms_version = DEVELOPER_TERMS_VERSION
            settings.developer_terms_accepted_at = datetime.now(timezone.utc).isoformat()
        settings.developer_mode = bool(enabled)
        if not enabled:
            settings.developer_nav_expanded = False
        settings.save(self.context.paths.root / "settings.json")
        self.developerModeChanged.emit(bool(enabled))
        if enabled:
            self.statusMessage.emit("Developer Profile 已启用；公开开发工具可用。内部 stress/fault injection 仍需要 Official Developer capability。")

    def _refresh_official_developer_status(self) -> None:
        manager = getattr(self.context, "developer_access", None)
        buttons = (self.official_developer_login_button, self.root_owner_login_button, self.official_developer_logout_button)
        if manager is None:
            self.official_developer_status.setText("Official Developer Access 后端不可用。")
            for button in buttons:
                button.setEnabled(False)
            return
        if not manager.ready:
            self.official_developer_status.setText(
                "未激活：当前构建没有嵌入 Developer Root Public Trust Artifact。正式 Root Ceremony 完成前会 fail-closed；普通 Personal/Web 功能不受影响。"
            )
            for button in buttons:
                button.setEnabled(False)
            return
        if bool(getattr(self.context, "root_developer_workstation", False)):
            try:
                manager.ensure_root_workstation_session()
            except Exception:
                                                                                                
                                                                                        
                LOGGER.exception("Root Developer workstation session refresh failed closed")
        status = manager.status()
        self.official_developer_login_button.setEnabled(not status.authenticated)
        self.root_owner_login_button.setEnabled(not status.authenticated)
        self.official_developer_logout_button.setEnabled(status.authenticated)
        if not status.authenticated:
            self.official_developer_status.setText("未登录。Official Developer 需要 .aryxdev 登录包 + 本机 Developer Personal Key Vault。")
            return
        root_line = "\nPlatform Root Authority: ACTIVE（Enterprise customer data remains separately authorized）" if "platform.root" in status.capabilities else ""
        binding_line = ""
        if "platform.root" in status.capabilities:
            binding = manager.root_workstation_status()
            if binding.active:
                binding_line = "\nRoot Workstation Binding: VERIFIED（restart will re-issue a fresh short-lived Root session）"
            else:
                binding_line = f"\nRoot Workstation Binding: {binding.reason or 'UNAVAILABLE'}"
        self.official_developer_status.setText(
            f"已认证：{status.kind} / {status.developer_id}\n"
            f"Fingerprint: {status.fingerprint}\n"
            f"Capabilities: {', '.join(status.capabilities)}"
            f"{root_line}{binding_line}\nSession expires: {status.session_expires_at}"
        )

    def _official_developer_login(self) -> None:
        manager = getattr(self.context, "developer_access", None)
        if manager is None or not manager.ready:
            self._refresh_official_developer_status()
            return
        bundle_path, _ = QFileDialog.getOpenFileName(
            self, "选择 Developer Login Bundle", str(self.context.paths.root),
            "Arenyxa Developer (*.aryxdev *.json);;JSON (*.json);;All Files (*)"
        )
        if not bundle_path:
            return
        vault_path, _ = QFileDialog.getOpenFileName(
            self, "选择 Developer Personal Key Vault", str(Path(bundle_path).parent),
            "Developer Vault (*.aryxkey *.json);;JSON (*.json);;All Files (*)"
        )
        if not vault_path:
            return
        passphrase, ok = QInputDialog.getText(self, "Official Developer Login", "Developer Personal Key 口令：", QLineEdit.EchoMode.Password)
        if not ok or not passphrase:
            return
        try:
            from arenyxa.application.developer_identity import load_vault, sign_login_challenge
            bundle = manager.load_bundle(Path(bundle_path))
            challenge = manager.begin_login(bundle)
            signature = sign_login_challenge(load_vault(Path(vault_path)), passphrase, challenge.to_dict())
            manager.complete_login(challenge.challenge_id, signature)
        except Exception as exc:
            self.statusMessage.emit(f"Official Developer Login 失败：{type(exc).__name__}: {exc}")
            QMessageBox.warning(self, "Official Developer Login", f"认证失败。\n\n{type(exc).__name__}: {exc}")
        else:
            self.statusMessage.emit("Official Developer Access 已认证；内部能力继续按证书 capability 精确授权。")
        finally:
            passphrase = ""
            self._refresh_official_developer_status()

    def _root_owner_login(self) -> None:
        manager = getattr(self.context, "developer_access", None)
        if manager is None or not manager.ready:
            self._refresh_official_developer_status()
            return
        bundle_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择 Root Owner / Authority Login Bundle",
            str(self.context.paths.root),
            "Arenyxa Owner Authority (*.aryxowner *.json);;JSON (*.json);;All Files (*)",
        )
        if not bundle_path:
            return
        vault_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择 Owner Device Personal Key Vault",
            str(Path(bundle_path).parent),
            "Owner/Developer Key Vault (*.aryxkey *.json);;JSON (*.json);;All Files (*)",
        )
        if not vault_path:
            return
        passphrase, ok = QInputDialog.getText(
            self, "Root Owner / Authority Login", "Owner Device Key 口令：", QLineEdit.EchoMode.Password
        )
        if not ok or not passphrase:
            return
        try:
            from arenyxa.application.developer_identity import load_vault, sign_login_challenge

            bundle = manager.load_bundle(Path(bundle_path))
            challenge = manager.begin_root_owner_login(bundle)
            vault = load_vault(Path(vault_path))
            signature = sign_login_challenge(vault, passphrase, challenge.to_dict())
            manager.complete_root_owner_login(challenge.challenge_id, signature)
            binding = manager.root_workstation_status()
            self.context.root_developer_workstation = bool(binding.active)
            if binding.active:
                self.developerModeChanged.emit(bool(self.context.settings.developer_mode))
        except Exception as exc:
            self.statusMessage.emit(f"Root Owner / Authority Login 失败：{type(exc).__name__}: {exc}")
            QMessageBox.warning(self, "Root Owner / Authority Login", f"认证失败。\n\n{type(exc).__name__}: {exc}")
        else:
            self.statusMessage.emit(
                "Root Owner / Authority 已认证；Windows Root Workstation Binding 已验证，重启后会重新签发短期 Root Session。Developer Root Private Key 仍保持离线。"
            )
        finally:
            passphrase = ""
            self._refresh_official_developer_status()

    def _official_developer_logout(self) -> None:
        manager = getattr(self.context, "developer_access", None)
        error = None
        if manager is not None:
            try:
                manager.logout()
            except Exception as exc:
                                                                                                 
                                                                                               
                error = exc
        self._refresh_official_developer_status()
        if error is not None:
            self.statusMessage.emit(f"Official Developer 已退出，但审计写入失败：{type(error).__name__}: {error}")
            QMessageBox.warning(self, "Official Developer Logout", f"会话已撤销，但审计写入失败。\n\n{type(error).__name__}: {error}")
        else:
            self.statusMessage.emit("Official Developer Access 已退出。")

    def _include_paths_toggled(self, enabled: bool) -> None:
        self.context.settings.diagnostics_include_paths = bool(enabled)
        self.context.settings.save(self.context.paths.root / "settings.json")

    def run_diagnostics(self) -> None:
        self.diagnostics_button.setEnabled(False)
        self.diagnostic_status.setText("正在后台运行健康诊断…")

        def worker():
            return StartupHealthScanner(
                self.context.paths, installation_root(), ignore_current_session=True
            ).scan()

        def completed(value: object) -> None:
            self.diagnostics_button.setEnabled(True)
            report = value
            findings = list(getattr(report, "findings", []))
            if not findings:
                self.diagnostic_status.setText("诊断完成：未发现需要处理的异常。")
                self.statusMessage.emit("诊断完成：系统健康")
                return
            critical = sum(1 for item in findings if getattr(item, "severity", "") == "critical")
            categories = len(getattr(report, "categories", []))
            self.diagnostic_status.setText(
                f"诊断完成：发现 {len(findings)} 项异常，涉及 {categories} 类，其中 {critical} 项为关键问题。可打开 Repair Center 自动处理。"
            )
            self.statusMessage.emit("诊断完成：发现需要关注的项目")

        def failed(message: str) -> None:
            self.diagnostics_button.setEnabled(True)
            self.diagnostic_status.setText(f"诊断失败：{message}")
            QMessageBox.warning(self, "诊断失败", message)

        run_background(worker, completed, failed)

    def export_diagnostics(self) -> None:
        self.export_diagnostics_button.setEnabled(False)
        self.diagnostic_status.setText("正在生成脱敏诊断包…")

        def worker() -> Path:
            report = StartupHealthScanner(
                self.context.paths, installation_root(), ignore_current_session=True
            ).scan()
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
            destination = self.context.paths.exports / f"Arenyxa-Diagnostics-{timestamp}.zip"
            destination.parent.mkdir(parents=True, exist_ok=True)
            settings_payload = asdict(self.context.settings)
            health_payload = report.to_dict()
            root_text = str(self.context.paths.root)
            install_text = str(installation_root())
            if not self.context.settings.diagnostics_include_paths:
                health_payload["data_root"] = "<redacted>"
                health_payload["install_root"] = "<redacted>"
                for finding in health_payload.get("findings", []):
                    if isinstance(finding, dict):
                        for key in ("detail", "evidence"):
                            value = str(finding.get(key, ""))
                            finding[key] = value.replace(root_text, "<data-root>").replace(install_text, "<install-root>")
            payload = Redactor().redact({
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "version": __version__,
                "platform": platform.platform(),
                "settings": settings_payload,
                "health": health_payload,
            })
            log_path = self.context.paths.readable_log_file
            log_tail = ""
            if log_path.is_file():
                with log_path.open("r", encoding="utf-8", errors="replace") as stream:
                    log_tail = "".join(deque(stream, maxlen=1200))
                if not self.context.settings.diagnostics_include_paths:
                    log_tail = log_tail.replace(root_text, "<data-root>").replace(install_text, "<install-root>")
                log_tail = str(Redactor().redact(log_tail))
            destination.parent.mkdir(parents=True, exist_ok=True)
            fd, raw_temp = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
            os.close(fd)
            temporary = Path(raw_temp)
            try:
                with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr("diagnostic.json", json.dumps(payload, ensure_ascii=False, indent=2))
                    if log_tail:
                        archive.writestr("logs-tail.jsonl", log_tail)
                fsync_existing_file(temporary)
                os.replace(temporary, destination)
            finally:
                temporary.unlink(missing_ok=True)
            return destination

        def completed(value: object) -> None:
            self.export_diagnostics_button.setEnabled(True)
            destination = Path(value)
            self.diagnostic_status.setText(f"诊断包已导出：{destination.name}")
            self.statusMessage.emit("诊断包导出完成")

        def failed(message: str) -> None:
            self.export_diagnostics_button.setEnabled(True)
            self.diagnostic_status.setText(f"诊断包导出失败：{message}")
            QMessageBox.warning(self, "导出诊断包失败", message)

        run_background(worker, completed, failed)

    def reset_settings(self) -> None:
        choice = QMessageBox.question(
            self,
            "恢复默认设置",
            "重置全部应用设置和个性化偏好，并关闭 Developer Mode。Projects、Captures、Exports、数据库与正式结果数据不会删除。继续？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
        )
        if choice != QMessageBox.StandardButton.Yes:
            return
        path = self.context.paths.root / "settings.json"
        if path.is_file():
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
            backup = self.context.paths.root / f"settings.backup-{stamp}.json"
            shutil.copy2(path, backup)
        defaults = AppSettings()
        for item in fields(AppSettings):
            setattr(self.context.settings, item.name, getattr(defaults, item.name))
        self.context.settings.save(path)
        self._sync_controls_from_settings()
        self.themeRequested.emit(defaults.theme)
        self.localeRequested.emit(defaults.locale)
        self.developerModeChanged.emit(False)
        self.uiScaleRequested.emit((defaults.ui_scale_mode, defaults.ui_scale_percent))
        profile = MotionProfile(
            glass_strength=defaults.glass_strength,
            transparency=max(0.18, min(0.52, 0.58 - defaults.glass_strength / 2)),
            blur=float(defaults.blur_strength),
            motion_strength=defaults.motion_strength,
            edge_flow=False,
            live_data_motion=defaults.live_data_motion,
            reduce_motion=defaults.reduce_motion,
            animation_mode=defaults.animation_mode,
            quality=self.context.performance.mode,
        )
        self.motionRequested.emit(profile)
        app = QApplication.instance()
        if app is not None:
            app.setProperty("arenyxa_high_contrast", bool(defaults.high_contrast))
        self.diagnostic_status.setText("设置已恢复默认值。原设置文件已备份；用户数据未删除。")
        self.statusMessage.emit("设置已恢复默认值")


class AboutPage(WorkspacePage):
    

    _STATE_LABELS = {
        "development": "源码 / 开发构建",
        "verified_official": "已验证官方版本",
        "verified_community": "已验证社区版本",
        "modified": "已修改版本",
        "unverified": "未验证发行版",
        "invalid": "发行签名无效",
    }

    _STATE_DETAILS = {
        "development": "源码模式允许自由修改；完整性检查不会把正常开发修改当成需要强制恢复的篡改。",
        "verified_official": "发布证明由内置官方信任根验证。深度校验可进一步核对全部已签名文件与可加载代码。",
        "verified_community": "发布签名有效，但属于社区/第三方发行身份，不代表 Arenyxa 官方背书。",
        "modified": "当前安装内容与签名发行清单不一致。软件仍可使用，但不能继续声称为未修改的已验证发行版。",
        "unverified": "当前发行版没有可验证的发布证明。这不等同于恶意软件，但不能确认其官方来源。",
        "invalid": "发布证明、签名链或发行清单无效。安装版建议运行深度验证并按结果使用自愈修复中心。",
    }

    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
                                                                                       
                                                                                               
        self.setProperty("arenyxa_motion_static", True)
        self.language_manager: LanguageManager | None = None
        self._quick_identity_at = 0.0
        outer = page_layout(self)
        outer.addWidget(PageHeader("关于 Arenyxa", "发行身份、运行环境、隐私边界与项目健康信息"))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        content = QWidget()
        body = QVBoxLayout(content)
        body.setContentsMargins(0, 0, 6, 4)
        body.setSpacing(12)
        scroll.setWidget(content)
        outer.addWidget(scroll, 1)

        hero = SectionCard(theme, f"Arenyxa V{__version__}")
        row = QHBoxLayout()
        icon = QLabel()
        icon.setFixedSize(132, 132)
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_path = application_icon_png_path()
        if icon_path.is_file():
            icon.setPixmap(
                QPixmap(str(icon_path)).scaled(
                    118,
                    118,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
            )
        row.addWidget(icon, 0, Qt.AlignmentFlag.AlignTop)
        info = QVBoxLayout()
        title = QLabel("Arenyxa")
        title.setStyleSheet("font-size: 30px; font-weight: 750;")
        info.addWidget(title)
        subtitle = QLabel("本地优先、开源的 Web 数据采集、检索与网络分析工作台")
        subtitle.setWordWrap(True)
        subtitle.setProperty("muted", True)
        info.addWidget(subtitle)
        self.identity_label = QLabel()
        self.identity_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        info.addWidget(self.identity_label)
        version_line = QLabel(f"Version {__version__} · Python {platform.python_version()} · Qt {self._qt_version()}")
        version_line.setProperty("muted", True)
        version_line.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        info.addWidget(version_line)
        button_row = QHBoxLayout()
        self.verify_button = QPushButton("深度验证安装")
        self.copy_button = QPushButton("复制构建信息")
        self.verify_button.clicked.connect(self._deep_verify)
        self.copy_button.clicked.connect(self._copy_build_info)
        button_row.addWidget(self.verify_button)
        button_row.addWidget(self.copy_button)
        button_row.addStretch()
        info.addLayout(button_row)
        info.addStretch()
        row.addLayout(info, 1)
        hero.body.addLayout(row)
        body.addWidget(hero)

        provenance_card = SectionCard(theme, "发行身份与完整性")
        self.provenance_text = QLabel()
        self.provenance_text.setWordWrap(True)
        self.provenance_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        provenance_card.body.addWidget(self.provenance_text)
        self.integrity_result = QLabel("深度文件验证尚未运行。点击“深度验证安装”可在后台核对程序文件、可加载代码、恢复包和 SQLite 数据库。")
        self.integrity_result.setWordWrap(True)
        self.integrity_result.setProperty("muted", True)
        self.integrity_result.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        provenance_card.body.addWidget(self.integrity_result)
        body.addWidget(provenance_card)

        environment = SectionCard(theme, "运行环境与本地数据")
        self.environment_text = QLabel(
            f"Operating system   {platform.platform()}\n"
            f"Architecture       {platform.machine() or 'unknown'}\n"
            f"Python             {platform.python_version()}\n"
            f"Qt Binding         {self._qt_version()}\n"
            f"Application root   {installation_root()}\n"
            f"Data root          {context.paths.root}\n"
            f"Database           {context.paths.database}\n"
            f"Logs               {context.paths.logs}"
        )
        self.environment_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.environment_text.setProperty("muted", True)
        environment.body.addWidget(self.environment_text)
        body.addWidget(environment)

        privacy = SectionCard(theme, "本地优先与隐私边界")
        privacy_text = QLabel(
            "• Arenyxa 核心任务、数据库、搜索索引和设置默认保存在本机，不要求 Arenyxa 官方云账户。\n"
            "• Arenyxa 核心采集、解析、检索、导出与网络分析采用本地确定性流程。\n"
            "• 抓取目标网站、用户主动启用的服务器/市场/网络分析功能会按其用途访问网络；本地优先不代表“永不联网”。\n"
            "• Cookie、Authorization、Token 等敏感值在日志、诊断和插件边界默认经过脱敏策略。"
        )
        privacy_text.setWordWrap(True)
        privacy.body.addWidget(privacy_text)
        body.addWidget(privacy)

        license_card = SectionCard(theme, "开源许可证与发行边界")
        license_text = QLabel(
            "License: GPL-3.0-or-later\n\n"
            + commercialization_notice()
            + "\n\n发行签名用于验证来源与完整性，不限制源码修改，也不是许可证授权、联网激活或硬件绑定。"
        )
        license_text.setWordWrap(True)
        license_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        license_card.body.addWidget(license_text)
        body.addWidget(license_card)

        capabilities = SectionCard(theme, "核心能力")
        capability_text = QLabel(
            "Capture & Replay · HTTP / Browser / Packet · Search & Data · Dataset Revision · Visualization\n"
            "Workflow & Automation · Headless Server / RBAC · Plugins & Sandbox · Terminal / Packet Console\n"
            "Repair Center · Release Provenance · Liquid Glass & Professional Motion · 10 Languages / RTL"
        )
        capability_text.setWordWrap(True)
        capability_text.setProperty("muted", True)
        capabilities.body.addWidget(capability_text)
        body.addWidget(capabilities)
        body.addStretch()

        self._quick_report = None
        self._refresh_quick_identity()

    def set_language_manager(self, manager: LanguageManager) -> None:
        self.language_manager = manager
        self._refresh_quick_identity()

    def _t(self, text: str) -> str:
        return self.language_manager.literal(text) if self.language_manager is not None else text

    def activated(self) -> None:
                                                                                             
                                                                                     
        self._refresh_quick_identity()

    def _refresh_quick_identity(self) -> None:
        now = time.monotonic()
        if self._quick_report is not None and now - self._quick_identity_at < 5.0:
            self._render_identity(self._quick_report, quick=True)
            return
        report = verify_release_attestation(installation_root(), deep_files=False)
        self._quick_identity_at = now
        self._render_identity(report, quick=True)

    def _render_identity(self, report, *, quick: bool) -> None:
        self._quick_report = report
        identity = self._STATE_LABELS.get(report.state.value, build_identity_summary(report))
        if report.build_id:
            identity += f" · Build {report.build_id}"
        if report.signer_key_id:
            identity += f" · Signer {report.signer_key_id}"
        self.identity_label.setText(self._t(identity))
        self.identity_label.setProperty(
            "muted", report.state.value not in {"verified_official", "verified_community"}
        )
        self.identity_label.style().unpolish(self.identity_label)
        self.identity_label.style().polish(self.identity_label)
        detail = self._STATE_DETAILS.get(report.state.value, "发行身份检查已完成。")
        hash_text = report.manifest_hash[:16] + "…" if report.manifest_hash else "n/a"
        scope = (
            "快速状态只验证发行证明；只有“深度验证安装”才会逐文件核对安装内容。"
            if quick
            else "当前身份状态已经包含本次深度安装完整性校验结果。"
        )
        metadata = f"Version: {report.version or __version__} · Channel: {report.channel or 'n/a'}"
        self.provenance_text.setText(
            self._t(f"{identity}\n{detail}\n\n{metadata}\nManifest SHA-256: {hash_text}\n{scope}")
        )

    def _deep_verify(self) -> None:
        if not self.verify_button.isEnabled():
            return
        self.verify_button.setEnabled(False)
        self.verify_button.setText(self._t("正在后台验证…"))
        self.integrity_result.setText(self._t("正在核对发布证明、签名清单、安装文件、额外可加载代码、恢复包与 SQLite 完整性…"))

        def worker() -> dict[str, object]:
            report = verify_release_attestation(installation_root(), deep_files=True)
            try:
                database_health = self.context.store.integrity_check()
            except Exception as exc:                                              
                database_health = f"ERROR: {exc}"
            return {"provenance": report, "database_health": database_health}

        def completed(result: object) -> None:
            self.verify_button.setEnabled(True)
            self.verify_button.setText(self._t("重新深度验证"))
            if not isinstance(result, dict):
                self.integrity_result.setText(self._t("深度验证返回了无法识别的结果。"))
                return
            report = result.get("provenance")
            if report is None:
                self.integrity_result.setText(self._t("深度验证未返回发行完整性结果。"))
                return
            modified = list(getattr(report, "modified_files", []))
            unexpected = list(getattr(report, "unexpected_files", []))
            db_health = str(result.get("database_health", "unknown"))
            state_name = self._STATE_LABELS.get(getattr(report.state, "value", ""), getattr(report, "display_name", "unknown"))
            lines = [
                f"发行状态：{state_name}",
                f"签名清单中已修改文件：{len(modified)}",
                f"额外可加载文件：{len(unexpected)}",
                f"SQLite integrity_check：{db_health}",
            ]
            if modified:
                lines.append("已修改：" + ", ".join(modified[:8]))
            if unexpected:
                lines.append("额外文件：" + ", ".join(unexpected[:8]))
            notes = list(getattr(report, "notes", []))
            if notes:
                lines.append("说明：" + " | ".join(notes[:4]))
            lines.append("深度验证仅读取本机安装内容与数据库完整性信息，不需要联网。")
            self.integrity_result.setText(self._t("\n".join(lines)))
            self._render_identity(report, quick=False)

        def failed(message: str) -> None:
            self.verify_button.setEnabled(True)
            self.verify_button.setText(self._t("重新深度验证"))
            self.integrity_result.setText(self._t(f"深度验证失败：{message}"))

        run_background(worker, completed, failed)

    def _copy_build_info(self) -> None:
        report = self._quick_report or verify_release_attestation(installation_root(), deep_files=False)
        lines = [
            f"Arenyxa {__version__}",
            f"Release: {report.display_name}",
            f"Channel: {report.channel}",
            f"Build ID: {report.build_id or 'n/a'}",
            f"Signer: {report.signer_key_id or 'n/a'}",
            f"Manifest SHA-256: {report.manifest_hash or 'n/a'}",
            f"Python: {platform.python_version()}",
            f"Qt Binding: {self._qt_version()}",
            f"Platform: {platform.platform()}",
            "License: GPL-3.0-or-later",
        ]
        QApplication.clipboard().setText("\n".join(lines))
        self.statusMessage.emit("构建信息已复制到剪贴板")

    @staticmethod
    def _qt_version() -> str:
        try:
            from arenyxa.qt_compat import binding_name, binding_version

            return f"{binding_name()} {binding_version()}"
        except (ImportError, AttributeError):
            return "unknown"

