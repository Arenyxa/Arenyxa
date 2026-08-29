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
from arenyxa import __display_version__ as __version__
from arenyxa.compat import strict_zip
from arenyxa.config import AppSettings
from arenyxa.application.developer_safety import (
    DEVELOPER_TERMS_VERSION,
    RISK_AGREEMENT_TEXT,
    RISK_AGREEMENT_TITLE,
    WAIVER_TEXT,
    WAIVER_TITLE,
)
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import MotionProfile
from arenyxa.provenance import build_identity_summary, commercialization_notice, verify_release_attestation
from arenyxa.repair import StartupHealthScanner, installation_root
from arenyxa.infrastructure.atomic_io import fsync_existing_file, read_text_limited
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


LOGGER = logging.getLogger(__name__)

from arenyxa.presentation.pages.settings_support import AboutPage, ThemePreviewCard, _DeveloperTermsDialog

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
        self.developer = QCheckBox("Developer Experience（仅界面偏好；不会授予 Developer Authority）")
        self.advanced_card.body.addWidget(self.developer)
        self.direct_shell = QCheckBox("Direct Shell（允许 PowerShell / CMD / Persistent Shell；仅 Developer Mode）")
        self.direct_shell.setToolTip("完整 Shell 使用当前 Windows 用户权限执行；高风险命令仍会额外确认并写入终端审计。")
        self.advanced_card.body.addWidget(self.direct_shell)

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

        self.official_developer_card = SectionCard(theme, "官方开发者授权")
        official_hint = QLabel(
            "用于 Arenyxa 官方开发调试能力。登录需要 .aryxdev Developer Login Bundle 与本机匹配的 "
            "Developer Personal Key Vault，并通过一次性私钥挑战；认证后只获得证书明确列出的 capability。"
            "它与公开 Developer Profile、企业管理员权限和 Root Developer 最高技术权限是彼此独立的授权流程。"
        )
        official_hint.setProperty("muted", True)
        official_hint.setWordWrap(True)
        self.official_developer_card.body.addWidget(official_hint)
        self.official_developer_status = QLabel()
        self.official_developer_status.setWordWrap(True)
        self.official_developer_status.setProperty("muted", True)
        self.official_developer_card.body.addWidget(self.official_developer_status)
        official_row = QHBoxLayout()
        self.official_developer_login_button = QPushButton("登录官方开发者")
        self.official_developer_logout_button = QPushButton("退出官方开发者")
        for button in (self.official_developer_login_button, self.official_developer_logout_button):
            official_row.addWidget(button)
        official_row.addStretch()
        self.official_developer_card.body.addLayout(official_row)
        body.addWidget(self.official_developer_card)

        # Root Developer is an explicit break-glass entry, not a normal preference.
        # Keep it completely hidden unless the user has deliberately selected the
        # Developer experience and enabled Developer Mode in Settings.
        self.root_developer_card = SectionCard(theme, "Root Developer · 最高技术权限")
        root_hint = QLabel(
            "仅供根开发者进行最高技术权限调试。这里使用独立的 Root Owner 身份包与设备密钥完成强认证，"
            "并继续执行 Root Integrity Challenge；它不是普通官方开发者登录，也不会由企业管理员身份自动获得。"
        )
        root_hint.setWordWrap(True)
        root_hint.setProperty("muted", True)
        self.root_developer_card.body.addWidget(root_hint)
        self.root_developer_status = QLabel()
        self.root_developer_status.setWordWrap(True)
        self.root_developer_status.setProperty("muted", True)
        self.root_developer_card.body.addWidget(self.root_developer_status)
        root_row = QHBoxLayout()
        self.root_developer_login_button = QPushButton("登录 Root Developer")
        self.root_developer_login_button.setToolTip(
            "最高风险权限入口：仅在 Developer Experience + Developer Mode 同时启用时显示。"
        )
        root_row.addWidget(self.root_developer_login_button)
        self.root_developer_logout_button = QPushButton("退出 Root Developer")
        self.root_developer_logout_button.setVisible(False)
        root_row.addWidget(self.root_developer_logout_button)
        root_row.addStretch()
        self.root_developer_card.body.addLayout(root_row)
        body.addWidget(self.root_developer_card)
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
        self.direct_shell.toggled.connect(self._direct_shell_toggled)
        self.include_paths.toggled.connect(self._include_paths_toggled)
        self.diagnostics_button.clicked.connect(self.run_diagnostics)
        self.repair_button.clicked.connect(self.repairRequested.emit)
        self.export_diagnostics_button.clicked.connect(self.export_diagnostics)
        self.reset_settings_button.clicked.connect(self.reset_settings)
        self.reopen_welcome_button.clicked.connect(self.welcomeRequested.emit)
        self.official_developer_login_button.clicked.connect(self._official_developer_login)
        self.official_developer_logout_button.clicked.connect(self._official_developer_logout)
        self.root_developer_login_button.clicked.connect(self._root_developer_login)
        self.root_developer_logout_button.clicked.connect(self._root_developer_logout)

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
            self.locale_box, self.developer, self.direct_shell, self.include_paths,
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
            self.direct_shell.setChecked(bool(settings.developer_direct_shell_enabled and settings.developer_mode))
            self.direct_shell.setEnabled(bool(settings.developer_mode))
            self.include_paths.setChecked(settings.diagnostics_include_paths)
        finally:
            for widget, old in strict_zip(widgets, previous, strict=False):
                widget.blockSignals(old)
        profile_labels = {
            "personal": "一般用户 · 简单模式",
            "power": "高级用户",
            "professional": "专业工作",
            "developer": "Developer Profile",
            "enterprise": "企业工作模式",
            "root_developer": "Root Developer",
        }
        profile_id = str(getattr(settings, "experience_profile", "") or "")
        self.experience_status.setText(profile_labels.get(profile_id, "尚未选择；下次启动将显示 Welcome Center"))
        self._refresh_resource_status()
        self._refresh_root_developer_entry()

    def _root_developer_entry_allowed(self) -> bool:
        settings = self.context.settings
        profile = str(getattr(settings, "experience_profile", "") or "").strip().casefold()
        # Keep the entry visible after a successful Root promotion so its authenticated
        # status remains inspectable.  Root promotion itself can only originate from a
        # Developer experience + Developer Mode request.
        return bool(settings.developer_mode and profile in {"developer", "root_developer"})

    def _refresh_root_developer_entry(self) -> None:
        visible = self._root_developer_entry_allowed()
        self.root_developer_card.setVisible(visible)
        if not visible:
            return
        manager = getattr(self.context, "developer_access", None)
        if manager is None:
            self.root_developer_status.setText("Root Developer 认证组件当前不可用。")
            self.root_developer_login_button.setEnabled(False)
            return
        if not manager.ready:
            self.root_developer_status.setText(
                "Root Developer 信任信息尚未就绪，因此登录已安全关闭（fail-closed）。"
            )
            self.root_developer_login_button.setEnabled(False)
            return
        status = manager.status()
        root_active = bool(
            status.authenticated
            and status.kind == "root_owner"
            and "platform.root" in status.capabilities
            and bool(getattr(self.context, "root_developer_workstation", False))
        )
        if root_active:
            self.root_developer_status.setText(
                f"已激活：{status.developer_id}\n"
                f"Fingerprint: {status.fingerprint}\n"
                "当前进程拥有经过验证的 platform.root 会话。退出只结束本次 Root Developer 会话，"
                "不会修改 Root 信任材料或工作站注册。"
            )
            self.root_developer_login_button.setText("Root Developer 已激活")
            self.root_developer_login_button.setEnabled(False)
            self.root_developer_logout_button.setVisible(True)
            self.root_developer_logout_button.setEnabled(True)
            return
        self.root_developer_logout_button.setVisible(False)
        self.root_developer_login_button.setText("登录 Root Developer")
        self.root_developer_login_button.setEnabled(True)
        self.root_developer_status.setText(
            "未登录。点击后会先显示最高风险确认，再要求 Root Owner 身份包、设备密钥口令和完整性验证；"
            "全部通过后才会为当前进程建立 platform.root。"
        )

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
        self._refresh_root_developer_entry()
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
        self.direct_shell.setEnabled(bool(enabled))
        if not enabled:
            settings.developer_nav_expanded = False
            settings.developer_direct_shell_enabled = False
            previous_shell = self.direct_shell.blockSignals(True)
            try:
                self.direct_shell.setChecked(False)
            finally:
                self.direct_shell.blockSignals(previous_shell)
        settings.save(self.context.paths.root / "settings.json")
        self.developerModeChanged.emit(bool(enabled))
        self._refresh_root_developer_entry()
        if enabled:
            self.statusMessage.emit("Developer Profile 已启用；公开开发工具可用。内部 stress/fault injection 仍需要官方开发者证书明确授权。")


    def _direct_shell_toggled(self, enabled: bool) -> None:
        settings = self.context.settings
        if enabled and not settings.developer_mode:
            previous = self.direct_shell.blockSignals(True)
            try:
                self.direct_shell.setChecked(False)
            finally:
                self.direct_shell.blockSignals(previous)
            settings.developer_direct_shell_enabled = False
            self.statusMessage.emit("Direct Shell 未启用：请先启用 Developer Mode。")
            return
        if enabled:
            box = QMessageBox(self)
            box.setWindowTitle("启用 Direct Shell")
            box.setIcon(QMessageBox.Icon.Warning)
            box.setText("PowerShell / CMD / Persistent Shell 将以当前 Windows 用户权限执行。")
            box.setInformativeText("这不是安全沙箱。Arenyxa 会保留进程树终止、输出预算、敏感信息脱敏与高风险命令提示，但无法限制当前用户本身拥有的系统权限。")
            box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            box.setDefaultButton(QMessageBox.StandardButton.No)
            if box.exec() != QMessageBox.StandardButton.Yes:
                previous = self.direct_shell.blockSignals(True)
                try:
                    self.direct_shell.setChecked(False)
                finally:
                    self.direct_shell.blockSignals(previous)
                settings.developer_direct_shell_enabled = False
                settings.save(self.context.paths.root / "settings.json")
                return
        settings.developer_direct_shell_enabled = bool(enabled)
        settings.save(self.context.paths.root / "settings.json")
        self.statusMessage.emit("Direct Shell 已启用。" if enabled else "Direct Shell 已关闭。")

    def _refresh_official_developer_status(self) -> None:
        manager = getattr(self.context, "developer_access", None)
        buttons = (self.official_developer_login_button, self.official_developer_logout_button)
        if manager is None:
            self.official_developer_status.setText("官方开发者授权后端不可用。")
            for button in buttons:
                button.setEnabled(False)
            return
        if not manager.ready:
            self.official_developer_status.setText(
                "当前构建没有可用的官方 Developer Trust Artifact，因此官方开发者登录保持关闭。"
                "Personal、Professional 和公开 Developer Profile 不受影响。"
            )
            for button in buttons:
                button.setEnabled(False)
            return
        status = manager.status()
        root_active = bool(status.authenticated and "platform.root" in status.capabilities)
        if root_active:
            self.official_developer_login_button.setEnabled(False)
            self.official_developer_logout_button.setEnabled(False)
            self.official_developer_logout_button.setText("退出官方开发者")
            self.official_developer_status.setText(
                "当前活动的是 Root Developer 会话。官方开发者授权不会管理或结束 Root Developer；"
                "请使用下方“Root Developer · 最高技术权限”区域查看或退出。"
            )
            return
        self.official_developer_login_button.setEnabled(not status.authenticated)
        self.official_developer_logout_button.setEnabled(status.authenticated)
        self.official_developer_logout_button.setText("退出官方开发者")
        if not status.authenticated:
            self.official_developer_status.setText(
                "未登录。需要 .aryxdev Developer Login Bundle 与本机匹配的 Developer Personal Key Vault。"
            )
            return
        self.official_developer_status.setText(
            f"已认证：{status.developer_id}\n"
            f"Fingerprint: {status.fingerprint}\n"
            f"Capabilities: {', '.join(status.capabilities)}\n"
            f"Session expires: {status.session_expires_at}"
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
        passphrase, ok = QInputDialog.getText(self, "官方开发者登录", "Developer Personal Key 口令：", QLineEdit.EchoMode.Password)
        if not ok or not passphrase:
            return
        try:
            from arenyxa.application.developer_identity import load_vault, sign_login_challenge
            bundle = manager.load_bundle(Path(bundle_path))
            challenge = manager.begin_login(bundle)
            signature = sign_login_challenge(load_vault(Path(vault_path)), passphrase, challenge.to_dict())
            manager.complete_login(challenge.challenge_id, signature)
        except Exception as exc:
            self.statusMessage.emit(f"官方开发者登录失败：{type(exc).__name__}: {exc}")
            QMessageBox.warning(self, "官方开发者登录", f"认证失败。\n\n{type(exc).__name__}: {exc}")
        else:
            self.statusMessage.emit("官方开发者已认证；内部能力继续按证书 capability 精确授权。")
            self.developerModeChanged.emit(bool(self.context.settings.developer_mode))
        finally:
            passphrase = ""
            self._refresh_official_developer_status()

    def _root_developer_login(self) -> None:
        if not self._root_developer_entry_allowed():
            self._refresh_root_developer_entry()
            return
        manager = getattr(self.context, "developer_access", None)
        if manager is None or not manager.ready:
            self._refresh_root_developer_entry()
            return

        from arenyxa.presentation.root_developer_gate import confirm_root_developer_login

        if not confirm_root_developer_login(self):
            self.statusMessage.emit("Root Developer 登录已取消；未发生任何权限变化。")
            return

        owner_bundle_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择 Root Owner Login Bundle",
            str(Path.home()),
            "Arenyxa Root Owner Login (*.aryxowner *.aryxowner.json *.json);;JSON (*.json);;All Files (*)",
        )
        if not owner_bundle_path:
            return
        vault_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择 Root Owner Device Key Vault",
            str(Path(owner_bundle_path).parent),
            "Arenyxa Owner Key Vault (*.aryxkey *.json);;JSON (*.json);;All Files (*)",
        )
        if not vault_path:
            return
        passphrase, ok = QInputDialog.getText(
            self,
            "Root Developer · Root Owner 强认证",
            "Root Owner Device Key 口令：",
            QLineEdit.EchoMode.Password,
        )
        if not ok or not passphrase:
            return

        try:
            from arenyxa.application.root_owner_identity import (
                load_owner_device_vault,
                sign_owner_login_challenge,
            )

            raw_bundle = json.loads(
                read_text_limited(Path(owner_bundle_path), 2 * 1024 * 1024, encoding="utf-8")
            )
            if not isinstance(raw_bundle, dict):
                raise ValueError("Root Owner Login Bundle 必须是 JSON object")
            challenge = manager.begin_root_owner_login(raw_bundle)
            signature = sign_owner_login_challenge(
                load_owner_device_vault(Path(vault_path)),
                passphrase,
                challenge.to_dict(),
                raw_bundle,
            )
            manager.complete_root_owner_login(challenge.challenge_id, signature)
            status = manager.status()
            if not (
                status.authenticated
                and status.kind == "root_owner"
                and "platform.root" in status.capabilities
            ):
                raise RuntimeError("Root Owner proof completed without a platform.root session")

            # complete_root_owner_login provisions/verifies the protected workstation
            # binding.  Only after that succeeds may the live ExperienceContext project
            # the Root Developer surface.
            binding = manager.root_workstation_status()
            if not bool(getattr(binding, "active", False)):
                manager.logout(reason="ROOT_WORKSTATION_BIND_REQUIRED")
                raise RuntimeError(
                    "Root Owner proof succeeded, but the protected Root Workstation binding is not active"
                )
            self.context.root_developer_workstation = True
            self.context.root_workstation_registered = bool(manager.root_workstation_registered())
            self.context.root_capability_state = manager.root_capability_state()
        except Exception as exc:
            self.context.root_developer_workstation = False
            self.statusMessage.emit(
                f"Root Developer 登录失败：{type(exc).__name__}: {exc}"
            )
            QMessageBox.critical(
                self,
                "Root Developer 认证失败",
                "Root Developer 未激活。安全边界保持 fail-closed。\n\n"
                f"{type(exc).__name__}: {exc}",
            )
        else:
            self.statusMessage.emit(
                "Root Owner 强认证与 Root Integrity 验证通过；Root Developer 已为当前进程激活。"
            )
            # Reuse the existing navigation/Experience rebuild signal instead of adding
            # a second authority path. NavigationContextFactory will promote the live
            # context to ROOT_DEVELOPER only when this verified Root session is active.
            self.developerModeChanged.emit(True)
            QMessageBox.information(
                self,
                "Root Developer 已激活",
                "Root Developer Authority 已激活。\n\n"
                "这是当前进程的受验证 Root 会话；不会因为 Settings 偏好而自动恢复。"
                "下次启动仍将按 Root Workstation 安全策略重新验证。",
            )
        finally:
            passphrase = ""
            self._refresh_official_developer_status()
            self._refresh_root_developer_entry()

    def _official_developer_logout(self) -> None:
        manager = getattr(self.context, "developer_access", None)
        if manager is None:
            self._refresh_official_developer_status()
            return
        try:
            status = manager.status()
            if status.authenticated and "platform.root" in status.capabilities:
                self.statusMessage.emit("当前活动的是 Root Developer；请使用下方 Root Developer 区域退出。")
                self._refresh_official_developer_status()
                self._refresh_root_developer_entry()
                return
            manager.logout()
        except Exception as exc:
            self.statusMessage.emit(f"官方开发者会话已退出，但审计写入失败：{type(exc).__name__}: {exc}")
            QMessageBox.warning(self, "官方开发者退出", f"会话已撤销，但审计写入失败。\n\n{type(exc).__name__}: {exc}")
        else:
            self.statusMessage.emit("官方开发者授权已退出。")
        self._refresh_official_developer_status()
        self._refresh_root_developer_entry()

    def _root_developer_logout(self) -> None:
        logout_started = time.perf_counter()
        manager = getattr(self.context, "developer_access", None)
        if manager is None:
            self._refresh_root_developer_entry()
            return
        error = None
        try:
            status = manager.status()
            if not (status.authenticated and "platform.root" in status.capabilities):
                self.statusMessage.emit("当前没有活动的 Root Developer 会话。")
                return
            manager.logout()
            self.context.root_developer_workstation = False
            self.developerModeChanged.emit(bool(self.context.settings.developer_mode))
        except (ArenyxaError, OSError, RuntimeError, ValueError) as exc:
            error = exc
        finally:
            self.context.navigation_metrics["root_logout_latency_ms"] = (
                time.perf_counter() - logout_started
            ) * 1000.0
            self._refresh_official_developer_status()
            self._refresh_root_developer_entry()
        if error is not None:
            self.statusMessage.emit(f"Root Developer 会话已撤销，但审计写入失败：{type(error).__name__}: {error}")
            QMessageBox.warning(self, "Root Developer 退出", f"会话已撤销，但审计写入失败。\n\n{type(error).__name__}: {error}")
        else:
            self.statusMessage.emit("Root Developer 已退出；Root 信任材料和工作站注册保持不变。")

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
