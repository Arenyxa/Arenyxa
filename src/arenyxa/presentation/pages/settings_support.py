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
from arenyxa import __display_version__, __version__
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

        hero = SectionCard(theme, f"Arenyxa V{__display_version__}")
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
        version_line = QLabel(f"Version {__display_version__} · Python {platform.python_version()} · Qt {self._qt_version()}")
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
            f"Arenyxa {__display_version__}",
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

