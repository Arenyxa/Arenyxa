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
from arenyxa import __display_version__, __display_version__ as __version__, __engineering_build__
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
from arenyxa.presentation.language import LOCALES, LanguageManager, current_text, literal_for_locale, source_text
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.themes import ThemeTokens
from arenyxa.presentation.widgets import (
    PageHeader,
    SectionCard,
    ScrollSafeComboBox,
    ScrollSafeSpinBox,
)

THEME_META = {
    "modern_dark": ("theme.modern_dark.meta", "theme.modern_dark.description"),
    "aurora_glass": ("theme.aurora_glass.meta", "theme.aurora_glass.description"),
    "clean_light": ("theme.clean_light.meta", "theme.clean_light.description"),
    "terminal_green": ("theme.terminal_green.meta", "theme.terminal_green.description"),
    "professional_graphite": ("theme.professional_graphite.meta", "theme.professional_graphite.description"),
    "blue_productivity": ("theme.blue_productivity.meta", "theme.blue_productivity.description"),
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
        meta_key, description_key = THEME_META.get(self.theme_id, ("theme.default.meta", "theme.default.description"))
        meta = current_text(meta_key)
        description = current_text(description_key)
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
        self.setWindowTitle(source_text("developer.terms.dialog_title"))
        self.setProperty("i18n_key_window_title", "developer.terms.dialog_title")
        self.setModal(True)
        self.setMinimumWidth(620)
        layout = QVBoxLayout(self)

        risk_title = QLabel(source_text("developer.terms.risk_title"))
        risk_title.setProperty("i18n_key_text", "developer.terms.risk_title")
        risk_title.setStyleSheet("font-weight: 700;")
        risk_text = QLabel(source_text("developer.terms.risk_text"))
        risk_text.setProperty("i18n_key_text", "developer.terms.risk_text")
        risk_text.setWordWrap(True)
        risk_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(risk_title)
        layout.addWidget(risk_text)

        waiver_title = QLabel(source_text("developer.terms.waiver_title"))
        waiver_title.setProperty("i18n_key_text", "developer.terms.waiver_title")
        waiver_title.setStyleSheet("font-weight: 700; margin-top: 8px;")
        waiver_text = QLabel(source_text("developer.terms.waiver_text"))
        waiver_text.setProperty("i18n_key_text", "developer.terms.waiver_text")
        waiver_text.setWordWrap(True)
        waiver_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(waiver_title)
        layout.addWidget(waiver_text)

        self.risk_accept = QCheckBox(source_text("developer.terms.accept_risk"))
        self.risk_accept.setProperty("i18n_key_text", "developer.terms.accept_risk")
        self.waiver_accept = QCheckBox(source_text("developer.terms.accept_waiver"))
        self.waiver_accept.setProperty("i18n_key_text", "developer.terms.accept_waiver")
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
        "development": "about.state.development",
        "verified_official": "about.state.verified_official",
        "verified_community": "about.state.verified_community",
        "modified": "about.state.modified",
        "unverified": "about.state.unverified",
        "invalid": "about.state.invalid",
    }

    _STATE_DETAILS = {
        "development": "about.detail.development",
        "verified_official": "about.detail.verified_official",
        "verified_community": "about.detail.verified_community",
        "modified": "about.detail.modified",
        "unverified": "about.detail.unverified",
        "invalid": "about.detail.invalid",
    }

    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
                                                                                       
                                                                                               
        self.setProperty("arenyxa_motion_static", True)
        self.language_manager: LanguageManager | None = None
        self._quick_identity_at = 0.0
        outer = page_layout(self)
        outer.addWidget(PageHeader(
            source_text("about.page.title"),
            source_text("about.page.subtitle"),
            title_key="about.page.title",
            subtitle_key="about.page.subtitle",
        ))

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

        hero = SectionCard(theme, f"Arenyxa v{__display_version__}")
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
        subtitle = QLabel(source_text("about.hero.subtitle"))
        subtitle.setProperty("i18n_key_text", "about.hero.subtitle")
        subtitle.setWordWrap(True)
        subtitle.setProperty("muted", True)
        info.addWidget(subtitle)
        self.identity_label = QLabel()
        self.identity_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        info.addWidget(self.identity_label)
        version_line = QLabel(
            current_text("about.version_line").format(
                public=__display_version__,
                engineering=__engineering_build__,
                python=platform.python_version(),
                qt=self._qt_version(),
            )
        )
        version_line.setProperty("muted", True)
        version_line.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        info.addWidget(version_line)
        button_row = QHBoxLayout()
        self.verify_button = QPushButton(source_text("about.verify.button"))
        self.verify_button.setProperty("i18n_key_text", "about.verify.button")
        self.copy_button = QPushButton(source_text("about.copy.button"))
        self.copy_button.setProperty("i18n_key_text", "about.copy.button")
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

        provenance_card = SectionCard(theme, source_text("about.provenance.title"), title_key="about.provenance.title")
        self.provenance_text = QLabel()
        self.provenance_text.setWordWrap(True)
        self.provenance_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        provenance_card.body.addWidget(self.provenance_text)
        self.integrity_result = QLabel(source_text("about.verify.not_run"))
        self.integrity_result.setProperty("i18n_key_text", "about.verify.not_run")
        self.integrity_result.setWordWrap(True)
        self.integrity_result.setProperty("muted", True)
        self.integrity_result.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        provenance_card.body.addWidget(self.integrity_result)
        body.addWidget(provenance_card)

        environment = SectionCard(theme, source_text("about.environment.title"), title_key="about.environment.title")
        self.environment_text = QLabel(
            current_text("about.environment.summary").format(
                os=platform.platform(),
                architecture=platform.machine() or "unknown",
                python=platform.python_version(),
                qt=self._qt_version(),
                app_root=installation_root(),
                data_root=context.paths.root,
                database=context.paths.database,
                logs=context.paths.logs,
            )
        )
        self.environment_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.environment_text.setProperty("muted", True)
        environment.body.addWidget(self.environment_text)
        body.addWidget(environment)

        privacy = SectionCard(theme, source_text("about.privacy.title"), title_key="about.privacy.title")
        privacy_text = QLabel(source_text("about.privacy.text"))
        privacy_text.setProperty("i18n_key_text", "about.privacy.text")
        privacy_text.setWordWrap(True)
        privacy.body.addWidget(privacy_text)
        body.addWidget(privacy)

        license_card = SectionCard(theme, source_text("about.license.title"), title_key="about.license.title")
        license_text = QLabel(
            current_text("about.license.text").format(notice=commercialization_notice())
        )
        license_text.setWordWrap(True)
        license_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        license_card.body.addWidget(license_text)
        body.addWidget(license_card)

        capabilities = SectionCard(theme, source_text("about.capabilities.title"), title_key="about.capabilities.title")
        capability_text = QLabel(source_text("about.capabilities.text"))
        capability_text.setProperty("i18n_key_text", "about.capabilities.text")
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
        label_key = self._STATE_LABELS.get(report.state.value)
        identity = current_text(label_key) if label_key else build_identity_summary(report)
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
        detail_key = self._STATE_DETAILS.get(report.state.value)
        detail = current_text(detail_key) if detail_key else current_text("about.detail.complete")
        hash_text = report.manifest_hash[:16] + "…" if report.manifest_hash else "n/a"
        scope = current_text("about.provenance.scope_quick" if quick else "about.provenance.scope_deep")
        metadata = current_text("about.provenance.metadata").format(
            version=report.version or __version__,
            channel=report.channel or "n/a",
            hash=hash_text,
        )
        self.provenance_text.setText(f"{identity}\n{detail}\n\n{metadata}\n{scope}")

    def _deep_verify(self) -> None:
        if not self.verify_button.isEnabled():
            return
        self.verify_button.setEnabled(False)
        self.verify_button.setText(current_text("about.verify.running_button"))
        self.integrity_result.setText(current_text("about.verify.running"))

        def worker() -> dict[str, object]:
            report = verify_release_attestation(installation_root(), deep_files=True)
            try:
                database_health = self.context.store.integrity_check()
            except Exception as exc:                                              
                database_health = f"ERROR: {exc}"
            return {"provenance": report, "database_health": database_health}

        def completed(result: object) -> None:
            self.verify_button.setEnabled(True)
            self.verify_button.setText(current_text("about.verify.rerun"))
            if not isinstance(result, dict):
                self.integrity_result.setText(current_text("about.verify.unrecognized"))
                return
            report = result.get("provenance")
            if report is None:
                self.integrity_result.setText(current_text("about.verify.no_provenance"))
                return
            modified = list(getattr(report, "modified_files", []))
            unexpected = list(getattr(report, "unexpected_files", []))
            db_health = str(result.get("database_health", "unknown"))
            state_key = self._STATE_LABELS.get(getattr(report.state, "value", ""))
            state_name = current_text(state_key) if state_key else getattr(report, "display_name", "unknown")
            lines = [
                current_text("about.verify.state").format(state=state_name),
                current_text("about.verify.modified_count").format(count=len(modified)),
                current_text("about.verify.unexpected_count").format(count=len(unexpected)),
                current_text("about.verify.sqlite").format(status=db_health),
            ]
            if modified:
                lines.append(current_text("about.verify.modified").format(files=", ".join(modified[:8])))
            if unexpected:
                lines.append(current_text("about.verify.unexpected").format(files=", ".join(unexpected[:8])))
            notes = list(getattr(report, "notes", []))
            if notes:
                lines.append(current_text("about.verify.notes").format(notes=" | ".join(notes[:4])))
            lines.append(current_text("about.verify.offline"))
            self.integrity_result.setText("\n".join(lines))
            self._render_identity(report, quick=False)

        def failed(message: str) -> None:
            self.verify_button.setEnabled(True)
            self.verify_button.setText(current_text("about.verify.rerun"))
            self.integrity_result.setText(current_text("about.verify.failed").format(message=message))

        run_background(worker, completed, failed)

    def _copy_build_info(self) -> None:
        report = self._quick_report or verify_release_attestation(installation_root(), deep_files=False)
        lines = [
            f"Arenyxa v{__display_version__}",
            current_text("about.copy.engineering").format(value=__engineering_build__),
            current_text("about.copy.release").format(value=report.display_name),
            current_text("about.copy.channel").format(value=report.channel),
            current_text("about.copy.build_id").format(value=report.build_id or "n/a"),
            current_text("about.copy.signer").format(value=report.signer_key_id or "n/a"),
            current_text("about.copy.manifest").format(value=report.manifest_hash or "n/a"),
            current_text("about.copy.python").format(value=platform.python_version()),
            current_text("about.copy.qt").format(value=self._qt_version()),
            current_text("about.copy.platform").format(value=platform.platform()),
            "License: GPL-3.0-or-later",
        ]
        QApplication.clipboard().setText("\n".join(lines))
        self.statusMessage.emit(current_text("about.copy.done"))

    @staticmethod
    def _qt_version() -> str:
        try:
            from arenyxa.qt_compat import binding_name, binding_version

            return f"{binding_name()} {binding_version()}"
        except (ImportError, AttributeError):
            return "unknown"
