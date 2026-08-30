from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from arenyxa.qt_compat.QtCore import QSettings, QSize, Qt, QThreadPool, QTimer, QUrl, Signal
from arenyxa.qt_compat.QtGui import QAction, QColor, QCloseEvent, QDesktopServices, QFont, QIcon, QKeySequence, QPainter, QPixmap, QShortcut
from arenyxa.qt_compat.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QBoxLayout,
    QButtonGroup,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QProgressBar,
    QScrollArea,
    QStackedWidget,
    QStatusBar,
    QSystemTrayIcon,
    QMenu,
    QVBoxLayout,
    QWidget,
)
from arenyxa import __display_version__ as __version__
from arenyxa.branding import preferred_window_icon_path
from arenyxa.bootstrap import ApplicationContext
from arenyxa.application.experience import apply_experience_profile
from arenyxa.domain.enums import MotionIntent
from arenyxa.domain.models import MotionProfile
from arenyxa.presentation.background import begin_background_shutdown, run_background
from arenyxa.presentation.glass import GlassPanel
from arenyxa.presentation.language import LanguageManager
from arenyxa.presentation.launch_geometry import LaunchGeometryPlan
from arenyxa.presentation.motion import MotionOrchestrator
from arenyxa.presentation.pages.base import WorkspacePage
from arenyxa.presentation.pages.dashboard import DashboardPage
from arenyxa.presentation.pages.data import DataPage, SearchPage, VersionPage
from arenyxa.presentation.pages.network import NetworkPage
from arenyxa.presentation.pages.proxy import ProxyPage
from arenyxa.presentation.pages.mitm_proxy import MitmInterceptionPage
from arenyxa.presentation.pages.recovery import RecoveryCenterPage
from arenyxa.presentation.pages.settings import AboutPage, SettingsPage
from arenyxa.presentation.pages.personalization import PersonalizationPage
from arenyxa.presentation.pages.enterprise import EnterprisePage
from arenyxa.presentation.pages.server_ops import ServerOperationsPage
from arenyxa.presentation.pages.welcome import WelcomeCenterDialog
from arenyxa.presentation.pages.tasks import TasksPage
from arenyxa.presentation.pages.tools import (
    AdvancedPlatformPage,
    AutomationPage,
    ConsolePage,
    LogsPage,
    PluginsPage,
    WorkflowPage,
)
from arenyxa.presentation.pages.visualization import VisualizationPage
from arenyxa.presentation.pages.studio import IntelligenceStudioPage
from arenyxa.presentation.pages.extraction import ExtractionStudioPage
from arenyxa.presentation.taskbar import WindowsTaskbarProgress
from arenyxa.presentation.themes import ThemeManager
from arenyxa.presentation.ui_scale import InterfaceScaleManager

from arenyxa.presentation.main_window_registry import DEVELOPER_SHORTCUTS, NAVIGATION

LOGGER = logging.getLogger(__name__)

class MainWindowLifecycleMixin:
    def apply_locale(self, locale: str) -> None:
        self.context.settings.locale = locale
        self.context.settings.save(self.context.paths.root / "settings.json")
        self.language.apply(locale)
        self._enforce_shell_ltr()

    def retranslate(self) -> None:
        self._enforce_shell_ltr()
                                                                                       
                                                                                           
                                                             
        expanded_rail = not bool(self.context.settings.left_sidebar_collapsed)
        rtl = self.language.locale.startswith("ar")
        for page_id, symbol, key, _page_type in NAVIGATION:
            button = self.nav_buttons[page_id]
            button.setToolTip(self.language.text(key))
            if expanded_rail:
                button.setText(self.language.text(key))
                indent = 24 if bool(button.property("navSub")) else 12
                button.setProperty("rtlNav", rtl)
                if rtl:
                    button.setStyleSheet(f"text-align:right; padding-right:{indent}px; padding-left:8px;")
                else:
                    button.setStyleSheet("")
        for action_id, symbol, key in DEVELOPER_SHORTCUTS:
            button = self.nav_action_buttons.get(action_id)
            if button is None:
                continue
            button.setToolTip(self.language.text(key))
            if expanded_rail:
                button.setText(self.language.text(key))
                button.setProperty("rtlNav", rtl)
                if rtl:
                    button.setStyleSheet("text-align:right; padding-right:24px; padding-left:8px;")
                else:
                    button.setStyleSheet("")
        advanced_open = self._nav_group_expanded("advanced")
        developer_open = self._nav_group_expanded("developer")
        advanced = self.nav_group_buttons.get("advanced")
        developer = self.nav_group_buttons.get("developer")
        closed_arrow = "›"
        if advanced is not None:
            advanced.setToolTip(self.language.text("nav.group.advanced"))
            advanced.setText((("⌄" if advanced_open else closed_arrow) + "    " + self.language.text("nav.group.advanced")) if expanded_rail else "⋯")
            advanced.setStyleSheet("text-align:right; padding-right:11px; padding-left:0;" if expanded_rail and rtl else ("" if expanded_rail else "text-align:center;"))
        if developer is not None:
            developer.setToolTip(self.language.text("nav.group.developer"))
            developer.setText((("⌄" if developer_open else closed_arrow) + "    " + self.language.text("nav.group.developer")) if expanded_rail else "⌘")
            developer.setStyleSheet("text-align:right; padding-right:11px; padding-left:0;" if expanded_rail and rtl else ("" if expanded_rail else "text-align:center;"))
        self.collapse_nav.setText("‹" if expanded_rail else "›")
        self.global_search.setPlaceholderText(self.language.text("top.search"))
        self.run_button.setText(self.language.text("top.run"))
        self.pause_button.setText(self.language.text("top.pause"))
        self.stop_button.setText(self.language.text("top.stop"))
        self.open_data_button.setText(self.language.text("top.open_data"))
        self.capture_button.setText(self.language.text("top.capture"))
        self.status_text.setText(self.language.text("status.ready"))
        self.inspector_title.setText(self.language.text("inspector.title"))
        self._update_inspector_button()
        settings_page = self.pages.get("settings")
        if isinstance(settings_page, SettingsPage):
            settings_page.refresh_localized_previews()
        personalization_page = self.pages.get("personalization")
        if isinstance(personalization_page, PersonalizationPage):
            personalization_page.refresh_localized_previews()

                                                                                           
                                                                                             
        for surface in (self.nav, self.topbar, self.inspector, self.statusBar()):
            if isinstance(surface, QWidget):
                self.language.translate_tree(surface)
        current = self.pages.get(self.current_page_id)
        if isinstance(current, QWidget):
            self.language.translate_tree(current)
        self.ui_scale.scale_tree(self.nav)
        if isinstance(current, QWidget):
            self.ui_scale.scale_tree(current)
                                                                                             
                                                                                            
        self._enforce_shell_ltr()

    def open_project(self, project_path: Path) -> None:
        try:
            manifest = self.context.projects.validate(project_path)
            self.show_status(f"项目已验证：{manifest.name} {manifest.version}")
            self.update_inspector(".arenyxa Project", manifest)
        except Exception as exc:                                                                     
            QMessageBox.critical(self, "项目无法打开", str(exc))

    def restore_window_state(self) -> None:
        settings = QSettings(str(self.context.paths.root / "window.ini"), QSettings.Format.IniFormat)
        geometry = settings.value("geometry")
        state = settings.value("state")
        if self._launch_geometry is not None:
                                                                                            
                                                                                                
                                                                                                   
            self.setGeometry(self._launch_geometry.rect)
        elif geometry:
            self.restoreGeometry(geometry)
        if state:
            self.restoreState(state)
        if self.context.settings.left_sidebar_collapsed:
            QTimer.singleShot(0, self.toggle_nav)
        if self.context.settings.inspector_collapsed:
            self.inspector.hide()
            self._update_inspector_button()

    def save_window_state(self) -> None:
        settings = QSettings(str(self.context.paths.root / "window.ini"), QSettings.Format.IniFormat)
        settings.setValue("geometry", self.saveGeometry())
        settings.setValue("state", self.saveState())
        settings.setValue("maximized", bool(self.isMaximized()))
        try:
            screen = self.screen()
            settings.setValue("screen_name", str(screen.name()) if screen is not None else "")
        except (AttributeError, RuntimeError, TypeError):
            settings.setValue("screen_name", "")
        settings.sync()

    def closeEvent(self, event: QCloseEvent) -> None:
        active = self.context.runner.active_handles()
        if active and not self._repair_exit_requested:
            choice = QMessageBox.question(
                self,
                "安全关闭",
                f"仍有 {len(active)} 个后台任务。停止任务并退出？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            )
            if choice != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
                                                                                       
        self._route_generation += 1
        self._status_generation += 1
        self.save_window_state()
        if self.tray is not None:
            self.tray.hide()
        self.taskbar_progress.clear()
        self.taskbar_progress.close()

        background_complete = begin_background_shutdown(timeout_ms=2500)
        if not background_complete:
            LOGGER.warning("UI background jobs did not fully quiesce before context shutdown")
            if self._repair_exit_requested:
                self.show_status(
                    "Repair 退出已阻止：仍有 UI 后台任务在运行；外部 Repair Worker 将保持 fail-safe。",
                    9000,
                )
                event.ignore()
                return

        reason = "repair" if self._repair_exit_requested else "user_exit"
        timeout = 12.0 if self._repair_exit_requested else 20.0
        if not self.context.shutdown(reason=reason, timeout=timeout):
            LOGGER.error("ApplicationContext shutdown incomplete; refusing to close MainWindow")
            self.show_status(
                "Arenyxa 安全关闭未完成；窗口保持打开，请检查 shutdown blocker 日志。",
                9000,
            )
            event.ignore()
            return
        self.crash_marker.unlink(missing_ok=True)
        event.accept()

    def showEvent(self, event: Any) -> None:
        super().showEvent(event)
        if self._startup_motion_done:
            return
        self._startup_motion_done = True
                                                                                            
        QTimer.singleShot(20, lambda: self.motion.reveal(self.centralWidget(), MotionIntent.ENTER))
