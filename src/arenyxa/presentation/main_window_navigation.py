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
from arenyxa import __version__
from arenyxa.branding import preferred_window_icon_path
from arenyxa.bootstrap import ApplicationContext
from arenyxa.application.experience import apply_experience_profile
from arenyxa.application.general_user import is_general_user
from arenyxa.domain.enums import MotionIntent
from arenyxa.domain.models import MotionProfile
from arenyxa.presentation.background import begin_background_shutdown, run_background
from arenyxa.presentation.glass import GlassPanel
from arenyxa.presentation.language import LanguageManager
from arenyxa.presentation.launch_geometry import LaunchGeometryPlan
from arenyxa.presentation.motion import MotionOrchestrator
from arenyxa.presentation.pages.base import WorkspacePage
from arenyxa.presentation.pages.task_center import TaskCenterPage
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

from arenyxa.presentation.main_window_registry import (
    DEVELOPER_PAGE_IDS,
    PAGE_GROUP,
    PAGE_TYPES,
)
from arenyxa.navigation import ExperienceContext, ExperienceMode, NavigationContext, NavigationDiff, RuntimeMode

LOGGER = logging.getLogger(__name__)

class MainWindowNavigationMixin:
    def _experience_context(self) -> ExperienceContext:
        return self.experience_controller.refresh()

    def _navigation_context(self) -> NavigationContext:
        return self._experience_context().navigation

    def _ensure_page(self, page_id: str) -> WorkspacePage:
        existing = self.pages.get(page_id)
        if existing is not None:
            return existing
        page_type = PAGE_TYPES.get(page_id)
        if page_type is None:
            raise KeyError(f"unknown page: {page_id}")

        def create_page() -> WorkspacePage:
            return page_type(self.context, self.theme, self.motion)

        page, created = self.page_factory.get_or_create(
            page_id,
            self._navigation_context(),
            create_page,
        )
        if not created:
            return page
        page.setProperty("arenyxa_shell_ltr", True)
        page.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        if isinstance(page, AboutPage):
            page.set_language_manager(self.language)
        page.statusMessage.connect(self.show_status)
        page.inspectorChanged.connect(self.update_inspector)
        page.operationProgress.connect(self.update_operation_progress)
        self.stack.addWidget(page)
        self.ui_scale.scale_tree(page)
        if isinstance(page, PersonalizationPage) and not self._personalization_signals_connected:
            page.themeRequested.connect(self._apply_theme_requested)
            page.motionRequested.connect(self.motion.set_profile)
            page.uiScaleRequested.connect(self._apply_ui_scale_requested)
            self._personalization_signals_connected = True
        if isinstance(page, TaskCenterPage):
            page.workflowRequested.connect(self.run_general_user_workflow)
            page.assistantRequested.connect(self.run_general_user_assistant)
        surface_requested = getattr(page, "surfaceRequested", None)
        if surface_requested is not None:
            surface_requested.connect(self.navigate)
        if isinstance(page, SettingsPage) and not self._settings_signals_connected:
                                                                                               
                                                                                            
            page.themeRequested.connect(self._apply_theme_requested)
            page.localeRequested.connect(self.apply_locale)
            page.motionRequested.connect(self.motion.set_profile)
            page.uiScaleRequested.connect(self._apply_ui_scale_requested)
            page.developerModeChanged.connect(self.set_developer_mode)
            page.repairRequested.connect(self.launch_repair_center)
            page.welcomeRequested.connect(self.show_welcome_center)
            self._settings_signals_connected = True
        return page

    def _apply_ui_scale_requested(self, payload: object) -> None:
        try:
            mode, percent = payload                      
        except (TypeError, ValueError):
            mode, percent = "auto", 100
        self.context.settings.ui_scale_mode = "manual" if str(mode).casefold() == "manual" else "auto"
        try:
            numeric_percent = int(percent)
        except (TypeError, ValueError, OverflowError):
            numeric_percent = 100
        self.context.settings.ui_scale_percent = max(85, min(160, numeric_percent))
        self.ui_scale.set_preferences(
            self.context.settings.ui_scale_mode, self.context.settings.ui_scale_percent
        )
        self.context.settings.save(self.context.paths.root / "settings.json")

    def _shell_metric(self, value: int) -> int:
        scale = max(0.85, min(1.60, float(getattr(self.ui_scale, "current_scale", 1.0))))
        return max(1, int(round(int(value) * scale)))

    def _on_ui_scale_changed(self, _scale: float) -> None:
        collapsed = bool(self.context.settings.left_sidebar_collapsed)
        self.nav.setFixedWidth(self._shell_metric(68 if collapsed else 236))
        self.collapse_nav.setFixedSize(self._shell_metric(32), self._shell_metric(32))
        self.global_search.setMaximumWidth(self._shell_metric(440))
        self.live_progress.setFixedWidth(self._shell_metric(150))
        self.inspector.setMinimumWidth(self._shell_metric(280))
        self.inspector.setMaximumWidth(self._shell_metric(460))
                                                                                          
        self.updateGeometry()

    def resizeEvent(self, event: Any) -> None:
        super().resizeEvent(event)
        manager = getattr(self, "ui_scale", None)
        if manager is not None:
            manager.schedule_recompute()

    def show_pending_welcome(self) -> None:
        if bool(getattr(self, "_welcome_pending", False)):
            self._welcome_pending = False
            QTimer.singleShot(80, self.show_welcome_center)

    def show_welcome_center(self) -> None:
        
        dialog = WelcomeCenterDialog(self.context, self.theme, self.motion, anchor=self)
        try:
            self.language.translate_tree(dialog)
        except Exception:
            LOGGER.exception("Welcome Center translation failed")

        def complete(profile_id: str) -> None:
            scenario = dialog.selected_personal_scenario() if profile_id == "personal" else ""
            if self._complete_welcome_center(profile_id, scenario):
                dialog.accept()

        def open_enterprise() -> None:
            if self._complete_welcome_center("enterprise"):
                dialog.accept()

        def open_fleet() -> None:
            dialog.accept()
            runtime = self._navigation_context().runtime_mode
            if runtime in {RuntimeMode.SERVER, RuntimeMode.WORKER}:
                self.navigate("server_ops")
            else:
                self.navigate("server")

        dialog.profileSelected.connect(complete)
        dialog.enterpriseRequested.connect(open_enterprise)
        dialog.fleetRequested.connect(open_fleet)
        self.show_status("Welcome Center · 独立使用模式窗口")
        dialog.exec()
        dialog.deleteLater()

    def _complete_welcome_center(self, profile_id: str, personal_scenario: str = "") -> bool:
        switch_started = time.perf_counter()
        self.show_status("正在切换使用模式并重建工作区导航…")
        try:
            if profile_id == "personal" and personal_scenario:
                self.context.settings.personal_scenario = personal_scenario
            profile, event = self.experience_controller.switch(profile_id)
        except Exception as exc:
            LOGGER.exception("Failed to apply Arenyxa experience profile")
            QMessageBox.warning(self, "无法切换使用模式", f"{type(exc).__name__}: {exc}")
            return False
        self._navigation_switch_generation += 1
        self._last_navigation_diff = self.navigation_policy_engine.diff(event.previous, event.current)
        self._refresh_nav_visibility()
        self.retranslate()

        # Mode selection controls presentation only.  Never convert a denied
        # privileged operation into a failure to select the workspace itself.
        # If a future manifest makes the preferred landing page unavailable,
        # land on the first visible workspace page instead of showing an access
        # denial immediately after a successful preset switch.
        resolved = self.navigation_policy_engine.rebuild(event.current)
        landing_page = event.current.workspace.landing_page
        if landing_page not in resolved.visible:
            landing_page = next(
                (page_id for page_id in event.current.workspace.primary_pages if page_id in resolved.visible),
                next(iter(resolved.page_ids), "settings"),
            )

        added_buttons = [
            self.nav_buttons[page_id]
            for page_id in self._last_navigation_diff.added_pages
            if page_id in self.nav_buttons and self.nav_buttons[page_id].isVisible()
        ]
        if added_buttons:
            self.motion.reveal_staggered(added_buttons, interval_ms=18)

        self.context.navigation_metrics["preset_switch_latency_ms"] = (
            time.perf_counter() - switch_started
        ) * 1000.0
        self.show_status(f"已选择 {profile.title}；使用模式不会改变安全权限。")
        self.navigate(landing_page)
        return True

    def _apply_theme_requested(self, theme_id: str) -> None:
        self.theme_transition.request(theme_id)

    def _root_authority_active(self) -> bool:
        active = self._navigation_context().root_session.active
        if not active:
            self.context.root_developer_workstation = False
        return active

    def _developer_surface_enabled(self, context: NavigationContext | None = None) -> bool:
        context = context or self._navigation_context()
        return bool(
            self.context.settings.developer_mode
            or context.experience_mode is ExperienceMode.DEVELOPER
            or context.root_session.active
            or context.developer_authority.active
        )

    def _developer_tools_enabled(self, context: NavigationContext | None = None) -> bool:
        context = context or self._navigation_context()
        return bool(
            self.context.settings.developer_mode
            or context.root_session.active
            or context.developer_authority.active
        )

    def _page_allowed(self, page_id: str) -> bool:
        if page_id not in PAGE_GROUP:
            return False
        simple = is_general_user(self.context.settings)
        if page_id == "task_center":
            return simple
        if simple:
            simple_visible = {
                "dashboard", "search", "tasks", "network", "data", "recovery",
                "personalization", "settings", "about",
            }
            if page_id not in simple_visible:
                return False
        # Legacy Developer-group gating remains a defense in depth; the resolver is authoritative.
        # return page_id not in DEVELOPER_PAGE_IDS or self._developer_surface_enabled()
        if page_id in DEVELOPER_PAGE_IDS and not self._developer_surface_enabled():
            return False
        return self.navigation_resolver.allowed(page_id, self._navigation_context())

    def _navigation_denied_message(self, page_id: str) -> str:
        decision = self.navigation_resolver.decision(page_id, self._navigation_context())
        messages = {
            "EXPERIENCE_MODE_MISMATCH": "当前 Experience Mode 不显示此页面。",
            "RUNTIME_MODE_MISMATCH": "当前 Runtime Mode 不允许访问此管理页面。",
            "ACCOUNT_ROLE_REQUIRED": "当前 Account Role 无权访问此页面。",
            "DEVELOPER_AUTHORITY_REQUIRED": "需要有效的 Developer Credential 与活动会话。",
            "ROOT_SESSION_REQUIRED": "需要活动且未过期、未撤销的 Root Session。",
            "CAPABILITY_REQUIRED": "当前会话缺少此页面要求的 capability。",
        }
        return messages.get(decision.reason, "此页面当前不可访问。")

    def _sync_navigation_selection(self, page_id: str) -> None:
        
        button = self.nav_buttons.get(page_id)
        if button is not None and not button.isChecked():
            button.setChecked(True)

        active_group = PAGE_GROUP.get(page_id, "core")
        for group, header in self.nav_group_buttons.items():
            active = group == active_group
            if bool(header.property("navGroupActive")) != active:
                header.setProperty("navGroupActive", active)
                header.style().unpolish(header)
                header.style().polish(header)

    def _commit_stack_page(self, page: WorkspacePage) -> None:
        







        index = self.stack.indexOf(page)
        if index < 0:
            index = self.stack.addWidget(page)
        self.stack.setCurrentIndex(index)
        page.show()
        self.stack.update()
        if self.stack.currentIndex() != index:
                                                                                             
                                                                                        
                                                                             
            self.stack.setCurrentWidget(page)
        if self.stack.currentIndex() != index:
            raise RuntimeError("QStackedWidget refused to commit the requested page")

    def _finish_navigation(self, page_id: str, page: WorkspacePage, generation: int) -> None:
        
        if generation != self._route_generation or self.current_page_id != page_id:
            return
        refresh_failed = False
        try:
            page.activated()
        except Exception as exc:
            refresh_failed = True
            LOGGER.exception("page activation failed: %s", page_id)
            self.show_status(f"{page_id} 页面已打开，但刷新失败：{type(exc).__name__}: {exc}")
        if generation != self._route_generation or self.current_page_id != page_id:
            return
        try:
            self.language.translate_tree(page)
        except Exception as exc:
            LOGGER.exception("page translation failed: %s", page_id)
            if not refresh_failed:
                self.show_status(f"{page_id} 页面已打开，但本地化刷新失败：{type(exc).__name__}: {exc}")

    def navigate(self, page_id: str) -> None:
        previous_page_id = self.current_page_id
        if not self._page_allowed(page_id):
            self._sync_navigation_selection(previous_page_id)
            self.show_status(self._navigation_denied_message(page_id))
            return
        group = PAGE_GROUP.get(page_id, "core")
        if group == "advanced" and not self.context.settings.advanced_nav_expanded:
            self.context.settings.advanced_nav_expanded = True
            self.context.settings.save(self.context.paths.root / "settings.json")
            self._refresh_nav_visibility()
        elif group == "developer" and not self.context.settings.developer_nav_expanded:
            self.context.settings.developer_nav_expanded = True
            self.context.settings.save(self.context.paths.root / "settings.json")
            self._refresh_nav_visibility()
        try:
            page = self._ensure_page(page_id)
        except Exception as exc:
                                                                                                
                                             
            self._sync_navigation_selection(previous_page_id)
            LOGGER.exception("page construction failed: %s", page_id)
            self.show_status(f"无法打开 {page_id}：{type(exc).__name__}: {exc}")
            QMessageBox.critical(
                self,
                "页面加载失败",
                f"无法打开 {page_id}。\n\n{type(exc).__name__}: {exc}",
            )
            return

                                                                                             
                                                                               
        previous = self.pages.get(previous_page_id)
        if isinstance(previous, WorkspacePage) and previous is not page:
            try:
                previous.deactivated()
            except Exception:
                                                                             
                LOGGER.exception("page deactivation failed: %s", previous_page_id)

                                                                                                 
                                                                                          
        self._route_generation += 1
        generation = self._route_generation
        captured_transition = (
            self.motion.capture_stack_transition(self.stack, page)
            if previous is not None and previous is not page
            else None
        )
        try:
            self._commit_stack_page(page)
        except Exception as exc:
            LOGGER.exception("page route commit failed: %s", page_id)
            self._sync_navigation_selection(previous_page_id)
            self.current_page_id = previous_page_id
            self.show_status(f"无法切换到 {page_id}：{type(exc).__name__}: {exc}")
            return
        self.current_page_id = page_id
        self._sync_navigation_selection(page_id)
        if previous is not page:
            self.motion.transition_committed_stack(
                self.stack, page, captured_transition, MotionIntent.ENTER
            )
        button = self.nav_buttons.get(page_id)
        self.show_status(button.toolTip() if button is not None else page_id)

                                                                                            
                                                                                                 
        QTimer.singleShot(0, lambda page_id=page_id, page=page, generation=generation: self._finish_navigation(page_id, page, generation))

    def _nav_group_expanded(self, group: str) -> bool:
        if group == "advanced":
            return bool(self.context.settings.advanced_nav_expanded)
        if group == "developer":
            return bool(self.context.settings.developer_nav_expanded)
        return True

    def toggle_nav_group(self, group: str) -> None:
        if group == "developer" and not self._developer_surface_enabled():
            return
        if group == "advanced":
            self.context.settings.advanced_nav_expanded = not self.context.settings.advanced_nav_expanded
        elif group == "developer":
            self.context.settings.developer_nav_expanded = not self.context.settings.developer_nav_expanded
        else:
            return
        self.context.settings.save(self.context.paths.root / "settings.json")
        self._refresh_nav_visibility()
        self.retranslate()
        if self._nav_group_expanded(group):
            for index, button in enumerate(self.nav_group_items.get(group, [])):
                QTimer.singleShot(
                    index * 18,
                    lambda button=button: self.motion.reveal(button, MotionIntent.ENTER),
                )

    def _refresh_nav_visibility(self) -> None:
        started = time.perf_counter()
        experience = self._experience_context()
        navigation = experience.navigation
        resolved = self.navigation_policy_engine.rebuild(experience)
        previous_visible = self._visible_page_ids
        self._visible_page_ids = resolved.page_ids
        self._last_navigation_diff = NavigationDiff.between(previous_visible, resolved.page_ids)
        allowed = resolved.visible
        primary_pages = set(experience.workspace.primary_pages)
        for page_id, button in self.nav_buttons.items():
            is_primary = page_id in primary_pages
            if bool(button.property("workspacePrimary")) != is_primary:
                button.setProperty("workspacePrimary", is_primary)
                button.setProperty("navSub", not is_primary)
                button.style().unpolish(button)
                button.style().polish(button)

        simple = is_general_user(self.context.settings)
        simple_visible = {
            "task_center", "dashboard", "search", "tasks", "network", "data",
            "recovery", "personalization", "settings", "about",
        }
        for page_id, button in self.nav_buttons.items():
            group = PAGE_GROUP.get(page_id, "core")
            if simple:
                button.setVisible(page_id in allowed and page_id in simple_visible)
            elif group == "core":
                button.setVisible(page_id in allowed and page_id != "task_center")
            elif group == "system":
                button.setVisible(page_id in allowed)

        advanced_header = self.nav_group_buttons.get("advanced")
        if advanced_header is not None:
            advanced_header.setVisible(not simple)
        if not simple:
            advanced_visible = self._nav_group_expanded("advanced")
            for button in self.nav_group_items["advanced"]:
                page_id = str(button.property("navPageId") or "")
                button.setVisible(advanced_visible and page_id in allowed)

        developer_enabled = (
            (not simple)
            and self._developer_surface_enabled(navigation)
            and any(page_id in allowed for page_id in DEVELOPER_PAGE_IDS)
        )
        developer_header = self.nav_group_buttons.get("developer")
        if developer_header is not None:
            developer_header.setVisible(developer_enabled)
        developer_visible = developer_enabled and self._nav_group_expanded("developer")
        developer_tools_enabled = self._developer_tools_enabled(navigation)
        for button in self.nav_group_items["developer"]:
            if bool(button.property("navAction")):
                target = str(button.property("navActionTarget") or "")
                button.setVisible(
                    developer_visible
                    and developer_tools_enabled
                    and (not target or target in allowed)
                )
                continue
            page_id = str(button.property("navPageId") or "")
            button.setVisible(developer_visible and page_id in allowed)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        self.context.navigation_metrics["preset_switch_latency_ms"] = elapsed_ms

    def open_developer_tool(self, action_id: str) -> None:
        if not self._developer_surface_enabled():
            self.show_status("Developer Mode 未启用；请在设置 → 高级设置中启用。")
            return
        if action_id == "dev_api":
            self.navigate("advanced")
            page = self.pages.get("advanced")
            if isinstance(page, AdvancedPlatformPage):
                page.open_section("api")
        elif action_id == "dev_performance":
            self.navigate("advanced")
            page = self.pages.get("advanced")
            if isinstance(page, AdvancedPlatformPage):
                page.open_section("performance")
        elif action_id == "dev_sandbox":
            self.navigate("plugins")
        else:
            self.show_status(f"Unknown developer tool: {action_id}")

    def set_developer_mode(self, enabled: bool) -> None:
        self.context.settings.developer_mode = bool(enabled)
        if enabled:
            # Opening Developer Mode is an explicit request to expose the
            # Developer child surfaces immediately. Do not rely on Experience
            # Profile side effects to expand this group.
            self.context.settings.developer_nav_expanded = True
        root_workstation = self._root_authority_active()
        if not enabled and not root_workstation:
            self.context.settings.developer_nav_expanded = False
                                                                                       
                                                                                                
            self.context.terminal.request_stop()
            if self.current_page_id in DEVELOPER_PAGE_IDS:
                self.navigate("settings")
        if enabled:
            try:
                _profile, event = self.experience_controller.switch("developer")
                self._last_navigation_diff = self.navigation_policy_engine.diff(event.previous, event.current)
            except Exception as exc:
                LOGGER.exception("Failed to enter Developer Experience")
                self.show_status(f"Developer Experience 切换失败：{type(exc).__name__}: {exc}")
                return
        else:
            self.context.settings.save(self.context.paths.root / "settings.json")
        self._refresh_nav_visibility()
        self.retranslate()
        if enabled or root_workstation:
            header = self.nav_group_buttons.get("developer")
            if header is not None:
                self.motion.reveal(header, MotionIntent.ENTER)
        if root_workstation and not enabled:
            self.show_status("Developer Mode 偏好已关闭；Root Developer Workstation 仍保持平台技术工具可用。")
        else:
            state = "已启用" if enabled else "已关闭"
            self.show_status(f"Developer Mode {state}")
        if enabled:
            self.navigate("developer_center")

    def _apply_nav_collapsed_visual(self, collapsed: bool) -> None:
        self.nav.setProperty("navCompact", collapsed)
        self.nav_header.setProperty("navCompact", collapsed)
        self.brand_icon.setVisible(not collapsed)
        self.brand_text.setVisible(not collapsed)
        self.service_label.setVisible(not collapsed)
        self.collapse_nav.setToolTip("展开侧边栏" if collapsed else "折叠侧边栏")
        self.collapse_nav.setText("›" if collapsed else "‹")
        for page_id, button in self.nav_buttons.items():
            button.setProperty("navCompact", collapsed)
            button.setText("" if collapsed else button.text())
            button.style().unpolish(button)
            button.style().polish(button)
        for action_id, button in self.nav_action_buttons.items():
            button.setProperty("navCompact", collapsed)
            button.setText("" if collapsed else button.text())
            button.style().unpolish(button)
            button.style().polish(button)
        for group, button in self.nav_group_buttons.items():
            button.setProperty("navCompact", collapsed)
            if collapsed:
                button.setText("⋯" if group == "advanced" else "⌘")
            button.style().unpolish(button)
            button.style().polish(button)
        self.nav.style().unpolish(self.nav)
        self.nav.style().polish(self.nav)
        if not collapsed:
            self.retranslate()

    def toggle_nav(self) -> None:
                                                                                        
        collapse = self.nav.maximumWidth() > 100
        self.context.settings.left_sidebar_collapsed = collapse
        self.collapse_nav.setEnabled(False)
        self._apply_nav_collapsed_visual(collapse)
        if collapse:
            def finished() -> None:
                self.nav.setFixedWidth(self._shell_metric(68))
                self.collapse_nav.setEnabled(True)

            self.motion.animate_width(self.nav, self._shell_metric(68), 210, finished)
        else:
            def finished() -> None:
                self.nav.setFixedWidth(self._shell_metric(236))
                self.collapse_nav.setEnabled(True)

            self.motion.animate_width(self.nav, self._shell_metric(236), 230, finished)
        self.context.settings.save(self.context.paths.root / "settings.json")

    def _update_inspector_button(self) -> None:
        hidden = bool(self.context.settings.inspector_collapsed)
                                                                                            
                                                                             
        arrow = "›" if hidden else "‹"
        self.inspector_button.setText(f"{self.language.text('inspector.title')} {arrow}")

    def toggle_inspector(self) -> None:
        if self.inspector.isVisible():
            self.context.settings.inspector_collapsed = True
            self._update_inspector_button()
            self.inspector_button.setEnabled(False)

            def hidden() -> None:
                self.inspector.hide()
                self.inspector.setMinimumWidth(self._shell_metric(280))
                self.inspector.setMaximumWidth(self._shell_metric(460))
                self.inspector_button.setEnabled(True)

            self.motion.animate_width(self.inspector, 0, 220, hidden)
        else:
            self.context.settings.inspector_collapsed = False
            self.inspector_button.setEnabled(False)
            self.inspector.setFixedWidth(0)
            self.inspector.show()
            self._update_inspector_button()

            def shown() -> None:
                self.inspector.setMinimumWidth(self._shell_metric(280))
                self.inspector.setMaximumWidth(self._shell_metric(460))
                self.inspector_button.setEnabled(True)

            self.motion.animate_width(self.inspector, self._shell_metric(320), 250, shown)
        self.context.settings.save(self.context.paths.root / "settings.json")

    def update_inspector(self, title: str, data: object) -> None:
        self.inspector_title.setText(title)
        try:
            text = json.dumps(data, ensure_ascii=False, indent=2, default=str)
        except (TypeError, ValueError):
            text = str(data)
        self.inspector_content.setPlainText(text)
