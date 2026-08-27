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

from arenyxa import __display_version__
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
from arenyxa.presentation.theme_transition import ThemeTransitionController
from arenyxa.presentation.ui_scale import InterfaceScaleManager
from arenyxa.presentation.main_window_registry import (
    DEVELOPER_PAGE_IDS,
    DEVELOPER_SHORTCUTS,
    DEVELOPER_SHORTCUT_TARGETS,
    NAVIGATION,
    PAGE_DEFINITIONS,
    PAGE_GROUP,
    PAGE_TYPES,
)
from arenyxa.presentation.main_window_navigation import MainWindowNavigationMixin
from arenyxa.presentation.main_window_operations import MainWindowOperationsMixin
from arenyxa.presentation.main_window_lifecycle import MainWindowLifecycleMixin
from arenyxa.navigation import (
    DEFAULT_PAGE_MANIFESTS,
    ExperienceContextController,
    NavigationContextFactory,
    NavigationPolicyEngine,
    NavigationResolver,
    PageFactory,
)


LOGGER = logging.getLogger(__name__)

class MainWindow(MainWindowNavigationMixin, MainWindowOperationsMixin, MainWindowLifecycleMixin, QMainWindow):
    runnerProgress = Signal()
    modeChanged = Signal(object)
    shellCloseRequested = Signal()

    def __init__(
        self,
        context: ApplicationContext,
        project_path: Path | None = None,
        launch_geometry: LaunchGeometryPlan | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.context = context
        self.project_path = project_path
        self._launch_geometry = launch_geometry
        self.setWindowTitle(f"Arenyxa V{__display_version__}")
        minimum_width = 1120
        minimum_height = 720
        if launch_geometry is not None and launch_geometry.rect.isValid():
                                                                                               
                                                                                               
                                                                                             
                                              
            minimum_width = min(minimum_width, max(1, int(launch_geometry.rect.width())))
            minimum_height = min(minimum_height, max(1, int(launch_geometry.rect.height())))
        self.setMinimumSize(minimum_width, minimum_height)
        self.resize(1500, 920)
        if launch_geometry is not None:
                                                                                                 
                                                                                             
                                                                         
            self.setGeometry(launch_geometry.rect)
        icon_path = preferred_window_icon_path()
        if icon_path.is_file():
            self.setWindowIcon(QIcon(str(icon_path)))
        app = QApplication.instance()
        assert isinstance(app, QApplication)
        pool = QThreadPool.globalInstance()
        pool.setMaxThreadCount(max(1, context.performance.background_workers))
        pool.setExpiryTimeout(15_000)
        self.theme = ThemeManager(app, context.settings.theme)
        self.language = LanguageManager(app, context.settings.locale)
        self.ui_scale = InterfaceScaleManager(app, self, context.settings, self.theme)
        self.ui_scale.changed.connect(self._on_ui_scale_changed)
        target_screen = None
        if launch_geometry is not None:
            try:
                screen_at = getattr(app, "screenAt", None)
                if callable(screen_at):
                    target_screen = screen_at(launch_geometry.rect.center())
            except (AttributeError, RuntimeError, TypeError):
                target_screen = None
        if target_screen is None:
            try:
                target_screen = self.screen()
            except RuntimeError:
                target_screen = None
        if target_screen is None:
            target_screen = app.primaryScreen()
        screen_hz = target_screen.refreshRate() if target_screen is not None else 60.0
        refresh_hz = min(float(screen_hz), float(context.performance.animation_hz_cap))
        self.motion = MotionOrchestrator(
            MotionProfile(
                glass_strength=context.settings.glass_strength,
                blur=context.settings.blur_strength,
                motion_strength=context.settings.motion_strength,
                edge_flow=False,
                live_data_motion=context.settings.live_data_motion,
                reduce_motion=context.settings.reduce_motion,
                animation_mode=context.settings.animation_mode,
                quality=context.performance.mode,
            ),
            refresh_hz,
            self,
            device_quality=context.performance.device.recommended_mode,
            system_reduce_motion=context.system_reduce_motion,
        )
        self.theme_transition = ThemeTransitionController(self, self.theme, self.motion, self)
        app.setProperty("arenyxa_high_contrast", bool(context.settings.high_contrast))
        app.setProperty("arenyxa_performance_mode", context.performance.mode)
        app.setProperty("arenyxa_glass_specular", bool(context.performance.glass_specular))
        self.navigation_resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)
        self.experience_controller = ExperienceContextController(context)
        self.experience_controller.subscribe(self.modeChanged.emit)
        self.navigation_policy_engine = NavigationPolicyEngine(self.navigation_resolver)
        self.page_factory = PageFactory(self.navigation_resolver)
        self.pages: dict[str, WorkspacePage] = self.page_factory.cache
        self._visible_page_ids: tuple[str, ...] = ()
        self._last_navigation_diff = None
        self._navigation_switch_generation = 0
        self.nav_buttons: dict[str, QPushButton] = {}
                                                                                 
                                                                                      
        self.nav_button_group = QButtonGroup(self)
        self.nav_button_group.setExclusive(True)
        self.nav_symbols: dict[str, str] = {}
        self.nav_group_buttons: dict[str, QPushButton] = {}
        self.nav_group_items: dict[str, list[QPushButton]] = {"advanced": [], "developer": []}
        self.nav_action_buttons: dict[str, QPushButton] = {}
        self.nav_action_symbols: dict[str, str] = {}
        self._repair_exit_requested = False
        self._repair_scan_in_progress = False
        self._startup_health_report = None
        self._settings_signals_connected = False
        self._personalization_signals_connected = False
        self._progress_emit_lock = threading.Lock()
        self._last_progress_emit = 0.0
        self._aux_progress: tuple[str, int, int, str] | None = None
        self.current_page_id = self.experience_controller.current.workspace.landing_page
        self._route_generation = 0
        self._status_generation = 0
        self._build_ui(icon_path)
        self._enforce_shell_ltr()
        self.theme.changed.connect(lambda _theme: self._refresh_nav_icons())
        self._refresh_nav_icons()
        self.taskbar_progress = WindowsTaskbarProgress(self)
        self._build_tray(icon_path)
        self._connect_global_actions()
        self.runnerProgress.connect(self.refresh_global_status)
        self.theme.apply(context.settings.theme, self)
        self.language.apply(context.settings.locale)
        self._enforce_shell_ltr()
        self.language.translate_tree(self)
        self._enforce_shell_ltr()
        self.ui_scale.apply(force=True)
        self.restore_window_state()
        self._welcome_pending = (
            not bool(getattr(context.settings, "experience_setup_completed", False))
            and not bool(getattr(context, "safe_mode", False))
        )
                                                                                             
                                                                          
        self.navigate(self.experience_controller.current.workspace.landing_page)
                                                                                                     
        self.crash_marker = context.paths.root / "crash.marker"
        if project_path:
            QTimer.singleShot(250, lambda: self.open_project(project_path))
        self._startup_motion_done = False

    def _make_nav_icon(self, symbol: str) -> QIcon:
        
        tokens = self.theme.current

        def pixmap(color: str) -> QPixmap:
            canvas = QPixmap(22, 22)
            canvas.fill(Qt.GlobalColor.transparent)
            painter = QPainter(canvas)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setPen(QColor(color))
            font = QFont("Segoe UI Symbol")
            font.setPixelSize(14 if len(symbol) <= 1 else 11)
            font.setWeight(QFont.Weight.DemiBold)
            painter.setFont(font)
            painter.drawText(canvas.rect(), Qt.AlignmentFlag.AlignCenter, symbol)
            painter.end()
            return canvas

        icon = QIcon()
        normal = pixmap(tokens.text_muted)
        active = pixmap(tokens.text)
        selected = pixmap(tokens.accent)
        icon.addPixmap(normal, QIcon.Mode.Normal, QIcon.State.Off)
        icon.addPixmap(active, QIcon.Mode.Active, QIcon.State.Off)
        icon.addPixmap(selected, QIcon.Mode.Normal, QIcon.State.On)
        icon.addPixmap(selected, QIcon.Mode.Active, QIcon.State.On)
        icon.addPixmap(selected, QIcon.Mode.Selected, QIcon.State.On)
        return icon

    def _refresh_nav_icons(self) -> None:
        for page_id, button in self.nav_buttons.items():
            button.setIcon(self._make_nav_icon(self.nav_symbols.get(page_id, "•")))
            button.setIconSize(QSize(18, 18))
        for action_id, button in self.nav_action_buttons.items():
            button.setIcon(self._make_nav_icon(self.nav_action_symbols.get(action_id, "•")))
            button.setIconSize(QSize(18, 18))

    def _build_ui(self, icon_path: Path) -> None:
        self.backdrop = QWidget()
        self.backdrop.setObjectName("Backdrop")
        self.backdrop.setProperty("arenyxa_shell_ltr", True)
        self.backdrop.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.setCentralWidget(self.backdrop)
        root = QHBoxLayout(self.backdrop)
        root.setDirection(QBoxLayout.Direction.LeftToRight)
        root.setContentsMargins(8, 8, 8, 0)
        root.setSpacing(8)

        self.nav = GlassPanel(self.theme, elevated=True)
                                                                                          
                                                                                             
                                                                                               
                                                                                           
        self.nav.setProperty("arenyxa_motion_static", True)
        self.nav.setProperty("arenyxa_shell_ltr", True)
        self.nav.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.nav.setObjectName("SidebarRail")
        self.nav.setProperty("sidebarRail", True)
                                                                                      
                                                                                         
        self.nav.setFixedWidth(self._shell_metric(236))
        self.nav_layout = QVBoxLayout(self.nav)
        self.nav_layout.setContentsMargins(10, 10, 10, 10)
        self.nav_layout.setSpacing(8)

        self.nav_header = QWidget()
        self.nav_header.setProperty("sidebarHeader", True)
        self.nav_header.setProperty("arenyxa_shell_ltr", True)
        self.nav_header.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        brand = QHBoxLayout(self.nav_header)
        brand.setDirection(QBoxLayout.Direction.LeftToRight)
        brand.setContentsMargins(4, 3, 2, 3)
        brand.setSpacing(9)
        self.brand_icon = QLabel()
        self.brand_icon.setFixedSize(40, 40)
        self.brand_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        if icon_path.exists():
            self.brand_icon.setPixmap(QIcon(str(icon_path)).pixmap(QSize(38, 38)))
        self.brand_text = QWidget()
        brand_copy = QVBoxLayout(self.brand_text)
        brand_copy.setContentsMargins(0, 0, 0, 0)
        brand_copy.setSpacing(0)
        self.brand_title = QLabel("Arenyxa")
        self.brand_title.setProperty("sidebarBrandTitle", True)
        self.brand_subtitle = QLabel("本地网络数据工作台")
        self.brand_subtitle.setProperty("sidebarBrandSubtitle", True)
        brand_copy.addWidget(self.brand_title)
        brand_copy.addWidget(self.brand_subtitle)
        self.collapse_nav = QPushButton("‹")
        self.collapse_nav.setProperty("sidebarCollapse", True)
        self.collapse_nav.setFixedSize(32, 32)
        self.collapse_nav.setToolTip("折叠侧边栏")
        brand.addWidget(self.brand_icon)
        brand.addWidget(self.brand_text, 1)
        brand.addWidget(self.collapse_nav)
        self.nav_layout.addWidget(self.nav_header)

        header_divider = QFrame()
        header_divider.setProperty("navDivider", True)
        header_divider.setFixedHeight(1)
        self.nav_layout.addWidget(header_divider)

        self.nav_scroll = QScrollArea()
        self.nav_scroll.setObjectName("SidebarScroll")
        self.nav_scroll.setWidgetResizable(True)
        self.nav_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        self.nav_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.nav_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        nav_items = QWidget()
        nav_items.setObjectName("SidebarItems")
        nav_items_layout = QVBoxLayout(nav_items)
        nav_items_layout.setContentsMargins(0, 0, 0, 0)
        nav_items_layout.setSpacing(3)

        def add_nav_button(
            page_id: str, symbol: str, key: str, group: str, target_layout: QVBoxLayout
        ) -> None:
            button = QPushButton(self.language.text(key))
            button.setProperty("nav", True)
            button.setProperty("navSub", group in {"advanced", "developer"})
            button.setProperty("navSystem", group == "system")
            button.setProperty("navGroupName", group)
            button.setProperty("navPageId", page_id)
            button.setCheckable(True)
            button.setAutoExclusive(False)
            button.setFixedHeight(40 if group in {"core", "system"} else 36)
            self.nav_button_group.addButton(button)
            button.setToolTip(self.language.text(key))
            button.clicked.connect(lambda _checked=False, page_id=page_id: self.navigate(page_id))
            self.nav_buttons[page_id] = button
            self.nav_symbols[page_id] = symbol
            if group in self.nav_group_items:
                self.nav_group_items[group].append(button)
            target_layout.addWidget(button)

        def add_developer_shortcut(action_id: str, symbol: str, key: str) -> None:
            button = QPushButton(self.language.text(key))
            button.setProperty("nav", True)
            button.setProperty("navSub", True)
            button.setProperty("navAction", True)
            button.setProperty("navGroupName", "developer")
            button.setProperty("navActionTarget", DEVELOPER_SHORTCUT_TARGETS.get(action_id, ""))
            button.setFixedHeight(36)
            button.setToolTip(self.language.text(key))
            button.clicked.connect(lambda _checked=False, action_id=action_id: self.open_developer_tool(action_id))
            self.nav_action_buttons[action_id] = button
            self.nav_action_symbols[action_id] = symbol
            self.nav_group_items["developer"].append(button)
            nav_items_layout.addWidget(button)

        for page_id, symbol, key, _page_type, group in PAGE_DEFINITIONS:
            if group == "core":
                add_nav_button(page_id, symbol, key, group, nav_items_layout)

        core_divider = QFrame()
        core_divider.setProperty("navDivider", True)
        core_divider.setFixedHeight(1)
        nav_items_layout.addWidget(core_divider)

        self.advanced_group_button = QPushButton()
        self.advanced_group_button.setProperty("navGroup", True)
        self.advanced_group_button.setProperty("navGroupName", "advanced")
        self.advanced_group_button.setFixedHeight(30)
        self.advanced_group_button.clicked.connect(lambda: self.toggle_nav_group("advanced"))
        self.nav_group_buttons["advanced"] = self.advanced_group_button
        nav_items_layout.addWidget(self.advanced_group_button)
        for page_id, symbol, key, _page_type, group in PAGE_DEFINITIONS:
            if group == "advanced":
                add_nav_button(page_id, symbol, key, group, nav_items_layout)

        self.developer_group_button = QPushButton()
        self.developer_group_button.setProperty("navGroup", True)
        self.developer_group_button.setProperty("navGroupName", "developer")
        self.developer_group_button.setFixedHeight(30)
        self.developer_group_button.clicked.connect(lambda: self.toggle_nav_group("developer"))
        self.nav_group_buttons["developer"] = self.developer_group_button
        nav_items_layout.addWidget(self.developer_group_button)
        for page_id, symbol, key, _page_type, group in PAGE_DEFINITIONS:
            if group == "developer":
                add_nav_button(page_id, symbol, key, group, nav_items_layout)
        for action_id, symbol, key in DEVELOPER_SHORTCUTS:
            add_developer_shortcut(action_id, symbol, key)

        nav_items_layout.addStretch()
        self._refresh_nav_visibility()
        self.nav_scroll.setWidget(nav_items)
        self.nav_layout.addWidget(self.nav_scroll, 1)

        footer_divider = QFrame()
        footer_divider.setProperty("navDivider", True)
        footer_divider.setFixedHeight(1)
        self.nav_layout.addWidget(footer_divider)
        self.nav_footer = QWidget()
        self.nav_footer.setProperty("sidebarFooter", True)
        footer_layout = QVBoxLayout(self.nav_footer)
        footer_layout.setContentsMargins(0, 0, 0, 0)
        footer_layout.setSpacing(3)
        for page_id, symbol, key, _page_type, group in PAGE_DEFINITIONS:
            if group == "system":
                add_nav_button(page_id, symbol, key, group, footer_layout)

        # The first visibility pass runs before footer/system buttons exist. Re-run it
        # now so a restored Experience/identity context is reflected before first paint.
        # This prevents restricted Fleet/Server/Worker/Jobs routes from flashing or
        # remaining visible until the user manually re-selects a mode.
        self._refresh_nav_visibility()

        self.service_label = QLabel("●  本地服务 · 127.0.0.1:8787")
        self.service_label.setProperty("servicePill", True)
        self.service_label.setToolTip("Headless Server 默认仅绑定 loopback")
        self.service_label.setFixedHeight(28)
        footer_layout.addWidget(self.service_label)
        self.nav_layout.addWidget(self.nav_footer)
        root.addWidget(self.nav)

        self.center_workspace = QWidget()
        self.center_workspace.setProperty("arenyxa_shell_ltr", True)
        self.center_workspace.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        center_layout = QVBoxLayout(self.center_workspace)
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setSpacing(8)
        self.topbar = GlassPanel(self.theme, elevated=True)
                                                                                        
                                                                                        
        self.topbar.setProperty("arenyxa_motion_static", True)
        self.topbar.setProperty("arenyxa_shell_ltr", True)
        self.topbar.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        top = QHBoxLayout(self.topbar)
        top.setDirection(QBoxLayout.Direction.LeftToRight)
        top.setContentsMargins(12, 8, 12, 8)
        self.global_search = QLineEdit()
        self.global_search.setPlaceholderText(self.language.text("top.search"))
        self.global_search.setMaximumWidth(440)
        self.run_button = QPushButton(self.language.text("top.run"))
        self.run_button.setProperty("primary", True)
        self.pause_button = QPushButton(self.language.text("top.pause"))
        self.stop_button = QPushButton(self.language.text("top.stop"))
        self.open_data_button = QPushButton(self.language.text("top.open_data"))
        self.capture_button = QPushButton(self.language.text("top.capture"))
        self.studio_button = QPushButton("⌬ Web Intelligence")
        self.studio_button.setToolTip("Web Intelligence · Ctrl+Shift+I")
        self.blueprint_button = QPushButton("◆ Blueprint")
        self.blueprint_button.setToolTip("Explainable Web Intelligence Blueprint · Ctrl+Shift+B")
        self.autopilot_button = QPushButton("✦ Autopilot")
        self.autopilot_button.setToolTip("Deterministic local learning · Ctrl+Shift+A")
        self.inspector_button = QPushButton("Inspector ›")
        self.live_progress = QProgressBar()
        self.live_progress.setRange(0, 100)
        self.live_progress.setValue(0)
        self.live_progress.setTextVisible(True)
        self.live_progress.setFormat("Idle")
        self.live_progress.setFixedWidth(150)
        self.live_progress.setVisible(False)
        top.addWidget(self.run_button)
        top.addWidget(self.pause_button)
        top.addWidget(self.stop_button)
        top.addStretch()
        top.addWidget(self.global_search)
        top.addWidget(self.live_progress)
        top.addWidget(self.studio_button)
        top.addWidget(self.blueprint_button)
        top.addWidget(self.autopilot_button)
        top.addWidget(self.capture_button)
        top.addWidget(self.open_data_button)
        top.addWidget(self.inspector_button)
        center_layout.addWidget(self.topbar)
        self.stack = QStackedWidget()
        self.stack.setProperty("arenyxa_shell_ltr", True)
        self.stack.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
                                                                                            
                                                                                             
                                                                   
        center_layout.addWidget(self.stack, 1)
        root.addWidget(self.center_workspace, 1)

        self.inspector = GlassPanel(self.theme, elevated=True)
        self.inspector.setProperty("arenyxa_shell_ltr", True)
        self.inspector.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.inspector.setMinimumWidth(self._shell_metric(280))
        self.inspector.setMaximumWidth(self._shell_metric(460))
        inspector_layout = QVBoxLayout(self.inspector)
        inspector_layout.setContentsMargins(14, 13, 14, 14)
        inspector_header = QHBoxLayout()
        inspector_header.setDirection(QBoxLayout.Direction.LeftToRight)
        self.inspector_title = QLabel("上下文检查器")
        self.inspector_title.setProperty("section", True)
        close_inspector = QPushButton("×")
        close_inspector.setFixedSize(30, 30)
        close_inspector.clicked.connect(self.toggle_inspector)
        inspector_header.addWidget(self.inspector_title)
        inspector_header.addStretch()
        inspector_header.addWidget(close_inspector)
        inspector_layout.addLayout(inspector_header)
        self.inspector_content = QPlainTextEdit()
        self.inspector_content.setReadOnly(True)
        self.inspector_content.setPlainText("选择任务、运行、请求或数据记录以查看上下文。")
        inspector_layout.addWidget(self.inspector_content, 1)
        root.addWidget(self.inspector)

        status = QStatusBar()
        self.setStatusBar(status)
        self.status_text = QLabel(self.language.text("status.ready"))
        self.worker_status = QLabel("0 background · DB ready · 60/120Hz adaptive")
        self.worker_status.setProperty("muted", True)
        status.addWidget(self.status_text, 1)
        status.addPermanentWidget(self.worker_status)
        self._start_status_timers()

    def _start_status_timers(self) -> None:
        self.worker_timer = QTimer(self)
        self.worker_timer.timeout.connect(self.refresh_global_status)
        self.worker_timer.start(self.context.performance.status_refresh_ms)
        self.supervisor_timer = QTimer(self)
        self.supervisor_timer.setInterval(500)
        self.supervisor_timer.timeout.connect(self._runtime_supervisor_heartbeat)
        self.supervisor_timer.start()
        self._runtime_supervisor_heartbeat()

    def _runtime_supervisor_heartbeat(self) -> None:
        supervisor = getattr(self.context, "runtime_supervisor", None)
        if supervisor is None:
            return
        supervisor.heartbeat(
            "ui_thread",
            {
                "page_id": self.current_page_id,
                "route_generation": self._route_generation,
                "visible_pages": len(self._visible_page_ids),
            },
        )

    def _enforce_shell_ltr(self) -> None:
        





        self.setProperty("arenyxa_shell_ltr", True)
        self.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        for name in ("backdrop", "nav", "nav_header", "center_workspace", "topbar", "stack", "inspector"):
            widget = getattr(self, name, None)
            if isinstance(widget, QWidget):
                widget.setProperty("arenyxa_shell_ltr", True)
                widget.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        central = self.centralWidget()
        if isinstance(central, QWidget):
            central.setProperty("arenyxa_shell_ltr", True)
            central.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        layout = central.layout() if isinstance(central, QWidget) else None
        if isinstance(layout, QBoxLayout):
            layout.setDirection(QBoxLayout.Direction.LeftToRight)

    def _build_tray(self, icon_path: Path) -> None:
        self.tray: QSystemTrayIcon | None = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        icon = QIcon(str(icon_path)) if icon_path.exists() else self.windowIcon()
        tray = QSystemTrayIcon(icon, self)
        menu = QMenu(self)
        show_action = QAction("Open Arenyxa", menu)
        studio_action = QAction("Web Intelligence", menu)
        live_action = QAction("Live Run Center", menu)
        blueprint_action = QAction("Explainable Blueprint", menu)
        autopilot_action = QAction("Autopilot Learning", menu)
        compatibility_action = QAction("Compatibility Lab", menu)
        capture_action = QAction("Network Capture", menu)
        quit_action = QAction("Exit Arenyxa", menu)
        show_action.triggered.connect(self._restore_from_tray)
        studio_action.triggered.connect(lambda: (self._restore_from_tray(), self.navigate("studio")))
        live_action.triggered.connect(lambda: self.open_studio_section("live"))
        blueprint_action.triggered.connect(lambda: self.open_studio_section("blueprint"))
        autopilot_action.triggered.connect(lambda: self.open_studio_section("autopilot"))
        compatibility_action.triggered.connect(lambda: self.open_studio_section("compatibility"))
        capture_action.triggered.connect(lambda: (self._restore_from_tray(), self.navigate("network")))
        quit_action.triggered.connect(self.close)
        for action in (show_action, studio_action, blueprint_action, autopilot_action, compatibility_action, live_action, capture_action):
            menu.addAction(action)
        menu.addSeparator()
        menu.addAction(quit_action)
        tray.setContextMenu(menu)
        tray.setToolTip("Arenyxa · Ready")
        tray.activated.connect(lambda reason: self._restore_from_tray() if reason == QSystemTrayIcon.ActivationReason.Trigger else None)
        tray.show()
        self.tray = tray

    def _restore_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def open_studio_section(self, section: str) -> None:
        self._restore_from_tray()
        self.navigate("studio")
        page = self.pages.get("studio")
        if isinstance(page, IntelligenceStudioPage):
            page.open_section(section)

    def _connect_global_actions(self) -> None:
        self.collapse_nav.clicked.connect(self.toggle_nav)
        self.inspector_button.clicked.connect(self.toggle_inspector)
        self.global_search.returnPressed.connect(self.global_search_action)
        self.capture_button.clicked.connect(lambda: self.navigate("network"))
        self.open_data_button.clicked.connect(self.open_data_folder)
        self.run_button.clicked.connect(self.run_selected_task)
        self.studio_button.clicked.connect(lambda: self.navigate("studio"))
        self.blueprint_button.clicked.connect(lambda: self.open_studio_section("blueprint"))
        self.autopilot_button.clicked.connect(lambda: self.open_studio_section("autopilot"))
        self.pause_button.clicked.connect(self.pause_active)
        self.stop_button.clicked.connect(self.stop_active)
        self.language.changed.connect(lambda _locale: self.retranslate())
        QShortcut(QKeySequence("Ctrl+K"), self, self.show_command_palette)
        QShortcut(QKeySequence("Ctrl+L"), self, self.global_search.setFocus)
        QShortcut(QKeySequence("Ctrl+Shift+C"), self, lambda: self.navigate("network"))
        QShortcut(QKeySequence("Ctrl+Shift+I"), self, lambda: self.open_studio_section("smartpath"))
        QShortcut(QKeySequence("Ctrl+Shift+B"), self, lambda: self.open_studio_section("blueprint"))
        QShortcut(QKeySequence("Ctrl+Shift+A"), self, lambda: self.open_studio_section("autopilot"))
        QShortcut(QKeySequence("Ctrl+Shift+H"), self, lambda: self.open_studio_section("http"))
        QShortcut(QKeySequence("Ctrl+Shift+L"), self, lambda: self.open_studio_section("compatibility"))
