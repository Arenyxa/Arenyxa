from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path

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
from arenyxa.presentation.pages.professional_suite import ProfessionalSuitePage
from arenyxa.presentation.pages.recovery import RecoveryCenterPage
from arenyxa.presentation.pages.settings import AboutPage, SettingsPage
from arenyxa.presentation.pages.personalization import PersonalizationPage
from arenyxa.presentation.pages.enterprise import EnterprisePage
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
from arenyxa.presentation.taskbar import WindowsTaskbarProgress
from arenyxa.presentation.themes import ThemeManager
from arenyxa.presentation.ui_scale import InterfaceScaleManager

PAGE_DEFINITIONS = [
                                                               
    ("dashboard", "⌂", "nav.dashboard", DashboardPage, "core"),
    ("search", "⌕", "nav.search", SearchPage, "core"),
    ("tasks", "◎", "nav.capture", TasksPage, "core"),
    ("professional", "⌬", "nav.professional", ProfessionalSuitePage, "core"),
    ("data", "▤", "nav.data", DataPage, "core"),
    ("visualization", "▥", "nav.visualization", VisualizationPage, "core"),
                                                                                        
    ("recovery", "↻", "nav.recovery", RecoveryCenterPage, "advanced"),
    ("advanced", "✦", "nav.advanced", AdvancedPlatformPage, "advanced"),
    ("version", "⑂", "nav.version", VersionPage, "advanced"),
    ("plugins", "⬡", "nav.plugins", PluginsPage, "advanced"),
                                                                                          
                                                                                              
    ("console", ">_", "nav.console", ConsolePage, "developer"),
    ("logs", "≣", "nav.logs", LogsPage, "developer"),
                                                                                               
                                                                                      
    ("enterprise", "▣", "nav.enterprise", EnterprisePage, "system"),
    ("personalization", "✧", "nav.personalization", PersonalizationPage, "system"),
    ("settings", "⚙", "nav.settings", SettingsPage, "system"),
    ("about", "ⓘ", "nav.about", AboutPage, "system"),
]
NAVIGATION = [(page_id, symbol, key, page_type) for page_id, symbol, key, page_type, _group in PAGE_DEFINITIONS]
PAGE_GROUP = {page_id: group for page_id, _symbol, _key, _page_type, group in PAGE_DEFINITIONS}
DEVELOPER_PAGE_IDS = {page_id for page_id, group in PAGE_GROUP.items() if group == "developer"}
PAGE_TYPES = {page_id: page_type for page_id, _symbol, _key, page_type, _group in PAGE_DEFINITIONS}
DEVELOPER_SHORTCUTS = [
    ("dev_api", "{}", "nav.dev.api"),
    ("dev_sandbox", "⬢", "nav.dev.sandbox"),
    ("dev_performance", "⌁", "nav.dev.performance"),
]


LOGGER = logging.getLogger(__name__)

class CommandPalette(QDialog):
    def __init__(self, commands: list[tuple[str, str, Callable[[], None]]], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Command Palette")
        self.setModal(True)
        self.resize(560, 430)
        self.commands = commands
        layout = QVBoxLayout(self)
        self.query = QLineEdit()
        self.query.setPlaceholderText("输入命令或页面名称")
        self.list = QListWidget()
        self.list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        layout.addWidget(self.query)
        layout.addWidget(self.list, 1)
        self.query.textChanged.connect(self.refresh)
        self.list.itemActivated.connect(self.execute_current)
        self.refresh()
        QTimer.singleShot(0, self.query.setFocus)

    def refresh(self) -> None:
        query = self.query.text().casefold()
        self.list.clear()
        for command_id, label, callback in self.commands:
            if query in label.casefold() or query in command_id.casefold():
                self.list.addItem(label)
                self.list.item(self.list.count() - 1).setData(
                    Qt.ItemDataRole.UserRole, (command_id, callback)
                )
        if self.list.count():
            self.list.setCurrentRow(0)

    def execute_current(self) -> None:
        item = self.list.currentItem()
        if not item:
            return
        _, callback = item.data(Qt.ItemDataRole.UserRole)
        self.accept()
        callback()


class MainWindow(QMainWindow):
    runnerProgress = Signal()

    def __init__(
        self,
        context: ApplicationContext,
        project_path: Path | None = None,
        launch_geometry: LaunchGeometryPlan | None = None,
    ) -> None:
        super().__init__()
        self.context = context
        self.project_path = project_path
        self._launch_geometry = launch_geometry
        self.setWindowTitle(f"Arenyxa V{__version__}")
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
        app.setProperty("arenyxa_high_contrast", bool(context.settings.high_contrast))
        app.setProperty("arenyxa_performance_mode", context.performance.mode)
        app.setProperty("arenyxa_glass_specular", bool(context.performance.glass_specular))
        self.pages: dict[str, WorkspacePage] = {}
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
        self.current_page_id = "dashboard"
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
                                                                                             
                                                                          
        self.navigate("dashboard")
                                                                                                     
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
        self.studio_button = QPushButton("⌬ Studio")
        self.studio_button.setToolTip("Arenyxa Intelligence Studio · Ctrl+Shift+I")
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
        self.worker_timer = QTimer(self)
        self.worker_timer.timeout.connect(self.refresh_global_status)
        self.worker_timer.start(self.context.performance.status_refresh_ms)

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
        studio_action = QAction("Intelligence Studio", menu)
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

    def _ensure_page(self, page_id: str) -> WorkspacePage:
        existing = self.pages.get(page_id)
        if existing is not None:
            return existing
        page_type = PAGE_TYPES.get(page_id)
        if page_type is None:
            raise KeyError(f"unknown page: {page_id}")
        page = page_type(self.context, self.theme, self.motion)
        page.setProperty("arenyxa_shell_ltr", True)
        page.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        if isinstance(page, AboutPage):
            page.set_language_manager(self.language)
        page.statusMessage.connect(self.show_status)
        page.inspectorChanged.connect(self.update_inspector)
        page.operationProgress.connect(self.update_operation_progress)
        self.pages[page_id] = page
        self.stack.addWidget(page)
        self.ui_scale.scale_tree(page)
        if isinstance(page, PersonalizationPage) and not self._personalization_signals_connected:
            page.themeRequested.connect(self._apply_theme_requested)
            page.motionRequested.connect(self.motion.set_profile)
            page.uiScaleRequested.connect(self._apply_ui_scale_requested)
            self._personalization_signals_connected = True
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

    def resizeEvent(self, event) -> None:
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
            if self._complete_welcome_center(profile_id):
                dialog.accept()

        def open_enterprise() -> None:
            dialog.accept()
            self.navigate("enterprise")

        dialog.profileSelected.connect(complete)
        dialog.enterpriseRequested.connect(open_enterprise)
        self.show_status("Welcome Center · 独立使用模式窗口")
        dialog.exec()
        dialog.deleteLater()

    def _complete_welcome_center(self, profile_id: str) -> bool:
        try:
            profile = apply_experience_profile(self.context.settings, profile_id)
            self.context.settings.save(self.context.paths.root / "settings.json")
        except Exception as exc:
            LOGGER.exception("Failed to persist Arenyxa experience profile")
            QMessageBox.warning(self, "无法保存使用模式", f"{type(exc).__name__}: {exc}")
            return False
        self._refresh_nav_visibility()
        self.retranslate()
        self.show_status(f"已选择 {profile.title}；使用模式不会改变安全权限。")
        self.navigate("dashboard")
        return True

    def _apply_theme_requested(self, theme_id: str) -> None:
        
        self.motion.crossfade_style(self, lambda: self.theme.apply(theme_id, self))

    def _developer_surface_enabled(self) -> bool:
        return bool(self.context.settings.developer_mode or getattr(self.context, "root_developer_workstation", False))

    def _page_allowed(self, page_id: str) -> bool:
        return page_id in PAGE_GROUP and (page_id not in DEVELOPER_PAGE_IDS or self._developer_surface_enabled())

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
            self.show_status("Developer Mode 未启用；请在设置 → 高级设置中启用。")
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
                                                                                          
                                                                                            
            self.motion.reveal(page, MotionIntent.ENTER)
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
        advanced_visible = self._nav_group_expanded("advanced")
        for button in self.nav_group_items["advanced"]:
            button.setVisible(advanced_visible)

        developer_enabled = self._developer_surface_enabled()
        developer_header = self.nav_group_buttons.get("developer")
        if developer_header is not None:
            developer_header.setVisible(developer_enabled)
        developer_visible = developer_enabled and self._nav_group_expanded("developer")
        for button in self.nav_group_items["developer"]:
            button.setVisible(developer_visible)

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
        root_workstation = bool(getattr(self.context, "root_developer_workstation", False))
        if not enabled and not root_workstation:
            self.context.settings.developer_nav_expanded = False
                                                                                       
                                                                                                
            self.context.terminal.request_stop()
            if self.current_page_id in DEVELOPER_PAGE_IDS:
                self.navigate("settings")
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

    def show_status(self, message: str, duration: int = 5000) -> None:
        localized = self.language.literal(message)
        self.status_text.setText(localized)
        self._status_generation += 1
        generation = self._status_generation
                                                                                  
        lowered = message.casefold()
        if any(token in message for token in ("失败", "错误")) or any(token in lowered for token in ("failed", "error")):
            self.motion.emphasize(self.status_text, MotionIntent.ERROR)
        elif any(token in message for token in ("完成", "成功")) or any(token in lowered for token in ("completed", "success")):
            self.motion.emphasize(self.status_text, MotionIntent.SUCCESS)

        def clear_if_current() -> None:
            if generation == self._status_generation:
                self.status_text.setText(self.language.text("status.ready"))

        QTimer.singleShot(duration, clear_if_current)

    def update_operation_progress(self, label: str, completed: int, total: int, state: str) -> None:
        state = str(state or "normal").casefold()
        if state == "clear":
            self._aux_progress = None
        else:
            self._aux_progress = (str(label), max(0, int(completed)), max(0, int(total)), state)
        self.refresh_global_status()

    def refresh_global_status(self) -> None:
        handles = self.context.runner.active_handles()
        capture = self.context.capture.session
        capture_text = capture.state.value if capture else "idle"
        frame = self.motion.profiler.snapshot()
        self.worker_status.setText(
            f"{len(handles)} background · capture {capture_text} · DB ready · "
            f"{self.motion.refresh_hz:.0f}Hz · {self.motion.effective_quality()} · p95 {float(frame['p95_ms']):.1f}ms"
        )
        active = [handle for handle in handles if not handle.future.done()]
        if active:
            completed = sum(max(0, int(handle.run.completed_units)) for handle in active)
            totals = [int(handle.run.total_units or 0) for handle in active]
            total = sum(value for value in totals if value > 0)
            paused = any(handle.run.status.value == "paused" for handle in active)
            failed = any(handle.run.status.value == "failed" for handle in active)
            if total > 0:
                percent = max(0, min(100, round(completed / total * 100)))
                self.live_progress.setRange(0, 100)
                self.live_progress.setValue(percent)
                self.live_progress.setFormat(f"{len(active)} runs · {percent}%")
                state = self.taskbar_progress.TBPF_PAUSED if paused else (self.taskbar_progress.TBPF_ERROR if failed else self.taskbar_progress.TBPF_NORMAL)
                self.taskbar_progress.set_progress(completed, total, state)
            else:
                self.live_progress.setRange(0, 0)
                self.live_progress.setFormat(f"{len(active)} runs")
                self.taskbar_progress.set_state(self.taskbar_progress.TBPF_INDETERMINATE)
            self.live_progress.setVisible(True)
        elif capture and capture_text in {"preparing", "capturing", "finalizing"}:
            self.live_progress.setVisible(True)
            self.live_progress.setRange(0, 0)
            self.live_progress.setFormat(f"Capture · {capture_text}")
            self.taskbar_progress.set_state(self.taskbar_progress.TBPF_INDETERMINATE)
        elif self._aux_progress is not None:
            label, completed, total, state_name = self._aux_progress
            self.live_progress.setVisible(True)
            if total > 0:
                percent = max(0, min(100, round(completed / total * 100)))
                self.live_progress.setRange(0, 100)
                self.live_progress.setValue(percent)
                self.live_progress.setFormat(f"{label} · {percent}%")
                taskbar_state = {
                    "paused": self.taskbar_progress.TBPF_PAUSED,
                    "error": self.taskbar_progress.TBPF_ERROR,
                }.get(state_name, self.taskbar_progress.TBPF_NORMAL)
                self.taskbar_progress.set_progress(completed, total, taskbar_state)
            else:
                self.live_progress.setRange(0, 0)
                self.live_progress.setFormat(label)
                self.taskbar_progress.set_state(self.taskbar_progress.TBPF_INDETERMINATE)
        else:
            self.live_progress.setVisible(False)
            self.live_progress.setRange(0, 100)
            self.live_progress.setValue(0)
            self.live_progress.setFormat("Idle")
            self.taskbar_progress.clear()
        if self.tray is not None:
            aux = f" · {self._aux_progress[0]}" if self._aux_progress else ""
            self.tray.setToolTip(f"Arenyxa · {len(active)} active · capture {capture_text}{aux}")

    def global_search_action(self) -> None:
        text = self.global_search.text().strip()
        if not text:
            self.show_command_palette()
            return
        search_page = self._ensure_page("search")
        assert isinstance(search_page, SearchPage)
        search_page.query.setText(text)
        self.navigate("search")
        search_page.search()

    def show_command_palette(self) -> None:
        commands: list[tuple[str, str, Callable[[], None]]] = []
        for page_id, _symbol, _key, _page_type, _group in PAGE_DEFINITIONS:
            if not self._page_allowed(page_id):
                continue
            button = self.nav_buttons.get(page_id)
            label = button.toolTip() if button is not None else page_id
            commands.append((f"nav.{page_id}", label, lambda page_id=page_id: self.navigate(page_id)))
        if self._developer_surface_enabled():
            for action_id, _symbol, key in DEVELOPER_SHORTCUTS:
                commands.append((f"dev.{action_id}", self.language.text(key), lambda action_id=action_id: self.open_developer_tool(action_id)))
        commands.extend(
            [
                ("action.run", self.language.text("top.run"), self.run_selected_task),
                ("action.capture", self.language.text("top.capture"), lambda: self.navigate("network")),
                ("action.open_data", self.language.text("top.open_data"), self.open_data_folder),
                ("action.diagnostics", self.language.text("action.diagnostics"), self._run_diagnostics_command),
                ("action.repair", self.language.text("action.repair"), self.launch_repair_center),
                ("studio.smartpath", "SmartPath 2.0 / Data Sources", lambda: self.open_studio_section("smartpath")),
                ("studio.blueprint", "Explainable Web Intelligence Blueprint", lambda: self.open_studio_section("blueprint")),
                ("studio.autopilot", "Autopilot Learning / Experience Store", lambda: self.open_studio_section("autopilot")),
                ("studio.compatibility", "Compatibility Lab", lambda: self.open_studio_section("compatibility")),
                ("studio.portability", "Open Workflow Portability", lambda: self.open_studio_section("portability")),
                ("studio.selector", "Selector Studio / Self-Heal", lambda: self.open_studio_section("selector")),
                ("studio.http", "HTTP Request Builder", lambda: self.open_studio_section("http")),
                ("studio.live", "Live Run & Activity Center", lambda: self.open_studio_section("live")),
                ("studio.secrets", "Secrets Vault", lambda: self.open_studio_section("secrets")),
                ("studio.profiles", "Browser Profiles & Marketplace", lambda: self.open_studio_section("profiles")),
                ("studio.workers", "Distributed Workers", lambda: self.open_studio_section("workers")),
                ("studio.recorder", "Browser Recorder 2.0", lambda: self.open_studio_section("recorder")),
                ("studio.debugger", "Workflow Debugger", lambda: self.open_studio_section("debugger")),
            ]
        )
        palette = CommandPalette(commands, self)
        QTimer.singleShot(0, lambda: self.language.translate_tree(palette))
        QTimer.singleShot(0, lambda: self.motion.reveal(palette, MotionIntent.EXPAND))
        palette.exec()

    def _run_diagnostics_command(self) -> None:
        page = self._ensure_page("settings")
        if isinstance(page, SettingsPage):
            page.run_diagnostics()

    def set_startup_health_report(self, report: object) -> None:
        
        self._startup_health_report = report

    def request_repair_exit(self) -> None:
        
        self._repair_exit_requested = True
        self.close()

    def launch_repair_center(self) -> None:
        from arenyxa.presentation.repair_dialog import RepairSelectionDialog
        from arenyxa.repair import StartupHealthScanner, create_repair_plan, installation_root, launch_repair_worker

        if self._repair_scan_in_progress:
            self.show_status("Repair Center 正在后台检查安装与运行状态…")
            return

                                                                                       
                                                                                         
                                               
        self._repair_scan_in_progress = True
        self.show_status("Repair Center 正在后台检查安装与运行状态…")

        def worker():
            from arenyxa.repair import append_feature_integration_findings

            report = StartupHealthScanner(
                self.context.paths, installation_root(), ignore_current_session=True
            ).scan()
            return append_feature_integration_findings(report, self.context)

        def completed(value: object) -> None:
            self._repair_scan_in_progress = False
            report = value
            self.set_startup_health_report(report)
            try:
                selector = RepairSelectionDialog(report, self.language.locale, self)
                if selector.exec() != selector.DialogCode.Accepted:
                    self.show_status("Repair Center 已取消")
                    return
                active = self.context.runner.active_handles()
                if active:
                    choice = QMessageBox.question(
                        self,
                        "Repair Center",
                        f"仍有 {len(active)} 个后台任务。执行修复将停止任务并退出 Arenyxa。继续？",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                    )
                    if choice != QMessageBox.StandardButton.Yes:
                        self.show_status("Repair Center 已取消；后台任务保持运行")
                        return
                    self.context.runner.cancel_all()
                plan_path = create_repair_plan(
                    self.context.paths,
                    report,
                    selector.selected_categories(),
                    parent_pid=__import__("os").getpid(),
                    relaunch=True,
                )
                launch_repair_worker(plan_path)
            except Exception as exc:                                                                   
                QMessageBox.critical(self, "Repair Center", str(exc))
                return
            self.request_repair_exit()

        def failed(message: str) -> None:
            self._repair_scan_in_progress = False
            QMessageBox.critical(self, "Repair Center", message)
            self.show_status("Repair Center 诊断失败")

                                                                                            
        run_background(worker, completed, failed)

    def _emit_runner_progress(self) -> None:
                                                                                            
                                                                                             
        interval = max(0.15, self.context.performance.status_refresh_ms / 1000.0 * 0.5)
        now = time.monotonic()
        with self._progress_emit_lock:
            if now - self._last_progress_emit < interval:
                return
            self._last_progress_emit = now
        self.runnerProgress.emit()

    def run_selected_task(self) -> None:
        tasks = self.context.store.list_tasks(limit=1)
        if not tasks:
            self.navigate("tasks")
            self.show_status("请先创建任务")
            return
        try:
            handle = self.context.runner.submit(
                tasks[0], lambda _run: self._emit_runner_progress()
            )
            self.context.nextgen.activity.publish("run", f"Started {tasks[0].name}", details={"run_id": handle.run.id, "task_id": tasks[0].id})
            def activity_done(_future, run=handle.run, task_name=tasks[0].name) -> None:
                level = "error" if run.status.value == "failed" else ("warning" if run.status.value == "cancelled" else "info")
                self.context.nextgen.activity.publish("run-complete", f"{task_name}: {run.status.value}", level=level, details={"run_id": run.id, "success": run.success_count, "failure": run.failure_count, "retry": run.retry_count})
            handle.future.add_done_callback(activity_done)
            self.show_status(f"已启动 {tasks[0].name} · {handle.run.id}")
        except Exception as exc:                                          
            QMessageBox.warning(self, "运行失败", str(exc))

    def pause_active(self) -> None:
        handles = self.context.runner.active_handles()
        for handle in handles:
            if handle.run.status.value == "paused":
                handle.resume()
            else:
                handle.pause()
        self.show_status("活动任务暂停/恢复状态已更新")

    def stop_active(self) -> None:
        self.context.runner.cancel_all()
        self.show_status("已请求协作式取消所有活动任务")

    def open_data_folder(self) -> None:
        target = QUrl.fromLocalFile(str(self.context.paths.root.resolve()))
        if not QDesktopServices.openUrl(target):
            QMessageBox.warning(self, "无法打开文件夹", str(self.context.paths.root))

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
        try:
            if self.tray is not None:
                self.tray.hide()
            self.taskbar_progress.clear()
            self.taskbar_progress.close()
                                                                                          
                                                                                         
                                                                                          
            if not begin_background_shutdown(timeout_ms=2500):
                LOGGER.warning("UI background jobs did not fully quiesce before context shutdown")
            self.context.shutdown()
            self.crash_marker.unlink(missing_ok=True)
        finally:
            event.accept()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if self._startup_motion_done:
            return
        self._startup_motion_done = True
                                                                                            
        QTimer.singleShot(20, lambda: self.motion.reveal(self.centralWidget(), MotionIntent.ENTER))
