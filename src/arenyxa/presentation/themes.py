from __future__ import annotations

import ctypes
from arenyxa.compat import dataclass

from arenyxa.qt_compat.QtCore import QObject, Signal
from arenyxa.qt_compat.QtGui import QColor, QPalette
from arenyxa.qt_compat.QtWidgets import QApplication, QWidget
from arenyxa.platform_compat import select_runtime
from arenyxa.presentation.ui_scale_math import clamp_ui_scale, scale_stylesheet_metrics


@dataclass(frozen=True, slots=True)
class ThemeTokens:
    id: str
    name: str
    dark: bool
    background: str
    background_alt: str
    surface: str
    surface_hover: str
    glass: str
    glass_elevated: str
    text: str
    text_muted: str
    accent: str
    accent_hover: str
    accent_soft: str
    border: str
    success: str
    warning: str
    danger: str
    info: str
    selection: str
    shadow: str
    gradient_start: str
    gradient_mid: str
    gradient_end: str
    radius: int = 14
    blur: int = 22


THEMES: dict[str, ThemeTokens] = {
    "clean_light": ThemeTokens(
        "clean_light",
        "Clean Light / 明亮浅色",
        False,
        "#f4f8f5",
        "#edf4ef",
        "rgba(255,255,255,0.92)",
        "#f7fbf8",
        "rgba(255,255,255,0.78)",
        "rgba(255,255,255,0.91)",
        "#14221b",
        "#617068",
        "#23b85a",
        "#1aa34e",
        "rgba(35,184,90,0.13)",
        "rgba(43,88,61,0.13)",
        "#24ad5a",
        "#e7a11a",
        "#e44b54",
        "#3b82f6",
        "rgba(35,184,90,0.18)",
        "rgba(20,50,30,0.16)",
        "#f8fffa",
        "#ebf8ef",
        "#f7fbff",
        13,
        18,
    ),
    "modern_dark": ThemeTokens(
        "modern_dark",
        "Modern Dark / 现代深色",
        True,
        "#0e141b",
        "#121c25",
        "rgba(24,34,44,0.94)",
        "#202d39",
        "rgba(22,33,43,0.76)",
        "rgba(30,43,55,0.91)",
        "#eef5f2",
        "#91a39d",
        "#45d67a",
        "#67e491",
        "rgba(69,214,122,0.16)",
        "rgba(151,195,177,0.16)",
        "#53d986",
        "#f1b84b",
        "#ff6570",
        "#62a8ff",
        "rgba(69,214,122,0.22)",
        "rgba(0,0,0,0.46)",
        "#111821",
        "#14232b",
        "#101720",
        14,
        22,
    ),
    "professional_graphite": ThemeTokens(
        "professional_graphite",
        "Professional Graphite / 专业石墨",
        True,
        "#151719",
        "#1a1d20",
        "rgba(34,37,40,0.95)",
        "#2a2e31",
        "rgba(36,39,42,0.80)",
        "rgba(46,50,54,0.92)",
        "#f2f3f3",
        "#a5aaad",
        "#8dc7a2",
        "#a4d6b5",
        "rgba(141,199,162,0.15)",
        "rgba(210,220,214,0.13)",
        "#73c68f",
        "#d3ad63",
        "#e06d70",
        "#86aee8",
        "rgba(141,199,162,0.21)",
        "rgba(0,0,0,0.48)",
        "#181b1d",
        "#222729",
        "#151719",
        10,
        18,
    ),
    "terminal_green": ThemeTokens(
        "terminal_green",
        "Terminal Green / 绿色终端",
        True,
        "#020806",
        "#04110b",
        "rgba(4,18,11,0.94)",
        "#092418",
        "rgba(3,24,13,0.79)",
        "rgba(7,34,19,0.92)",
        "#adffc9",
        "#5eaa79",
        "#00ef71",
        "#40ff94",
        "rgba(0,239,113,0.14)",
        "rgba(0,239,113,0.23)",
        "#00e874",
        "#d9d55b",
        "#ff5a6a",
        "#4adfff",
        "rgba(0,239,113,0.22)",
        "rgba(0,0,0,0.64)",
        "#020b07",
        "#032113",
        "#020806",
        7,
        16,
    ),
    "blue_productivity": ThemeTokens(
        "blue_productivity",
        "Blue Productivity / 蓝色生产力",
        False,
        "#f3f7fc",
        "#eaf1fb",
        "rgba(255,255,255,0.93)",
        "#f4f8ff",
        "rgba(250,253,255,0.78)",
        "rgba(255,255,255,0.92)",
        "#17233a",
        "#66738a",
        "#377ef2",
        "#246de1",
        "rgba(55,126,242,0.13)",
        "rgba(51,88,143,0.14)",
        "#23a968",
        "#d99819",
        "#dc5360",
        "#377ef2",
        "rgba(55,126,242,0.18)",
        "rgba(26,52,92,0.18)",
        "#f8fbff",
        "#edf5ff",
        "#f9f8ff",
        12,
        18,
    ),
    "aurora_glass": ThemeTokens(
        "aurora_glass",
        "Aurora Glass / 极光玻璃",
        True,
        "#031126",
        "#061a31",
        "rgba(6,25,47,0.86)",
        "rgba(10,42,65,0.92)",
        "rgba(5,31,55,0.64)",
        "rgba(7,39,67,0.82)",
        "#ecfbff",
        "#8eaec2",
        "#17ee8c",
        "#35ffac",
        "rgba(23,238,140,0.15)",
        "rgba(82,214,255,0.24)",
        "#20ed8b",
        "#ffd35c",
        "#ff5778",
        "#47cfff",
        "rgba(23,238,140,0.23)",
        "rgba(0,0,10,0.58)",
        "#031127",
        "#053753",
        "#13042f",
        15,
        26,
    ),
}


class ThemeManager(QObject):
    changed = Signal(str)

    def __init__(self, application: QApplication, initial: str = "modern_dark") -> None:
        super().__init__()
        self.application = application
        self.current = THEMES.get(initial, THEMES["modern_dark"])
        self.ui_scale = 1.0

    def apply(self, theme_id: str, window: QWidget | None = None) -> None:
        theme = THEMES.get(theme_id, THEMES["modern_dark"])
        self.current = theme
        self.application.setPalette(self._palette(theme))
        self.application.setStyleSheet(self._stylesheet(theme, self.ui_scale))
        if window:
            window.setProperty("theme", theme.id)
            window.style().unpolish(window)
            window.style().polish(window)
            apply_windows_backdrop(window, theme.dark)
        self.changed.emit(theme.id)

    def set_ui_scale(self, scale: float, window: QWidget | None = None) -> None:
        self.ui_scale = clamp_ui_scale(scale)
        self.apply(self.current.id, window)

    @staticmethod
    def _palette(theme: ThemeTokens) -> QPalette:
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(theme.background))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(theme.text))
        palette.setColor(QPalette.ColorRole.Base, QColor(theme.surface))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(theme.background_alt))
        palette.setColor(QPalette.ColorRole.Text, QColor(theme.text))
        palette.setColor(QPalette.ColorRole.Button, QColor(theme.surface))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(theme.text))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(theme.selection))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor(theme.text))
        return palette

    @staticmethod
    def _stylesheet(t: ThemeTokens, scale: float = 1.0) -> str:
        stylesheet = f"""
        * {{ font-family: 'Segoe UI Variable', 'Segoe UI', sans-serif; font-size: 13px; color: {t.text}; }}
        QMainWindow, QWidget#AppRoot {{ background: transparent; }}
        QWidget#Backdrop {{
            background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 {t.gradient_start}, stop:0.5 {t.gradient_mid}, stop:1 {t.gradient_end});
        }}
        QWidget[glass="true"], QFrame[glass="true"] {{
            background-color: {t.glass}; border: 1px solid {t.border}; border-radius: {t.radius}px;
        }}
        QFrame[card="true"] {{
            background-color: {t.surface}; border: 1px solid {t.border}; border-radius: {t.radius}px;
        }}
        QFrame[card="true"]:hover {{ background-color: {t.surface_hover}; }}
        QLabel[muted="true"] {{ color: {t.text_muted}; }}
        QLabel[accent="true"] {{ color: {t.accent}; }}
        QLabel[title="true"] {{ font-size: 22px; font-weight: 650; }}
        QLabel[section="true"] {{ font-size: 15px; font-weight: 650; }}
        QPushButton {{
            min-height: 34px; padding: 0 13px; background-color: {t.surface}; border: 1px solid {t.border};
            border-radius: 9px; color: {t.text};
        }}
        QPushButton:hover {{ background-color: {t.surface_hover}; border-color: {t.accent}; }}
        QPushButton:pressed {{ background-color: {t.accent_soft}; }}
        QPushButton:disabled {{ color: {t.text_muted}; background-color: {t.background_alt}; }}
        QPushButton[primary="true"] {{ background-color: {t.accent}; color: #03130b; border-color: {t.accent}; font-weight: 650; }}
        QPushButton[primary="true"]:hover {{ background-color: {t.accent_hover}; }}
        QPushButton[danger="true"] {{ color: {t.danger}; border-color: {t.danger}; }}
        QWidget[sidebarHeader="true"], QWidget[sidebarFooter="true"], QWidget#SidebarItems,
        QScrollArea#SidebarScroll, QScrollArea#SidebarScroll QWidget {{
            background: transparent; border: 0;
        }}
        QLabel[sidebarBrandTitle="true"] {{ font-size: 16px; font-weight: 700; color: {t.text}; }}
        QLabel[sidebarBrandSubtitle="true"] {{ font-size: 10.5px; color: {t.text_muted}; }}
        QPushButton[sidebarCollapse="true"] {{
            min-width: 30px; min-height: 30px; padding: 0; border-radius: 9px;
            background-color: transparent; border: 1px solid transparent; color: {t.text_muted}; font-size: 17px;
        }}
        QPushButton[sidebarCollapse="true"]:hover {{
            background-color: {t.surface_hover}; border-color: {t.border}; color: {t.text};
        }}
        QFrame[navDivider="true"] {{ background-color: {t.border}; border: 0; max-height: 1px; }}
        QPushButton[nav="true"] {{
            text-align: left; min-height: 0; padding: 0 11px; border: 1px solid transparent;
            border-radius: 10px; background-color: transparent; color: {t.text}; font-weight: 500;
        }}
        QPushButton[navSub="true"] {{ padding-left: 22px; color: {t.text_muted}; font-weight: 500; }}
        QPushButton[navSystem="true"] {{ color: {t.text_muted}; }}
        QPushButton[nav="true"]:hover {{
            background-color: {t.surface_hover}; border-color: {t.border}; color: {t.text};
        }}
        QPushButton[nav="true"]:checked {{
            background-color: {t.accent_soft}; color: {t.text}; border: 1px solid {t.selection};
            border-left: 3px solid {t.accent}; font-weight: 650; padding-left: 9px;
        }}
        QPushButton[navSub="true"]:checked {{ padding-left: 20px; }}
        QPushButton[nav="true"][navCompact="true"] {{ text-align: center; padding: 0; font-size: 16px; }}
        QPushButton[nav="true"][navCompact="true"]:checked {{ padding: 0; border-left: 3px solid {t.accent}; }}
        QPushButton[navGroup="true"] {{
            text-align: left; min-height: 0; border: 1px solid transparent; background: transparent;
            padding: 0 10px; border-radius: 8px; color: {t.text_muted}; font-size: 11.5px; font-weight: 650;
        }}
        QPushButton[navGroup="true"]:hover {{ color: {t.text}; background-color: {t.surface_hover}; border-color: {t.border}; }}
        QPushButton[navGroup="true"][navGroupActive="true"] {{ color: {t.text}; }}
        QPushButton[navGroup="true"][navCompact="true"] {{ text-align: center; padding: 0; font-size: 15px; }}
        QLabel[servicePill="true"] {{
            padding-left: 9px; color: {t.text_muted}; background-color: {t.background_alt};
            border: 1px solid {t.border}; border-radius: 8px; font-size: 10.5px;
        }}
        QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QDoubleSpinBox, QDateTimeEdit {{
            min-height: 34px; background-color: {t.glass_elevated}; border: 1px solid {t.border}; border-radius: 9px; padding: 0 10px;
            selection-background-color: {t.selection};
        }}
        QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {{ border: 1px solid {t.accent}; }}
        QComboBox QAbstractItemView {{ background: {t.background_alt}; border: 1px solid {t.border}; selection-background-color: {t.selection}; }}
        QTableView, QTableWidget, QListView, QListWidget, QTreeView, QTreeWidget {{
            background-color: transparent; alternate-background-color: {t.background_alt}; border: 1px solid {t.border}; border-radius: 10px;
            selection-background-color: {t.selection}; gridline-color: {t.border}; outline: 0;
        }}
        QHeaderView::section {{ background-color: {t.glass_elevated}; color: {t.text_muted}; border: 0; border-bottom: 1px solid {t.border}; padding: 8px; }}
        QTabWidget::pane {{ border: 1px solid {t.border}; border-radius: 10px; background-color: transparent; }}
        QTabBar::tab {{ padding: 9px 14px; color: {t.text_muted}; border-bottom: 2px solid transparent; }}
        QTabBar::tab:selected {{ color: {t.accent}; border-bottom-color: {t.accent}; }}
        QMenu {{ background-color: {t.glass_elevated}; border: 1px solid {t.border}; padding: 6px; }}
        QMenu::item {{ padding: 7px 22px; border-radius: 7px; }}
        QMenu::item:selected {{ background-color: {t.accent_soft}; }}
        QToolTip {{ background-color: {t.glass_elevated}; border: 1px solid {t.border}; color: {t.text}; padding: 6px; }}
        QProgressBar {{ border: 0; border-radius: 4px; background-color: {t.background_alt}; text-align: center; }}
        QProgressBar::chunk {{ border-radius: 4px; background-color: {t.accent}; }}
        QScrollBar:vertical {{ width: 9px; background: transparent; margin: 2px; }}
        QScrollBar::handle:vertical {{ min-height: 30px; border-radius: 4px; background: {t.border}; }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
        QSplitter::handle {{ background: transparent; width: 4px; }}
        QStatusBar {{ background-color: {t.glass}; border-top: 1px solid {t.border}; }}
        """
        return scale_stylesheet_metrics(stylesheet, scale)


def apply_windows_backdrop(widget: QWidget, dark: bool) -> None:
    
    try:
        if not select_runtime().modern_backdrop:
            return
        hwnd = int(widget.winId())
        dwm = ctypes.windll.dwmapi
        value = ctypes.c_int(1 if dark else 0)
        dwm.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(value), ctypes.sizeof(value))
        backdrop = ctypes.c_int(3 if dark else 2)
        dwm.DwmSetWindowAttribute(hwnd, 38, ctypes.byref(backdrop), ctypes.sizeof(backdrop))
    except (AttributeError, OSError):
        return
