from __future__ import annotations
from arenyxa.recoverable import record_current_exception

from dataclasses import dataclass
from pathlib import Path

from arenyxa.qt_compat.QtCore import QRect, QSettings
from arenyxa.qt_compat.QtGui import QCursor
from arenyxa.qt_compat.QtWidgets import QApplication, QMainWindow


@dataclass(frozen=True)
class LaunchGeometryPlan:
    






    rect: QRect
    screen_name: str
    maximized: bool = False
    restored: bool = False


def _setting_bool(value: object, default: bool = False) -> bool:
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in {"1", "true", "yes", "on"}


def _screen_name(screen: object | None) -> str:
    if screen is None:
        return ""
    try:
        return str(screen.name())
    except (AttributeError, RuntimeError, TypeError):
        return ""


def _screen_by_name(app: QApplication, name: str) -> object | None:
    wanted = str(name or "").strip()
    if not wanted:
        return None
    for screen in app.screens():
        if _screen_name(screen) == wanted:
            return screen
    return None


def _screen_under_cursor(app: QApplication) -> object | None:
    try:
        screen_at = getattr(app, "screenAt", None)
        if callable(screen_at):
            screen = screen_at(QCursor.pos())
            if screen is not None:
                return screen
    except (AttributeError, RuntimeError, TypeError):
        record_current_exception(__name__, '_screen_under_cursor:60')
    return app.primaryScreen()


def _screen_for_rect(app: QApplication, rect: QRect) -> object | None:
    best = None
    best_area = 0
    for screen in app.screens():
        try:
            intersection = rect.intersected(screen.availableGeometry())
            area = max(0, int(intersection.width())) * max(0, int(intersection.height()))
        except (AttributeError, RuntimeError, TypeError):
            area = 0
        if area > best_area:
            best = screen
            best_area = area
    return best if best_area > 0 else None


def _centered_rect(screen: object, *, width: int, height: int) -> QRect:
    available = screen.availableGeometry()
    actual_width = min(max(1, int(width)), max(1, int(available.width())))
    actual_height = min(max(1, int(height)), max(1, int(available.height())))
    x = int(available.x()) + max(0, (int(available.width()) - actual_width) // 2)
    y = int(available.y()) + max(0, (int(available.height()) - actual_height) // 2)
    return QRect(x, y, actual_width, actual_height)


def _clamp_rect_to_screen(rect: QRect, screen: object, *, minimum_width: int, minimum_height: int) -> QRect:
    available = screen.availableGeometry()
    max_width = max(1, int(available.width()))
    max_height = max(1, int(available.height()))
    width = min(max_width, max(minimum_width if max_width >= minimum_width else 1, int(rect.width())))
    height = min(max_height, max(minimum_height if max_height >= minimum_height else 1, int(rect.height())))
    x_min = int(available.x())
    y_min = int(available.y())
    x_max = x_min + max(0, max_width - width)
    y_max = y_min + max(0, max_height - height)
    x = min(max(int(rect.x()), x_min), x_max)
    y = min(max(int(rect.y()), y_min), y_max)
    return QRect(x, y, width, height)


def resolve_launch_geometry(
    settings_path: Path,
    *,
    default_width: int = 1500,
    default_height: int = 920,
    minimum_width: int = 1120,
    minimum_height: int = 720,
) -> LaunchGeometryPlan:
    







    app = QApplication.instance()
    if not isinstance(app, QApplication):
        return LaunchGeometryPlan(QRect(0, 0, default_width, default_height), "", False, False)

    settings = QSettings(str(settings_path), QSettings.Format.IniFormat)
    saved_geometry = settings.value("geometry")
    saved_screen_name = str(settings.value("screen_name", "") or "")
    explicit_maximized = settings.value("maximized", None)

    restored_rect: QRect | None = None
    restored = False
    probed_maximized = False
    if saved_geometry:
        probe = QMainWindow()
        probe.setMinimumSize(minimum_width, minimum_height)
        probe.resize(default_width, default_height)
        try:
            restored = bool(probe.restoreGeometry(saved_geometry))
            if restored:
                restored_rect = QRect(probe.geometry())
                probed_maximized = bool(probe.isMaximized())
        except (RuntimeError, TypeError, ValueError):
            restored = False
            restored_rect = None
        finally:
            probe.deleteLater()

    screen = _screen_by_name(app, saved_screen_name)
    if screen is None and restored_rect is not None:
        screen = _screen_for_rect(app, restored_rect)
    if screen is None:
        screen = _screen_under_cursor(app)
    if screen is None:
                                                                                               
                                                                                             
        return LaunchGeometryPlan(
            QRect(0, 0, default_width, default_height),
            "",
            _setting_bool(explicit_maximized, probed_maximized),
            restored,
        )

    maximized = _setting_bool(explicit_maximized, probed_maximized)
    if maximized:
        rect = QRect(screen.availableGeometry())
    elif restored_rect is not None:
        rect = _clamp_rect_to_screen(
            restored_rect,
            screen,
            minimum_width=minimum_width,
            minimum_height=minimum_height,
        )
    else:
        rect = _centered_rect(screen, width=default_width, height=default_height)

    return LaunchGeometryPlan(rect, _screen_name(screen), maximized, restored)
