from __future__ import annotations

import logging
import math
import time
from collections.abc import Callable
from pathlib import Path

from arenyxa.presentation.startup_motion_math import (
    clamp01 as _clamp01,
)
from arenyxa.presentation.startup_motion_math import (
    exit_duration_ms as _exit_duration_ms,
)
from arenyxa.presentation.startup_motion_math import (
    frame_interval_ms as _frame_interval_ms,
)
from arenyxa.presentation.startup_motion_math import (
    handoff_visuals as _handoff_visuals,
)
from arenyxa.presentation.startup_motion_math import (
    reveal_radius as _reveal_radius,
)
from arenyxa.qt_compat.QtCore import QObject, QRect, QRectF, Qt, QTimer
from arenyxa.qt_compat.QtGui import QColor, QCursor, QPainter, QPainterPath, QPixmap
from arenyxa.qt_compat.QtWidgets import (
    QApplication,
    QGraphicsOpacityEffect,
    QLabel,
    QVBoxLayout,
    QWidget,
)

LOGGER = logging.getLogger(__name__)
_STARTUP_SURFACE = (3, 7, 6)


def _widget_refresh_hz(widget: QWidget) -> float:
    





    try:
        screen = widget.screen()
        if screen is not None:
            refresh = float(screen.refreshRate())
            if math.isfinite(refresh) and refresh >= 30.0:
                return max(30.0, min(240.0, refresh))
    except (AttributeError, RuntimeError, TypeError, ValueError):
        pass
    return 60.0


class _SmoothFrameDriver(QObject):
    





    def __init__(
        self,
        owner: QWidget,
        *,
        duration_ms: int,
        refresh_hz: float,
        update: Callable[[float], None],
        complete: Callable[[], None],
    ) -> None:
        super().__init__(owner)
        self._duration_s = max(0.001, int(duration_ms) / 1000.0)
        self._update = update
        self._complete = complete
        self._started_at = 0.0
        self._finished = False
        self._timer = QTimer(self)
        self._timer.setTimerType(Qt.TimerType.PreciseTimer)
        self._timer.setInterval(_frame_interval_ms(refresh_hz))
        self._timer.timeout.connect(self._tick)

    def start(self) -> None:
        if self._finished or self._timer.isActive():
            return
        self._started_at = time.perf_counter()
        self._update(0.0)
        self._timer.start()

    def stop(self) -> None:
        self._timer.stop()
        self._finished = True

    def _tick(self) -> None:
        if self._finished or self._started_at <= 0.0:
            return
        progress = _clamp01((time.perf_counter() - self._started_at) / self._duration_s)
        self._update(progress)
        if progress >= 1.0:
            self._timer.stop()
            self._finished = True
            self._complete()


class _StartupHandoffOverlay(QWidget):
    








    def __init__(
        self,
        parent: QWidget,
        pixmap: QPixmap,
        *,
        icon_size: int,
        animated: bool,
        performance_mode: str,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("ArenyxaStartupHandoffOverlay")
        self.setProperty("arenyxa_motion_static", True)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setAutoFillBackground(False)
        self._base_pixmap = pixmap
        self._icon_size = max(48, int(icon_size))
        self._animated = bool(animated)
        self._performance_mode = str(performance_mode or "balanced").lower()
        self._animation: _SmoothFrameDriver | None = None
        self._icon_scale = 1.0
        self._icon_opacity = 1.0
        self._reveal_progress = 0.0
        self._workspace_snapshot = QPixmap()

    def paintEvent(self, event: object) -> None:
        del event
        painter = QPainter(self)
        try:
            painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
            has_snapshot = not self._workspace_snapshot.isNull()
            cover_alpha = 255 if has_snapshot else round(
                255.0 * (1.0 - _clamp01(self._reveal_progress))
            )
            painter.fillRect(self.rect(), QColor(*_STARTUP_SURFACE, cover_alpha))
            if has_snapshot and self._reveal_progress > 0.0:
                radius = _reveal_radius(self.width(), self.height(), self._reveal_progress)
                aperture = QPainterPath()
                aperture.addEllipse(QRectF(
                    (self.width() * 0.5) - radius,
                    (self.height() * 0.5) - radius,
                    radius * 2.0,
                    radius * 2.0,
                ))
                painter.save()
                painter.setClipPath(aperture)
                painter.setOpacity(1.0)
                try:
                    ratio = max(1.0, float(self._workspace_snapshot.devicePixelRatioF()))
                except (AttributeError, RuntimeError, TypeError, ValueError):
                    ratio = 1.0
                logical_width = self._workspace_snapshot.width() / ratio
                logical_height = self._workspace_snapshot.height() / ratio
                if abs(logical_width - self.width()) <= 1.0 and abs(logical_height - self.height()) <= 1.0:
                                                                                                 
                                                                                               
                    painter.drawPixmap(0, 0, self._workspace_snapshot)
                else:
                    painter.drawPixmap(self.rect(), self._workspace_snapshot)
                painter.restore()
            if self._base_pixmap.isNull() or self._icon_opacity <= 0.001:
                return
            size = max(48, round(self._icon_size * max(0.5, self._icon_scale)))
            x = (self.width() - size) // 2
            y = (self.height() - size) // 2
            painter.setOpacity(_clamp01(self._icon_opacity))
            painter.drawPixmap(QRect(x, y, size, size), self._base_pixmap)
        finally:
            painter.end()

    def present(self) -> None:
        parent = self.parentWidget()
        if parent is not None:
            self.setGeometry(parent.rect())
        self.show()
        self.raise_()
        self.update()

    def capture_workspace(self) -> bool:
        
        parent = self.parentWidget()
        if parent is None:
            return False
        was_visible = self.isVisible()
        try:
                                                                                                 
                                                                                                  
            self.hide()
            snapshot = parent.grab()
        except (RuntimeError, TypeError):
            LOGGER.exception("Startup workspace snapshot failed; using translucent fallback")
            return False
        finally:
            if was_visible:
                try:
                    self.show()
                    self.raise_()
                except RuntimeError:
                    pass
        if snapshot.isNull():
            return False
        self._workspace_snapshot = snapshot
        self.update()
        return True

    def start_exit(self) -> None:
        if not self._animated:
                                                                                                  
            self._icon_opacity = 0.0
            self._reveal_progress = 1.0
            self.update()
            QTimer.singleShot(0, self.deleteLater)
            return

        use_scale = self._performance_mode != "efficiency"

        def update(progress: float) -> None:
            try:
                parent = self.parentWidget()
                if parent is not None and self.geometry() != parent.rect():
                    self.setGeometry(parent.rect())
                self._icon_scale, self._icon_opacity, self._reveal_progress = _handoff_visuals(
                    _clamp01(progress),
                    allow_scale=use_scale,
                )
                self.update()
            except (RuntimeError, TypeError, ValueError):
                return

        def complete() -> None:
            self._animation = None
            try:
                self._icon_opacity = 0.0
                self._reveal_progress = 1.0
                self.hide()
                self.deleteLater()
            except RuntimeError:
                pass

        animation = _SmoothFrameDriver(
            self,
            duration_ms=_exit_duration_ms(self._performance_mode),
            refresh_hz=_widget_refresh_hz(self),
            update=update,
            complete=complete,
        )
        self._animation = animation
                                                                                                
                                                                                                  
                                                                                
        QTimer.singleShot(0, animation.start)


class StartupSplash(QWidget):
    







    def __init__(
        self,
        icon_path: Path,
        *,
        animated: bool,
        performance_mode: str = "balanced",
        geometry: QRect | None = None,
    ) -> None:
        flags = (
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.SplashScreen
            | Qt.WindowType.WindowStaysOnTopHint
        )
        super().__init__(None, flags)
        self.setObjectName("ArenyxaStartupSplash")
        self.setProperty("arenyxa_motion_static", True)
        self.setStyleSheet("#ArenyxaStartupSplash { background-color: #030706; }")
        self._animated = bool(animated)
        self._performance_mode = str(performance_mode or "balanced").lower()
        self._closing = False
        self._animation: _SmoothFrameDriver | None = None
        self._handoff_overlay: _StartupHandoffOverlay | None = None
        self._base_pixmap = QPixmap(str(icon_path)) if icon_path.is_file() else QPixmap()
        self._icon_size = 196

        self._icon = QLabel(self)
        self._icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._icon.setProperty("arenyxa_motion_static", True)
        self._icon_opacity = QGraphicsOpacityEffect(self._icon)
        self._icon_opacity.setOpacity(1.0)
        self._icon.setGraphicsEffect(self._icon_opacity)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addStretch(1)
        layout.addWidget(self._icon, 0, Qt.AlignmentFlag.AlignCenter)
        layout.addStretch(1)

        self._place_on_launch_geometry(geometry)
        self._render_icon(1.0)

    def _place_on_launch_geometry(self, geometry: QRect | None) -> None:
        if geometry is not None and geometry.isValid():
            self.setGeometry(QRect(geometry))
            width = int(geometry.width())
            height = int(geometry.height())
            self._icon_size = max(132, min(220, int(min(width, height) * 0.235)))
            return

                                                                                                 
                                                                                                   
        app = QApplication.instance()
        screen = None
        if app is not None:
            try:
                screen_at = getattr(app, "screenAt", None)
                if callable(screen_at):
                    screen = screen_at(QCursor.pos())
            except (AttributeError, RuntimeError, TypeError):
                screen = None
            if screen is None:
                screen = app.primaryScreen()
        if screen is None:
            self.resize(1200, 760)
            return
        available = screen.availableGeometry()
        width = min(1500, max(900, int(available.width() * 0.86)))
        height = min(920, max(600, int(available.height() * 0.84)))
        width = min(width, available.width())
        height = min(height, available.height())
        x = available.x() + max(0, (available.width() - width) // 2)
        y = available.y() + max(0, (available.height() - height) // 2)
        self.setGeometry(x, y, width, height)
        self._icon_size = max(132, min(220, int(min(width, height) * 0.235)))

    def _render_icon(self, scale: float) -> None:
        if self._base_pixmap.isNull():
            self._icon.clear()
            return
        size = max(48, round(self._icon_size * max(0.5, float(scale))))
        try:
            device_ratio = max(1.0, float(self.devicePixelRatioF()))
        except (AttributeError, RuntimeError, TypeError, ValueError):
            device_ratio = 1.0
        physical_size = max(1, round(size * device_ratio))
        pixmap = self._base_pixmap.scaled(
            physical_size,
            physical_size,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        pixmap.setDevicePixelRatio(device_ratio)
        self._icon.setPixmap(pixmap)

    def present(self) -> None:
        if self._closing:
            return
        self.setWindowOpacity(1.0)
        self._icon_opacity.setOpacity(1.0)
        self.show()
        self.raise_()
        app = QApplication.instance()
        if app is not None:
                                                                                                
                                                                                      
            app.processEvents()

    def abort(self) -> None:
        if self._closing:
            return
        self._closing = True
        if self._animation is not None:
            try:
                self._animation.stop()
            except RuntimeError:
                pass
            self._animation = None
        try:
            self.hide()
            self.deleteLater()
        except RuntimeError:
            pass

    def prepare_handoff(self, main_window: QWidget | None) -> bool:
        
        if self._closing or main_window is None:
            return False
        if self._handoff_overlay is not None:
            return True
        try:
            overlay = _StartupHandoffOverlay(
                main_window,
                self._base_pixmap,
                icon_size=self._icon_size,
                animated=self._animated,
                performance_mode=self._performance_mode,
            )
            overlay.present()
            self._handoff_overlay = overlay
            return True
        except Exception:
            LOGGER.exception("Startup in-window handoff preparation failed")
            self._handoff_overlay = None
            return False

    def finish(self, main_window: QWidget | None = None) -> None:
        
        if self._closing:
            return

        overlay = self._handoff_overlay
        if overlay is None and main_window is not None:
            self.prepare_handoff(main_window)
            overlay = self._handoff_overlay

        if overlay is not None:
            try:
                parent = overlay.parentWidget()
                if parent is not None:
                    overlay.setGeometry(parent.rect())
                overlay.show()
                overlay.raise_()
                app = QApplication.instance()
                if app is not None:
                                                                                                  
                                                                                     
                    app.processEvents()
                                                                                                 
                                                                                                
                overlay.capture_workspace()
                self.hide()
                self._closing = True
                self._handoff_overlay = None
                self.deleteLater()
                overlay.start_exit()
                return
            except Exception:
                LOGGER.exception("Startup in-window handoff failed; falling back to top-level exit")
                try:
                    overlay.hide()
                    overlay.deleteLater()
                except RuntimeError:
                    pass
                self._handoff_overlay = None

        if not self._animated:
            self.abort()
            return

                                                                                                  
                                                                                                   
        self._closing = True
        use_scale = self._performance_mode != "efficiency"

        def update(progress: float) -> None:
            try:
                scale, icon_opacity, reveal_progress = _handoff_visuals(
                    _clamp01(progress),
                    allow_scale=use_scale,
                )
                if use_scale:
                    self._render_icon(scale)
                self._icon_opacity.setOpacity(icon_opacity)
                self.setWindowOpacity(1.0 - reveal_progress)
            except (RuntimeError, TypeError, ValueError):
                return

        def complete() -> None:
            self._animation = None
            try:
                self.hide()
                self.deleteLater()
            except RuntimeError:
                pass

        animation = _SmoothFrameDriver(
            self,
            duration_ms=_exit_duration_ms(self._performance_mode),
            refresh_hz=_widget_refresh_hz(self),
            update=update,
            complete=complete,
        )
        self._animation = animation
        QTimer.singleShot(0, animation.start)


def create_startup_splash(
    icon_path: Path,
    *,
    reduce_motion: bool,
    safe_mode: bool,
    smoke_test: bool,
    reduced_visuals: bool,
    performance_mode: str,
    geometry: QRect | None = None,
) -> StartupSplash | None:
    
    if safe_mode or smoke_test or reduced_visuals:
        return None
    try:
        return StartupSplash(
            icon_path,
            animated=not bool(reduce_motion),
            performance_mode=performance_mode,
            geometry=geometry,
        )
    except Exception:
        LOGGER.exception("Startup splash creation failed; continuing with ordinary startup")
        return None
