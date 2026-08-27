from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import time
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import replace
from arenyxa.qt_compat.QtCore import (
    QEasingCurve,
    QEvent,
    QObject,
    QPoint,
    QPointF,
    QParallelAnimationGroup,
    QPropertyAnimation,
    QRect,
    QTimer,
    Qt,
    QVariantAnimation,
    Signal,
)
from arenyxa.qt_compat.QtGui import QColor, QPixmap
from arenyxa.qt_compat.QtWidgets import (
    QAbstractButton,
    QApplication,
    QGraphicsColorizeEffect,
    QGraphicsOpacityEffect,
    QLabel,
    QProgressBar,
    QStackedWidget,
    QWidget,
)
from arenyxa.domain.enums import MotionIntent
from arenyxa.domain.models import MotionProfile

from arenyxa.presentation.motion_support import FrameProfiler, FrameSampler, SpringAnimator

class MotionOrchestrator(QObject):
    






    intentStarted = Signal(str)
    intentFinished = Signal(str)
    qualityChanged = Signal(str)

    _QUALITY_RANK = {"efficiency": 0, "balanced": 1, "high": 2, "quality": 2}

    def __init__(
        self,
        profile: MotionProfile,
        refresh_hz: float = 60.0,
        parent: QObject | None = None,
        device_quality: str = "balanced",
        system_reduce_motion: bool = False,
    ) -> None:
        super().__init__(parent)
        self.system_reduce_motion = bool(system_reduce_motion)
        self.profile = self._effective_profile(profile)
        self.device_quality = device_quality if device_quality in {"efficiency", "balanced", "high"} else "balanced"
        self.refresh_hz = max(30.0, float(refresh_hz))
        self.active: dict[object, QObject] = {}
        self._page_transition_cleanup: dict[int, Callable[[], None]] = {}
        self._style_transition_cleanup: dict[int, Callable[[], None]] = {}
        self.profiler = FrameProfiler(self.refresh_hz, self)
        self.sampler = FrameSampler(self.profiler, self.refresh_hz, self)
        self.profiler.qualityChanged.connect(self._on_adaptive_quality)
        self.adaptive_quality = "high"
        self._glass_refresh_timer = QTimer(self)
        self._glass_refresh_timer.setSingleShot(True)
        self._glass_refresh_timer.setInterval(33)
        self._glass_refresh_timer.timeout.connect(self._refresh_visible_glass_widgets)
        app = QApplication.instance()
        if app is not None:
            app.installEventFilter(self)
            app.applicationStateChanged.connect(
                lambda state: self.sampler.set_active(state == Qt.ApplicationState.ApplicationActive)
            )
        self._publish_profile_properties()

    @staticmethod
    def _has_static_motion_ancestor(widget: QWidget) -> bool:
        current: QWidget | None = widget
        while current is not None:
            try:
                if bool(current.property("arenyxa_motion_static")):
                    return True
                parent = current.parentWidget()
            except RuntimeError:
                return True
            current = parent
        return False

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
                                                                                              
                                                                                                
        if (
            isinstance(watched, QAbstractButton)
            and watched.isEnabled()
            and self.effective_quality() == "high"
            and not self._has_static_motion_ancestor(watched)
        ):
            if event.type() == QEvent.Type.Enter:
                self._button_opacity(watched, 0.965, 110)
            elif event.type() == QEvent.Type.Leave:
                self._button_opacity(watched, 1.0, 130)
            elif event.type() == QEvent.Type.MouseButtonPress:
                self._button_opacity(watched, 0.86, 70)
            elif event.type() == QEvent.Type.MouseButtonRelease:
                self._button_opacity(watched, 0.98 if watched.underMouse() else 1.0, 105)
        return super().eventFilter(watched, event)

    def _button_opacity(self, button: QAbstractButton, target: float, duration_ms: int) -> None:
        if not self._enabled() or self.effective_quality() == "efficiency":
            return
        effect = button.graphicsEffect()
        if effect is not None and not isinstance(effect, QGraphicsOpacityEffect):
            return
        if not isinstance(effect, QGraphicsOpacityEffect):
            effect = QGraphicsOpacityEffect(button)
            effect.setOpacity(1.0)
            button.setGraphicsEffect(effect)
        start = float(effect.opacity())
        animation = QVariantAnimation(self)
        animation.setStartValue(start)
        animation.setEndValue(float(target))
        animation.setDuration(self._duration(duration_ms, minimum=55))
        animation.setEasingCurve(self._ios_micro_curve())
        def update_opacity(value: object) -> None:
            try:
                effect.setOpacity(float(value))
            except RuntimeError:
                                                                                             
                                                                                                  
                return

        animation.valueChanged.connect(update_opacity)
        key = (button, "micro_opacity")
        self._stop_active(key)
        self.active[key] = animation

        def done() -> None:
                                                                                              
                                                                                            
                                                                              
            if self.active.get(key) is not animation:
                return
            try:
                if float(target) >= 0.999:
                    effect.setOpacity(1.0)
                    if button.graphicsEffect() is effect:
                        button.setGraphicsEffect(None)
            except RuntimeError:
                record_current_exception(__name__, 'MotionOrchestrator._button_opacity.done:155')
            self.active.pop(key, None)

        animation.finished.connect(done)
        animation.start()

    @staticmethod
    def _bezier_curve(x1: float, y1: float, x2: float, y2: float) -> QEasingCurve:
        curve = QEasingCurve(QEasingCurve.Type.BezierSpline)
        curve.addCubicBezierSegment(
            QPointF(float(x1), float(y1)),
            QPointF(float(x2), float(y2)),
            QPointF(1.0, 1.0),
        )
        return curve

    @classmethod
    def _ios_ease_out(cls) -> QEasingCurve:
        return cls._bezier_curve(0.22, 1.0, 0.36, 1.0)

    @classmethod
    def _ios_ease_in_out(cls) -> QEasingCurve:
        return cls._bezier_curve(0.65, 0.0, 0.35, 1.0)

    @classmethod
    def _ios_micro_curve(cls) -> QEasingCurve:
        return cls._bezier_curve(0.25, 0.82, 0.25, 1.0)

    def _publish_profile_properties(self) -> None:
        app = QApplication.instance()
        if app is None:
            return
        app.setProperty("arenyxa_reduce_motion", bool(self.profile.reduce_motion))
        app.setProperty("arenyxa_motion_strength", float(self.profile.motion_strength))
        app.setProperty("arenyxa_animation_mode", self._animation_mode())
        app.setProperty("arenyxa_glass_strength", float(self.profile.glass_strength))
        app.setProperty("arenyxa_blur_strength", float(self.profile.blur))
        effective = self.effective_quality()
        app.setProperty("arenyxa_motion_quality", effective)
        app.setProperty("arenyxa_glass_specular", effective != "efficiency")

    def _refresh_visible_glass_widgets(self) -> None:
        app = QApplication.instance()
        if app is None:
            return
        for widget in app.allWidgets():
            try:
                if widget.isVisible() and bool(widget.property("glass")):
                    widget.update()
            except RuntimeError:
                continue

    def _schedule_glass_refresh(self) -> None:
        if not self._glass_refresh_timer.isActive():
            self._glass_refresh_timer.start()

    def _on_adaptive_quality(self, quality: str) -> None:
        self.adaptive_quality = quality
        self._publish_profile_properties()
        self._schedule_glass_refresh()
        self.qualityChanged.emit(self.effective_quality())

    def set_profile(self, profile: MotionProfile) -> None:
        self.profile = self._effective_profile(profile)
        self._publish_profile_properties()
                                                                                          
                                                                                               
        self._schedule_glass_refresh()

    def _effective_profile(self, profile: MotionProfile) -> MotionProfile:
        if not self.system_reduce_motion or profile.reduce_motion:
            return profile
                                                                                              
                                                                                   
        return replace(profile, reduce_motion=True)

    def effective_quality(self) -> str:
        requested = str(getattr(self.profile, "quality", "balanced"))
        if requested == "auto":
            requested = self.device_quality
        requested_rank = self._QUALITY_RANK.get(requested, 1)
        adaptive_rank = self._QUALITY_RANK.get(self.adaptive_quality, 2)
        rank = min(requested_rank, adaptive_rank)
        return {0: "efficiency", 1: "balanced", 2: "high"}[rank]

    def _strength(self) -> float:
        strength = max(0.0, min(1.0, float(self.profile.motion_strength)))
        quality = self.effective_quality()
        if quality == "efficiency":
            strength *= 0.42
        elif quality == "balanced":
            strength *= 0.78
        return strength

    def _animation_mode(self) -> str:
        mode = str(getattr(self.profile, "animation_mode", "auto")).strip().casefold()
        return mode if mode in {"auto", "always", "minimal"} else "auto"

    def _duration(self, base_ms: int, minimum: int = 90) -> int:
        scale = 0.64 + 0.48 * self._strength()
        if self.effective_quality() == "efficiency" and self._animation_mode() != "always":
            scale *= 0.78
        return max(minimum, round(base_ms * scale))

    def _enabled(self, live: bool = False) -> bool:
        mode = self._animation_mode()
        if mode == "minimal" or self.profile.reduce_motion or self._strength() <= 0.05:
            return False
        if mode == "always":
            return True
        if live and self.effective_quality() == "efficiency":
            return False
        return not live or bool(getattr(self.profile, "live_data_motion", True))

    def _stop_active(self, key: object) -> None:
        old = self.active.pop(key, None)
        if old is not None and hasattr(old, "stop"):
            old.stop()                              

    @staticmethod
    def _clamp01(value: float) -> float:
        return max(0.0, min(1.0, float(value)))

    def reveal(self, widget: QWidget, intent: MotionIntent = MotionIntent.ENTER) -> None:
        self.intentStarted.emit(intent.value)
        widget.show()
        quality = self.effective_quality()
        quality_allows_transition = quality != "efficiency" or self._animation_mode() == "always"
        if not self._enabled() or not quality_allows_transition:
            self.intentFinished.emit(intent.value)
            return
        key = (widget, "reveal")
        self._stop_active(key)
        effect = widget.graphicsEffect()
        if effect is not None and not isinstance(effect, QGraphicsOpacityEffect):
            self.intentFinished.emit(intent.value)
            return
        if not isinstance(effect, QGraphicsOpacityEffect):
            effect = QGraphicsOpacityEffect(widget)
            widget.setGraphicsEffect(effect)
        effect.setOpacity(0.90 if intent == MotionIntent.ENTER else 0.94)
        animation = QVariantAnimation(self)
        animation.setStartValue(float(effect.opacity()))
        animation.setEndValue(1.0)
        animation.setDuration(self._duration(260, minimum=180))
        animation.setEasingCurve(self._ios_ease_out())

        def update_opacity(value: object) -> None:
            try:
                effect.setOpacity(float(value))
            except RuntimeError:
                return

        animation.valueChanged.connect(update_opacity)
        self.active[key] = animation

        def completed() -> None:
            try:
                effect.setOpacity(1.0)
                if widget.graphicsEffect() is effect:
                    widget.setGraphicsEffect(None)
            except RuntimeError:
                record_current_exception(__name__, 'MotionOrchestrator.reveal.completed:317')
            self.active.pop(key, None)
            self.intentFinished.emit(intent.value)

        animation.finished.connect(completed)
        animation.start()

    def reveal_window(self, widget: QWidget, duration_ms: int = 340, offset_px: int = 14) -> None:
        key = (widget, "window_reveal")
        self._stop_active(key)
        target_pos = widget.pos()
        if not self._enabled() or self.effective_quality() == "efficiency":
            widget.setWindowOpacity(1.0)
            widget.move(target_pos)
            return

        start_pos = target_pos + QPoint(0, max(6, int(offset_px)))
        widget.setWindowOpacity(0.0)
        widget.move(start_pos)

        group = QParallelAnimationGroup(self)
        opacity = QPropertyAnimation(widget, b"windowOpacity", group)
        opacity.setStartValue(0.0)
        opacity.setEndValue(1.0)
        opacity.setDuration(self._duration(duration_ms, minimum=240))
        opacity.setEasingCurve(self._ios_ease_out())

        position = QPropertyAnimation(widget, b"pos", group)
        position.setStartValue(start_pos)
        position.setEndValue(target_pos)
        position.setDuration(self._duration(duration_ms + 40, minimum=260))
        position.setEasingCurve(self._ios_ease_out())

        self.active[key] = group

        def done() -> None:
            try:
                widget.setWindowOpacity(1.0)
                widget.move(target_pos)
            except RuntimeError:
                record_current_exception(__name__, 'MotionOrchestrator.reveal_window.done:357')
            self.active.pop(key, None)

        group.finished.connect(done)
        group.start()

    def _style_crossfade_allowed(self, widget: QWidget) -> bool:
        quality = self.effective_quality()
        pixel_area = max(0, widget.width()) * max(0, widget.height())
        device_ratio = (
            float(widget.devicePixelRatioF())
            if hasattr(widget, "devicePixelRatioF")
            else 1.0
        )
        return bool(
            self._enabled()
            and (quality != "efficiency" or self._animation_mode() == "always")
            and widget.isVisible()
            and pixel_area > 0
            and pixel_area * device_ratio * device_ratio <= 2_200_000
        )

    def crossfade_style(
        self,
        widget: QWidget,
        apply_update: Callable[[], None],
        duration_ms: int = 220,
    ) -> None:
        """Apply an expensive style update behind an already-painted snapshot.

        Theme changes rebuild the application stylesheet and can take a noticeable
        fraction of a frame on large workspaces.  The previous implementation took
        a snapshot but did not display it until *after* the expensive update, so the
        user still perceived a frozen click.  Paint the overlay first, flush one UI
        turn, then update the theme behind it and fade the snapshot away.
        """
        cleanup = self._style_transition_cleanup.pop(id(widget), None)
        if cleanup is not None:
            cleanup()
        key = (widget, "style_crossfade")
        self._stop_active(key)

        if not self._style_crossfade_allowed(widget):
            apply_update()
            return

        try:
            snapshot = widget.grab()
        except RuntimeError:
            apply_update()
            return
        if snapshot.isNull():
            apply_update()
            return

        overlay = QLabel(widget)
        overlay.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        overlay.setPixmap(snapshot)
        overlay.setScaledContents(False)
        overlay.setGeometry(widget.rect())
        effect = QGraphicsOpacityEffect(overlay)
        effect.setOpacity(1.0)
        overlay.setGraphicsEffect(effect)
        overlay.show()
        overlay.raise_()
        cleaned = False

        def finish_overlay() -> None:
            nonlocal cleaned
            if cleaned:
                return
            cleaned = True
            try:
                effect.setOpacity(0.0)
                overlay.deleteLater()
            except RuntimeError:
                record_current_exception(__name__, 'MotionOrchestrator.crossfade_style.finish_overlay')

        self._style_transition_cleanup[id(widget)] = finish_overlay

        # Ensure the old visual is on screen before the global stylesheet rebuild.
        # This does not add a nested event loop and therefore avoids the stutter that
        # previously made preset changes feel like the application had frozen.
        app = QApplication.instance()
        if app is not None:
            app.processEvents()

        try:
            apply_update()
        except (OSError, RuntimeError, TypeError, ValueError):
            finish_overlay()
            self._style_transition_cleanup.pop(id(widget), None)
            raise

        animation = QVariantAnimation(self)
        animation.setStartValue(0.0)
        animation.setKeyValueAt(0.72, 0.94)
        animation.setEndValue(1.0)
        animation.setDuration(self._duration(duration_ms, minimum=130))
        animation.setEasingCurve(self._ios_ease_in_out())

        def update(value: object) -> None:
            try:
                effect.setOpacity(1.0 - self._clamp01(float(value)))
            except RuntimeError:
                return

        animation.valueChanged.connect(update)
        self.active[key] = animation

        def done() -> None:
            finish_overlay()
            self._style_transition_cleanup.pop(id(widget), None)
            self.active.pop(key, None)

        animation.finished.connect(done)
        animation.start()

    def _cancel_page_transition(self, stack: QStackedWidget) -> None:
        key = (stack, "page_transition")
        self._stop_active(key)
        cleanup = self._page_transition_cleanup.pop(id(stack), None)
        if cleanup is not None:
            cleanup()

    def capture_stack_transition(
        self,
        stack: QStackedWidget,
        target: QWidget,
    ) -> tuple[QPixmap, QRect] | None:
        current = stack.currentWidget()
        quality = self.effective_quality()
        quality_allows_transition = quality != "efficiency" or self._animation_mode() == "always"
        if (
            current is None
            or current is target
            or not stack.isVisible()
            or not self._enabled()
            or not quality_allows_transition
            or current.width() <= 1
            or current.height() <= 1
        ):
            return None
        try:
            snapshot = current.grab()
        except RuntimeError:
            return None
        if snapshot.isNull():
            return None
        return snapshot, current.geometry()

    def transition_committed_stack(
        self,
        stack: QStackedWidget,
        target: QWidget,
        captured: tuple[QPixmap, QRect] | None,
        intent: MotionIntent = MotionIntent.ENTER,
    ) -> None:
        self._cancel_page_transition(stack)
        if captured is None or stack.currentWidget() is not target:
            return
        snapshot, source_geometry = captured
        self.intentStarted.emit(intent.value)
        overlay = QLabel(stack)
        overlay.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        overlay.setPixmap(snapshot)
        overlay.setScaledContents(False)
        overlay.setGeometry(source_geometry)
        overlay_effect = QGraphicsOpacityEffect(overlay)
        overlay_effect.setOpacity(1.0)
        overlay.setGraphicsEffect(overlay_effect)

        target_effect = target.graphicsEffect()
        created_target_effect = target_effect is None
        original_target_opacity: float | None = None
        if target_effect is None:
            target_effect = QGraphicsOpacityEffect(target)
            target.setGraphicsEffect(target_effect)
        if isinstance(target_effect, QGraphicsOpacityEffect):
            if not created_target_effect:
                original_target_opacity = float(target_effect.opacity())
            target_effect.setOpacity(0.84)

        target.show()
        target.update()
        overlay.show()
        overlay.raise_()
        cleaned = False

        def cleanup() -> None:
            nonlocal cleaned
            if cleaned:
                return
            cleaned = True
            try:
                overlay_effect.setOpacity(0.0)
                overlay.deleteLater()
            except RuntimeError:
                record_current_exception(__name__, 'MotionOrchestrator.transition_committed_stack.cleanup:533')
            if isinstance(target_effect, QGraphicsOpacityEffect):
                try:
                    if created_target_effect:
                        target_effect.setOpacity(1.0)
                        if target.graphicsEffect() is target_effect:
                            target.setGraphicsEffect(None)
                    elif original_target_opacity is not None:
                        target_effect.setOpacity(original_target_opacity)
                except RuntimeError:
                    record_current_exception(__name__, 'MotionOrchestrator.transition_committed_stack.cleanup:543')

        self._page_transition_cleanup[id(stack)] = cleanup
        animation = QVariantAnimation(self)
        animation.setStartValue(0.0)
        animation.setEndValue(1.0)
        animation.setDuration(self._duration(300, minimum=220))
        animation.setEasingCurve(self._ios_ease_out())

        def update(value: object) -> None:
            progress = self._clamp01(float(value))
            try:
                overlay_effect.setOpacity(max(0.0, 1.0 - progress * 1.08))
                drift = round(10.0 * progress)
                overlay.setGeometry(source_geometry.translated(-drift, 0))
            except RuntimeError:
                return
            if isinstance(target_effect, QGraphicsOpacityEffect):
                try:
                    target_effect.setOpacity(0.84 + 0.16 * progress)
                except RuntimeError:
                    record_current_exception(__name__, 'MotionOrchestrator.transition_committed_stack.update:564')

        animation.valueChanged.connect(update)
        key = (stack, "page_transition")
        self.active[key] = animation

        def done() -> None:
            cleanup()
            self._page_transition_cleanup.pop(id(stack), None)
            self.active.pop(key, None)
            self.intentFinished.emit(intent.value)

        animation.finished.connect(done)
        animation.start()

    def transition_stack(
        self,
        stack: QStackedWidget,
        target: QWidget,
        intent: MotionIntent = MotionIntent.ENTER,
    ) -> None:
        captured = self.capture_stack_transition(stack, target)
        stack.setCurrentWidget(target)
        self.transition_committed_stack(stack, target, captured, intent)

    def reveal_staggered(self, widgets: Iterable[QWidget], interval_ms: int = 28) -> None:
        items = list(widgets)
        quality = self.effective_quality()
        if not self._enabled() or (quality == "efficiency" and self._animation_mode() != "always"):
            for widget in items:
                widget.show()
            return

                                                                                                
                                                                                                    
        animation_cap = 18 if quality == "high" else 8
        animated = items[:animation_cap]
        for widget in items[animation_cap:]:
            widget.show()
                                                                             
        interval = max(12, min(interval_ms, 220 // max(1, len(animated) - 1))) if len(animated) > 1 else 0
        for index, widget in enumerate(animated):
            QTimer.singleShot(index * interval, lambda widget=widget: self.reveal(widget))

    def morph_geometry(self, widget: QWidget, destination: QRect, intent: MotionIntent = MotionIntent.MOVE) -> None:
        self.intentStarted.emit(intent.value)
        if not self._enabled():
            widget.setGeometry(destination)
            self.intentFinished.emit(intent.value)
            return
        key = (widget, "geometry")
        self._stop_active(key)
        animation = QPropertyAnimation(widget, b"geometry", self)
        animation.setStartValue(widget.geometry())
        animation.setEndValue(destination)
        animation.setDuration(self._duration(300))
        animation.setEasingCurve(self._ios_ease_in_out())
        self.active[key] = animation
        animation.finished.connect(lambda: self.active.pop(key, None))
        animation.finished.connect(lambda: self.intentFinished.emit(intent.value))
        animation.start()

    def animate_width(
        self,
        widget: QWidget,
        target: int,
        duration_ms: int = 250,
        on_finished: Callable[[], None] | None = None,
    ) -> None:
        





        target = max(0, int(target))
        start = max(0, int(widget.width()))
        key = (widget, "layout_width")
        old = self.active.get(key)
        if isinstance(old, SpringAnimator):
            start = max(0, int(round(old.position)))
        if not self._enabled() or start == target:
            self._stop_active(key)
            widget.setFixedWidth(target)
            if on_finished is not None:
                on_finished()
            return

        self._stop_active(key)
        low, high = sorted((float(start), float(target)))
        requested_response = max(0.16, min(0.52, float(self.profile.spring_response)))
        response = requested_response * max(0.72, min(1.30, duration_ms / 250.0))
                                                                                            
                                                                                                
        damping = max(1.0, min(1.28, float(self.profile.spring_damping)))
        refresh = min(60.0, self.refresh_hz)
        if self.effective_quality() == "efficiency":
            refresh = 30.0

        def update(value: float) -> None:
            bounded = max(low, min(high, float(value)))
            try:
                widget.setFixedWidth(max(0, int(round(bounded))))
            except RuntimeError:
                return

        animation = SpringAnimator(
            float(start),
            float(target),
            update,
            response=response,
            damping=damping,
            refresh_hz=refresh,
            position_epsilon=0.35,
            velocity_epsilon=2.5,
            max_duration=max(0.45, min(1.15, duration_ms / 1000.0 * 3.0)),
            parent=self,
        )
        self.active[key] = animation

        def done() -> None:
            try:
                widget.setFixedWidth(target)
            except RuntimeError:
                record_current_exception(__name__, 'MotionOrchestrator.animate_width.done:688')
            self.active.pop(key, None)
            if on_finished is not None:
                on_finished()

        animation.finished.connect(done)
        animation.start()

    def animate_progress(self, bar: QProgressBar, target: int, duration_ms: int = 380) -> None:
        target = max(bar.minimum(), min(bar.maximum(), int(target)))
        if not self._enabled(live=True):
            bar.setValue(target)
            return
        start = bar.value()
        if start == target:
            return
        key = (bar, "progress")
        old = self.active.get(key)
        if isinstance(old, QVariantAnimation) and old.currentValue() is not None:
            start = int(old.currentValue())
        self._stop_active(key)
        animation = QVariantAnimation(self)
        animation.setStartValue(start)
        animation.setEndValue(target)
        animation.setDuration(self._duration(duration_ms, minimum=100))
        animation.setEasingCurve(self._ios_ease_out())
        animation.valueChanged.connect(lambda value: bar.setValue(int(round(float(value)))))
        self.active[key] = animation
        animation.finished.connect(lambda: self.active.pop(key, None))
        animation.start()

    def animate_scalar(
        self,
        owner: object,
        key_name: str,
        start: float,
        target: float,
        update: Callable[[float], None],
        duration_ms: int = 380,
        live: bool = True,
    ) -> None:
        active_key = (owner, key_name)
        old = self.active.get(active_key)
        if isinstance(old, QVariantAnimation) and old.currentValue() is not None:
            start = float(old.currentValue())
        if not self._enabled(live=live) or abs(float(target) - float(start)) < 1e-9:
            self._stop_active(active_key)
            update(float(target))
            return
        self._stop_active(active_key)
        animation = QVariantAnimation(self)
        animation.setStartValue(float(start))
        animation.setEndValue(float(target))
        animation.setDuration(self._duration(duration_ms, minimum=100))
        animation.setEasingCurve(self._ios_ease_out())
        animation.valueChanged.connect(lambda value: update(float(value)))
        self.active[active_key] = animation
        animation.finished.connect(lambda: self.active.pop(active_key, None))
        animation.start()

    def animate_number(self, label: QLabel, target: float, formatter: Callable[[float], str], duration_ms: int = 420) -> None:
        current = label.property("motion_numeric_current")
        start = float(current) if current is not None else 0.0
        active_key = (label, "number")
        old = self.active.get(active_key)
        if isinstance(old, QVariantAnimation) and old.currentValue() is not None:
            start = float(old.currentValue())
        if not self._enabled(live=True) or abs(float(target) - start) < 1e-9:
            self._stop_active(active_key)
            label.setProperty("motion_numeric_current", float(target))
            label.setText(formatter(float(target)))
            return

        self._stop_active(active_key)
        animation = QVariantAnimation(self)
        animation.setStartValue(start)
        animation.setEndValue(float(target))
        animation.setDuration(self._duration(duration_ms, minimum=120))
        animation.setEasingCurve(self._ios_ease_out())

        def update(value) -> None:
            numeric = float(value)
            label.setProperty("motion_numeric_current", numeric)
            label.setText(formatter(numeric))

        animation.valueChanged.connect(update)
        self.active[active_key] = animation

        def done() -> None:
            label.setProperty("motion_numeric_current", float(target))
            label.setText(formatter(float(target)))
            self.active.pop(active_key, None)

        animation.finished.connect(done)
        animation.start()

    def emphasize(self, widget: QWidget, intent: MotionIntent = MotionIntent.EMPHASIZE) -> None:
        
        if not self._enabled():
            return
        self.intentStarted.emit(intent.value)
        color = {
            MotionIntent.SUCCESS: QColor("#35d07f"),
            MotionIntent.WARNING: QColor("#e6ad45"),
            MotionIntent.ERROR: QColor("#ff6570"),
        }.get(intent, QColor("#62a8ff"))
        effect = widget.graphicsEffect()
        if effect is not None and not isinstance(effect, QGraphicsColorizeEffect):
            return
        if not isinstance(effect, QGraphicsColorizeEffect):
            effect = QGraphicsColorizeEffect(widget)
            widget.setGraphicsEffect(effect)
        effect.setColor(color)
        effect.setStrength(0.0)
        animation = QVariantAnimation(self)
        animation.setStartValue(0.0)
        animation.setKeyValueAt(0.34, 0.46)
        animation.setEndValue(0.0)
        animation.setDuration(self._duration(360, minimum=150))
        animation.setEasingCurve(self._ios_ease_out())
        def update_strength(value: object) -> None:
            try:
                effect.setStrength(float(value))
            except RuntimeError:
                return

        animation.valueChanged.connect(update_strength)
        key = (widget, "emphasis")
        self._stop_active(key)
        self.active[key] = animation

        def done() -> None:
            try:
                if widget.graphicsEffect() is effect:
                    widget.setGraphicsEffect(None)
            except RuntimeError:
                record_current_exception(__name__, 'MotionOrchestrator.emphasize.done:824')
            self.active.pop(key, None)
            self.intentFinished.emit(intent.value)

        animation.finished.connect(done)
        animation.start()

