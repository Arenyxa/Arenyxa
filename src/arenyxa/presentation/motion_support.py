from __future__ import annotations

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

class SpringAnimator(QObject):
    






    finished = Signal()

    def __init__(
        self,
        start: float,
        target: float,
        update: Callable[[float], None],
        response: float = 0.38,
        damping: float = 0.86,
        refresh_hz: float = 60.0,
        position_epsilon: float = 0.0008,
        velocity_epsilon: float = 0.008,
        max_duration: float = 1.6,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.position = float(start)
        self.target = float(target)
        self.velocity = 0.0
        self.update_callback = update
        self.response = max(0.12, float(response))
        self.damping = max(0.35, min(1.4, float(damping)))
        self.position_epsilon = max(1e-6, float(position_epsilon))
        self.velocity_epsilon = max(1e-6, float(velocity_epsilon))
        self.max_duration = max(0.20, float(max_duration))
        self.timer = QTimer(self)
        self.timer.setTimerType(
            Qt.TimerType.CoarseTimer if refresh_hz <= 30.0 else Qt.TimerType.PreciseTimer
        )
        self.timer.setInterval(max(1, round(1000 / max(30.0, refresh_hz))))
        self.timer.timeout.connect(self._tick)
        self.last = 0.0
        self._started_at = 0.0
        self._stopped = False

    def start(self) -> None:
        self._stopped = False
        self.last = time.perf_counter()
        self._started_at = self.last
        self.timer.start()

    def stop(self) -> None:
        self._stopped = True
        self.timer.stop()

    def retarget(self, target: float) -> None:
        self.target = float(target)
        if not self.timer.isActive():
            self.start()

    def _tick(self) -> None:
        if self._stopped:
            return
        now = time.perf_counter()
        delta = min(0.025, max(0.0005, now - self.last))
        self.last = now
        angular = 2.0 * 3.141592653589793 / self.response
        acceleration = (
            (self.target - self.position) * angular * angular
            - 2.0 * self.damping * angular * self.velocity
        )
        self.velocity += acceleration * delta
        self.position += self.velocity * delta
        self.update_callback(self.position)
        settled = (
            abs(self.target - self.position) < self.position_epsilon
            and abs(self.velocity) < self.velocity_epsilon
        )
        expired = self._started_at > 0.0 and now - self._started_at >= self.max_duration
        if settled or expired:
            self.position = self.target
            self.velocity = 0.0
            self.update_callback(self.target)
            self.timer.stop()
            self.finished.emit()

class FrameProfiler(QObject):
    

    qualityChanged = Signal(str)

    def __init__(self, refresh_hz: float = 60.0, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.refresh_hz = max(30.0, float(refresh_hz))
        self.budget_ms = 1000.0 / self.refresh_hz
        self.samples: deque[float] = deque(maxlen=180)
        self.dropped_frames = 0
        self.quality = "high"
        self._candidate = "high"
        self._candidate_windows = 0
        self._last_change = 0.0

    def record(self, frame_ms: float) -> None:
        frame_ms = max(0.0, float(frame_ms))
        self.samples.append(frame_ms)
        if frame_ms > self.budget_ms * 1.5:
            self.dropped_frames += 1
        if len(self.samples) < 45:
            return

        values = sorted(self.samples)
        p95 = values[round((len(values) - 1) * 0.95)]
                                                                                             
        if self.quality == "high":
            requested = "efficiency" if p95 > self.budget_ms * 1.58 else "balanced" if p95 > self.budget_ms * 1.16 else "high"
        elif self.quality == "balanced":
            requested = "efficiency" if p95 > self.budget_ms * 1.52 else "high" if p95 < self.budget_ms * 0.98 else "balanced"
        else:
            requested = "balanced" if p95 < self.budget_ms * 1.18 else "efficiency"

        if requested != self._candidate:
            self._candidate = requested
            self._candidate_windows = 1
        else:
            self._candidate_windows += 1

                                                                                           
        needed = 2 if self._quality_rank(requested) < self._quality_rank(self.quality) else 8
        now = time.monotonic()
        if requested != self.quality and self._candidate_windows >= needed and now - self._last_change > 0.30:
            self.quality = requested
            self._last_change = now
            self._candidate_windows = 0
            self.qualityChanged.emit(requested)

    @staticmethod
    def _quality_rank(value: str) -> int:
        return {"efficiency": 0, "balanced": 1, "high": 2, "quality": 2}.get(value, 1)

    def snapshot(self) -> dict[str, float | int | str]:
        values = sorted(self.samples)
        return {
            "refresh_hz": self.refresh_hz,
            "budget_ms": self.budget_ms,
            "p50_ms": values[len(values) // 2] if values else 0,
            "p95_ms": values[round((len(values) - 1) * 0.95)] if values else 0,
            "dropped_frames": self.dropped_frames,
            "quality": self.quality,
        }

class FrameSampler(QObject):
    

    def __init__(self, profiler: FrameProfiler, refresh_hz: float, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.profiler = profiler
                                                                                           
                                                                                               
        sample_hz = min(60.0, max(30.0, float(refresh_hz)))
        self.interval_ms = max(8, round(1000 / sample_hz))
        self.timer = QTimer(self)
        self.timer.setTimerType(
            Qt.TimerType.CoarseTimer if refresh_hz <= 30.0 else Qt.TimerType.PreciseTimer
        )
        self.timer.setInterval(self.interval_ms)
        self.timer.timeout.connect(self._sample)
        self.last = time.perf_counter()
        self.timer.start()

    def set_active(self, active: bool) -> None:
        if active:
            self.last = time.perf_counter()
            if not self.timer.isActive():
                self.timer.start()
        else:
            self.timer.stop()

    def _sample(self) -> None:
        now = time.perf_counter()
        elapsed = (now - self.last) * 1000.0
        self.last = now
                                                                                         
        if 0.0 < elapsed < 250.0:
            self.profiler.record(elapsed)

