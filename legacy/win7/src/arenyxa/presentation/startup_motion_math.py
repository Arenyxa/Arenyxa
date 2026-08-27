from __future__ import annotations

import math


def clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def smootherstep(value: float) -> float:
    
    t = clamp01(value)
    return t * t * t * (t * (t * 6.0 - 15.0) + 10.0)


def stage(progress: float, start: float, end: float) -> float:
    if end <= start:
        return 1.0 if progress >= end else 0.0
    return smootherstep((float(progress) - start) / (end - start))


def handoff_visuals(progress: float, *, allow_scale: bool) -> tuple[float, float, float]:
    





    p = clamp01(progress)
    scale = 1.0 + (0.92 * stage(p, 0.04, 0.68) if allow_scale else 0.0)
    icon_opacity = 1.0 - stage(p, 0.42, 0.74)
    reveal_progress = stage(p, 0.48, 1.0)
    return scale, clamp01(icon_opacity), clamp01(reveal_progress)


def reveal_radius(width: float, height: float, progress: float) -> float:
    
    diagonal_radius = math.hypot(max(0.0, float(width)), max(0.0, float(height))) * 0.5
    return (diagonal_radius + 2.0) * clamp01(progress)




def frame_interval_ms(refresh_hz: float) -> int:
    





    try:
        refresh = float(refresh_hz)
    except (TypeError, ValueError):
        refresh = 60.0
    if not math.isfinite(refresh):
        refresh = 60.0
    refresh = max(30.0, min(240.0, refresh))
    return max(4, min(33, int(1000.0 / refresh)))


def exit_duration_ms(performance_mode: str) -> int:
    mode = str(performance_mode or "balanced").lower()
    if mode == "efficiency":
        return 360
    if mode in {"quality", "high"}:
        return 600
    return 520
