from __future__ import annotations

import math
import re


_PX_VALUE = re.compile(r"(?P<value>-?\d+(?:\.\d+)?)px")


def clamp_ui_scale(value: float) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError, OverflowError):
        numeric = 1.0
    if not math.isfinite(numeric):
        numeric = 1.0
    return max(0.85, min(1.60, numeric))


def effective_ui_scale(mode: str, manual_percent: int, width: int, height: int) -> float:
    
    if str(mode or "auto").casefold() == "manual":
        return clamp_ui_scale(max(85, min(160, int(manual_percent))) / 100.0)
    safe_width = max(640, int(width or 0))
    safe_height = max(480, int(height or 0))
    reference_area = 1600.0 * 900.0
    area_ratio = max(0.35, (safe_width * safe_height) / reference_area)
    scale = 1.0 + 0.12 * math.log(area_ratio, 2.0)
    scale = max(0.95, min(1.30, scale))
    return round(scale / 0.05) * 0.05


def scale_stylesheet_metrics(stylesheet: str, scale: float) -> str:
    
    if not stylesheet:
        return stylesheet
    factor = clamp_ui_scale(scale)

    def replace(match: re.Match[str]) -> str:
        raw = float(match.group("value"))
        value = raw * factor
        if abs(value - round(value)) < 0.05:
            rendered = str(int(round(value)))
        else:
            rendered = f"{value:.1f}".rstrip("0").rstrip(".")
        return rendered + "px"

    return _PX_VALUE.sub(replace, stylesheet)
