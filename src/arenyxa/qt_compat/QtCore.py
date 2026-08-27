from __future__ import annotations

__dynamic_exports__ = True

from arenyxa.qt_compat import binding_module
from arenyxa.qt_compat._helpers import QtProxy, class_with_scopes, export_public

_base = binding_module("QtCore")
export_public(_base, globals())

Qt = QtProxy(_base.Qt, {
    "AlignmentFlag": {"AlignCenter":"AlignCenter","AlignHCenter":"AlignHCenter","AlignLeft":"AlignLeft","AlignRight":"AlignRight","AlignTop":"AlignTop","AlignVCenter":"AlignVCenter","AlignBottom":"AlignBottom"},
    "ApplicationState": {"ApplicationActive":"ApplicationActive"},
    "AspectRatioMode": {"KeepAspectRatio":"KeepAspectRatio"},
    "BrushStyle": {"NoBrush":"NoBrush"},
    "CaseSensitivity": {"CaseInsensitive":"CaseInsensitive"},
    "CursorShape": {"PointingHandCursor":"PointingHandCursor"},
    "GlobalColor": {"transparent":"transparent"},
    "ItemDataRole": {"DisplayRole":"DisplayRole","ForegroundRole":"ForegroundRole","ToolTipRole":"ToolTipRole","UserRole":"UserRole"},
    "Key": {"Key_C":"Key_C","Key_Down":"Key_Down","Key_L":"Key_L","Key_Tab":"Key_Tab","Key_Up":"Key_Up"},
    "KeyboardModifier": {"ControlModifier":"ControlModifier"},
    "LayoutDirection": {"LeftToRight":"LeftToRight","RightToLeft":"RightToLeft"},
    "MouseButton": {"LeftButton":"LeftButton"},
    "Orientation": {"Horizontal":"Horizontal","Vertical":"Vertical"},
    "PenCapStyle": {"FlatCap":"FlatCap","RoundCap":"RoundCap"},
    "PenJoinStyle": {"RoundJoin":"RoundJoin"},
    "PenStyle": {"NoPen":"NoPen","SolidLine":"SolidLine"},
    "ScrollBarPolicy": {"ScrollBarAlwaysOff":"ScrollBarAlwaysOff","ScrollBarAsNeeded":"ScrollBarAsNeeded"},
    "TextFlag": {"TextWordWrap":"TextWordWrap"},
    "TextInteractionFlag": {"TextSelectableByMouse":"TextSelectableByMouse"},
    "TimerType": {"CoarseTimer":"CoarseTimer","PreciseTimer":"PreciseTimer"},
    "TransformationMode": {"SmoothTransformation":"SmoothTransformation"},
    "WidgetAttribute": {"WA_Hover":"WA_Hover","WA_TransparentForMouseEvents":"WA_TransparentForMouseEvents","WA_TranslucentBackground":"WA_TranslucentBackground"},
    "WindowType": {
        "FramelessWindowHint":"FramelessWindowHint",
        "SplashScreen":"SplashScreen",
        "WindowStaysOnTopHint":"WindowStaysOnTopHint",
        "Tool":"Tool",
    },
})

QEvent = class_with_scopes(_base.QEvent, {"Type": {
    "ChildAdded":"ChildAdded","Enter":"Enter","Leave":"Leave","MouseButtonPress":"MouseButtonPress","MouseButtonRelease":"MouseButtonRelease","Show":"Show"
}})
QSettings = class_with_scopes(_base.QSettings, {"Format": {"IniFormat":"IniFormat"}})
QEasingCurve = class_with_scopes(_base.QEasingCurve, {"Type": {"OutCubic":"OutCubic","BezierSpline":"BezierSpline"}})
