from __future__ import annotations

__dynamic_exports__ = True

from arenyxa.qt_compat import binding_module
from arenyxa.qt_compat._helpers import class_with_scopes, export_public

_base = binding_module("QtGui")
_widgets = binding_module("QtWidgets")
export_public(_base, globals())

                                                                  
if "QAction" not in globals() and hasattr(_widgets, "QAction"):
    QAction = _widgets.QAction
if "QShortcut" not in globals() and hasattr(_widgets, "QShortcut"):
    QShortcut = _widgets.QShortcut

QPalette = class_with_scopes(_base.QPalette, {"ColorRole": {
    "AlternateBase":"AlternateBase","Base":"Base","Button":"Button","ButtonText":"ButtonText",
    "Highlight":"Highlight","HighlightedText":"HighlightedText","Text":"Text","Window":"Window","WindowText":"WindowText"
}})
QFont = class_with_scopes(_base.QFont, {"Weight": {"DemiBold":"DemiBold"}})
QIcon = class_with_scopes(_base.QIcon, {
    "Mode": {"Active":"Active","Normal":"Normal","Selected":"Selected"},
    "State": {"Off":"Off","On":"On"},
})
QPainter = class_with_scopes(_base.QPainter, {"RenderHint": {
    "Antialiasing":"Antialiasing",
    "SmoothPixmapTransform":"SmoothPixmapTransform",
}})
QTextCursor = class_with_scopes(_base.QTextCursor, {"MoveOperation": {"End":"End"}})
