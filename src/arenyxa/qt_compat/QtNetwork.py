from __future__ import annotations

__dynamic_exports__ = True

from arenyxa.qt_compat import binding_module
from arenyxa.qt_compat._helpers import export_public

_base = binding_module("QtNetwork")
export_public(_base, globals())
