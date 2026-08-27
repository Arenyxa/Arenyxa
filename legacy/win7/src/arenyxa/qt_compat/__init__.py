from __future__ import annotations

"""Qt 6 / Qt 5 binding selector used by the Desktop runtime.

Modern builds prefer PySide6.  Legacy Enterprise builds prefer PySide2 so Windows 7 can use
Qt 5 without contaminating the core/application layers with version checks.
"""

import importlib
import importlib.util
import os
import sys
from types import ModuleType

from arenyxa.branding import LEGACY_RUNTIME_TIER_ENV, RUNTIME_TIER_ENV

_BINDING: ModuleType | None = None
_BINDING_NAME: str | None = None


def _binding_order() -> tuple[str, str]:
    legacy_hint = sys.version_info < (3, 11) or (
        os.environ.get(RUNTIME_TIER_ENV) == "legacy-enterprise"
        or os.environ.get(LEGACY_RUNTIME_TIER_ENV) == "legacy-enterprise"
    )
    return ("PySide2", "PySide6") if legacy_hint else ("PySide6", "PySide2")


def available_binding_name() -> str | None:
    for name in _binding_order():
        try:
            if importlib.util.find_spec(name) is not None:
                return name
        except (ImportError, AttributeError, ValueError):
            continue
    return None


def binding_available() -> bool:
    return available_binding_name() is not None


def _load_binding() -> ModuleType:
    global _BINDING, _BINDING_NAME
    if _BINDING is not None:
        return _BINDING
    name = available_binding_name()
    if name is None:
        raise ImportError("Neither PySide6 nor PySide2 is installed")
    _BINDING = importlib.import_module(name)
    _BINDING_NAME = name
    return _BINDING


def binding_name() -> str:
    _load_binding()
    assert _BINDING_NAME is not None
    return _BINDING_NAME


def binding_version() -> str:
    binding = _load_binding()
    return str(getattr(binding, "__version__", "unknown"))


def is_legacy_binding() -> bool:
    return binding_name() == "PySide2"


def binding_module(component: str) -> ModuleType:
    name = binding_name()
    return importlib.import_module(f"{name}.{component}")
