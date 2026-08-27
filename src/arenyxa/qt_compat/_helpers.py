from __future__ import annotations

from types import SimpleNamespace
from typing import Any


def export_public(module: Any, target: dict[str, Any]) -> None:
    for name in dir(module):
        if not name.startswith("_"):
            target.setdefault(name, getattr(module, name))


def scoped_namespace(owner: Any, scoped_name: str, mapping: dict[str, str]) -> Any:
    current = getattr(owner, scoped_name, None)
    if current is not None and all(hasattr(current, member) for member in mapping):
        return current
    values = {}
    for new_name, legacy_name in mapping.items():
        if current is not None and hasattr(current, new_name):
            values[new_name] = getattr(current, new_name)
        else:
            values[new_name] = getattr(owner, legacy_name)
    return SimpleNamespace(**values)


def class_with_scopes(base: Any, scopes: dict[str, dict[str, str]], *, ensure_exec: bool = False) -> Any:
    additions: dict[str, Any] = {}
    for scoped_name, mapping in scopes.items():
        namespace = scoped_namespace(base, scoped_name, mapping)
        if getattr(base, scoped_name, None) is not namespace:
            additions[scoped_name] = namespace
    if ensure_exec and not hasattr(base, "exec") and hasattr(base, "exec_"):
        additions["exec"] = base.exec_
    if not additions:
        return base
    try:
        for name, value in additions.items():
            setattr(base, name, value)
        return base
    except (AttributeError, TypeError):
        return type(base.__name__, (base,), additions)


class QtProxy:
    def __init__(self, base: Any, scopes: dict[str, dict[str, str]]) -> None:
        self._base = base
        for scoped_name, mapping in scopes.items():
            setattr(self, scoped_name, scoped_namespace(base, scoped_name, mapping))

    def __getattr__(self, name: str) -> Any:
        return getattr(self._base, name)
