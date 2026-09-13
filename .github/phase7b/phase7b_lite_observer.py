from __future__ import annotations

from collections.abc import Callable
from typing import Any


def _observe_safely(callback: Callable[[], Any] | None) -> None:
    if callback is None:
        return
    try:
        callback()
    except Exception:
        return


def invoke_business_preserving(
    original: Callable[..., Any],
    cur: Any,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    *,
    before: Callable[[], Any] | None = None,
    after: Callable[[], Any] | None = None,
) -> Any:
    """Run diagnostics fail-open while preserving business args/result/exception."""
    _observe_safely(before)
    try:
        return original(cur, *args, **kwargs)
    finally:
        _observe_safely(after)
