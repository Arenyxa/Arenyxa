from __future__ import annotations

from typing import Callable, TypeVar

T = TypeVar("T")


def call_exception_boundary(
    action: Callable[[], T],
    *,
    on_error: Callable[[Exception], None] | None = None,
    fallback: T | Callable[[Exception], T] | None = None,
    reraise: bool = False,
) -> T | None:
    """Run one explicit isolation boundary while keeping broad catching centralized.

    This helper is reserved for process/plugin/cleanup boundaries where an arbitrary
    third-party or subsystem exception must not escape unintentionally. Callers keep
    their fail-closed state transitions in ``on_error``.
    """
    try:
        return action()
    except Exception as exc:  # broad-exception-boundary: centralized isolation point
        if on_error is not None:
            on_error(exc)
        if reraise:
            raise
        if callable(fallback):
            return fallback(exc)
        return fallback
