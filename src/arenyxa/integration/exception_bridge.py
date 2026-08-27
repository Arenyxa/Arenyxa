from __future__ import annotations

from arenyxa.exceptions.context import exception_context


def capture_exception_context(exc: Exception) -> dict:
    return exception_context(exc)
