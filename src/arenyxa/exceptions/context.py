from __future__ import annotations


def exception_context(exc: Exception) -> dict:
    return {
        "type": type(exc).__name__,
        "message": str(exc),
    }
