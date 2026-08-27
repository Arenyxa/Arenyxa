from __future__ import annotations

import os
from .exceptions import SecretNotFoundError


class SecretProvider:
    """Central secret resolution entry point.

    Phase 1 introduces a single access boundary so callers do not embed
    credentials directly in application code.
    """

    @staticmethod
    def get(name: str, *, required: bool = True, default: str | None = None) -> str | None:
        value = os.environ.get(name, default)
        if required and not value:
            raise SecretNotFoundError(f"Missing secret: {name}")
        return value
