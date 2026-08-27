from __future__ import annotations
from functools import lru_cache
from collections.abc import Callable
from typing import Any


def bounded_cache(maxsize: int = 256) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    return lru_cache(maxsize=maxsize)
