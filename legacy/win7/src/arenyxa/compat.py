from __future__ import annotations

__dynamic_exports__ = True

"""Small, audited compatibility helpers for the Windows 7 / Python 3.8 runtime.

The modern runtime still uses the standard-library implementations directly.  This module
only fills APIs that were added after Python 3.8 so the same Arenyxa source tree can be
packaged into the Legacy Enterprise build without forking application logic.
"""

import sys
from dataclasses import dataclass as _stdlib_dataclass
from datetime import timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, TypeVar

T = TypeVar("T")
UTC = timezone.utc


def dataclass(_cls: T | None = None, /, **kwargs: Any):
    




    if sys.version_info < (3, 10):
        kwargs.pop("slots", None)
    decorator = _stdlib_dataclass(**kwargs)
    if _cls is None:
        return decorator
    return decorator(_cls)


try:                
    from enum import StrEnum as StrEnum                              
except ImportError:                                        
    class StrEnum(str, Enum):
        

        def __str__(self) -> str:
            return str(self.value)

        def __format__(self, spec: str) -> str:
            return format(str(self.value), spec)


try:               
    from zoneinfo import ZoneInfo as ZoneInfo, ZoneInfoNotFoundError as ZoneInfoNotFoundError
except ImportError:              
    from backports.zoneinfo import ZoneInfo as ZoneInfo, ZoneInfoNotFoundError as ZoneInfoNotFoundError                                  


def removeprefix(value: str, prefix: str) -> str:
    if hasattr(value, "removeprefix"):
        return value.removeprefix(prefix)                              
    return value[len(prefix):] if value.startswith(prefix) else value


def removesuffix(value: str, suffix: str) -> str:
    if hasattr(value, "removesuffix"):
        return value.removesuffix(suffix)                              
    return value[:-len(suffix)] if suffix and value.endswith(suffix) else value


def path_is_relative_to(path: Path, root: Path) -> bool:
    
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def strict_zip(*iterables: Any, strict: bool = False):
    





    if sys.version_info >= (3, 10):
        return zip(*iterables, strict=strict)
    if not strict:
        return zip(*iterables)

    def _strict_iterator():
        iterators = tuple(iter(item) for item in iterables)
        sentinel = object()
        while True:
            values = [next(iterator, sentinel) for iterator in iterators]
            ended = [value is sentinel for value in values]
            if all(ended):
                return
            if any(ended):
                raise ValueError("zip() arguments have different lengths")
            yield tuple(values)

    return _strict_iterator()


def shutdown_executor(executor: Any, *, wait: bool, cancel_futures: bool = False) -> None:
    




    if sys.version_info >= (3, 9):
        executor.shutdown(wait=wait, cancel_futures=cancel_futures)
    else:
        executor.shutdown(wait=wait)
