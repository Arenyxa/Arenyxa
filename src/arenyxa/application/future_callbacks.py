"""Lifecycle-safe Future callbacks.

Future callbacks outlive the submission frame and can accidentally retain large service or
Qt object graphs. These callable objects make ownership explicit and use weak references
when the owner should not be kept alive by a Future.
"""

from __future__ import annotations

import logging
import weakref
from concurrent.futures import Future
from typing import Any

LOGGER = logging.getLogger(__name__)


class WeakMethodFutureCallback:
    __slots__ = ("_owner_ref", "_method_name", "_prefix", "_suffix")

    def __init__(
        self,
        owner: Any,
        method_name: str,
        *,
        prefix: tuple[Any, ...] = (),
        suffix: tuple[Any, ...] = (),
    ) -> None:
        self._owner_ref = weakref.ref(owner)
        self._method_name = str(method_name)
        self._prefix = tuple(prefix)
        self._suffix = tuple(suffix)

    def __call__(self, future: Future[Any]) -> None:
        owner = self._owner_ref()
        if owner is None:
            return
        method = getattr(owner, self._method_name, None)
        if method is None or not callable(method):
            LOGGER.error("Future callback target disappeared: %s", self._method_name)
            return
        method(*self._prefix, future, *self._suffix)


class ReleaseFutureCallback:
    __slots__ = ("_release", "_cancelled_only")

    def __init__(self, release: Any, *, cancelled_only: bool = False) -> None:
        if not callable(release):
            raise TypeError("release callback must be callable")
        self._release = release
        self._cancelled_only = bool(cancelled_only)

    def __call__(self, future: Future[Any]) -> None:
        if self._cancelled_only and not future.cancelled():
            return
        self._release()
