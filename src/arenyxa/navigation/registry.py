"""Thread-safe page manifest registry used by core and optional extensions."""

from __future__ import annotations

import threading
from collections.abc import Iterable

from arenyxa.navigation.manifest import DEFAULT_PAGE_MANIFESTS
from arenyxa.navigation.models import PageManifest


class NavigationRegistry:
    def __init__(self, manifests: Iterable[PageManifest] = ()) -> None:
        self._lock = threading.RLock()
        self._manifests: dict[str, PageManifest] = {}
        for manifest in manifests:
            self.register(manifest)

    def register(self, manifest: PageManifest, *, replace: bool = False) -> None:
        if not manifest.id.strip():
            raise ValueError("navigation page ID cannot be empty")
        with self._lock:
            if manifest.id in self._manifests and not replace:
                raise ValueError(f"navigation page already registered: {manifest.id}")
            self._manifests[manifest.id] = manifest

    def unregister(self, page_id: str) -> PageManifest | None:
        with self._lock:
            return self._manifests.pop(str(page_id), None)

    def get(self, page_id: str) -> PageManifest | None:
        with self._lock:
            return self._manifests.get(str(page_id))

    def snapshot(self) -> tuple[PageManifest, ...]:
        with self._lock:
            return tuple(self._manifests.values())


_DEFAULT_REGISTRY = NavigationRegistry(DEFAULT_PAGE_MANIFESTS)


def default_navigation_registry() -> NavigationRegistry:
    return _DEFAULT_REGISTRY
