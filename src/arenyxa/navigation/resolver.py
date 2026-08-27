"""Deterministic, side-effect-free page visibility and access resolution."""

from __future__ import annotations

import time
from collections.abc import Iterable

from arenyxa.navigation.models import (
    NavigationContext,
    NavigationDecision,
    NavigationDiff,
    PageManifest,
    ResolvedNavigation,
)


class NavigationResolver:
    def __init__(self, manifests: Iterable[PageManifest]) -> None:
        ordered = tuple(manifests)
        ids = [item.id for item in ordered]
        if len(ids) != len(set(ids)):
            raise ValueError("navigation page manifest IDs must be unique")
        self._ordered = ordered
        self._by_id = {item.id: item for item in ordered}

    @property
    def manifests(self) -> tuple[PageManifest, ...]:
        return self._ordered

    def decision(self, page_id: str, context: NavigationContext) -> NavigationDecision:
        manifest = self._by_id.get(str(page_id))
        if manifest is None:
            return NavigationDecision(str(page_id), False, "PAGE_UNKNOWN")
        if context.root_session.active:
            return NavigationDecision(manifest.id, True, "ACTIVE_ROOT_SESSION_SHOW_ALL")
        if manifest.root_only:
            return NavigationDecision(manifest.id, False, "ROOT_SESSION_REQUIRED")
        if context.experience_mode not in manifest.experience_modes:
            return NavigationDecision(manifest.id, False, "EXPERIENCE_MODE_MISMATCH")
        if context.runtime_mode not in manifest.runtime_modes:
            return NavigationDecision(manifest.id, False, "RUNTIME_MODE_MISMATCH")
        if manifest.required_roles and context.account_role not in manifest.required_roles:
            return NavigationDecision(manifest.id, False, "ACCOUNT_ROLE_REQUIRED")
        if manifest.requires_developer_authority and not context.developer_authority.active:
            return NavigationDecision(manifest.id, False, "DEVELOPER_AUTHORITY_REQUIRED")
        if not manifest.required_capabilities.issubset(context.effective_capabilities):
            return NavigationDecision(manifest.id, False, "CAPABILITY_REQUIRED")
        return NavigationDecision(manifest.id, True, "ALLOWED")

    def allowed(self, page_id: str, context: NavigationContext) -> bool:
        return self.decision(page_id, context).allowed

    def resolve(self, context: NavigationContext) -> ResolvedNavigation:
        decisions = tuple(self.decision(item.id, context) for item in self._ordered)
        return ResolvedNavigation(
            tuple(item.page_id for item in decisions if item.allowed),
            decisions,
        )

    def diff(self, previous: NavigationContext, current: NavigationContext) -> NavigationDiff:
        before = self.resolve(previous).page_ids
        after = self.resolve(current).page_ids
        updated: tuple[str, ...] = ()
        if previous != current:
            updated = tuple(item for item in after if item in set(before))
        return NavigationDiff.between(before, after, updated=updated)

    def timed_diff(
        self, previous: NavigationContext, current: NavigationContext
    ) -> tuple[NavigationDiff, float]:
        started = time.perf_counter()
        diff = self.diff(previous, current)
        return diff, (time.perf_counter() - started) * 1000.0
