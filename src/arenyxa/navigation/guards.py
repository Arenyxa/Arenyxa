"""Navigation access guards shared by UI routing and deep-link entry points."""

from __future__ import annotations

from arenyxa.domain.errors import ArenyxaError
from arenyxa.navigation.models import NavigationContext, NavigationDecision
from arenyxa.navigation.resolver import NavigationResolver


class NavigationAccessError(ArenyxaError):
    def __init__(self, decision: NavigationDecision) -> None:
        super().__init__(
            "NAVIGATION_ACCESS_DENIED",
            f"Page {decision.page_id} is not available: {decision.reason}",
            domain="NAVIGATION",
            context={"page_id": decision.page_id, "reason": decision.reason},
        )
        self.decision = decision


def require_page(
    resolver: NavigationResolver,
    page_id: str,
    context: NavigationContext,
) -> NavigationDecision:
    decision = resolver.decision(page_id, context)
    if not decision.allowed:
        raise NavigationAccessError(decision)
    return decision
