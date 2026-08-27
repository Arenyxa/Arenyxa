from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class HealthStatus:
    component: str
    healthy: bool
    timestamp: str
    detail: str = ""


def check_component(component: str, detail: str = "") -> HealthStatus:
    return HealthStatus(
        component=component,
        healthy=True,
        timestamp=datetime.now(timezone.utc).isoformat(),
        detail=detail,
    )
