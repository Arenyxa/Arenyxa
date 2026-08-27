from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone


@dataclass(frozen=True)
class AuditRecord:
    action: str
    actor: str
    timestamp: str
    result: str


def create_audit_record(action: str, actor: str, result: str = "success") -> dict:
    return asdict(AuditRecord(action, actor, datetime.now(timezone.utc).isoformat(), result))
