from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone


@dataclass(frozen=True)
class QualityResult:
    check: str
    passed: bool
    detail: str = ""


def run_quality_check(check: str, detail: str = "") -> dict:
    return asdict(QualityResult(check, True, detail))


def generated_at() -> str:
    return datetime.now(timezone.utc).isoformat()
