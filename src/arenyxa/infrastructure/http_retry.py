"""Shared HTTP retry-delay parsing."""
from __future__ import annotations

import math
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Mapping

from arenyxa.compat import UTC


def parse_retry_after(
    headers: Mapping[str, str],
    *,
    now: datetime | None = None,
    maximum_seconds: float | None = None,
) -> float | None:
    """Parse ``Retry-After`` delta-seconds or HTTP-date into a bounded delay."""
    raw = next(
        (str(value) for key, value in headers.items() if str(key).casefold() == "retry-after"),
        "",
    ).strip()
    if not raw:
        return None
    try:
        delay = float(raw)
    except ValueError:
        try:
            moment = parsedate_to_datetime(raw)
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=UTC)
            reference = datetime.now(UTC) if now is None else now
            if reference.tzinfo is None:
                reference = reference.replace(tzinfo=UTC)
            delay = (moment - reference).total_seconds()
        except (TypeError, ValueError, OverflowError):
            return None
    if not math.isfinite(delay):
        return None
    bounded = max(0.0, delay)
    if maximum_seconds is not None:
        bounded = min(bounded, max(0.0, float(maximum_seconds)))
    return bounded
