from __future__ import annotations


class CircuitBreaker:
    """Minimal circuit breaker foundation for unstable dependencies."""

    def __init__(self, failure_threshold: int = 5) -> None:
        self.failure_threshold = failure_threshold
        self.failures = 0
        self.open = False

    def record_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.open = True

    def reset(self) -> None:
        self.failures = 0
        self.open = False
