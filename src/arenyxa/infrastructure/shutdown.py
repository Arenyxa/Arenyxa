from __future__ import annotations

import logging
import math
import time
from dataclasses import field
from typing import Callable, Iterable

from arenyxa.compat import dataclass


@dataclass(frozen=True, slots=True)
class ShutdownDeadline:
    expires_at: float

    @classmethod
    def from_timeout(cls, timeout: float) -> "ShutdownDeadline":
        seconds = float(timeout)
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError("shutdown timeout must be finite and non-negative")
        return cls(time.monotonic() + seconds)

    def remaining(self) -> float:
        return max(0.0, self.expires_at - time.monotonic())


@dataclass(frozen=True, slots=True)
class ShutdownStep:
    name: str
    action: Callable[[], bool | None]
    after: tuple[str, ...] = field(default_factory=tuple)


class DependencyShutdownCoordinator:
    """Run shutdown steps in dependency order while preserving best-effort cleanup."""

    def __init__(
        self, logger: logging.Logger, *, reason: str = "unspecified",
        deadline: ShutdownDeadline | None = None, completed: set[str] | None = None,
    ) -> None:
        self._logger = logger
        self._steps: dict[str, ShutdownStep] = {}
        self._reason = str(reason)
        self._deadline = deadline
        self._completed = completed if completed is not None else set()

    def add(self, name: str, action: Callable[[], bool | None], *, after: Iterable[str] = ()) -> None:
        key = str(name).strip()
        if not key or key in self._steps:
            raise ValueError("shutdown step name must be unique and non-empty")
        self._steps[key] = ShutdownStep(key, action, tuple(str(item) for item in after))

    def ordered_steps(self) -> tuple[ShutdownStep, ...]:
        remaining = dict(self._steps)
        completed: set[str] = set()
        ordered: list[ShutdownStep] = []
        while remaining:
            ready = [
                step for step in remaining.values()
                if all(dep in completed for dep in step.after)
            ]
            if not ready:
                unresolved = {name: step.after for name, step in remaining.items()}
                raise RuntimeError("shutdown dependency graph contains a cycle or missing dependency: %r" % unresolved)
            for step in sorted(ready, key=lambda item: item.name):
                ordered.append(step)
                completed.add(step.name)
                remaining.pop(step.name, None)
        return tuple(ordered)

    def run(self) -> tuple[str, ...]:
        failures: list[str] = []
        for step in self.ordered_steps():
            if step.name in self._completed:
                continue
            started = time.monotonic()
            if any(dep in failures for dep in step.after) or (
                self._deadline is not None and self._deadline.remaining() <= 0.0
            ):
                failures.append(step.name)
                self._logger.warning("Shutdown blocked reason=%s phase=%s elapsed_ms=0", self._reason, step.name)
                continue
            try:
                result = step.action()
                if result is False or (self._deadline is not None and self._deadline.remaining() <= 0.0):
                    failures.append(step.name)
                else:
                    self._completed.add(step.name)
            except Exception:
                failures.append(step.name)
                self._logger.exception("Shutdown step failed: %s", step.name)
            finally:
                self._logger.info(
                    "Shutdown reason=%s phase=%s elapsed_ms=%.3f completed=%s",
                    self._reason, step.name, (time.monotonic() - started) * 1000.0,
                    step.name in self._completed,
                )
        return tuple(failures)
