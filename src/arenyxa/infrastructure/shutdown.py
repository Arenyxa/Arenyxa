from __future__ import annotations

import logging
import os
import time
from dataclasses import field
from typing import Callable, Iterable

from arenyxa.compat import dataclass


@dataclass(frozen=True, slots=True)
class ShutdownDeadline:
    """One monotonic budget shared by every owner in a shutdown attempt.

    The deadline is diagnostic and a source of remaining-time budgets.  It never
    implies that a resource is stopped merely because time expired; resource owners
    must report their own quiescence truthfully.
    """

    started_at: float
    deadline_at: float

    @classmethod
    def from_timeout(cls, timeout: float) -> "ShutdownDeadline":
        started = time.monotonic()
        return cls(started, started + max(0.0, float(timeout)))

    def remaining(self) -> float:
        return max(0.0, self.deadline_at - time.monotonic())

    def elapsed(self) -> float:
        return max(0.0, time.monotonic() - self.started_at)

    @property
    def expired(self) -> bool:
        return self.remaining() <= 0.0


@dataclass(frozen=True, slots=True)
class ShutdownStep:
    name: str
    action: Callable[[], bool | None]
    after: tuple[str, ...] = field(default_factory=tuple)


class DependencyShutdownCoordinator:
    """Run shutdown steps in dependency order with timing/reason diagnostics.

    Actions still execute synchronously in their owning thread.  This coordinator
    deliberately does *not* wrap actions in an outer timeout because abandoning a
    still-running cleanup action would create concurrent teardown races.  Boundedness
    belongs inside each resource owner, using the shared :class:`ShutdownDeadline`.
    """

    def __init__(
        self,
        logger: logging.Logger,
        *,
        reason: str = "unspecified",
        deadline: ShutdownDeadline | None = None,
    ) -> None:
        self._logger = logger
        self._steps: dict[str, ShutdownStep] = {}
        self.reason = str(reason or "unspecified")
        self.deadline = deadline

    def add(
        self,
        name: str,
        action: Callable[[], bool | None],
        *,
        after: Iterable[str] = (),
    ) -> None:
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
                raise RuntimeError(
                    "shutdown dependency graph contains a cycle or missing dependency: %r"
                    % unresolved
                )
            for step in sorted(ready, key=lambda item: item.name):
                ordered.append(step)
                completed.add(step.name)
                remaining.pop(step.name, None)
        return tuple(ordered)

    def run(self) -> tuple[str, ...]:
        failures: list[str] = []
        successful: set[str] = set()
        for step in self.ordered_steps():
            blocked_by = tuple(dep for dep in step.after if dep not in successful)
            if blocked_by:
                failures.append(step.name)
                self._logger.error(
                    "Shutdown phase skipped reason=%s pid=%s phase=%s failed_dependencies=%s",
                    self.reason,
                    os.getpid(),
                    step.name,
                    blocked_by,
                )
                continue
            phase_started = time.monotonic()
            remaining_ms = (
                None if self.deadline is None else int(self.deadline.remaining() * 1000.0)
            )
            self._logger.info(
                "Shutdown phase start reason=%s pid=%s phase=%s deadline_remaining_ms=%s",
                self.reason,
                os.getpid(),
                step.name,
                remaining_ms,
            )
            try:
                result = step.action()
                if result is False:
                    failures.append(step.name)
                    self._logger.error(
                        "Shutdown phase incomplete reason=%s pid=%s phase=%s elapsed_ms=%d deadline_remaining_ms=%s",
                        self.reason,
                        os.getpid(),
                        step.name,
                        int((time.monotonic() - phase_started) * 1000.0),
                        None if self.deadline is None else int(self.deadline.remaining() * 1000.0),
                    )
                    continue
            except Exception:
                failures.append(step.name)
                self._logger.exception(
                    "Shutdown step failed reason=%s pid=%s phase=%s elapsed_ms=%d",
                    self.reason,
                    os.getpid(),
                    step.name,
                    int((time.monotonic() - phase_started) * 1000.0),
                )
                continue
            successful.add(step.name)
            self._logger.info(
                "Shutdown phase end reason=%s pid=%s phase=%s elapsed_ms=%d deadline_remaining_ms=%s success=true",
                self.reason,
                os.getpid(),
                step.name,
                int((time.monotonic() - phase_started) * 1000.0),
                None if self.deadline is None else int(self.deadline.remaining() * 1000.0),
            )
        return tuple(failures)
