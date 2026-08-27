from __future__ import annotations

import logging
from dataclasses import field
from typing import Callable, Iterable

from arenyxa.compat import dataclass


@dataclass(frozen=True, slots=True)
class ShutdownStep:
    name: str
    action: Callable[[], None]
    after: tuple[str, ...] = field(default_factory=tuple)


class DependencyShutdownCoordinator:
    """Run shutdown steps in dependency order while preserving best-effort cleanup."""

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger
        self._steps: dict[str, ShutdownStep] = {}

    def add(self, name: str, action: Callable[[], None], *, after: Iterable[str] = ()) -> None:
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
            try:
                step.action()
            except Exception:
                failures.append(step.name)
                self._logger.exception("Shutdown step failed: %s", step.name)
        return tuple(failures)
