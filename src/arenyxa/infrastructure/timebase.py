"""Clock primitives that separate elapsed-time safety from wall-clock timestamps."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True, slots=True)
class ClockSnapshot:
    stable_epoch: float
    wall_epoch: float
    monotonic: float
    wall_drift_seconds: float


class StableEpochClock:
    """Project a monotonic clock onto epoch seconds without following wall-clock jumps.

    Persisted lease/heartbeat fields historically use REAL epoch seconds.  Replacing them with
    raw ``time.monotonic()`` would make values meaningless across processes and restarts.  This
    clock anchors epoch once, then advances it only by monotonic elapsed time.  NTP/manual wall
    clock rollback or fast-forward therefore cannot shorten or extend an in-process lease.
    """

    def __init__(
        self,
        *,
        wall: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._wall = wall
        self._monotonic = monotonic
        self._lock = threading.Lock()
        self._wall_anchor = float(wall())
        self._mono_anchor = float(monotonic())
        self._last = self._wall_anchor

    def monotonic(self) -> float:
        return float(self._monotonic())

    def stable_epoch(self) -> float:
        candidate = self._wall_anchor + max(0.0, self.monotonic() - self._mono_anchor)
        with self._lock:
            if candidate < self._last:
                candidate = self._last
            self._last = candidate
            return candidate

    def deadline_epoch(self, seconds: float) -> float:
        duration = max(0.0, float(seconds))
        return self.stable_epoch() + duration

    def snapshot(self) -> ClockSnapshot:
        stable = self.stable_epoch()
        wall = float(self._wall())
        mono = self.monotonic()
        return ClockSnapshot(
            stable_epoch=stable,
            wall_epoch=wall,
            monotonic=mono,
            wall_drift_seconds=wall - stable,
        )


PROCESS_CLOCK = StableEpochClock()
