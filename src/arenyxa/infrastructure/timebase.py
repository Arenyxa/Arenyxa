"""Clock primitives that separate elapsed-time safety from wall-clock timestamps."""
from __future__ import annotations

import threading
import time
import math
import sys
import uuid
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

    def anchored(self, epoch: float, monotonic: float) -> "StableEpochClock":
        """Return a private clock using a durable anchor in the same boot domain."""
        if not math.isfinite(epoch) or not math.isfinite(monotonic):
            raise ValueError("Clock anchor must be finite")
        value = StableEpochClock(wall=self._wall, monotonic=self._monotonic)
        value._wall_anchor = epoch
        value._mono_anchor = monotonic
        value._last = epoch
        return value

    def stable_epoch(self) -> float:
        candidate = self._wall_anchor + max(0.0, self.monotonic() - self._mono_anchor)
        if not math.isfinite(candidate):
            raise ValueError("Clock epoch must be finite")
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


def boot_clock_domain() -> str:
    """Identify OS boot without deriving it from the adjustable wall clock."""
    if sys.platform == "win32":
        import ctypes

        # SystemBootEnvironmentInformation begins with the boot identifier GUID.
        buffer = ctypes.create_string_buffer(32)
        status = ctypes.windll.ntdll.NtQuerySystemInformation(90, buffer, len(buffer), None)
        if status == 0:
            return "windows:" + bytes(buffer[:16]).hex()
    elif sys.platform.startswith("linux"):
        from pathlib import Path

        try:
            return "linux:" + Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        except OSError:
            pass
    # Unknown boot identity is deliberately process-scoped: reopening in another
    # process expires old leases instead of trusting an unrelated monotonic epoch.
    return "process:" + _PROCESS_CLOCK_DOMAIN


_PROCESS_CLOCK_DOMAIN = uuid.uuid4().hex
PROCESS_CLOCK = StableEpochClock()
