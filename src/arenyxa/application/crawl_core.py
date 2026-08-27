"""Industrial crawl-kernel primitives used by Arenyxa Crawler Lab.

The module deliberately contains no network transport.  It provides deterministic
frontier ordering, bounded deduplication, per-origin concurrency/rate governance,
run statistics and durable checkpoint serialization so transports remain owned by
Arenyxa's existing security-governed HTTP stack.
"""
from __future__ import annotations

import hashlib
import heapq
import json
import os
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit


@dataclass(slots=True, frozen=True)
class FrontierRequest:
    url: str
    depth: int
    parent_url: str = ""
    priority: int = 0
    sequence: int = 0


class PriorityFrontier:
    """Thread-safe stable priority frontier. Higher priority is dispatched first."""

    def __init__(self, initial: Iterable[FrontierRequest] = ()) -> None:
        self._heap: list[tuple[int, int, FrontierRequest]] = []
        self._sequence = 0
        self._lock = threading.RLock()
        for item in initial:
            self.push(item.url, item.depth, item.parent_url, item.priority)

    def push(self, url: str, depth: int, parent_url: str = "", priority: int = 0) -> FrontierRequest:
        with self._lock:
            self._sequence += 1
            item = FrontierRequest(str(url), int(depth), str(parent_url), int(priority), self._sequence)
            heapq.heappush(self._heap, (-item.priority, item.sequence, item))
            return item

    def pop(self) -> FrontierRequest:
        with self._lock:
            return heapq.heappop(self._heap)[2]

    def __len__(self) -> int:
        with self._lock:
            return len(self._heap)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            ordered = sorted(self._heap)
            return [asdict(row[2]) for row in ordered]


class UrlDeduplicator:
    """Bounded SHA-256 URL identity set; avoids retaining a second copy of every URL."""

    def __init__(self, *, max_entries: int = 2_000_000) -> None:
        self.max_entries = max(1, int(max_entries))
        self._seen: set[bytes] = set()
        self._lock = threading.RLock()

    @staticmethod
    def _key(url: str) -> bytes:
        return hashlib.sha256(url.encode("utf-8", errors="strict")).digest()

    def add(self, url: str) -> bool:
        key = self._key(url)
        with self._lock:
            if key in self._seen:
                return False
            if len(self._seen) >= self.max_entries:
                raise RuntimeError("Crawler deduplication safety bound reached")
            self._seen.add(key)
            return True

    def __contains__(self, url: str) -> bool:
        key = self._key(url)
        with self._lock:
            return key in self._seen

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)


class HostRateController:
    """Per-host pacing plus in-flight limits with monotonic-time accounting."""

    def __init__(self, *, per_host_concurrency: int = 2) -> None:
        self.per_host_concurrency = max(1, int(per_host_concurrency))
        self._ready_at: dict[str, float] = {}
        self._active: dict[str, int] = {}
        self._lock = threading.RLock()

    @staticmethod
    def host(url: str) -> str:
        return (urlsplit(url).hostname or "").casefold().rstrip(".")

    def can_acquire(self, url: str, now: float | None = None) -> bool:
        host = self.host(url)
        moment = time.monotonic() if now is None else now
        with self._lock:
            return bool(host and self._active.get(host, 0) < self.per_host_concurrency and moment >= self._ready_at.get(host, 0.0))

    def acquire(self, url: str, delay_seconds: float, now: float | None = None) -> bool:
        host = self.host(url)
        moment = time.monotonic() if now is None else now
        with self._lock:
            if not host or self._active.get(host, 0) >= self.per_host_concurrency or moment < self._ready_at.get(host, 0.0):
                return False
            self._active[host] = self._active.get(host, 0) + 1
            self._ready_at[host] = moment + max(0.0, float(delay_seconds))
            return True

    def release(self, url: str) -> None:
        host = self.host(url)
        with self._lock:
            active = self._active.get(host, 0)
            if active <= 1:
                self._active.pop(host, None)
            else:
                self._active[host] = active - 1

    def wait_seconds(self, urls: Iterable[str]) -> float:
        now = time.monotonic()
        with self._lock:
            waits = [max(0.0, self._ready_at.get(self.host(url), now) - now) for url in urls if self.host(url)]
        return min(waits) if waits else 0.05


@dataclass(slots=True)
class CrawlStats:
    started_monotonic: float = field(default_factory=time.monotonic)
    submitted: int = 0
    succeeded: int = 0
    failed: int = 0
    discovered: int = 0
    skipped: int = 0
    duplicates: int = 0
    robots_denied: int = 0
    bytes_received: int = 0
    retries: int = 0

    def snapshot(self, *, frontier: int = 0, active: int = 0) -> dict[str, Any]:
        elapsed = max(0.000001, time.monotonic() - self.started_monotonic)
        return {
            "submitted": self.submitted, "succeeded": self.succeeded, "failed": self.failed,
            "discovered": self.discovered, "skipped": self.skipped, "duplicates": self.duplicates,
            "robots_denied": self.robots_denied, "bytes_received": self.bytes_received,
            "retries": self.retries, "frontier": int(frontier), "active": int(active),
            "elapsed_seconds": elapsed, "pages_per_second": (self.succeeded + self.failed) / elapsed,
            "bytes_per_second": self.bytes_received / elapsed,
        }


class CrawlCheckpointStore:
    """Atomic JSON checkpoint storage. Caller decides when a run is safe to checkpoint."""

    VERSION = 1

    @classmethod
    def save(cls, path: str | Path, payload: dict[str, Any]) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        document = {"version": cls.VERSION, "saved_at_unix": time.time(), **payload}
        fd, temp_name = tempfile.mkstemp(prefix=target.name + ".", suffix=".tmp", dir=str(target.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(document, handle, ensure_ascii=False, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, target)
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass

    @classmethod
    def load(cls, path: str | Path) -> dict[str, Any]:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("version") != cls.VERSION:
            raise ValueError("Unsupported crawler checkpoint format")
        return payload
