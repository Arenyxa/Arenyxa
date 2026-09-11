from __future__ import annotations

import threading
from contextlib import contextmanager

from scripts.postgresql_p99_attribution_gate import _prewarm_client_pool


class _FakeQueue:
    def __init__(self, pool_max: int = 8) -> None:
        self._pool_max = pool_max
        self.active = 0
        self.max_active = 0
        self._lock = threading.Lock()

    @contextmanager
    def _connection(self):
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            yield object()
        finally:
            with self._lock:
                self.active -= 1

    def storage_metrics(self) -> dict[str, int | str | bool]:
        return {
            "backend": "postgresql",
            "pool_max": self._pool_max,
            "pool_size": self.max_active,
            "open": True,
        }


def test_prewarm_client_pool_reaches_configured_pool_max() -> None:
    queue = _FakeQueue(pool_max=8)
    _prewarm_client_pool(queue, timeout_seconds=2.0)

    assert queue.max_active == 8
    assert queue.active == 0
