from __future__ import annotations

import gc
import os
import time
import tracemalloc
import weakref
from concurrent.futures import Future

import pytest

from arenyxa.application.future_callbacks import WeakMethodFutureCallback


@pytest.mark.skipif(
    os.getenv("ARENYXA_24H_LEAK_TEST", "0") != "1",
    reason="24-hour callback leak soak is an explicit release/soak gate",
)
def test_future_callback_owner_lifecycle_24h() -> None:
    hours = float(os.getenv("ARENYXA_LEAK_TEST_HOURS", "24"))
    if hours <= 0 or hours > 72:
        raise ValueError("ARENYXA_LEAK_TEST_HOURS must be >0 and <=72")
    deadline = time.monotonic() + hours * 3600.0

    class Owner:
        def complete(self, future: Future[object]) -> None:
            future.result()

    tracemalloc.start()
    baseline = tracemalloc.take_snapshot()
    iterations = 0
    while time.monotonic() < deadline:
        for _ in range(2_000):
            owner = Owner()
            owner_ref = weakref.ref(owner)
            future: Future[object] = Future()
            future.add_done_callback(WeakMethodFutureCallback(owner, "complete"))
            del owner
            future.set_result(None)
            assert owner_ref() is None
        iterations += 2_000
        if iterations % 20_000 == 0:
            gc.collect()
            current = tracemalloc.take_snapshot()
            growth = sum(
                stat.size_diff
                for stat in current.compare_to(baseline, "filename")
                if "arenyxa" in str(stat.traceback)
            )
            assert growth < 32 * 1024 * 1024, f"callback-owned memory growth={growth} bytes"
    tracemalloc.stop()
