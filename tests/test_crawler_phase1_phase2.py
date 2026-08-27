from __future__ import annotations

from pathlib import Path

from arenyxa.application.crawl_core import CrawlCheckpointStore, HostRateController, PriorityFrontier, UrlDeduplicator
from arenyxa.infrastructure.crawler_transport import ProxyPool


def test_priority_frontier_is_stable_and_priority_aware() -> None:
    frontier = PriorityFrontier()
    frontier.push("https://example.test/low", 1, priority=0)
    frontier.push("https://example.test/high-a", 1, priority=10)
    frontier.push("https://example.test/high-b", 1, priority=10)
    assert [frontier.pop().url for _ in range(3)] == [
        "https://example.test/high-a", "https://example.test/high-b", "https://example.test/low"
    ]


def test_url_deduplicator_uses_bounded_identity() -> None:
    dedup = UrlDeduplicator(max_entries=2)
    assert dedup.add("https://example.test/a") is True
    assert dedup.add("https://example.test/a") is False
    assert dedup.add("https://example.test/b") is True
    try:
        dedup.add("https://example.test/c")
    except RuntimeError:
        pass
    else:
        raise AssertionError("dedup safety bound must fail closed")


def test_host_rate_controller_enforces_parallel_limit() -> None:
    limiter = HostRateController(per_host_concurrency=1)
    url = "https://example.test/a"
    assert limiter.acquire(url, 0.0)
    assert not limiter.acquire("https://example.test/b", 0.0)
    limiter.release(url)
    assert limiter.acquire("https://example.test/b", 0.0)


def test_checkpoint_store_is_atomic_and_versioned(tmp_path: Path) -> None:
    path = tmp_path / "crawl.checkpoint.json"
    CrawlCheckpointStore.save(path, {"frontier": [{"url": "https://example.test/"}]})
    loaded = CrawlCheckpointStore.load(path)
    assert loaded["version"] == 1
    assert loaded["frontier"][0]["url"] == "https://example.test/"


def test_proxy_pool_cools_down_repeated_failure() -> None:
    pool = ProxyPool(["http://127.0.0.1:8080"], failure_threshold=2, cooldown_seconds=10)
    endpoint = pool.select()
    assert endpoint is not None
    pool.report_failure(endpoint, OSError("one"))
    assert pool.select() is endpoint
    pool.report_failure(endpoint, OSError("two"))
    assert pool.select() is None
    assert pool.snapshot()[0]["cooldown_remaining"] > 0
