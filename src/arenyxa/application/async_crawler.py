"""Native asyncio facade for Arenyxa's bounded crawler and browser engines."""
from __future__ import annotations

import asyncio
from typing import Any

from arenyxa.application.browser_engine import BrowserFetchResult, BrowserPool, BrowserRequest
from arenyxa.application.crawler import CrawlerConfig, CrawlerEngine, CrawlerFetchUnit, CrawlerRunResult
from arenyxa.infrastructure.http_client import CancellationToken


class AsyncCrawlerEngine:
    """Async facade that preserves the tested synchronous crawler semantics."""

    def __init__(self, engine: CrawlerEngine | None = None) -> None:
        self.engine = engine or CrawlerEngine()

    async def run(
        self,
        config: CrawlerConfig,
        *,
        token: CancellationToken | None = None,
        progress: Any | None = None,
    ) -> CrawlerRunResult:
        return await asyncio.to_thread(self.engine.run, config, token=token, progress=progress)

    async def fetch_one(
        self,
        url: str,
        *,
        depth: int = 0,
        parent_url: str = "",
        config: CrawlerConfig,
        token: CancellationToken | None = None,
    ) -> CrawlerFetchUnit:
        return await asyncio.to_thread(
            self.engine.fetch_one,
            config,
            url,
            depth=depth,
            parent_url=parent_url,
            token=token,
        )


class AsyncBrowserPool:
    """Awaitable facade for the bounded, thread-affine Playwright pool."""

    def __init__(self, pool: BrowserPool | None = None) -> None:
        self.pool = pool or BrowserPool()

    async def fetch(self, request: BrowserRequest) -> BrowserFetchResult:
        return await asyncio.to_thread(self.pool.fetch, request)

    async def close(self) -> None:
        await asyncio.to_thread(self.pool.close)

    async def __aenter__(self) -> "AsyncBrowserPool":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.close()
