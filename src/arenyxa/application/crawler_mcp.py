"""Optional MCP exposure for Arenyxa crawler and Web Intelligence primitives.

The MCP tools preserve Arenyxa's NetworkUseGuard and crawler safety bounds. They
do not expose CAPTCHA solving, stealth fingerprint spoofing, credential theft, or
access-control bypass capabilities.
"""
from __future__ import annotations

from typing import Any

from arenyxa.application.browser_engine import BrowserPool, BrowserRequest
from arenyxa.application.crawler import CrawlerConfig, CrawlerEngine
from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.doh_resolver import DoHResolver


def create_mcp_server() -> Any:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise ArenyxaError(
            "CRAWLER_MCP_UNAVAILABLE",
            "Crawler MCP requires the optional 'mcp' dependency",
            domain="CRAWLER",
        ) from exc

    server = FastMCP("Arenyxa Web Intelligence")

    @server.tool()
    def crawler_fetch(url: str) -> dict[str, Any]:
        """Fetch one public/authorized HTTP(S) page through Arenyxa governance."""
        engine = CrawlerEngine()
        config = CrawlerConfig(seeds=[url], max_pages=1, max_depth=0)
        unit = engine.fetch_one(config, url)
        return unit.snapshot()

    @server.tool()
    def crawler_run(url: str, max_pages: int = 25, max_depth: int = 2) -> dict[str, Any]:
        """Run a bounded, robots-aware crawl."""
        config = CrawlerConfig(
            seeds=[url],
            max_pages=max(1, min(int(max_pages), 500)),
            max_depth=max(0, min(int(max_depth), 8)),
            respect_robots_txt=True,
        )
        return CrawlerEngine().run(config).snapshot()

    @server.tool()
    def browser_fetch(url: str) -> dict[str, Any]:
        """Render a page with the governed Playwright browser engine."""
        with BrowserPool() as pool:
            result = pool.fetch(BrowserRequest(url=url))
        payload = result.snapshot()
        # Avoid dumping arbitrary full-page HTML into an MCP response by default.
        payload["html"] = result.html[:200_000]
        if len(result.html) > 200_000:
            payload.setdefault("warnings", []).append("mcp-html-preview-truncated")
        return payload

    @server.tool()
    def doh_resolve(host: str) -> dict[str, Any]:
        """Resolve a host using the configured DNS-over-HTTPS resolver."""
        return {"host": host, "addresses": list(DoHResolver().resolve(host))}

    return server


def main() -> int:
    create_mcp_server().run()
    return 0
