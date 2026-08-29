"""Reusable spider templates for Arenyxa Crawler Lab.

These templates intentionally inherit the same NetworkUseGuard, robots.txt and
bounded crawl semantics as CrawlerEngine. They are convenience layers rather
than alternate network stacks.
"""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urljoin, urlsplit

from lxml import etree

from arenyxa.application.crawler import CrawlerConfig, CrawlerEngine, CrawlerRunResult, canonicalize_url
from arenyxa.domain.models import FetchResponse, RequestSpec, RetryPolicy
from arenyxa.infrastructure.crawler_transport import CrawlerTransport, SessionPolicy
from arenyxa.infrastructure.http_client import CancellationToken


@dataclass(slots=True)
class Spider:
    seeds: list[str]
    config_overrides: dict[str, Any] = field(default_factory=dict)

    def build_config(self) -> CrawlerConfig:
        allowed = set(CrawlerConfig.__dataclass_fields__)
        values = {k: v for k, v in self.config_overrides.items() if k in allowed and k != "seeds"}
        return CrawlerConfig(seeds=list(self.seeds), **values).normalized()

    def run(self, engine: CrawlerEngine | None = None, *, token: CancellationToken | None = None) -> CrawlerRunResult:
        return (engine or CrawlerEngine()).run(self.build_config(), token=token)


@dataclass(slots=True)
class CrawlSpider(Spider):
    """General recursive spider template."""


@dataclass(slots=True)
class SitemapSpider:
    sitemap_url: str
    config_overrides: dict[str, Any] = field(default_factory=dict)
    max_sitemap_urls: int = 50_000
    max_sitemap_documents: int = 64
    same_origin_indexes_only: bool = True

    def discover(self, engine: CrawlerEngine | None = None, *, token: CancellationToken | None = None) -> list[str]:
        crawler = engine or CrawlerEngine()
        root_url = canonicalize_url(self.sitemap_url)
        if not root_url:
            raise ValueError("SitemapSpider requires a valid HTTP/HTTPS sitemap URL")
        cancellation = token or CancellationToken()
        transport = CrawlerTransport(crawler.fetcher, policy=SessionPolicy())
        queue = [root_url]
        seen_documents: set[str] = set()
        seen_urls: set[str] = set()
        urls: list[str] = []
        root_origin = _origin_key(root_url)
        doc_limit = max(1, min(int(self.max_sitemap_documents), 4096))
        url_limit = max(1, min(int(self.max_sitemap_urls), 250_000))

        while queue and len(seen_documents) < doc_limit and len(urls) < url_limit:
            cancellation.checkpoint()
            current = queue.pop(0)
            if current in seen_documents:
                continue
            seen_documents.add(current)
            host = urlsplit(current).hostname or ""
            crawler.guard.check_target(host, resolve_dns=True)
            response = transport.fetch(
                RequestSpec(current, retry=RetryPolicy(attempts=2), user_agent="Arenyxa-SitemapSpider/8.1.1"),
                token=cancellation,
            )
            if response.status >= 400:
                raise RuntimeError(f"Sitemap request failed with HTTP {response.status}: {current}")
            parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False, recover=False)
            root = etree.fromstring(response.body, parser=parser)
            root_name = etree.QName(root).localname.casefold()
            locations = []
            for node in root.xpath("//*[local-name()='loc']"):
                text = "".join(node.itertext()).strip()
                resolved = canonicalize_url(urljoin(current, text))
                if resolved:
                    locations.append(resolved)
            if root_name == "sitemapindex":
                for child in locations:
                    if self.same_origin_indexes_only and _origin_key(child) != root_origin:
                        continue
                    if child not in seen_documents and child not in queue and len(queue) + len(seen_documents) < doc_limit:
                        queue.append(child)
                continue
            for resolved in locations:
                if resolved not in seen_urls:
                    seen_urls.add(resolved)
                    urls.append(resolved)
                    if len(urls) >= url_limit:
                        break
        return urls

    def run(self, engine: CrawlerEngine | None = None, *, token: CancellationToken | None = None) -> CrawlerRunResult:
        crawler = engine or CrawlerEngine()
        seeds = self.discover(crawler, token=token)
        if not seeds:
            raise ValueError("Sitemap contained no crawlable URLs")
        allowed = set(CrawlerConfig.__dataclass_fields__)
        values = {k: v for k, v in self.config_overrides.items() if k in allowed and k != "seeds"}
        return crawler.run(CrawlerConfig(seeds=seeds, **values), token=token)


@dataclass(slots=True)
class FeedResult:
    source_url: str
    records: list[dict[str, Any]]
    content_type: str
    status: int


class _FeedSpider:
    def __init__(self, feed_url: str, *, max_records: int = 100_000) -> None:
        self.feed_url = feed_url
        self.max_records = max(1, min(int(max_records), 1_000_000))

    def _fetch(self, engine: CrawlerEngine | None, token: CancellationToken | None) -> FetchResponse:
        crawler = engine or CrawlerEngine()
        value = canonicalize_url(self.feed_url)
        if not value:
            raise ValueError("Feed URL must be valid HTTP/HTTPS")
        crawler.guard.check_target(urlsplit(value).hostname or "", resolve_dns=True)
        return CrawlerTransport(crawler.fetcher).fetch(
                RequestSpec(value, retry=RetryPolicy(attempts=2), user_agent="Arenyxa-FeedSpider/8.1.1"),
            token=token or CancellationToken(),
        )


class XMLFeedSpider(_FeedSpider):
    def run(self, engine: CrawlerEngine | None = None, *, token: CancellationToken | None = None) -> FeedResult:
        response = self._fetch(engine, token)
        parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False, recover=False)
        root = etree.fromstring(response.body, parser=parser)
        records: list[dict[str, Any]] = []
        candidates = root.xpath("//*[local-name()='item' or local-name()='entry']")
        if not candidates:
            candidates = list(root)[: self.max_records]
        for node in candidates[: self.max_records]:
            record: dict[str, Any] = {}
            for child in list(node)[:256]:
                key = etree.QName(child).localname
                text = " ".join("".join(child.itertext()).split())
                if key and key not in record:
                    record[key] = text[:1_000_000]
            if record:
                records.append(record)
        return FeedResult(response.final_url, records, response.content_type, response.status)


class CSVFeedSpider(_FeedSpider):
    def run(self, engine: CrawlerEngine | None = None, *, token: CancellationToken | None = None) -> FeedResult:
        response = self._fetch(engine, token)
        text = response.body.decode(response.encoding or "utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        records: list[dict[str, Any]] = []
        for row in reader:
            records.append({str(k): str(v)[:1_000_000] for k, v in list(row.items())[:256]})
            if len(records) >= self.max_records:
                break
        return FeedResult(response.final_url, records, response.content_type, response.status)


def _origin_key(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError:
        port = None
    return parsed.scheme.casefold(), (parsed.hostname or "").casefold().rstrip("."), port


class ShopifySpider(CrawlSpider):
    """Convenience template for public storefront pages and documented feeds.

    No CAPTCHA solving, authentication bypass, or private/admin endpoint discovery
    is performed. The template simply provides conservative storefront defaults.
    """

    @classmethod
    def storefront(cls, root_url: str, **overrides: Any) -> "ShopifySpider":
        root = canonicalize_url(root_url)
        if not root:
            raise ValueError("ShopifySpider requires a valid storefront URL")
        defaults = {
            "max_depth": 4,
            "same_site_only": True,
            "respect_robots_txt": True,
            "include_url_globs": ["*/products/*", "*/collections/*", "*/pages/*"],
        }
        defaults.update(overrides)
        return cls([root], defaults)
