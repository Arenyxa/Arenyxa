"""Bounded, policy-aware recursive web crawler for Arenyxa Crawler Lab.

The crawler intentionally builds on Arenyxa's existing HTTP, parser, extraction,
DLP and network-governance layers instead of introducing a second transport stack.
It is a breadth-first URL-frontier scheduler with explicit scope, robots.txt,
per-host pacing, bounded concurrency, cooperative pause/cancel and deterministic
export-friendly results.
"""

from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import csv
import fnmatch
import json
import logging
import os
import tempfile
import threading
import time
import urllib.robotparser
from contextlib import nullcontext
from collections import OrderedDict
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable
from urllib.parse import urljoin, urlsplit, urlunsplit

from lxml import etree, html
from openpyxl import Workbook

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import DEFAULT_USER_AGENT, FieldSpec, FetchResponse, RequestSpec, RetryPolicy
from arenyxa.infrastructure.atomic_io import fsync_existing_file
from arenyxa.infrastructure.http_client import CancellationToken, HttpFetcher
from arenyxa.infrastructure.crawler_transport import CrawlerTransport, SessionPolicy
from arenyxa.infrastructure.crawler_cache import CachePolicy
from arenyxa.application.crawl_core import CrawlStats, HostRateController, PriorityFrontier, UrlDeduplicator
from arenyxa.application.anti_bot_intelligence import AntiBotHostGovernor, AntiBotIntelligenceEngine, BlockKind, HumanVerificationCoordinator
from arenyxa.application.browser_engine import BrowserEngineConfig, BrowserPool, BrowserRequest
from arenyxa.application.crawler_web_intelligence import browser_result_to_fetch_response
from arenyxa.infrastructure.parsers import FieldExtractor, ParserRegistry
from arenyxa.security.network_guard import NetworkGuardPolicy, NetworkUseGuard


LOGGER = logging.getLogger(__name__)

ProgressCallback = Callable[[Dict[str, Any]], None]


@dataclass(slots=True)
class CrawlerConfig:
    seeds: list[str]
    fields: list[FieldSpec] = field(default_factory=list)
    max_pages: int = 250
    max_depth: int = 3
    concurrency: int = 8
    per_host_concurrency: int = 2
    per_host_delay_seconds: float = 0.35
    request_headers: dict[str, str] = field(default_factory=dict)
    proxies: list[str] = field(default_factory=list)
    http3_mode: str = "off"
    cache_mode: str = "off"
    cache_root: str = ""
    cache_ttl_seconds: float = 3600.0
    blocked_domains: list[str] = field(default_factory=list)
    browser_fallback_on_js: bool = False
    browser_workers: int = 2
    browser_remote_cdp_url: str = ""
    respect_robots_txt: bool = True
    same_site_only: bool = True
    include_subdomains: bool = True
    allowed_domains: list[str] = field(default_factory=list)
    include_url_globs: list[str] = field(default_factory=list)
    exclude_url_globs: list[str] = field(default_factory=list)
    user_agent: str = DEFAULT_USER_AGENT
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    retry_attempts: int = 2
    max_links_per_page: int = 5000
    max_records: int = 100000

    def normalized(self) -> "CrawlerConfig":
        seeds: list[str] = []
        seen: set[str] = set()
        for raw in self.seeds:
            url = canonicalize_url(str(raw).strip())
            if not url or url in seen:
                continue
            seen.add(url)
            seeds.append(url)
        if not seeds:
            raise ValueError("Crawler requires at least one valid http/https seed URL")
        if len(seeds) > 10000:
            raise ValueError("Crawler seed count exceeds the 10000 URL safety bound")
        fields = list(self.fields)[:256]
        for item in fields:
            errors = item.validate()
            if errors:
                raise ValueError("Invalid crawler extraction field: " + "; ".join(errors))
        domains = []
        for raw in self.allowed_domains:
            value = normalize_domain(raw)
            if value and value not in domains:
                domains.append(value)
        include_globs = [str(item).strip()[:2048] for item in self.include_url_globs if str(item).strip()][:128]
        exclude_globs = [str(item).strip()[:2048] for item in self.exclude_url_globs if str(item).strip()][:128]
        user_agent = str(self.user_agent).strip()
        if not user_agent or any((ord(ch) < 32 and ch != "\t") or ord(ch) == 127 for ch in user_agent):
            raise ValueError("Crawler User-Agent is invalid")
        return CrawlerConfig(
            seeds=seeds,
            fields=fields,
            max_pages=max(1, min(int(self.max_pages), 10000)),
            max_depth=max(0, min(int(self.max_depth), 32)),
            concurrency=max(1, min(int(self.concurrency), 64)),
            per_host_concurrency=max(1, min(int(self.per_host_concurrency), 16)),
            per_host_delay_seconds=max(0.0, min(float(self.per_host_delay_seconds), 60.0)),
            request_headers={str(k): str(v) for k, v in list(self.request_headers.items())[:128]},
            proxies=[str(v).strip() for v in self.proxies if str(v).strip()][:256],
            http3_mode=_normalize_http3_mode(self.http3_mode),
            cache_mode=_normalize_cache_mode(self.cache_mode),
            cache_root=str(self.cache_root or "").strip(),
            cache_ttl_seconds=max(1.0, min(float(self.cache_ttl_seconds), 30 * 86400.0)),
            blocked_domains=[normalize_domain(v) if "*" not in str(v) else str(v).strip().casefold() for v in self.blocked_domains if str(v).strip()][:4096],
            browser_fallback_on_js=bool(self.browser_fallback_on_js),
            browser_workers=max(1, min(int(self.browser_workers), 8)),
            browser_remote_cdp_url=str(self.browser_remote_cdp_url or "").strip(),
            respect_robots_txt=bool(self.respect_robots_txt),
            same_site_only=bool(self.same_site_only),
            include_subdomains=bool(self.include_subdomains),
            allowed_domains=domains,
            include_url_globs=include_globs,
            exclude_url_globs=exclude_globs,
            user_agent=user_agent[:512],
            connect_timeout=max(0.25, min(float(self.connect_timeout), 120.0)),
            read_timeout=max(0.25, min(float(self.read_timeout), 300.0)),
            retry_attempts=max(0, min(int(self.retry_attempts), 10)),
            max_links_per_page=max(1, min(int(self.max_links_per_page), 50000)),
            max_records=max(1, min(int(self.max_records), 1_000_000)),
        )

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CrawlPage:
    requested_url: str
    final_url: str
    depth: int
    parent_url: str
    status: int
    content_type: str
    bytes_received: int
    elapsed_ms: float
    title: str = ""
    links_discovered: int = 0
    extracted: dict[str, Any] = field(default_factory=dict)
    quality_flags: list[str] = field(default_factory=list)

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CrawlerRunResult:
    pages: list[CrawlPage]
    records: list[dict[str, Any]]
    pages_submitted: int
    pages_succeeded: int
    pages_failed: int
    urls_discovered: int
    urls_skipped: int
    duplicates_removed: int
    robots_denied: int
    duration_seconds: float
    cancelled: bool = False
    errors: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def snapshot(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["pages"] = [item.snapshot() for item in self.pages]
        return payload


@dataclass(slots=True)
class _FrontierItem:
    url: str
    depth: int
    parent_url: str = ""


@dataclass(slots=True)
class _FetchedPage:
    page: CrawlPage
    links: list[str]


@dataclass(slots=True)
class CrawlerFetchUnit:
    """One crawler page plus its normalized in-scope discovery set.

    This is the public single-page primitive used by the distributed crawler.
    It preserves robots.txt, NetworkUseGuard, transport, extraction and anti-bot
    behavior from the normal local crawl engine instead of duplicating them.
    """

    page: CrawlPage
    links: list[str]
    robots_denied: bool = False
    warnings: list[str] = field(default_factory=list)

    def snapshot(self) -> dict[str, Any]:
        return {
            "page": self.page.snapshot(),
            "links": list(self.links),
            "robots_denied": self.robots_denied,
            "warnings": list(self.warnings),
        }


@dataclass(slots=True)
class _RobotsPolicy:
    parser: urllib.robotparser.RobotFileParser | None
    delay_seconds: float
    deny_all: bool = False

    def allowed(self, user_agent: str, url: str) -> bool:
        if self.deny_all:
            return False
        if self.parser is None:
            return True
        return bool(self.parser.can_fetch(user_agent, url))


class CrawlerEngine:
    """Recursive crawler with a bounded BFS frontier and conservative defaults."""

    def __init__(
        self,
        *,
        fetcher: HttpFetcher | Any | None = None,
        network_policy: NetworkGuardPolicy | None = None,
        robots_cache_limit: int = 2048,
    ) -> None:
        self.guard = NetworkUseGuard(network_policy or NetworkGuardPolicy())
        base_fetcher = fetcher or HttpFetcher(network_guard=self.guard)
        if isinstance(base_fetcher, HttpFetcher):
            base_fetcher.network_guard = self.guard
        self.fetcher = base_fetcher
        self._robots_cache_limit = max(32, min(10000, int(robots_cache_limit)))
        self._robots_cache: OrderedDict[str, _RobotsPolicy] = OrderedDict()
        self._robots_lock = threading.RLock()
        self._extractor = FieldExtractor()
        self._anti_bot = AntiBotIntelligenceEngine()
        self._anti_bot_governor = AntiBotHostGovernor()
        self._human_verification = HumanVerificationCoordinator()

    def trim_caches(self, level: str = "critical") -> dict[str, int | str]:
        """Bound or clear advisory crawl caches under memory pressure."""
        normalized = str(level or "critical").strip().casefold()
        with self._robots_lock:
            before = len(self._robots_cache)
            if normalized == "critical":
                self._robots_cache.clear()
            elif normalized in {"warning", "soft"}:
                target = max(16, self._robots_cache_limit // 4)
                while len(self._robots_cache) > target:
                    self._robots_cache.popitem(last=False)
            after = len(self._robots_cache)
        return {"level": normalized, "before": before, "after": after}

    def pending_human_verifications(self) -> list[dict[str, object]]:
        return [ticket.snapshot() for ticket in self._human_verification.pending()]

    def anti_bot_state(self) -> dict[str, dict[str, object]]:
        return self._anti_bot_governor.snapshot()

    def run(
        self,
        config: CrawlerConfig,
        *,
        token: CancellationToken | None = None,
        progress: ProgressCallback | None = None,
    ) -> CrawlerRunResult:
        item = config.normalized()
        token = token or CancellationToken()
        started = time.monotonic()
        run_transport = CrawlerTransport(
            self.fetcher,
            policy=SessionPolicy(
                default_headers=dict(item.request_headers),
                proxies=list(item.proxies),
                http3_mode=item.http3_mode,
                cache=CachePolicy(root=item.cache_root, mode=item.cache_mode, ttl_seconds=item.cache_ttl_seconds),
            ),
        )
        seed_hosts = {normalize_domain(urlsplit(url).hostname or "") for url in item.seeds}
        seed_hosts.discard("")
        frontier = PriorityFrontier()
        dedup = UrlDeduplicator(max_entries=min(2_000_000, max(10000, item.max_pages * 100)))
        for url in item.seeds:
            frontier.push(url, 0, "", priority=0)
            dedup.add(url)
        completed: set[str] = set()
        pages: list[CrawlPage] = []
        records: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        warnings: list[str] = []
        pending: dict[Future[_FetchedPage], _FrontierItem] = {}
        rate_controller = HostRateController(per_host_concurrency=item.per_host_concurrency)
        submitted = 0
        succeeded = 0
        failed = 0
        discovered = len(item.seeds)
        discovery_cap = min(1_000_000, max(len(item.seeds), item.max_pages * 50))
        skipped = 0
        duplicates = 0
        robots_denied = 0

        def emit(stage: str, **payload: Any) -> None:
            if progress is None:
                return
            try:
                progress({
                    "stage": stage,
                    "submitted": submitted,
                    "completed": len(completed),
                    "records": len(records),
                    "frontier": len(frontier),
                    **payload,
                })
            except Exception:
                # Progress callbacks are external/advisory and cannot own crawler reliability.
                LOGGER.debug("Crawler progress callback failed", exc_info=True)
                return

        browser_context = (
            BrowserPool(BrowserEngineConfig(
                workers=item.browser_workers,
                blocked_domains=list(item.blocked_domains),
                remote_cdp_url=item.browser_remote_cdp_url,
            ))
            if item.browser_fallback_on_js else nullcontext(None)
        )
        with browser_context as browser_pool, ThreadPoolExecutor(max_workers=item.concurrency, thread_name_prefix="arenyxa-crawler") as executor:
            while (frontier or pending) and len(completed) < item.max_pages:
                if not _checkpoint(token):
                    break
                scheduled_this_round = False
                scan_budget = len(frontier)
                while (
                    frontier
                    and len(pending) < item.concurrency
                    and submitted < item.max_pages
                    and scan_budget > 0
                ):
                    if not _checkpoint(token):
                        break
                    core_entry = frontier.pop()
                    entry = _FrontierItem(core_entry.url, core_entry.depth, core_entry.parent_url)
                    scan_budget -= 1
                    if entry.url in completed:
                        duplicates += 1
                        continue
                    if entry.depth > 0 and not self._in_scope(entry.url, item, seed_hosts):
                        skipped += 1
                        continue
                    host = normalize_domain(urlsplit(entry.url).hostname or "")
                    if not host:
                        skipped += 1
                        continue
                    policy = self._robots_policy(entry.url, item, token, warnings, run_transport)
                    if item.respect_robots_txt and not policy.allowed(item.user_agent, entry.url):
                        robots_denied += 1
                        completed.add(entry.url)
                        emit("robots_denied", url=entry.url)
                        continue
                    delay = max(item.per_host_delay_seconds, policy.delay_seconds if item.respect_robots_txt else 0.0)
                    if not rate_controller.acquire(entry.url, delay):
                        frontier.push(entry.url, entry.depth, entry.parent_url)
                        continue
                    future = executor.submit(self._fetch_page, entry, item, token, run_transport, browser_pool)
                    pending[future] = entry
                    submitted += 1
                    scheduled_this_round = True
                    emit("scheduled", url=entry.url, depth=entry.depth)

                if not pending:
                    if not frontier or submitted >= item.max_pages:
                        break
                    if not scheduled_this_round:
                        self._sleep_until_ready(frontier, rate_controller, token)
                    continue

                done, _not_done = wait(tuple(pending), timeout=0.1, return_when=FIRST_COMPLETED)
                if not done:
                    continue
                for future in done:
                    entry = pending.pop(future)
                    rate_controller.release(entry.url)
                    completed.add(entry.url)
                    try:
                        fetched = future.result()
                    except Exception as exc:
                        # Worker futures may surface transport/plugin exceptions outside Arenyxa's taxonomy.
                        LOGGER.warning("Crawler page worker failed for %s: %s", entry.url, exc, exc_info=True)
                        failed += 1
                        errors.append({"url": entry.url, "error": f"{type(exc).__name__}: {exc}"})
                        emit("error", url=entry.url, error=str(exc))
                        continue
                    page = fetched.page
                    pages.append(page)
                    if 200 <= page.status < 400:
                        succeeded += 1
                    else:
                        failed += 1
                    if page.extracted and len(records) < item.max_records:
                        records.append({
                            "url": page.final_url,
                            "depth": page.depth,
                            **page.extracted,
                            "_quality_flags": list(page.quality_flags),
                        })
                    if page.depth < item.max_depth and 200 <= page.status < 400:
                        for link in fetched.links:
                            if len(dedup) >= discovery_cap:
                                warnings.append("Crawler frontier discovery bound reached; additional links were ignored")
                                break
                            if link in completed or not dedup.add(link):
                                duplicates += 1
                                continue
                            if not self._in_scope(link, item, seed_hosts):
                                skipped += 1
                                continue
                            frontier.push(link, page.depth + 1, page.final_url, priority=-(page.depth + 1))
                            discovered += 1
                    emit("page", url=page.final_url, status=page.status, depth=page.depth)

            if token.cancelled:
                for future in pending:
                    future.cancel()

        cancelled = token.cancelled
        emit("finished", cancelled=cancelled)
        return CrawlerRunResult(
            pages=pages,
            records=records,
            pages_submitted=submitted,
            pages_succeeded=succeeded,
            pages_failed=failed,
            urls_discovered=discovered,
            urls_skipped=skipped,
            duplicates_removed=duplicates,
            robots_denied=robots_denied,
            duration_seconds=round(max(0.0, time.monotonic() - started), 6),
            cancelled=cancelled,
            errors=errors[:10000],
            warnings=_dedupe_strings(warnings)[:1000],
        )

    def fetch_one(
        self,
        config: CrawlerConfig,
        url: str,
        *,
        depth: int = 0,
        parent_url: str = "",
        token: CancellationToken | None = None,
    ) -> CrawlerFetchUnit:
        """Fetch exactly one URL through the crawler's governed stack.

        The method is intentionally narrow: discovery is returned to the caller
        rather than recursively scheduled.  Distributed crawling uses this to
        keep the global frontier/deduplication state in the durable coordinator.
        """
        item = config.normalized()
        target = canonicalize_url(str(url).strip())
        if not target:
            raise ValueError("Crawler single-page fetch requires a valid http/https URL")
        if int(depth) < 0 or int(depth) > item.max_depth:
            raise ValueError("Crawler single-page depth is outside the configured bound")
        seed_hosts = {normalize_domain(urlsplit(seed).hostname or "") for seed in item.seeds}
        seed_hosts.discard("")
        if int(depth) > 0 and not self._in_scope(target, item, seed_hosts):
            raise ValueError("Crawler single-page target is outside configured crawl scope")
        warnings: list[str] = []
        token = token or CancellationToken()
        transport = CrawlerTransport(
            self.fetcher,
            policy=SessionPolicy(
                default_headers=dict(item.request_headers),
                proxies=list(item.proxies),
                http3_mode=item.http3_mode,
                cache=CachePolicy(root=item.cache_root, mode=item.cache_mode, ttl_seconds=item.cache_ttl_seconds),
            ),
        )
        policy = self._robots_policy(target, item, token, warnings, transport)
        if item.respect_robots_txt and not policy.allowed(item.user_agent, target):
            page = CrawlPage(
                requested_url=target, final_url=target, depth=int(depth), parent_url=str(parent_url),
                status=0, content_type="", bytes_received=0, elapsed_ms=0.0,
                quality_flags=["robots:denied"],
            )
            return CrawlerFetchUnit(page=page, links=[], robots_denied=True, warnings=warnings)
        if item.browser_fallback_on_js:
            with BrowserPool(BrowserEngineConfig(
                workers=item.browser_workers,
                blocked_domains=list(item.blocked_domains),
                remote_cdp_url=item.browser_remote_cdp_url,
            )) as browser_pool:
                fetched = self._fetch_page(_FrontierItem(target, int(depth), str(parent_url)), item, token, transport, browser_pool)
        else:
            fetched = self._fetch_page(_FrontierItem(target, int(depth), str(parent_url)), item, token, transport, None)
        links: list[str] = []
        seen: set[str] = set()
        if int(depth) < item.max_depth and 200 <= fetched.page.status < 400:
            for link in fetched.links:
                if link in seen or not self._in_scope(link, item, seed_hosts):
                    continue
                seen.add(link)
                links.append(link)
                if len(links) >= item.max_links_per_page:
                    break
        return CrawlerFetchUnit(page=fetched.page, links=links, warnings=warnings)

    def _fetch_page(
        self,
        entry: _FrontierItem,
        config: CrawlerConfig,
        token: CancellationToken,
        transport: CrawlerTransport,
        browser_pool: BrowserPool | None = None,
    ) -> _FetchedPage:
        parsed = urlsplit(entry.url)
        if not parsed.hostname:
            raise ValueError("Crawler target has no hostname")
        self.guard.check_target(parsed.hostname, resolve_dns=True)
        anti_bot_delay = self._anti_bot_governor.wait_seconds(parsed.hostname)
        while anti_bot_delay > 0:
            token.checkpoint()
            time.sleep(min(0.25, anti_bot_delay))
            anti_bot_delay = self._anti_bot_governor.wait_seconds(parsed.hostname)
        retry = RetryPolicy(attempts=config.retry_attempts)
        spec = RequestSpec(
            url=entry.url,
            method="GET",
            connect_timeout=config.connect_timeout,
            read_timeout=config.read_timeout,
            user_agent=config.user_agent,
            headers=dict(config.request_headers),
            retry=retry,
        )
        response: FetchResponse = transport.fetch(spec, token=token)
        anti_bot = self._anti_bot.assess(response)
        browser_used = False
        browser_fallback_error = ""
        if anti_bot.kind is BlockKind.JS_REQUIRED and browser_pool is not None:
            try:
                browser_result = browser_pool.fetch(BrowserRequest(
                    url=entry.url,
                    headers=dict(config.request_headers),
                    user_agent=config.user_agent,
                    wait_until="domcontentloaded",
                ))
                response = browser_result_to_fetch_response(browser_result)
                anti_bot = self._anti_bot.assess(response)
                browser_used = True
            except (ArenyxaError, OSError, RuntimeError, TimeoutError, TypeError, ValueError) as exc:
                browser_fallback_error = type(exc).__name__
        self._anti_bot_governor.observe(parsed.hostname, anti_bot)
        for target in [*response.redirect_chain, response.final_url]:
            host = urlsplit(str(target)).hostname
            if host:
                self.guard.check_target(host, resolve_dns=True)
        links: list[str] = []
        title = ""
        extracted: dict[str, Any] = {}
        quality: list[str] = []
        if browser_used:
            quality.append("browser_fallback:used")
        if browser_fallback_error:
            quality.append(f"browser_fallback:error:{browser_fallback_error}")
        if anti_bot.blocked:
            quality.append(f"anti_bot:{anti_bot.kind.value.casefold()}")
            quality.append(f"anti_bot_confidence:{anti_bot.confidence:.2f}")
            if anti_bot.kind in {BlockKind.CAPTCHA_PRESENT, BlockKind.BOT_CHALLENGE_PRESENT}:
                ticket = self._human_verification.issue(response.final_url or entry.url, anti_bot)
                quality.append(f"human_verification:{ticket.ticket_id}")
        if response.body and 200 <= response.status < 400:
            if _is_html(response):
                text = response.body.decode(response.encoding or "utf-8", errors="replace")
                try:
                    document = html.fromstring(text, base_url=response.final_url)
                    titles = document.xpath("//title[1]/text()")
                    if titles:
                        title = " ".join(str(titles[0]).split())[:512]
                    links = self._extract_links(document, response.final_url, config.max_links_per_page)
                except (ValueError, TypeError):
                    links = []
            if config.fields:
                try:
                    document = ParserRegistry.parse(response, "auto")
                    extracted, extraction_quality = self._extractor.extract(document, config.fields)
                    quality.extend(extraction_quality)
                except ArenyxaError as exc:
                    quality.append(f"page:extract_error:{type(exc).__name__}")
        page = CrawlPage(
            requested_url=entry.url,
            final_url=canonicalize_url(response.final_url) or entry.url,
            depth=entry.depth,
            parent_url=entry.parent_url,
            status=int(response.status),
            content_type=str(response.content_type or ""),
            bytes_received=len(response.body),
            elapsed_ms=round(float(response.elapsed_ms), 3),
            title=title,
            links_discovered=len(links),
            extracted=extracted,
            quality_flags=quality,
        )
        return _FetchedPage(page=page, links=links)

    @staticmethod
    def _extract_links(document: Any, base_url: str, limit: int) -> list[str]:
        output: list[str] = []
        seen: set[str] = set()
        try:
            hrefs = document.xpath("//a[@href]/@href")
        except (AttributeError, TypeError, ValueError, etree.XPathError):
            return output
        for raw in hrefs:
            value = str(raw).strip()
            if not value or value.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                continue
            url = canonicalize_url(urljoin(base_url, value))
            if not url or url in seen:
                continue
            seen.add(url)
            output.append(url)
            if len(output) >= limit:
                break
        return output

    def _robots_policy(
        self,
        url: str,
        config: CrawlerConfig,
        token: CancellationToken,
        warnings: list[str],
        transport: CrawlerTransport,
    ) -> _RobotsPolicy:
        if not config.respect_robots_txt:
            return _RobotsPolicy(None, 0.0)
        parsed = urlsplit(url)
        origin = _origin(parsed)
        if not origin:
            return _RobotsPolicy(None, 0.0, deny_all=True)
        with self._robots_lock:
            cached = self._robots_cache.get(origin)
            if cached is not None:
                self._robots_cache.move_to_end(origin)
                return cached
            robots_url = f"{origin}/robots.txt"
            host = parsed.hostname or ""
            try:
                self.guard.check_target(host, resolve_dns=True)
                response = transport.fetch(
                    RequestSpec(
                        robots_url,
                        method="GET",
                        user_agent=config.user_agent,
                        headers=dict(config.request_headers),
                        connect_timeout=config.connect_timeout,
                        read_timeout=min(config.read_timeout, 20.0),
                        retry=RetryPolicy(attempts=min(config.retry_attempts, 1)),
                    ),
                    token=token,
                )
                if response.status in {401, 403}:
                    policy = _RobotsPolicy(None, 0.0, deny_all=True)
                elif 500 <= response.status <= 599:
                    warnings.append(f"robots.txt unavailable with HTTP {response.status}; host was conservatively blocked: {origin}")
                    policy = _RobotsPolicy(None, 0.0, deny_all=True)
                elif 400 <= response.status <= 499:
                    policy = _RobotsPolicy(None, 0.0)
                else:
                    parser = urllib.robotparser.RobotFileParser()
                    parser.set_url(robots_url)
                    parser.parse(response.body.decode(response.encoding or "utf-8", errors="replace").splitlines())
                    delay = parser.crawl_delay(config.user_agent)
                    if delay is None:
                        delay = parser.crawl_delay("*")
                    try:
                        delay_value = max(0.0, min(float(delay or 0.0), 60.0))
                    except (TypeError, ValueError, OverflowError):
                        delay_value = 0.0
                    policy = _RobotsPolicy(parser, delay_value)
            except Exception as exc:
                # Custom transports can raise provider-specific exceptions; robots failures fail closed.
                LOGGER.warning("Crawler robots policy check failed for %s: %s", origin, exc, exc_info=True)
                warnings.append(f"robots.txt check failed; host was conservatively blocked: {origin} ({type(exc).__name__})")
                policy = _RobotsPolicy(None, 0.0, deny_all=True)
            self._robots_cache[origin] = policy
            self._robots_cache.move_to_end(origin)
            while len(self._robots_cache) > self._robots_cache_limit:
                self._robots_cache.popitem(last=False)
            return policy

    @staticmethod
    def _in_scope(url: str, config: CrawlerConfig, seed_hosts: set[str]) -> bool:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        host = normalize_domain(parsed.hostname)
        if not host:
            return False
        if _blocked_domain(host, config.blocked_domains):
            return False
        if config.allowed_domains:
            if not any(_domain_matches(host, allowed, config.include_subdomains) for allowed in config.allowed_domains):
                return False
        elif config.same_site_only:
            if not any(_domain_matches(host, seed, config.include_subdomains) for seed in seed_hosts):
                return False
        if config.include_url_globs and not any(fnmatch.fnmatchcase(url, pattern) for pattern in config.include_url_globs):
            return False
        if any(fnmatch.fnmatchcase(url, pattern) for pattern in config.exclude_url_globs):
            return False
        return True

    @staticmethod
    def _sleep_until_ready(
        frontier: PriorityFrontier,
        rate_controller: HostRateController,
        token: CancellationToken,
    ) -> None:
        urls = [str(row.get("url", "")) for row in frontier.snapshot()[:128]]
        delay = rate_controller.wait_seconds(urls)
        stop = time.monotonic() + min(max(delay, 0.01), 0.25)
        while time.monotonic() < stop:
            if not _checkpoint(token):
                return
            time.sleep(min(0.025, max(0.0, stop - time.monotonic())))


class CrawlerResultExporter:
    """Atomic export of crawler page/record results without requiring a persisted Run."""

    def export(self, result: CrawlerRunResult, destination: Path, format_name: str) -> int:
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        normalized = str(format_name).strip().casefold().lstrip(".")
        if normalized not in {"json", "jsonl", "ndjson", "csv", "xlsx", "excel", "xml"}:
            raise ValueError(f"Unsupported crawler export format: {format_name}")
        fd, raw_temp = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
        os.close(fd)
        temp_path = Path(raw_temp)
        try:
            count = self._write(result, temp_path, normalized)
            fsync_existing_file(temp_path)
            os.replace(temp_path, destination)
            return count
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                record_current_exception(__name__, 'CrawlerResultExporter.export:584')

    def _write(self, result: CrawlerRunResult, path: Path, format_name: str) -> int:
        rows = list(self._rows(result))
        if format_name == "json":
            path.write_text(json.dumps(result.snapshot(), ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
            return len(rows)
        if format_name in {"jsonl", "ndjson"}:
            with path.open("w", encoding="utf-8", newline="\n") as stream:
                for row in rows:
                    stream.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
            return len(rows)
        fields = self._field_names(rows)
        if format_name == "csv":
            with path.open("w", encoding="utf-8-sig", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                for row in rows:
                    writer.writerow({key: _scalar(row.get(key)) for key in fields})
            return len(rows)
        if format_name == "xml":
            root = etree.Element("crawlerResults")
            root.set("schema", "arenyxa.crawler-results/v1")
            for row in rows:
                record = etree.SubElement(root, "record")
                for key in fields:
                    element = etree.SubElement(record, "field")
                    element.set("name", str(key))
                    value = _scalar(row.get(key))
                    element.text = "" if value is None else str(value)
            path.write_bytes(etree.tostring(root, encoding="utf-8", xml_declaration=True, pretty_print=True))
            return len(rows)
        workbook = Workbook(write_only=True)
        sheet = workbook.create_sheet("Crawler Results")
        sheet.append(fields)
        for row in rows:
            sheet.append([_scalar(row.get(key)) for key in fields])
        workbook.save(path)
        return len(rows)

    @staticmethod
    def _rows(result: CrawlerRunResult) -> Iterable[dict[str, Any]]:
        if result.records:
            yield from result.records
            return
        for page in result.pages:
            yield page.snapshot()

    @staticmethod
    def _field_names(rows: list[dict[str, Any]]) -> list[str]:
        fields: list[str] = []
        seen: set[str] = set()
        for row in rows:
            for key in row:
                if key not in seen:
                    seen.add(key)
                    fields.append(key)
        return fields or ["url"]


def _normalize_http3_mode(value: str) -> str:
    mode = str(value or "off").strip().casefold()
    if mode not in {"off", "prefer", "require"}:
        raise ValueError(f"Unsupported crawler HTTP/3 mode: {value}")
    return mode


def _normalize_cache_mode(value: str) -> str:
    mode = str(value or "off").strip().casefold()
    if mode not in {"off", "read", "write", "read-write"}:
        raise ValueError(f"Unsupported crawler cache mode: {value}")
    return mode


def _blocked_domain(host: str, patterns: list[str]) -> bool:
    normalized = normalize_domain(host)
    for pattern in patterns:
        value = str(pattern or "").casefold().strip().rstrip(".")
        if not value:
            continue
        if "*" in value or "?" in value or "[" in value:
            if fnmatch.fnmatchcase(normalized, value):
                return True
        elif normalized == value or normalized.endswith("." + value):
            return True
    return False


def canonicalize_url(raw: str) -> str:
    try:
        parsed = urlsplit(str(raw).strip())
        if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
            return ""
        scheme = parsed.scheme.casefold()
        host = parsed.hostname.encode("idna").decode("ascii").casefold().rstrip(".")
        try:
            port = parsed.port
        except ValueError:
            return ""
        if port is None or (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            netloc = host
        else:
            netloc = f"{host}:{port}"
        path = parsed.path or "/"
        return urlunsplit((scheme, netloc, path, parsed.query, ""))
    except (TypeError, ValueError, UnicodeError):
        return ""


def normalize_domain(raw: str) -> str:
    value = str(raw or "").strip().casefold().rstrip(".")
    if "://" in value:
        value = urlsplit(value).hostname or ""
    value = value.lstrip(".")
    try:
        return value.encode("idna").decode("ascii").casefold().rstrip(".")
    except UnicodeError:
        return ""


def _domain_matches(host: str, allowed: str, include_subdomains: bool) -> bool:
    if host == allowed:
        return True
    return bool(include_subdomains and host.endswith("." + allowed))


def _origin(parsed: Any) -> str:
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    host = normalize_domain(parsed.hostname)
    try:
        port = parsed.port
    except ValueError:
        return ""
    if port is None or (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443):
        return f"{parsed.scheme}://{host}"
    return f"{parsed.scheme}://{host}:{port}"


def _is_html(response: FetchResponse) -> bool:
    content_type = str(response.content_type or "").casefold()
    if "html" in content_type or "xhtml" in content_type:
        return True
    return response.body.lstrip()[:32].lower().startswith((b"<!doctype html", b"<html"))


def _scalar(value: Any) -> Any:
    if isinstance(value, (dict, list, tuple, set)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return value



def _checkpoint(token: CancellationToken) -> bool:
    if token.cancelled:
        return False
    try:
        token.checkpoint()
        return True
    except ArenyxaError as exc:
        if exc.code == "RUN_CANCELLED":
            return False
        raise


def _dedupe_strings(values: Iterable[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = str(value)
        if item not in seen:
            seen.add(item)
            output.append(item)
    return output


__all__ = [
    "CrawlerConfig",
    "CrawlerEngine",
    "CrawlerResultExporter",
    "CrawlerRunResult",
    "CrawlPage",
    "canonicalize_url",
    "normalize_domain",
]
