from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from arenyxa.application.anti_bot_intelligence import (
    AntiBotIntelligenceEngine,
    BlockKind,
    HumanVerificationCoordinator,
)
from arenyxa.application.async_crawler import AsyncCrawlerEngine
from arenyxa.application.browser_engine import BrowserEngineConfig, _domain_blocked
from arenyxa.application.crawler import CrawlerConfig, CrawlerResultExporter, CrawlerRunResult
from arenyxa.application.crawler_spiders import CSVFeedSpider, ShopifySpider, SitemapSpider, XMLFeedSpider
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import FetchResponse, RequestSpec
from arenyxa.infrastructure.crawler_cache import CachePolicy, CrawlerResponseCache
from arenyxa.infrastructure.crawler_transport import CrawlerTransport, SessionPolicy
from arenyxa.infrastructure.doh_resolver import DoHResolver
from arenyxa.infrastructure.http3_client import Http3Fetcher
from arenyxa.security.network_guard import NetworkGuardPolicy


def response(url: str, body: bytes, *, content_type: str = "text/html", status: int = 200, headers=None):
    return FetchResponse(
        url=url,
        final_url=url,
        status=status,
        headers=dict(headers or {}),
        body=body,
        elapsed_ms=1.5,
        encoding="utf-8",
        content_type=content_type,
    )


class FakeFetcher:
    def __init__(self, mapping=None):
        self.mapping = dict(mapping or {})
        self.calls = 0

    def fetch(self, spec, token=None, on_attempt=None):
        self.calls += 1
        value = self.mapping.get(spec.url)
        if value is not None:
            return value
        return response(spec.url, b"<html><title>ok</title></html>")

    def close(self):
        return None


def test_cache_roundtrip_is_bounded_and_redacts_sensitive_headers(tmp_path: Path) -> None:
    cache = CrawlerResponseCache(CachePolicy(root=str(tmp_path), mode="read-write", ttl_seconds=60))
    spec = RequestSpec("https://example.com/a", headers={"Authorization": "secret"})
    original = response(spec.url, b"payload", headers={"Set-Cookie": "sid=secret", "ETag": "abc"})
    assert cache.put(spec, original) is True
    restored = cache.get(spec)
    assert restored is not None
    assert restored.body == b"payload"
    assert restored.headers["Set-Cookie"] == "<redacted>"
    assert restored.headers["ETag"] == "abc"
    assert "secret" not in "".join(p.read_text(errors="ignore") for p in tmp_path.glob("*.json"))


def test_transport_uses_cache_before_network(tmp_path: Path) -> None:
    fake = FakeFetcher()
    transport = CrawlerTransport(fake, policy=SessionPolicy(cache=CachePolicy(root=str(tmp_path), mode="read-write")))
    spec = RequestSpec("https://example.com/cache")
    first = transport.fetch(spec)
    second = transport.fetch(spec)
    assert first.body == second.body
    assert fake.calls == 1


def test_http3_require_fails_closed_when_runtime_is_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(Http3Fetcher, "dependency_available", staticmethod(lambda: False))
    fetcher = Http3Fetcher(network_policy=NetworkGuardPolicy(enabled=False))
    with pytest.raises(ArenyxaError, match="HTTP/3"):
        fetcher.fetch(RequestSpec("https://example.com"))


def test_browser_remote_cdp_and_domain_block_configuration() -> None:
    cfg = BrowserEngineConfig(
        remote_cdp_url="ws://127.0.0.1:9222/devtools/browser/abc",
        blocked_domains=["ads.example", "*.tracker.example"],
    ).normalized()
    assert cfg.remote_cdp_url.startswith("ws://")
    assert _domain_blocked("cdn.ads.example", cfg.blocked_domains)
    assert _domain_blocked("a.tracker.example", cfg.blocked_domains)
    assert not _domain_blocked("example.com", cfg.blocked_domains)
    with pytest.raises(ValueError):
        BrowserEngineConfig(remote_cdp_url="file:///tmp/socket").normalized()


def test_shopify_template_preserves_robots_and_scope_defaults() -> None:
    spider = ShopifySpider.storefront("https://shop.example/")
    cfg = spider.build_config()
    assert cfg.respect_robots_txt is True
    assert cfg.same_site_only is True
    assert "*/products/*" in cfg.include_url_globs


def test_sitemap_and_feed_templates_parse_real_payloads_without_network() -> None:
    sitemap_url = "https://example.com/sitemap.xml"
    xml_feed_url = "https://example.com/feed.xml"
    csv_feed_url = "https://example.com/feed.csv"
    fake = FakeFetcher({
        sitemap_url: response(sitemap_url, b"<?xml version='1.0'?><urlset><url><loc>https://example.com/a</loc></url><url><loc>https://example.com/b</loc></url></urlset>", content_type="application/xml"),
        xml_feed_url: response(xml_feed_url, b"<rss><channel><item><title>A</title><link>https://example.com/a</link></item></channel></rss>", content_type="application/xml"),
        csv_feed_url: response(csv_feed_url, b"name,url\nA,https://example.com/a\n", content_type="text/csv"),
    })
    from arenyxa.application.crawler import CrawlerEngine
    engine = CrawlerEngine(fetcher=fake, network_policy=NetworkGuardPolicy(enabled=False))
    assert SitemapSpider(sitemap_url).discover(engine) == ["https://example.com/a", "https://example.com/b"]
    xml_result = XMLFeedSpider(xml_feed_url).run(engine)
    assert xml_result.records[0]["title"] == "A"
    csv_result = CSVFeedSpider(csv_feed_url).run(engine)
    assert csv_result.records[0]["name"] == "A"


def test_xml_exporter(tmp_path: Path) -> None:
    result = CrawlerRunResult(
        pages=[], records=[{"url": "https://example.com", "name": "A&B"}],
        pages_submitted=1, pages_succeeded=1, pages_failed=0, urls_discovered=1,
        urls_skipped=0, duplicates_removed=0, robots_denied=0, duration_seconds=0.1,
    )
    target = tmp_path / "result.xml"
    assert CrawlerResultExporter().export(result, target, "xml") == 1
    text = target.read_text(encoding="utf-8")
    assert "crawlerResults" in text
    assert "A&amp;B" in text


def test_doh_direct_ip_requires_no_network() -> None:
    resolver = DoHResolver(network_policy=NetworkGuardPolicy(enabled=False))
    assert resolver.resolve("1.1.1.1") == ("1.1.1.1",)


def test_human_verification_is_manual_and_fail_closed() -> None:
    assessment = AntiBotIntelligenceEngine().assess(
        response("https://example.com", b"<html>Cloud challenge captcha</html>", status=403)
    )
    assert assessment.kind is BlockKind.CAPTCHA_PRESENT
    coordinator = HumanVerificationCoordinator(ttl_seconds=60)
    ticket = coordinator.issue("https://example.com/?token=secret", assessment)
    assert "secret" not in repr(ticket.snapshot())
    assert ticket.state == "pending"
    approved = coordinator.resolve(ticket.ticket_id, operator_id="operator-1", approved=True)
    assert approved.state == "approved"
    with pytest.raises(RuntimeError):
        coordinator.resolve(ticket.ticket_id, operator_id="operator-1", approved=True)


def test_crawler_blocked_domain_scope() -> None:
    from arenyxa.application.crawler import CrawlerEngine
    cfg = CrawlerConfig(seeds=["https://example.com"], blocked_domains=["ads.example"]).normalized()
    assert CrawlerEngine._in_scope("https://cdn.ads.example/x", cfg, {"example.com"}) is False


def test_async_crawler_facade_calls_underlying_engine() -> None:
    class Engine:
        def run(self, config, *, token=None, progress=None):
            return "ok"

        def fetch_one(self, config, url, *, depth=0, parent_url="", token=None):
            return (config.seeds[0], url, depth)

    async def exercise():
        wrapper = AsyncCrawlerEngine(Engine())
        cfg = CrawlerConfig(seeds=["https://example.com"])
        assert await wrapper.run(cfg) == "ok"
        assert await wrapper.fetch_one("https://example.com/x", config=cfg, depth=1) == (
            "https://example.com", "https://example.com/x", 1
        )

    asyncio.run(exercise())


def test_crawler_safe_browser_fallback_for_js_required() -> None:
    from arenyxa.application.browser_engine import BrowserFetchResult
    from arenyxa.application.crawler import CrawlerEngine, _FrontierItem
    from arenyxa.infrastructure.crawler_transport import CrawlerTransport
    from arenyxa.infrastructure.http_client import CancellationToken

    target = "https://example.com/js"
    fake = FakeFetcher({
        target: response(target, b"<html>JavaScript is required</html>", status=403),
    })
    engine = CrawlerEngine(fetcher=fake, network_policy=NetworkGuardPolicy(enabled=False))

    class Browser:
        def fetch(self, request):
            return BrowserFetchResult(
                requested_url=request.url,
                final_url=request.url,
                status=200,
                title="Rendered",
                html="<html><title>Rendered</title><a href='/next'>Next</a></html>",
                elapsed_ms=3.0,
            )

    cfg = CrawlerConfig(
        seeds=[target],
        max_pages=1,
        max_depth=1,
        browser_fallback_on_js=True,
        respect_robots_txt=False,
    ).normalized()
    fetched = engine._fetch_page(
        _FrontierItem(target, 0, ""), cfg, CancellationToken(), CrawlerTransport(fake), Browser()
    )
    assert fetched.page.status == 200
    assert fetched.page.title == "Rendered"
    assert "browser_fallback:used" in fetched.page.quality_flags
    assert "https://example.com/next" in fetched.links


def test_crawler_captcha_creates_manual_ticket_without_bypass() -> None:
    from arenyxa.application.crawler import CrawlerEngine, _FrontierItem
    from arenyxa.infrastructure.crawler_transport import CrawlerTransport
    from arenyxa.infrastructure.http_client import CancellationToken

    target = "https://example.com/challenge"
    fake = FakeFetcher({target: response(target, b"<html>reCAPTCHA challenge</html>", status=403)})
    engine = CrawlerEngine(fetcher=fake, network_policy=NetworkGuardPolicy(enabled=False))
    cfg = CrawlerConfig(seeds=[target], respect_robots_txt=False).normalized()
    fetched = engine._fetch_page(_FrontierItem(target, 0, ""), cfg, CancellationToken(), CrawlerTransport(fake), None)
    assert any(flag.startswith("anti_bot:captcha_present") for flag in fetched.page.quality_flags)
    assert any(flag.startswith("human_verification:human_") for flag in fetched.page.quality_flags)
    pending = engine.pending_human_verifications()
    assert len(pending) == 1
    assert pending[0]["state"] == "pending"


def test_adaptive_selector_benchmark_meets_release_gate() -> None:
    from arenyxa.application.adaptive_selector_benchmark import AdaptiveSelectorBenchmark
    result = AdaptiveSelectorBenchmark().run()
    assert result.recovery_rate >= 0.95
    assert result.false_match_rate <= 0.01
    assert result.passed_default_gate is True


def test_sitemap_spider_follows_same_origin_sitemap_indexes() -> None:
    from arenyxa.application.crawler import CrawlerEngine
    root = "https://example.com/sitemap.xml"
    child = "https://example.com/products-sitemap.xml"
    fake = FakeFetcher({
        root: response(root, b"<sitemapindex><sitemap><loc>https://example.com/products-sitemap.xml</loc></sitemap><sitemap><loc>https://other.example/sitemap.xml</loc></sitemap></sitemapindex>", content_type="application/xml"),
        child: response(child, b"<urlset><url><loc>https://example.com/products/a</loc></url></urlset>", content_type="application/xml"),
    })
    engine = CrawlerEngine(fetcher=fake, network_policy=NetworkGuardPolicy(enabled=False))
    assert SitemapSpider(root).discover(engine) == ["https://example.com/products/a"]
    assert fake.calls == 2


def test_client_profile_rejects_conflicting_reserved_headers() -> None:
    from arenyxa.application.anti_bot_intelligence import ClientProfile
    profile = ClientProfile(user_agent="Arenyxa-Test/1", accept_language="en-US,en;q=0.8")
    assert profile.browser_settings() == {"user_agent": "Arenyxa-Test/1", "locale": "en-US"}
    with pytest.raises(ValueError):
        ClientProfile(extra_headers={"User-Agent": "conflict"}).headers()


def test_anti_bot_governor_applies_backoff_without_identity_evasion() -> None:
    from arenyxa.application.anti_bot_intelligence import AntiBotHostGovernor, BlockAssessment, SafeAction
    governor = AntiBotHostGovernor(max_backoff_seconds=10)
    assessment = BlockAssessment(
        kind=BlockKind.RATE_LIMITED,
        confidence=0.99,
        actions=[SafeAction.THROTTLE, SafeAction.BACKOFF],
        retry_after_seconds=2.0,
        status=429,
    )
    governor.observe("example.com", assessment)
    assert 0.0 < governor.wait_seconds("example.com") <= 2.0
    snap = governor.snapshot()["example.com"]
    assert snap["last_kind"] == "RATE_LIMITED"
    assert snap["failures"] == 1


def test_bot_challenge_is_operator_gated_not_browser_bypassed() -> None:
    engine = AntiBotIntelligenceEngine()
    assessment = engine.assess(
        response("https://example.com", b"<html>Checking your browser - verify you are human</html>", status=403)
    )
    assert assessment.kind is BlockKind.BOT_CHALLENGE_PRESENT
    assert "operator-intervention" in {action.value for action in assessment.actions}
    assert "browser-render" not in {action.value for action in assessment.actions}
    coordinator = HumanVerificationCoordinator(ttl_seconds=60)
    ticket = coordinator.issue("https://example.com", assessment)
    assert ticket.state == "pending"
