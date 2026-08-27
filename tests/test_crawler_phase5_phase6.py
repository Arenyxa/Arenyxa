from __future__ import annotations

import base64
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arenyxa.application.browser_engine import BrowserFetchResult, BrowserNetworkObservation
from arenyxa.application.competitive import ContextBridgeService, WebIntelligenceEngine
from arenyxa.application.crawler import CrawlerConfig, CrawlerEngine
from arenyxa.application.crawler_web_intelligence import CrawlerWebIntelligencePipeline, browser_observations_to_events
from arenyxa.application.distributed_crawler import (
    DISTRIBUTED_CRAWL_JOB_KIND,
    DistributedCrawlPolicy,
    DistributedCrawlerCoordinator,
    DistributedCrawlerWorker,
)
from arenyxa.application.nextgen import DataSourceDiscovery, ProtocolInspector, RequestCodeGenerator, SelectorStudio, BrowserRecorderService, SmartPathV2
from arenyxa.application.web_intelligence import WebIntelligenceCenter, WebTimeMachine
from arenyxa.domain.models import FetchResponse
from arenyxa.enterprise.distributed_queue import DurableDistributedQueue
from arenyxa.enterprise.distributed_runtime import EnterpriseWorkerRuntime
from arenyxa.security.network_guard import NetworkGuardPolicy


class FakeFetcher:
    def __init__(self, pages):
        self.pages = pages

    def fetch(self, spec, token=None, on_attempt=None):
        status, ctype, body = self.pages.get(spec.url, (404, "text/html", b"missing"))
        return FetchResponse(
            url=spec.url,
            final_url=spec.url,
            status=status,
            headers={"Content-Type": ctype},
            body=body,
            elapsed_ms=1.0,
            encoding="utf-8",
            content_type=ctype,
        )


def _worker_public_key() -> str:
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _center(tmp_path: Path) -> WebIntelligenceCenter:
    smart = SmartPathV2()
    request = RequestCodeGenerator()
    return WebIntelligenceCenter(
        intelligence=WebIntelligenceEngine(smart),
        sources=DataSourceDiscovery(),
        protocols=ProtocolInspector(),
        context_bridge=ContextBridgeService(request),
        selector=SelectorStudio(),
        recorder=BrowserRecorderService(),
        time_machine=WebTimeMachine(tmp_path / "time-machine.json"),
    )


def test_phase5_distributed_frontier_uses_enterprise_leases_and_global_dedup(tmp_path: Path) -> None:
    queue = DurableDistributedQueue(tmp_path / "crawl.sqlite")
    queue.register_worker("crawler-worker", _worker_public_key(), {"crawler": True}, max_slots=1)
    pages = {
        "https://example.test/": (200, "text/html", b'<a href="/next">next</a><a href="/next#dup">dup</a>'),
        "https://example.test/next": (200, "text/html", b"<h1>done</h1>"),
    }
    config = CrawlerConfig(
        seeds=["https://example.test/"], max_pages=10, max_depth=2,
        respect_robots_txt=False, per_host_delay_seconds=0,
    )
    coordinator = DistributedCrawlerCoordinator(
        queue, config, crawl_id="phase5-test", policy=DistributedCrawlPolicy(max_pending_jobs=10)
    )
    started = coordinator.start()
    assert len(started["job_ids"]) == 1

    engine = CrawlerEngine(fetcher=FakeFetcher(pages), network_policy=NetworkGuardPolicy(enabled=False))
    worker = DistributedCrawlerWorker(engine, "crawler-worker")

    first = queue.lease_next("crawler-worker")
    assert first is not None and first.kind == DISTRIBUTED_CRAWL_JOB_KIND
    first_result = worker.execute_lease(queue, first)
    assert first_result["children_enqueued"] == 1

    second = queue.lease_next("crawler-worker")
    assert second is not None
    second_result = worker.execute_lease(queue, second)
    assert second_result["status"] == 200
    assert queue.lease_next("crawler-worker") is None

    snap = coordinator.snapshot()
    assert snap.jobs_total == 2
    assert snap.completed == 2
    assert snap.failed == 0
    assert queue.invariant_violations() == []


def test_phase5_namespace_limit_is_fail_closed(tmp_path: Path) -> None:
    queue = DurableDistributedQueue(tmp_path / "crawl.sqlite")
    config = CrawlerConfig(
        seeds=["https://example.test/"], max_pages=1, max_depth=1,
        respect_robots_txt=False, per_host_delay_seconds=0,
    )
    coordinator = DistributedCrawlerCoordinator(queue, config, crawl_id="bounded")
    assert coordinator.start()["snapshot"]["jobs_total"] == 1
    job, state = coordinator.enqueue_url("https://example.test/other", depth=1, parent_url="https://example.test/")
    assert job is None and state == "max-pages"


def test_phase5_distributed_payload_rejects_persisted_credentials(tmp_path: Path) -> None:
    queue = DurableDistributedQueue(tmp_path / "crawl.sqlite")
    with pytest.raises(ValueError, match="credential-bearing request headers"):
        DistributedCrawlerCoordinator(
            queue,
            CrawlerConfig(seeds=["https://example.test/"], request_headers={"Authorization": "Bearer secret"}),
        )
    with pytest.raises(ValueError, match="credential-bearing proxy URLs"):
        DistributedCrawlerCoordinator(
            queue,
            CrawlerConfig(seeds=["https://example.test/"], proxies=["http://user:pass@proxy.test:8080"]),
        )


def test_phase6_browser_events_feed_api_map_and_web_intelligence(tmp_path: Path) -> None:
    result = BrowserFetchResult(
        requested_url="https://example.test/products",
        final_url="https://example.test/products",
        status=200,
        title="Products",
        html="<html><body>Products</body></html>",
        elapsed_ms=20.0,
        response_headers={"content-type": "text/html"},
        network_events=[
            BrowserNetworkObservation(
                kind="xhr", url="https://example.test/api/products?page=1", method="GET", status=200,
                resource_type="xhr", response_headers={"content-type": "application/json"},
            ),
            BrowserNetworkObservation(
                kind="http", url="https://example.test/graphql", method="GET", status=200,
                resource_type="graphql", response_headers={"content-type": "application/json"},
            ),
            BrowserNetworkObservation(
                kind="websocket-open", url="wss://example.test/live", resource_type="websocket",
            ),
        ],
    )
    events = browser_observations_to_events(result, session_id="browser-phase6")
    assert len(events) == 3
    assert any(event.protocol == "wss" for event in events)

    bundle = CrawlerWebIntelligencePipeline(_center(tmp_path)).analyze_browser(
        result, session_id="browser-phase6"
    )
    assert bundle.recommended_collection_path == "api"
    assert bundle.safe_api_candidates
    assert bundle.api_map.endpoint_count >= 2
    assert bundle.network_summary["api_like_events"] >= 2
    assert bundle.network_summary["websocket_events"] == 1


def test_phase6_sensitive_captured_endpoint_never_becomes_safe_api_candidate(tmp_path: Path) -> None:
    result = BrowserFetchResult(
        requested_url="https://example.test/me",
        final_url="https://example.test/me",
        status=200,
        title="Me",
        html="<html></html>",
        elapsed_ms=5.0,
        response_headers={"content-type": "text/html"},
        network_events=[
            BrowserNetworkObservation(
                kind="xhr", url="https://example.test/api/me?token=secret", method="GET", status=200,
                resource_type="xhr",
                request_headers={"authorization": "<redacted>"},
                response_headers={"content-type": "application/json"},
            )
        ],
    )
    bundle = CrawlerWebIntelligencePipeline(_center(tmp_path)).analyze_browser(result)
    assert bundle.safe_api_candidates == []
    serialized = str(bundle.snapshot())
    assert "token=secret" not in serialized


def test_phase5_worker_runtime_executes_registered_crawler_job_handler(tmp_path: Path) -> None:
    queue = DurableDistributedQueue(tmp_path / "runtime.sqlite")
    queue.register_worker("runtime-worker", _worker_public_key(), {"crawler": True}, max_slots=1)
    job_id = queue.enqueue(
        "crawler.test.v1",
        {"url": "https://example.test/"},
        resource_id="crawl:test",
        permission="crawler.execute",
        idempotency_key="crawler-runtime-handler",
    )
    lease = queue.lease_next("runtime-worker")
    assert lease is not None and lease.job_id == job_id

    def handler(active_queue, active_lease):
        active_queue.start_job(active_lease.job_id, "runtime-worker", active_lease.lease_token)
        result = {"ok": True, "url": active_lease.payload["url"]}
        active_queue.complete(active_lease.job_id, "runtime-worker", active_lease.lease_token, result)
        return result

    runtime = EnterpriseWorkerRuntime(object(), "runtime-worker", job_handlers={"crawler.test.v1": handler})
    assert runtime.execute_lease(queue, lease) == {"ok": True, "url": "https://example.test/"}
    assert queue.job(job_id)["state"] == "completed"
