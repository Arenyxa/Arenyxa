from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from arenyxa.application.crawler import CrawlerEngine
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import RequestSpec
from arenyxa.infrastructure.http_client import HttpFetcher
from arenyxa.security.network_guard import NetworkGuardPolicy


class _MetadataRedirect(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(302)
        self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:
        return


@pytest.fixture
def metadata_redirect_url() -> str:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MetadataRedirect)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/redirect"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("transport", ["urllib", "httpx"])
def test_fetcher_blocks_cloud_metadata_redirect_before_following(
    metadata_redirect_url: str,
    transport: str,
) -> None:
    fetcher = HttpFetcher(transport=transport)
    with pytest.raises(ArenyxaError) as captured:
        fetcher.fetch(RequestSpec(metadata_redirect_url))
    assert captured.value.code == "NETWORK_PROTECTED_TARGET"


def test_fetcher_blocks_direct_cloud_metadata_target_by_default() -> None:
    with pytest.raises(ArenyxaError) as captured:
        HttpFetcher(transport="urllib").fetch(RequestSpec("http://169.254.169.254/latest/meta-data/"))
    assert captured.value.code == "NETWORK_PROTECTED_TARGET"


def test_crawler_attaches_its_stricter_network_policy_to_supplied_fetcher() -> None:
    fetcher = HttpFetcher(transport="urllib")
    crawler = CrawlerEngine(
        fetcher=fetcher,
        network_policy=NetworkGuardPolicy(block_private_or_loopback=True),
    )
    assert fetcher.network_guard is crawler.guard
    with pytest.raises(ArenyxaError) as captured:
        fetcher.fetch(RequestSpec("http://127.0.0.1/"))
    assert captured.value.code == "NETWORK_PRIVATE_TARGET_BLOCKED"
