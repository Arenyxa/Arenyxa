from __future__ import annotations

import json
from pathlib import Path

from arenyxa.application.crawler import (
    CrawlerConfig,
    CrawlerEngine,
    CrawlerResultExporter,
    canonicalize_url,
)
from arenyxa.domain.models import FetchResponse, FieldSpec
from arenyxa.security.network_guard import NetworkGuardPolicy


class FakeFetcher:
    def __init__(self, pages: dict[str, tuple[int, str, bytes]]) -> None:
        self.pages = pages
        self.calls: list[str] = []

    def fetch(self, spec, token=None, on_attempt=None):
        self.calls.append(spec.url)
        status, content_type, body = self.pages.get(
            spec.url,
            (404, "text/html", b"<html><title>missing</title></html>"),
        )
        return FetchResponse(
            url=spec.url,
            final_url=spec.url,
            status=status,
            headers={"Content-Type": content_type},
            body=body,
            elapsed_ms=1.0,
            encoding="utf-8",
            content_type=content_type,
        )


def _engine(pages):
    return CrawlerEngine(fetcher=FakeFetcher(pages), network_policy=NetworkGuardPolicy(enabled=False))


def test_recursive_crawl_discovers_links_with_scope_and_depth() -> None:
    pages = {
        "https://example.test/": (200, "text/html", b'<html><title>Home</title><a href="/a">A</a><a href="https://other.test/x">X</a></html>'),
        "https://example.test/a": (200, "text/html", b'<html><title>A</title><a href="/b#frag">B</a><a href="/b">B2</a></html>'),
        "https://example.test/b": (200, "text/html", b"<html><title>B</title></html>"),
    }
    result = _engine(pages).run(CrawlerConfig(
        seeds=["https://example.test"],
        max_pages=10,
        max_depth=2,
        concurrency=2,
        per_host_delay_seconds=0,
        respect_robots_txt=False,
    ))
    assert [page.final_url for page in result.pages] == [
        "https://example.test/",
        "https://example.test/a",
        "https://example.test/b",
    ]
    assert result.pages_succeeded == 3
    assert result.urls_skipped >= 1
    assert result.urls_discovered == 3


def test_robots_txt_blocks_disallowed_path() -> None:
    pages = {
        "https://example.test/robots.txt": (200, "text/plain", b"User-agent: *\nDisallow: /private\nCrawl-delay: 1\n"),
        "https://example.test/": (200, "text/html", b'<a href="/private">P</a><a href="/public">U</a>'),
        "https://example.test/public": (200, "text/html", b"<html>ok</html>"),
        "https://example.test/private": (200, "text/html", b"<html>secret</html>"),
    }
    engine = _engine(pages)
    result = engine.run(CrawlerConfig(
        seeds=["https://example.test/"],
        max_pages=10,
        max_depth=1,
        concurrency=2,
        per_host_delay_seconds=0,
        respect_robots_txt=True,
    ))
    assert result.robots_denied == 1
    assert "https://example.test/private" not in [page.final_url for page in result.pages]
    assert "https://example.test/public" in [page.final_url for page in result.pages]


def test_crawler_extracts_fields_from_each_page() -> None:
    pages = {
        "https://example.test/": (200, "text/html", b'<html><h1>Alpha</h1><a href="/two">next</a></html>'),
        "https://example.test/two": (200, "text/html", b"<html><h1>Beta</h1></html>"),
    }
    result = _engine(pages).run(CrawlerConfig(
        seeds=["https://example.test/"],
        fields=[FieldSpec(name="name", selector="h1", selector_type="css")],
        max_pages=5,
        max_depth=1,
        per_host_delay_seconds=0,
        respect_robots_txt=False,
    ))
    assert [row["name"] for row in result.records] == ["Alpha", "Beta"]
    assert all("url" in row for row in result.records)


def test_explicit_allowed_domain_can_restrict_scope() -> None:
    pages = {
        "https://seed.test/": (200, "text/html", b'<a href="https://api.example.test/x">api</a><a href="https://else.test/x">else</a>'),
        "https://api.example.test/x": (200, "application/json", b'{"ok": true}'),
    }
    result = _engine(pages).run(CrawlerConfig(
        seeds=["https://seed.test/"],
        same_site_only=False,
        allowed_domains=["example.test"],
        include_subdomains=True,
        max_pages=5,
        max_depth=1,
        per_host_delay_seconds=0,
        respect_robots_txt=False,
    ))
    # The seed is admitted by definition when queued, but discovered URLs obey explicit scope.
    assert "https://api.example.test/x" in [page.final_url for page in result.pages]
    assert "https://else.test/x" not in [page.final_url for page in result.pages]


def test_export_json_and_csv(tmp_path: Path) -> None:
    result = _engine({
        "https://example.test/": (200, "text/html", b"<html><h1>Alpha</h1></html>"),
    }).run(CrawlerConfig(
        seeds=["https://example.test/"],
        fields=[FieldSpec(name="name", selector="h1")],
        respect_robots_txt=False,
        per_host_delay_seconds=0,
    ))
    exporter = CrawlerResultExporter()
    json_path = tmp_path / "crawl.json"
    csv_path = tmp_path / "crawl.csv"
    assert exporter.export(result, json_path, "json") == 1
    assert exporter.export(result, csv_path, "csv") == 1
    assert json.loads(json_path.read_text(encoding="utf-8"))["records"][0]["name"] == "Alpha"
    assert "Alpha" in csv_path.read_text(encoding="utf-8-sig")


def test_canonicalize_removes_fragments_and_default_ports() -> None:
    assert canonicalize_url("HTTPS://Example.COM:443/a#x") == "https://example.com/a"
    assert canonicalize_url("mailto:test@example.com") == ""


def test_real_http_loopback_recursive_crawl() -> None:
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                payload = b'<html><title>Root</title><a href="/next">next</a></html>'
            elif self.path == "/next":
                payload = b"<html><title>Next</title></html>"
            else:
                payload = b"not found"
            self.send_response(200 if self.path in {"/", "/next"} else 404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        seed = f"http://127.0.0.1:{server.server_port}/"
        result = CrawlerEngine().run(CrawlerConfig(
            seeds=[seed],
            max_pages=4,
            max_depth=1,
            concurrency=2,
            per_host_delay_seconds=0,
            respect_robots_txt=False,
        ))
    finally:
        server.shutdown()
        server.server_close()
    assert result.pages_succeeded == 2
    assert {page.title for page in result.pages} == {"Root", "Next"}
