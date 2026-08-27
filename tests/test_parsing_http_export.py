from __future__ import annotations

import gzip
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from arenyxa.application.export import ExportService
from arenyxa.domain.enums import RunStatus, TaskStatus
from arenyxa.domain.models import CleanerStep, FetchResponse, FieldSpec, RequestSpec, ResultRecord, Run, Task
from arenyxa.infrastructure.http_client import HttpFetcher
from arenyxa.infrastructure.parsers import FieldExtractor, ParserRegistry


def response(body: bytes, content_type: str) -> FetchResponse:
    return FetchResponse("https://x", "https://x", 200, {}, body, 1.0, "utf-8", content_type)


def test_html_json_and_xml_parsing_and_cleaning() -> None:
    extractor = FieldExtractor()
    html_document = ParserRegistry.parse(
        response(b'<html><h1 data-id="7">  Arenyxa   V6 </h1></html>', "text/html")
    )
    record, quality = extractor.extract(
        html_document,
        [FieldSpec("title", "h1", cleaners=[CleanerStep("normalize_whitespace")])],
    )
    assert record == {"title": "Arenyxa V6"}
    assert quality == []

    json_document = ParserRegistry.parse(response(b'{"items":[{"price":"1,234"}]}', "application/json"))
    record, _ = extractor.extract(json_document, [FieldSpec("price", "items.0.price", data_type="integer")])
    assert record["price"] == 1234

    xml_document = ParserRegistry.parse(response(b"<root><value>ok</value></root>", "application/xml"))
    record, _ = extractor.extract(xml_document, [FieldSpec("value", "//value")])
    assert record["value"] == "ok"


def test_http_fetcher_gzip_and_size_guard() -> None:
    payload = gzip.compress("你好 Arenyxa".encode())

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Encoding", "gzip")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        fetched = HttpFetcher(1024).fetch(RequestSpec(f"http://127.0.0.1:{server.server_port}/"))
        assert fetched.body.decode() == "你好 Arenyxa"
        with pytest.raises(Exception) as error:
            HttpFetcher(3).fetch(RequestSpec(f"http://127.0.0.1:{server.server_port}/"))
        assert "FETCH_TOO_LARGE" in str(error.value)
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize(
    "format_name,extension", [("csv", "csv"), ("jsonl", "jsonl"), ("json", "json"), ("xlsx", "xlsx")]
)
def test_streaming_exports(store, tmp_path, format_name: str, extension: str) -> None:
    task = Task("Export", [RequestSpec("https://example.com")], status=TaskStatus.READY)
    store.save_task(task)
    run = Run(task.id, task.to_dict(), status=RunStatus.COMPLETED)
    store.save_run(run)
    store.append_results([ResultRecord(task.id, run.id, "https://example.com", {"name": "样例", "value": 6})])
    destination = tmp_path / f"export.{extension}"
    assert ExportService(store).export_run(run.id, destination, format_name) == 1
    assert destination.exists() and destination.stat().st_size > 0
    if format_name == "json":
        assert json.loads(destination.read_text(encoding="utf-8"))[0]["name"] == "样例"
