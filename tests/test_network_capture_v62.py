from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace

from arenyxa.domain.enums import CaptureSource, CaptureState
from arenyxa.domain.models import CaptureSession, NetworkEvent
from arenyxa.domain.network import NetworkNormalizer
from arenyxa.infrastructure.capture.adapters import TsharkPacketAdapter
from arenyxa.infrastructure.capture.bodies import NetworkBodyStore
from arenyxa.infrastructure.capture.har import HarAnalyzer


def test_body_store_is_bounded_content_addressed_and_persisted(store, tmp_path: Path) -> None:
    session = CaptureSession("body capture", CaptureSource.BROWSER)
    store.save_capture(session)
    bodies = NetworkBodyStore(tmp_path / "bodies", max_body_bytes=8)
    artifact = bodies.put(
        session.id,
        b"0123456789abcdef",
        content_type="application/octet-stream",
        sensitive=True,
    )
    assert artifact.byte_size == 16
    assert artifact.stored_size == 8
    assert artifact.truncated is True
    assert artifact.sensitive is True
    assert bodies.get_path(artifact).suffix == ".partial"
    assert bodies.read(artifact) == b"01234567"

    event = NetworkEvent(
        session.id,
        CaptureSource.BROWSER,
        "https",
        "bidirectional",
        artifact.byte_size,
        method="POST",
        url="https://example.test/upload",
        status=200,
        host="example.test",
        request_body_ref=artifact.id,
        metadata={"body_artifacts": [bodies.metadata(artifact)]},
    )
    assert store.append_network_events([event]) == 1
    saved = store.get_network_body(artifact.id)
    assert saved is not None
    assert saved["sha256"] == artifact.sha256
    assert saved["stored_sha256"] == artifact.stored_sha256
    assert saved["truncated"] is True
    assert saved["sensitive"] is True
    quality = store.network_capture_quality_metrics(session.id)
    assert quality["bodies"] == 1
    assert quality["body_bytes"] == 16
    assert quality["stored_body_bytes"] == 8
    assert quality["truncated_bodies"] == 1


def test_har_import_enriches_body_connection_and_tls_metadata(store, tmp_path: Path) -> None:
    session = CaptureSession("HAR", CaptureSource.HAR_IMPORT)
    store.save_capture(session)
    har = {
        "log": {
            "pages": [{"title": "https://example.com"}],
            "entries": [
                {
                    "startedDateTime": "2026-08-09T00:00:00Z",
                    "time": 23.5,
                    "connection": "42",
                    "serverIPAddress": "203.0.113.9",
                    "_securityDetails": {
                        "protocol": "TLS 1.3",
                        "cipher": "AES_128_GCM",
                        "subjectName": "example.com",
                        "issuer": "Fixture CA",
                    },
                    "request": {
                        "method": "POST",
                        "url": "https://example.com/api/items",
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "postData": {"mimeType": "application/json", "text": '{"name":"arenyxa"}'},
                    },
                    "response": {
                        "status": 201,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "bodySize": 11,
                        "content": {"size": 11, "mimeType": "application/json", "text": '{"ok":true}'},
                    },
                    "timings": {"dns": 1.0, "connect": 2.0, "ssl": 3.0, "wait": 10.0},
                }
            ],
        }
    }
    path = tmp_path / "capture.har"
    path.write_text(json.dumps(har), encoding="utf-8")
    body_store = NetworkBodyStore(tmp_path / "capture-bodies")
    events, _summary = HarAnalyzer.load(path, session, body_store=body_store)
    assert len(events) == 1
    event = events[0]
    assert event.flow_ref == "har:42"
    assert event.request_body_ref and event.response_body_ref
    assert event.metadata["remote_address"] == "203.0.113.9"
    assert event.metadata["tls_version"] == "TLS 1.3"
    assert len(event.metadata["body_artifacts"]) == 2

    store.append_network_events(events)
    exchange = list(store.iter_http_exchanges(session.id))[0]
    assert exchange["request_body_ref"] == event.request_body_ref
    assert exchange["response_body_ref"] == event.response_body_ref
    assert len(store.list_network_bodies(session.id)) == 2
    with store.connect() as connection:
        tls = connection.execute("SELECT host,version,cipher FROM tls_handshakes WHERE session_id=?", (session.id,)).fetchone()
        flow = connection.execute("SELECT remote_address FROM network_flows WHERE session_id=?", (session.id,)).fetchone()
    assert tls is not None and tuple(tls) == ("example.com", "TLS 1.3", "AES_128_GCM")
    assert flow is not None and flow[0] == "203.0.113.9"


def test_tshark_enrichment_projects_endpoints_dns_and_tls(monkeypatch) -> None:
    adapter = TsharkPacketAdapter("1")
    adapter._active_fields = adapter.FIELDS + adapter.OPTIONAL_FIELDS
    monkeypatch.setattr(adapter, "_process_port_map", lambda: {53000: "browser.exe", 54321: "browser.exe"})

    def line(**values: str) -> str:
        return "\t".join(values.get(field, "") for field in adapter._active_fields) + "\n"

    payload = "".join(
        [
            line(
                **{
                    "frame.time_epoch": "1786233600.125",
                    "frame.len": "82",
                    "ip.src": "10.0.0.2",
                    "ip.dst": "8.8.8.8",
                    "udp.srcport": "53000",
                    "udp.dstport": "53",
                    "_ws.col.Protocol": "DNS",
                    "udp.stream": "3",
                    "dns.qry.name": "example.com",
                    "dns.qry.type": "1",
                    "dns.a": "203.0.113.7",
                    "dns.time": "0.004",
                }
            ),
            line(
                **{
                    "frame.time_epoch": "1786233600.250",
                    "frame.len": "250",
                    "ip.src": "10.0.0.2",
                    "ip.dst": "203.0.113.7",
                    "tcp.srcport": "54321",
                    "tcp.dstport": "443",
                    "_ws.col.Protocol": "TLSv1.3",
                    "tcp.stream": "7",
                    "tls.handshake.version": "TLSv1.3",
                    "tls.handshake.ciphersuite": "0x1301",
                    "tls.handshake.extensions_alpn_str": "h2",
                    "tls.handshake.extensions_server_name": "example.com",
                }
            ),
        ]
    )
    adapter._process = SimpleNamespace(stdout=io.StringIO(payload))
    events: list[NetworkEvent] = []
    session = CaptureSession("system", CaptureSource.SYSTEM)
    adapter._read_impl(session, events.append)
    assert len(events) == 2

    dns_event, tls_event = events
    assert dns_event.direction == "outbound"
    assert dns_event.metadata["query_name"] == "example.com"
    assert dns_event.metadata["query_type"] == "A"
    assert dns_event.metadata["answers"] == ["203.0.113.7"]
    assert dns_event.metadata["elapsed_ms"] == 4.0
    dns = NetworkNormalizer.normalize(dns_event)
    assert dns.dns is not None and dns.dns.answers == ["203.0.113.7"]
    assert dns.flow.local_address == "10.0.0.2:53000"
    assert dns.flow.remote_address == "8.8.8.8:53"

    assert tls_event.protocol == "tls"
    assert tls_event.host == "example.com"
    assert tls_event.metadata["alpn"] == "h2"
    tls = NetworkNormalizer.normalize(tls_event)
    assert tls.tls is not None
    assert tls.tls.host == "example.com"
    assert tls.tls.version == "TLSv1.3"
    assert tls.tls.cipher == "0x1301"
    assert tls.tls.alpn == "h2"
    assert tls.flow.local_address == "10.0.0.2:54321"
    assert tls.flow.remote_address == "203.0.113.7:443"


def test_tshark_optional_field_negotiation_does_not_force_unknown_fields(monkeypatch) -> None:
    adapter = TsharkPacketAdapter
    adapter._field_cache.clear()
    completed = SimpleNamespace(returncode=0, stdout="F\tDNS Query Type\tdns.qry.type\n")
    monkeypatch.setattr("arenyxa.infrastructure.capture.adapters.subprocess.run", lambda *args, **kwargs: completed)
    fields = adapter._supported_fields("tshark-fixture")
    assert "dns.qry.type" in fields
    assert "tls.handshake.extensions_alpn_str" not in fields


def test_v61_database_receives_additive_v62_body_migration(tmp_path: Path) -> None:
    import sqlite3

    from arenyxa.infrastructure.database import MIGRATIONS, SQLiteStore

    path = tmp_path / "legacy-v61.db"
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        for version, script in enumerate(MIGRATIONS[:-1], start=1):
            connection.executescript(script)
            connection.execute("INSERT INTO schema_migrations VALUES(?,?)", (version, "legacy"))
        connection.commit()
    finally:
        connection.close()

    store = SQLiteStore(path)
    store.initialize()
    with store.connect() as connection:
        applied = {int(row[0]) for row in connection.execute("SELECT version FROM schema_migrations")}
        body_table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='network_bodies'"
        ).fetchone()
    assert applied == set(range(1, len(MIGRATIONS) + 1))
    assert body_table is not None
    assert path.with_name("legacy-v61.pre-migration.bak").is_file()


def test_browser_body_helper_uses_normalized_body_ids(tmp_path: Path) -> None:
    from arenyxa.infrastructure.capture.adapters import BrowserCaptureAdapter

    session = CaptureSession("browser", CaptureSource.BROWSER)
    body_store = NetworkBodyStore(tmp_path / "bodies")
    adapter = BrowserCaptureAdapter("https://example.test", tmp_path / "profile", body_store=body_store)
    body_ref, metadata = adapter._store_payload(
        session,
        '{"query":"hello"}',
        content_type="application/json",
        encoding="utf-8",
        sensitive=True,
    )
    assert body_ref is not None and body_ref.startswith("body_")
    assert metadata is not None
    assert metadata["id"] == body_ref
    assert metadata["sensitive"] is True
    assert body_store.read(metadata) == b'{"query":"hello"}'


def test_one_shot_capture_commit_creates_session_events_and_core_atomically(store) -> None:
    session = CaptureSession("one-shot HAR", CaptureSource.HAR_IMPORT)
    session.state = CaptureState.COMPLETED
    session.started_at = "2026-08-09T00:00:00+00:00"
    session.finished_at = "2026-08-09T00:00:01+00:00"
    event = NetworkEvent(
        session.id,
        CaptureSource.HAR_IMPORT,
        "https",
        "bidirectional",
        12,
        method="GET",
        url="https://example.test/api",
        status=200,
        host="example.test",
    )
    session.event_count = 1
    session.bytes_captured = 12
    assert store.append_capture_events(session, [event]) == 1
    with store.connect() as connection:
        assert connection.execute("SELECT state,event_count FROM capture_sessions WHERE id=?", (session.id,)).fetchone() is not None
        assert connection.execute("SELECT count(*) FROM network_events WHERE session_id=?", (session.id,)).fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM http_requests WHERE session_id=?", (session.id,)).fetchone()[0] == 1
