from __future__ import annotations

from arenyxa.domain.enums import CaptureSource, SourceKind
from arenyxa.domain.models import CaptureSession, NetworkEvent, Project, ProjectSource
from arenyxa.domain.network import NetworkNormalizer


def test_network_normalizer_projects_http_without_breaking_ingestion_model() -> None:
    event = NetworkEvent(
        "capture_v61",
        CaptureSource.BROWSER,
        "https",
        "bidirectional",
        512,
        flow_ref="tcp:7",
        method="GET",
        url="https://api.example.com/v1/items?page=2&page=3&empty=",
        status=200,
        host="api.example.com",
        request_headers={"Accept": "application/json"},
        response_headers={"Content-Type": "application/json; charset=utf-8"},
        timing={"total_ms": 18.5},
    )
    first = NetworkNormalizer.normalize(event)
    second = NetworkNormalizer.normalize(event)
    assert first.flow.id == second.flow.id
    assert first.request is not None and first.response is not None
    assert first.request.query == {"page": ["2", "3"], "empty": [""]}
    assert first.response.request_id == first.request.id
    assert first.response.content_type.startswith("application/json")


def test_project_source_and_capture_binding_roundtrip(store) -> None:
    project = Project("Research", description="V6.1 unified network domain", tags=["network"])
    store.save_project(project)
    source = ProjectSource(project.id, "Browser", SourceKind.BROWSER, config={"profile": "default"})
    store.save_project_source(source)
    session = CaptureSession(
        "bound capture", CaptureSource.BROWSER, project_id=project.id, source_id=source.id
    )
    store.save_capture(session)
    restored = store.get_project(project.id)
    assert restored is not None and restored.name == "Research"
    assert store.list_project_sources(project.id)[0]["config"]["profile"] == "default"
    with store.connect() as connection:
        binding = connection.execute(
            "SELECT project_id,source_id FROM capture_bindings WHERE session_id=?", (session.id,)
        ).fetchone()
    assert binding is not None
    assert tuple(binding) == (project.id, source.id)


def test_network_events_are_atomically_normalized_into_core_tables(store) -> None:
    session = CaptureSession("capture", CaptureSource.BROWSER)
    store.save_capture(session)
    events = [
        NetworkEvent(
            session.id,
            CaptureSource.BROWSER,
            "https",
            "bidirectional",
            321,
            flow_ref="tcp:11",
            method="POST",
            url="https://example.com/api/items?limit=50",
            status=201,
            host="example.com",
            request_headers={"Content-Type": "application/json"},
            response_headers={"content-type": "application/json"},
            request_body_ref="blob:req",
            response_body_ref="blob:resp",
            timing={"total_ms": 42.0},
        ),
        NetworkEvent(
            session.id,
            CaptureSource.SYSTEM,
            "dns",
            "outbound",
            80,
            host="example.com",
            metadata={"query_name": "example.com", "query_type": "A", "answers": ["203.0.113.7"]},
        ),
        NetworkEvent(
            session.id,
            CaptureSource.SYSTEM,
            "tls",
            "bidirectional",
            240,
            host="example.com",
            flow_ref="tcp:11",
            metadata={"tls_version": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256", "alpn": "h2"},
        ),
        NetworkEvent(
            session.id,
            CaptureSource.BROWSER,
            "websocket",
            "inbound",
            64,
            host="example.com",
            url="wss://example.com/live",
            flow_ref="tcp:12",
            response_body_ref="blob:ws1",
            metadata={"resource_type": "websocket", "opcode": "text", "websocket_id": "live-1"},
        ),
    ]
    assert store.append_network_events(iter(events)) == 4
    metrics = store.network_core_metrics(session.id)
    assert metrics == {
        "flows": 3,
        "http_requests": 1,
        "http_responses": 1,
        "dns": 1,
        "tls": 1,
        "websockets": 1,
        "websocket_messages": 1,
    }
    exchange = list(store.iter_http_exchanges(session.id))[0]
    assert exchange["method"] == "POST"
    assert exchange["status"] == 201
    assert exchange["query"] == {"limit": ["50"]}
    assert exchange["timing"]["total_ms"] == 42.0


def test_append_capture_events_keeps_legacy_and_normalized_rows_in_one_transaction(store) -> None:
    session = CaptureSession("atomic", CaptureSource.HTTP_RUNNER)
    store.save_capture(session)
    event = NetworkEvent(
        session.id,
        CaptureSource.HTTP_RUNNER,
        "https",
        "bidirectional",
        99,
        method="GET",
        url="https://example.test/health",
        status=204,
        host="example.test",
    )
    session.event_count = 1
    session.bytes_captured = 99
    assert store.append_capture_events(session, [event]) == 1
    with store.connect() as connection:
        assert connection.execute("SELECT count(*) FROM network_events").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM http_requests").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM http_responses").fetchone()[0] == 1


def test_v60_database_receives_additive_v61_network_core_migration(tmp_path) -> None:
    import sqlite3

    from arenyxa.infrastructure.database import MIGRATIONS, SQLiteStore

    path = tmp_path / "legacy-v60.db"
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
                                                                                   
        for version, script in enumerate(MIGRATIONS[:-2], start=1):
            connection.executescript(script)
            connection.execute("INSERT INTO schema_migrations VALUES(?,?)", (version, "legacy"))
        connection.commit()
    finally:
        connection.close()

    store = SQLiteStore(path)
    store.initialize()
    with store.connect() as connection:
        applied = {int(row[0]) for row in connection.execute("SELECT version FROM schema_migrations")}
        names = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
                "('projects','project_sources','network_flows','http_requests','http_responses')"
            )
        }
    assert applied == set(range(1, len(MIGRATIONS) + 1))
    assert names == {"projects", "project_sources", "network_flows", "http_requests", "http_responses"}
    assert path.with_name("legacy-v60.pre-migration.bak").is_file()


def test_normalization_failure_rolls_back_legacy_and_core_rows(store, monkeypatch) -> None:
    from arenyxa.domain.network import NetworkNormalizer

    session = CaptureSession("rollback", CaptureSource.BROWSER)
    store.save_capture(session)
    event = NetworkEvent(
        session.id,
        CaptureSource.BROWSER,
        "https",
        "bidirectional",
        10,
        method="GET",
        url="https://example.test/",
        status=200,
        host="example.test",
    )

    def fail(_event):
        raise RuntimeError("projection failed")

    monkeypatch.setattr(NetworkNormalizer, "normalize", fail)
    try:
        store.append_network_events([event])
    except RuntimeError as exc:
        assert "projection failed" in str(exc)
    else:
        raise AssertionError("normalization failure must escape so caller can mark capture failed")

    with store.connect() as connection:
        assert connection.execute("SELECT count(*) FROM network_events").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM network_flows").fetchone()[0] == 0


def test_backfill_projects_legacy_events_once_and_is_idempotent(store) -> None:
    import json

    session = CaptureSession("legacy", CaptureSource.BROWSER)
    store.save_capture(session)
    event = NetworkEvent(
        session.id,
        CaptureSource.BROWSER,
        "https",
        "bidirectional",
        55,
        method="GET",
        url="https://legacy.example/api?q=1",
        status=200,
        host="legacy.example",
    )
                                                                           
    with store.connect() as connection:
        connection.execute(
            "INSERT INTO network_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event.id, event.session_id, event.source_type.value, event.timestamp, event.process_ref,
                event.flow_ref, event.request_ref, event.protocol, event.direction, event.size, event.method,
                event.url, event.status, event.host, json.dumps(event.timing), json.dumps(event.request_headers),
                json.dumps(event.response_headers), event.request_body_ref, event.response_body_ref,
                json.dumps(event.sensitivity_flags), event.initiator, json.dumps(event.metadata),
            ),
        )
    assert store.network_core_backlog(session.id) == 1
    assert store.backfill_network_core(session.id) == 1
    assert store.network_core_backlog(session.id) == 0
    assert store.network_core_metrics(session.id)["http_requests"] == 1
    assert store.backfill_network_core(session.id) == 0
    assert store.network_core_metrics(session.id)["flows"] == 1


def test_capture_binding_rejects_source_from_another_project_atomically(store) -> None:
    from arenyxa.domain.errors import ArenyxaError

    left = Project("Left")
    right = Project("Right")
    store.save_project(left)
    store.save_project(right)
    source = ProjectSource(left.id, "Left Browser", SourceKind.BROWSER)
    store.save_project_source(source)
    session = CaptureSession("bad binding", CaptureSource.BROWSER, project_id=right.id, source_id=source.id)
    try:
        store.save_capture(session)
    except ArenyxaError as exc:
        assert exc.code == "PROJECT_SOURCE_MISMATCH"
    else:
        raise AssertionError("cross-project source binding must be rejected")
    with store.connect() as connection:
        assert connection.execute("SELECT 1 FROM capture_sessions WHERE id=?", (session.id,)).fetchone() is None


def test_bind_capture_rejects_missing_session(store) -> None:
    from arenyxa.domain.errors import ArenyxaError

    project = Project("P")
    store.save_project(project)
    try:
        store.bind_capture("capture_missing", project.id, None)
    except ArenyxaError as exc:
        assert exc.code == "CAPTURE_NOT_FOUND"
    else:
        raise AssertionError("binding a missing capture must fail with a domain error")
