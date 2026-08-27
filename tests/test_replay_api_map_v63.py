from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

import pytest

from arenyxa.application.api_map import ApiMapService
from arenyxa.domain.enums import CaptureSource, CaptureState
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import CaptureSession, FetchResponse, NetworkEvent
from arenyxa.infrastructure.capture.bodies import NetworkBodyStore
from arenyxa.infrastructure.capture.replay import CapturedBodyResolver, RequestReplayService
from arenyxa.infrastructure.database import MIGRATIONS, SQLiteStore
from arenyxa.infrastructure.http_client import CancellationToken


def _event(
    session: CaptureSession,
    *,
    event_id: str,
    url: str,
    status: int = 200,
    request_headers: dict[str, str] | None = None,
    request_body_ref: str | None = None,
    response_body_ref: str | None = None,
    body_artifacts: list[dict] | None = None,
) -> NetworkEvent:
    return NetworkEvent(
        session.id,
        CaptureSource.BROWSER,
        "https",
        "bidirectional",
        128,
        id=event_id,
        request_ref=f"req-{event_id}",
        method="POST" if request_body_ref else "GET",
        url=url,
        status=status,
        host="api.example.test",
        request_headers=request_headers or {},
        response_headers={"Content-Type": "application/json; charset=utf-8"},
        request_body_ref=request_body_ref,
        response_body_ref=response_body_ref,
        timing={"total_ms": 25.0},
        metadata={"body_artifacts": body_artifacts or []},
    )


def test_api_map_v2_groups_routes_profiles_parameters_and_infers_json_schema(store, tmp_path: Path) -> None:
    session = CaptureSession("api-map", CaptureSource.BROWSER)
    session.state = CaptureState.COMPLETED
    store.save_capture(session)
    bodies = NetworkBodyStore.for_capture(tmp_path / "captures", session.id)
    response_a = bodies.put(
        session.id,
        b'{"items":[{"id":1,"name":"one"}],"next":"abc"}',
        content_type="application/json",
    )
    response_b = bodies.put(
        session.id,
        b'{"items":[{"id":2,"name":"two","price":9.5}],"next":null}',
        content_type="application/json",
    )
    events = [
        _event(
            session,
            event_id="net-a",
            url="https://api.example.test/api/items/42?page=1&limit=25",
            response_body_ref=response_a.id,
            body_artifacts=[asdict(response_a)],
            request_headers={"Authorization": "Bearer super-secret"},
        ),
        _event(
            session,
            event_id="net-b",
            url="https://api.example.test/api/items/99?page=2&limit=25",
            status=201,
            response_body_ref=response_b.id,
            body_artifacts=[asdict(response_b)],
            request_headers={"Authorization": "Bearer another-secret"},
        ),
    ]
    store.append_network_events(events)
    resolver = CapturedBodyResolver(store, tmp_path / "captures")
    snapshot = ApiMapService().build(
        session.id,
        store.iter_http_exchanges(session.id),
        body_loader=resolver.load_for_schema,
    )
    assert snapshot.endpoint_count == 1
    endpoint = snapshot.endpoints[0]
    assert endpoint.path == "/api/items/{id}"
    assert endpoint.samples == 2
    assert endpoint.statuses == [200, 201]
    assert endpoint.pagination_candidates == ["limit", "page"]
    assert endpoint.auth_signals == ["authorization"]
    assert "super-secret" not in str(snapshot.to_dict())
    assert endpoint.response_schema is not None
    properties = endpoint.response_schema["properties"]
    assert properties["items"]["type"] == "array"
    assert properties["items"]["items"]["properties"]["price"]["optional"] is True
    assert endpoint.schema_fingerprint


def test_replay_draft_restores_verified_body_but_never_auto_replays_credentials(store, tmp_path: Path) -> None:
    session = CaptureSession("replay", CaptureSource.BROWSER)
    store.save_capture(session)
    bodies = NetworkBodyStore.for_capture(tmp_path / "captures", session.id)
    request_body = bodies.put(session.id, '{"name":"Arenyxa"}', content_type="application/json", encoding="utf-8")
    response_body = bodies.put(session.id, '{"ok":true}', content_type="application/json", encoding="utf-8")
    event = _event(
        session,
        event_id="net-replay",
        url="https://api.example.test/api/items",
        status=201,
        request_headers={
            "Authorization": "Bearer actual-secret",
            "Content-Type": "application/json",
            "Content-Length": "17",
        },
        request_body_ref=request_body.id,
        response_body_ref=response_body.id,
        body_artifacts=[asdict(request_body), asdict(response_body)],
    )
    store.append_network_events([event])
    exchange = store.get_http_exchange_by_event(event.id)
    assert exchange is not None
    resolver = CapturedBodyResolver(store, tmp_path / "captures")
    service = RequestReplayService()
    draft = service.draft_from_exchange(exchange, body_resolver=resolver)
    assert draft.request.body == '{"name":"Arenyxa"}'
    assert "Content-Length" not in draft.request.headers
    assert draft.request.headers["Authorization"].startswith("${secret.header.")
    assert "actual-secret" not in str(draft)
    with pytest.raises(ArenyxaError) as caught:
        service.replay(draft, confirm_side_effect=True)
    assert caught.value.code == "REPLAY_SECRET_REQUIRED"

    bound = service.bind_secrets(draft, {draft.request.headers["Authorization"]: "Bearer explicitly-bound"})
    assert bound.request.headers["Authorization"] == "Bearer explicitly-bound"
    assert not service.unresolved_secret_refs(bound.request)


def test_replay_execute_compares_json_and_persists_redacted_history(store, tmp_path: Path) -> None:
    session = CaptureSession("replay-history", CaptureSource.BROWSER)
    store.save_capture(session)
    bodies = NetworkBodyStore.for_capture(tmp_path / "captures", session.id)
    original = bodies.put(session.id, b'{"ok":true,"version":1}', content_type="application/json")
    event = _event(
        session,
        event_id="net-history",
        url="https://api.example.test/api/state",
        request_headers={"Authorization": "Bearer captured-value"},
        response_body_ref=original.id,
        body_artifacts=[asdict(original)],
    )
    store.append_network_events([event])
    exchange = store.get_http_exchange_by_event(event.id)
    assert exchange is not None

    class FakeFetcher:
        def fetch(self, spec, token: CancellationToken):
            token.checkpoint()
            assert "Authorization" not in spec.headers
            return FetchResponse(
                spec.url,
                spec.url,
                200,
                {"Content-Type": "application/json"},
                b'{"ok":true,"version":2,"new":1}',
                30.0,
                "utf-8",
                "application/json",
            )

    service = RequestReplayService(fetcher=FakeFetcher())
    resolver = CapturedBodyResolver(store, tmp_path / "captures")
    draft = service.draft_from_exchange(exchange, body_resolver=resolver)
    draft = service.without_secrets(draft)
    result = service.execute(draft)
    assert result.state == "completed"
    assert result.comparison is not None
    changes = result.comparison["json_diff"]["changes"]
    assert any(change["path"] == "$.version" for change in changes)
    assert any(change["path"] == "$.new" and change["kind"] == "added" for change in changes)

    record = service.persistence_record(draft, result)
    store.save_replay_run(record)
    history = store.list_replay_runs(session.id)
    assert len(history) == 1
    assert history[0]["state"] == "completed"
    assert history[0]["request_fingerprint"] == draft.request_fingerprint
    assert "captured-value" not in str(history[0])


def test_replay_refuses_truncated_request_body_by_default(store, tmp_path: Path) -> None:
    session = CaptureSession("truncated", CaptureSource.BROWSER)
    store.save_capture(session)
    bodies = NetworkBodyStore.for_capture(tmp_path / "captures", session.id, max_body_bytes=4)
    request_body = bodies.put(session.id, "0123456789", content_type="text/plain")
    event = _event(
        session,
        event_id="net-truncated",
        url="https://api.example.test/api/write",
        request_body_ref=request_body.id,
        body_artifacts=[asdict(request_body)],
    )
    store.append_network_events([event])
    resolver = CapturedBodyResolver(store, tmp_path / "captures")
    draft = RequestReplayService().draft_from_exchange(
        store.get_http_exchange_by_event(event.id), body_resolver=resolver
    )
    assert draft.request_body_truncated is True
    with pytest.raises(ArenyxaError) as caught:
        RequestReplayService().replay(draft, confirm_side_effect=True)
    assert caught.value.code == "REPLAY_BODY_TRUNCATED"


def test_network_core_corruption_has_stable_error_code(store) -> None:
    session = CaptureSession("corrupt", CaptureSource.BROWSER)
    store.save_capture(session)
    event = _event(session, event_id="net-corrupt", url="https://api.example.test/api/items")
    store.append_network_events([event])
    with store.connect() as connection:
        connection.execute("UPDATE http_requests SET query_json='{broken' WHERE event_id=?", (event.id,))
        connection.commit()
    with pytest.raises(ArenyxaError) as caught:
        list(store.iter_http_exchanges(session.id))
    assert caught.value.code == "NETWORK_CORE_CORRUPT"
    assert caught.value.context["field"] == "query_json"


def test_v62_database_receives_additive_v63_replay_and_api_map_migration(tmp_path: Path) -> None:
    import sqlite3

    path = tmp_path / "legacy-v62.db"
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
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('api_map_snapshots','api_endpoints','replay_runs')"
            )
        }
    assert applied == set(range(1, len(MIGRATIONS) + 1))
    assert tables == {"api_map_snapshots", "api_endpoints", "replay_runs"}
    assert path.with_name("legacy-v62.pre-migration.bak").is_file()



def test_sensitive_query_values_are_not_persisted_or_auto_replayed(store, tmp_path: Path) -> None:
    session = CaptureSession("query-secret", CaptureSource.BROWSER)
    store.save_capture(session)
    event = _event(
        session,
        event_id="net-query-secret",
        url="https://api.example.test/api/items?page=1&access_token=raw-secret-token",
    )
    store.append_network_events([event])
    exchange = store.get_http_exchange_by_event(event.id)
    assert exchange is not None
    service = RequestReplayService()
    draft = service.draft_from_exchange(exchange)
    assert "raw-secret-token" not in draft.request.url
    assert draft.request.query["access_token"].startswith("${secret.query.")
    assert service.unresolved_secret_refs(draft.request)

    snapshot = ApiMapService().build(session.id, store.iter_http_exchanges(session.id))
    profile = next(item for item in snapshot.endpoints[0].query_parameters if item.name == "access_token")
    assert profile.sensitive is True
    assert profile.examples == []
    assert "raw-secret-token" not in str(snapshot.to_dict())


def test_bounded_body_read_is_never_treated_as_complete(store, tmp_path: Path) -> None:
    session = CaptureSession("partial-read", CaptureSource.BROWSER)
    store.save_capture(session)
    bodies = NetworkBodyStore.for_capture(tmp_path / "captures", session.id, max_body_bytes=64)
    artifact = bodies.put(session.id, b"0123456789", content_type="text/plain")
    event = _event(
        session,
        event_id="net-partial-read",
        url="https://api.example.test/api/write",
        request_body_ref=artifact.id,
        body_artifacts=[asdict(artifact)],
    )
    store.append_network_events([event])
    resolver = CapturedBodyResolver(store, tmp_path / "captures")
    resolved = resolver.resolve(artifact.id, max_bytes=4)
    assert resolved is not None
    assert resolved.payload == b"0123"
    assert resolved.truncated is True


def test_replay_cancellation_is_recorded_as_cancelled(store) -> None:
    session = CaptureSession("cancelled", CaptureSource.BROWSER)
    store.save_capture(session)
    event = _event(session, event_id="net-cancelled", url="https://api.example.test/api/items")
    store.append_network_events([event])
    exchange = store.get_http_exchange_by_event(event.id)
    assert exchange is not None

    class CancelAwareFetcher:
        def fetch(self, spec, token: CancellationToken):
            token.checkpoint()
            raise AssertionError("cancelled token should have raised before fetch body")

    service = RequestReplayService(fetcher=CancelAwareFetcher())
    draft = service.draft_from_exchange(exchange)
    token = CancellationToken()
    token.cancel()
    result = service.execute(draft, token=token)
    assert result.state == "cancelled"
    assert result.error_code == "RUN_CANCELLED"
    store.save_replay_run(service.persistence_record(draft, result))
    assert store.list_replay_runs(session.id)[0]["state"] == "cancelled"

def test_api_map_snapshot_is_persisted_atomically(store) -> None:
    session = CaptureSession("snapshot", CaptureSource.BROWSER)
    store.save_capture(session)
    event = _event(
        session,
        event_id="net-snapshot",
        url="https://api.example.test/graphql?cursor=abc",
    )
    store.append_network_events([event])
    snapshot = ApiMapService().build(session.id, store.iter_http_exchanges(session.id))
    store.save_api_map_snapshot(snapshot.to_dict())
    saved = store.list_api_map_snapshots(session.id)
    endpoints = store.list_api_endpoints(snapshot.id)
    assert saved[0]["id"] == snapshot.id
    assert saved[0]["endpoint_count"] == 1
    assert endpoints[0]["definition"]["graphql"] is True
    assert endpoints[0]["definition"]["pagination_candidates"] == ["cursor"]
