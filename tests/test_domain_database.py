from __future__ import annotations

from arenyxa.domain.enums import CaptureSource, CaptureState, RunStatus, TaskStatus
from arenyxa.domain.models import CaptureSession, NetworkEvent, RequestSpec, ResultRecord, Run, Task


def sample_task() -> Task:
    return Task("Example", [RequestSpec("https://example.com")], status=TaskStatus.READY)


def test_task_validation_and_snapshot_are_deterministic() -> None:
    invalid = Task("", [RequestSpec("file:///etc/passwd")])
    assert invalid.validate()
    task = sample_task()
    assert task.validate() == []
    assert task.snapshot_hash() == task.snapshot_hash()


def test_request_validation_handles_corrupt_types_without_raising() -> None:
    spec = RequestSpec("https://example.com")
    spec.method = None                            
    spec.connect_timeout = float("nan")
    spec.read_timeout = "bad"                            
    spec.headers = []                            
    spec.retry.attempts = "2"                            
    errors = spec.validate()
    assert errors
    assert any("HTTP 方法" in item for item in errors)
    assert any("读取超时" in item for item in errors)
    assert any("重试次数" in item for item in errors)


def test_store_roundtrip_results_search_and_metrics(store) -> None:
    task = sample_task()
    store.save_task(task)
    loaded = store.get_task(task.id)
    assert loaded and loaded.name == "Example"

    run = Run(task.id, task.to_dict(), status=RunStatus.COMPLETED, result_count=2)
    store.save_run(run)
    records = [
        ResultRecord(task.id, run.id, "https://example.com/a", {"title": "Alpha", "rank": 1}),
        ResultRecord(task.id, run.id, "https://example.com/b", {"title": "Beta", "rank": 2}),
    ]
    assert store.append_results(records) == 2
    assert store.count_results(run.id) == 2
    assert {row["title"] for row in store.result_page(run.id, 0, 2)} == {"Alpha", "Beta"}
    store.index_object("result", records[0].id, "Alpha page", records[0].source_url, "searchable")
    assert store.search("Alpha")[0]["object_id"] == records[0].id
    metrics = store.dashboard_metrics()
    assert metrics["tasks"] == 1
    assert metrics["records"] == 2
    assert store.integrity_check() == "ok"


def test_capture_roundtrip(store) -> None:
    session = CaptureSession("capture", CaptureSource.BROWSER, state=CaptureState.CAPTURING)
    store.save_capture(session)
    event = NetworkEvent(
        session.id,
        CaptureSource.BROWSER,
        "https",
        "bidirectional",
        123,
        method="GET",
        url="https://example.com/api/items",
        status=200,
        host="example.com",
        timing={"total_ms": 42.5},
    )
    assert store.append_network_events([event]) == 1
    restored = list(store.iter_network_events(session.id))
    assert restored[0]["host"] == "example.com"
    assert restored[0]["timing"]["total_ms"] == 42.5


def test_corrupt_task_definition_does_not_break_task_listing(store) -> None:
    good = sample_task()
    store.save_task(good)
    with store.connect() as connection:
        connection.execute(
            "INSERT INTO tasks(id,name,status,tags_json,parser_hint,definition_json,snapshot_hash,created_at,updated_at,schema_version,deleted_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,NULL)",
            ("task_corrupt", "Broken", "ready", "[]", "auto", "{bad-json", "x", "2026-01-01", "2026-01-01", 1),
        )
    tasks = store.list_tasks()
    assert [task.id for task in tasks] == [good.id]
    from arenyxa.domain.errors import ArenyxaError

    try:
        store.get_task("task_corrupt")
    except ArenyxaError as exc:
        assert exc.code == "TASK_DEFINITION_CORRUPT"
    else:
        raise AssertionError("corrupt task must raise a stable domain error when loaded directly")
