from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

from arenyxa.application.scheduler import SchedulerService, ScheduleRule
from arenyxa.infrastructure.database_adapters import SQLiteDatabaseAdapter


def test_scheduler_fires_and_reports_reschedule() -> None:
    fired = threading.Event()
    persisted: list[tuple[str, datetime]] = []
    scheduler = SchedulerService(lambda schedule_id, next_run: persisted.append((schedule_id, next_run)))
    scheduler.add(
        "schedule_test",
        ScheduleRule(interval_minutes=1, timezone="UTC"),
        fired.set,
        next_run=datetime.now(UTC) + timedelta(milliseconds=50),
    )
    scheduler.start()
    try:
        assert fired.wait(2)
        assert persisted and persisted[0][0] == "schedule_test"
    finally:
        scheduler.stop()


def test_sqlite_database_adapter_streams_and_guards_identifiers(tmp_path) -> None:
    adapter = SQLiteDatabaseAdapter()
    adapter.open({"path": str(tmp_path / "external.db")}, {})
    try:
        adapter.ensure_schema("items", {"name": "TEXT", "value": "INTEGER"})
        assert (
            adapter.bulk_write("items", ({"name": f"n{index}", "value": index} for index in range(5)), 2) == 5
        )
        rows = list(adapter.query("SELECT * FROM items WHERE value >= ? ORDER BY value", (3,)))
        assert [row["value"] for row in rows] == [3, 4]
        try:
            adapter.ensure_schema("items; DROP TABLE items", {"x": "TEXT"})
        except ValueError:
            pass
        else:
            raise AssertionError("unsafe identifier accepted")
    finally:
        adapter.close()


def test_weekly_schedule_requires_at_least_one_weekday() -> None:
    import pytest

    from arenyxa.application.scheduler import ScheduleRule

    with pytest.raises(ValueError):
        ScheduleRule(kind="weekly", weekdays=()).validate()


def test_corrupt_persisted_schedule_rule_is_quarantined(store) -> None:
    from arenyxa.domain.models import RequestSpec, Task, utc_now

    task = Task("schedule-owner", [RequestSpec("https://example.test")])
    store.save_task(task)
    with store.connect() as connection:
        connection.execute(
            "INSERT INTO schedules(id,task_id,rule_json,timezone,enabled,next_run_at,last_run_at,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            ("bad", task.id, "[]", "UTC", 1, None, None, utc_now(), utc_now()),
        )
    rows = store.list_schedules()
    bad = next(item for item in rows if item["id"] == "bad")
    assert bad["rule"] == {}
    assert "rule_error" in bad
