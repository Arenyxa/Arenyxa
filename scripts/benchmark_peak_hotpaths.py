from __future__ import annotations

import base64
import json
import logging
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from arenyxa.domain.enums import RunStatus, TaskStatus
from arenyxa.domain.models import RequestSpec, ResultRecord, Run, Task, utc_now
from arenyxa.enterprise.distributed import DurableDistributedQueue
from arenyxa.enterprise.transport_security import BoundedWindowRateLimiter
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.observability import JsonFormatter, Redactor


class ConnectionCountingStore(SQLiteStore):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.connection_count = 0

    def connect(self) -> sqlite3.Connection:
        self.connection_count += 1
        return super().connect()


def measure(callback: Callable[[], Any], repetitions: int = 1) -> float:
    started = time.perf_counter()
    for _ in range(repetitions):
        callback()
    return time.perf_counter() - started


def main() -> int:
    
    report: dict[str, object] = {
        "schema": "arenyxa.peak-hotpaths/v1",
        "clock": "perf_counter",
    }
    with tempfile.TemporaryDirectory(prefix="arenyxa-hotpaths-") as raw:
        root = Path(raw)
        store = ConnectionCountingStore(root / "main.db")
        store.initialize()

        now = utc_now()
        project_rows = [
            (
                f"project-{index}",
                None,
                f"Project {index}",
                "benchmark",
                "[]",
                now,
                now,
                7,
            )
            for index in range(1_000)
        ]
        with store.transaction() as connection:
            connection.executemany(
                "INSERT INTO projects(id,workspace_id,name,description,tags_json,created_at,updated_at,schema_version) "
                "VALUES(?,?,?,?,?,?,?,?)",
                project_rows,
            )
        store.connection_count = 0
        report["list_projects_1000_seconds"] = round(
            measure(lambda: store.list_projects(limit=1_000)), 6
        )
        report["list_projects_1000_connections"] = store.connection_count

        task = Task(
            "benchmark",
            [RequestSpec("https://example.test")],
            id="benchmark-task",
            status=TaskStatus.READY,
        )
        run = Run(task.id, task.to_dict(), id="benchmark-run", status=RunStatus.RUNNING)
        store.save_task(task)
        store.save_run(run)
        records = [
            ResultRecord(
                task.id,
                run.id,
                f"https://example.test/{index}",
                {"index": index, "payload": "x" * 32},
            )
            for index in range(5_000)
        ]
        report["append_results_5000_seconds"] = round(
            measure(lambda: store.append_results(records, batch_size=500)), 6
        )
        report["append_results_5000_count"] = store.count_results(run.id)
        report["append_results_5000_duplicate_seconds"] = round(
            measure(lambda: store.append_results(records, batch_size=500)), 6
        )
        report["dashboard_metrics_250_seconds"] = round(
            measure(store.dashboard_metrics, repetitions=250), 6
        )

        queue = DurableDistributedQueue(root / "distributed.db")
        public_key = base64.urlsafe_b64encode(bytes(range(32))).decode("ascii").rstrip("=")
        queue.register_worker("benchmark-worker", public_key, {"cpu": 8})
        report["empty_lease_poll_250_seconds"] = round(
            measure(lambda: queue.lease_next("benchmark-worker"), repetitions=250), 6
        )

    limiter = BoundedWindowRateLimiter(4_096)
    report["rate_limiter_100k_seconds"] = round(
        measure(lambda: limiter.allow("peer", limit=200_000), repetitions=100_000), 6
    )

    formatter = JsonFormatter(Redactor())
    record = logging.LogRecord(
        "arenyxa.benchmark",
        logging.INFO,
        __file__,
        1,
        "normal enterprise request completed",
        (),
        None,
    )
    record.context = {"worker_id": "worker-a", "status": "completed"}
    rendered = formatter.format(record)
    report["json_log_bytes"] = len(rendered.encode("utf-8"))
    report["json_log_format_20k_seconds"] = round(
        measure(lambda: formatter.format(record), repetitions=20_000), 6
    )

    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
