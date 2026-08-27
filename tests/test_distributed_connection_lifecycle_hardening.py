from pathlib import Path

from arenyxa.enterprise.distributed import DurableDistributedQueue


def test_distributed_connection_context_always_closes(tmp_path: Path) -> None:
    queue = DurableDistributedQueue(tmp_path / "queue.sqlite3")
    with queue._connection() as connection:
        connection.execute("SELECT 1").fetchone()
    try:
        connection.execute("SELECT 1")
    except Exception as exc:
        assert "closed" in str(exc).lower()
    else:
        raise AssertionError("distributed SQLite handle remained open after context exit")
