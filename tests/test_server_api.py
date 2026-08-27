from __future__ import annotations

import hashlib

from fastapi.testclient import TestClient

from arenyxa.config import AppPaths
from arenyxa.domain.enums import TaskStatus, WorkspaceRole
from arenyxa.domain.models import RequestSpec, Task
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.server import create_app


def test_headless_server_auth_health_and_task_listing(tmp_path) -> None:
    token = "test-token"
    digest = hashlib.sha256(token.encode()).hexdigest()
    paths = AppPaths.discover(tmp_path / "server")
    paths.initialize()
    store = SQLiteStore(paths.database)
    store.initialize()
    store.save_task(Task("Server Task", [RequestSpec("https://example.com")], status=TaskStatus.READY))

    app = create_app(paths.root, {digest: ("tester", WorkspaceRole.ADMIN)})
    with TestClient(app) as client:
        assert client.get("/health").json()["status"] == "ok"
        assert client.get("/api/v1/tasks").status_code == 401
        response = client.get("/api/v1/tasks", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        assert response.json()[0]["name"] == "Server Task"


def test_headless_server_refuses_data_directory_already_owned_by_runtime(tmp_path) -> None:
    token = "test-token"
    digest = hashlib.sha256(token.encode()).hexdigest()
    data_root = tmp_path / "shared"
    first = create_app(data_root, {digest: ("tester", WorkspaceRole.ADMIN)})
    try:
        import pytest

        with pytest.raises(RuntimeError, match="already in use"):
            create_app(data_root, {digest: ("tester", WorkspaceRole.ADMIN)})
    finally:
        first.state.data_root_lease.release()
