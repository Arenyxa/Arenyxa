from __future__ import annotations

import asyncio
import hashlib
from types import SimpleNamespace

import httpx
import pytest

from arenyxa.domain.enums import WorkspaceRole
from arenyxa.enterprise.server_api import CORRELATION_HEADER, create_enterprise_server_app
from arenyxa.infrastructure.data_root_lock import DataRootLease
from arenyxa.infrastructure.server import create_app


@pytest.mark.asyncio
async def test_headless_server_lifespan_releases_data_root_lease(tmp_path) -> None:
    """The async lifespan must release the exclusive data-root lease on shutdown."""
    token = "async-lifecycle-token"
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    app = create_app(tmp_path, {digest: ("async-admin", WorkspaceRole.ADMIN)})

    async with app.router.lifespan_context(app):
        contender = DataRootLease(tmp_path)
        assert contender.acquire() is False

    contender = DataRootLease(tmp_path)
    assert contender.acquire() is True
    contender.release()


@pytest.mark.asyncio
async def test_enterprise_transport_guard_sets_security_headers_and_correlation_id() -> None:
    """The async HTTP middleware must preserve correlation and no-store boundaries."""
    app = create_enterprise_server_app(SimpleNamespace(), {"server_id": "test"})
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://arenyxa.test") as client:
        response = await client.get(
            "/enterprise/v1/live",
            headers={CORRELATION_HEADER: "async-boundary-1"},
        )

    assert response.status_code == 200
    assert response.headers[CORRELATION_HEADER] == "async-boundary-1"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.asyncio
async def test_enterprise_transport_guard_rejects_mismatched_body_length_before_dispatch() -> None:
    """Malformed async request bodies must fail before enterprise runtime methods execute."""
    app = create_enterprise_server_app(SimpleNamespace(), {"server_id": "test"})
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://arenyxa.test") as client:
        response = await client.post(
            "/enterprise/v1/worker/challenge",
            content=b"{}",
            headers={"content-length": "3"},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "content-length mismatch"


@pytest.mark.asyncio
async def test_enterprise_transport_guard_handles_concurrent_live_requests() -> None:
    """Concurrent ASGI requests exercise the middleware's async path and semaphore accounting."""
    app = create_enterprise_server_app(SimpleNamespace(), {"server_id": "test"})
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://arenyxa.test") as client:
        responses = await asyncio.gather(*(client.get("/enterprise/v1/live") for _ in range(16)))

    assert all(response.status_code == 200 for response in responses)
    assert all(CORRELATION_HEADER in response.headers for response in responses)
