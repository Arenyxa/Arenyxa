from __future__ import annotations

import asyncio
import tomllib
from pathlib import Path

from arenyxa import __package_version__, __version__
from arenyxa.application.async_runner import AsyncRunOrchestrator
from arenyxa.application.traffic_automation import (
    TrafficAction,
    TrafficAutomationEngine,
    TrafficEvent,
)
from arenyxa.infrastructure.async_http_client import AsyncHttpFetcher
from arenyxa.infrastructure.http_client import HttpFetcher

ROOT = Path(__file__).resolve().parents[1]


def test_v78_release_identity_and_architecture_documents() -> None:
    assert __version__ == "8.2"
    assert __package_version__ == "8.2.0"
    assert (ROOT / "docs/architecture/V7_8_ARCHITECTURE_CONSOLIDATION.md").is_file()
    assert (ROOT / "docs/adr/ADR_V78_ASYNC_IO_AND_CAPABILITY_LAYERS.md").is_file()
