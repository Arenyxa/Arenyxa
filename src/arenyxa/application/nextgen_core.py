from __future__ import annotations

from arenyxa.infrastructure.process_safety import validated_argv
from arenyxa.compat import path_is_relative_to
import base64
import hashlib
import json
import logging
import math
import os
import re
import shutil
import subprocess
import sys
import statistics
import threading
import time
import urllib.error
import urllib.request
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, field
from arenyxa.compat import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse
from cryptography.fernet import Fernet, InvalidToken
from lxml import etree, html
from arenyxa import __version__
from arenyxa.application.advanced import SmartExecutionPlanner
from arenyxa.application.autopilot import AutopilotEngine, ExperienceStore
from arenyxa.application.reliability import ResourceLeasePool
from arenyxa.application.competitive import (
    CompatibilityLab, ContextBridgeService, ReliabilityAdvisor,
    WebIntelligenceEngine, WorkflowPortabilityService,
)
from arenyxa.application.runtime_ecosystem import BrowserProfileService, RegressionLab, WorkflowMarketplaceService
from arenyxa.application.web_intelligence import WebIntelligenceCenter, WebTimeMachine
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import FetchResponse, NetworkEvent, RequestSpec, RetryPolicy, Workflow, WorkflowNode, new_id, utc_now
from arenyxa.infrastructure.http_client import HttpFetcher
from arenyxa.infrastructure.atomic_io import atomic_write_bytes, atomic_write_json, read_bytes_limited, read_text_limited
from arenyxa.platform_compat import select_runtime

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ActivityEvent:
    kind: str
    message: str
    level: str = "info"
    details: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("activity"))
    timestamp: str = field(default_factory=utc_now)

class ActivityCenter:
    






    def __init__(self, capacity: int = 1000) -> None:
        self.capacity = max(100, min(20_000, int(capacity)))
        self._events: deque[ActivityEvent] = deque(maxlen=self.capacity)
        self._lock = threading.RLock()
        self._subscribers: list[Callable[[ActivityEvent], None]] = []

    def publish(self, kind: str, message: str, *, level: str = "info", details: Mapping[str, Any] | None = None) -> ActivityEvent:
        event = ActivityEvent(kind=kind, message=message, level=level, details=dict(details or {}))
        with self._lock:
            self._events.append(event)
            subscribers = tuple(self._subscribers)
        for callback in subscribers:
            try:
                callback(event)
            except Exception:
                                                                                              
                                                                                    
                LOGGER.exception("Activity Center subscriber callback failed for event %s", event.kind)
        return event

    def snapshot(self, limit: int = 200) -> list[ActivityEvent]:
        with self._lock:
            items = list(self._events)
        return items[-max(1, min(5000, int(limit))):]

    def subscribe(self, callback: Callable[[ActivityEvent], None]) -> Callable[[], None]:
        with self._lock:
            self._subscribers.append(callback)

        def unsubscribe() -> None:
            with self._lock:
                if callback in self._subscribers:
                    self._subscribers.remove(callback)

        return unsubscribe

