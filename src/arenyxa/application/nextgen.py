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
from arenyxa.application.crawler_web_intelligence import CrawlerWebIntelligencePipeline
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import FetchResponse, NetworkEvent, RequestSpec, RetryPolicy, Workflow, WorkflowNode, new_id, utc_now
from arenyxa.infrastructure.http_client import HttpFetcher
from arenyxa.infrastructure.atomic_io import atomic_write_bytes, atomic_write_json, read_bytes_limited, read_text_limited
from arenyxa.platform_compat import select_runtime

LOGGER = logging.getLogger(__name__)

from arenyxa.application.nextgen_core import ActivityCenter, ActivityEvent
from arenyxa.application.nextgen_browser import (
    BrowserAction, BrowserRecorderService, HealCandidate, SelectorCandidate, SelectorFingerprint, SelectorStudio, SemanticStage,
)
from arenyxa.application.nextgen_http import (
    AdaptiveRateLimiter, DataQualityStudio, DataSourceCandidate, DataSourceDiscovery, HttpRequestWorkbench, ProtocolInspector,
    RateDecision, RequestAssertion, RequestCodeGenerator, SchemaInference, SmartPathV2, SmartPathV2Result,
)
from arenyxa.application.nextgen_runtime import (
    DistributedWorker, DistributedWorkerService, ProjectEnvironmentService, ProjectPythonEnvironmentService, SecretVault,
)
from arenyxa.application.nextgen_workflow import DebugSnapshot, WorkflowDebugger, WorkflowTemplateLibrary, WorkflowVariables

@dataclass(slots=True)
class NextGenFeatureHub:
    selector: SelectorStudio
    recorder: BrowserRecorderService
    request: HttpRequestWorkbench
    protocols: ProtocolInspector
    sources: DataSourceDiscovery
    smartpath: SmartPathV2
    quality: DataQualityStudio
    vault: SecretVault
    projects: ProjectEnvironmentService
    variables: WorkflowVariables
    templates: WorkflowTemplateLibrary
    activity: ActivityCenter
    python_envs: ProjectPythonEnvironmentService
    workers: DistributedWorkerService
    browser_profiles: BrowserProfileService
    marketplace: WorkflowMarketplaceService
    regression: RegressionLab
    intelligence: WebIntelligenceEngine
    context_bridge: ContextBridgeService
    portability: WorkflowPortabilityService
    compatibility: CompatibilityLab
    reliability: ReliabilityAdvisor
    web_intelligence: WebIntelligenceCenter
    crawler_intelligence: CrawlerWebIntelligencePipeline
    time_machine: WebTimeMachine
    autopilot: AutopilotEngine

    @classmethod
    def create(
        cls, *, data_root: Path, projects_root: Path, max_response_bytes: int,
        browser_pool: ResourceLeasePool | None = None,
    ) -> "NextGenFeatureHub":
        vault = SecretVault(data_root / "secure")
        projects = ProjectEnvironmentService(projects_root)
        request = HttpRequestWorkbench(max_response_bytes)
        smartpath = SmartPathV2()
        intelligence = WebIntelligenceEngine(smartpath)
        selector = SelectorStudio()
        recorder = BrowserRecorderService(browser_pool)
        protocols = ProtocolInspector()
        sources = DataSourceDiscovery()
        context_bridge = ContextBridgeService(request.generator)
        time_machine = WebTimeMachine(data_root / "intelligence" / "time_machine.json")
        web_intelligence = WebIntelligenceCenter(
            intelligence=intelligence,
            sources=sources,
            protocols=protocols,
            context_bridge=context_bridge,
            selector=selector,
            recorder=recorder,
            time_machine=time_machine,
        )
        crawler_intelligence = CrawlerWebIntelligencePipeline(web_intelligence)
        experience = ExperienceStore(data_root / "intelligence" / "experience.db")
        autopilot = AutopilotEngine(smartpath, experience)
        return cls(
            selector=selector,
            recorder=recorder,
            request=request,
            protocols=protocols,
            sources=sources,
            smartpath=smartpath,
            quality=DataQualityStudio(),
            vault=vault,
            projects=projects,
            variables=WorkflowVariables(),
            templates=WorkflowTemplateLibrary(),
            activity=ActivityCenter(),
            python_envs=ProjectPythonEnvironmentService(projects),
            workers=DistributedWorkerService(data_root / "workers", vault),
            browser_profiles=BrowserProfileService(data_root / "profiles"),
            marketplace=WorkflowMarketplaceService(),
            regression=RegressionLab(),
            intelligence=intelligence,
            context_bridge=context_bridge,
            portability=WorkflowPortabilityService(),
            compatibility=CompatibilityLab(intelligence),
            reliability=ReliabilityAdvisor(),
            web_intelligence=web_intelligence,
            crawler_intelligence=crawler_intelligence,
            time_machine=time_machine,
            autopilot=autopilot,
        )

