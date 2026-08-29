"""Stable facade for the Arenyxa command control plane."""
from __future__ import annotations

import json
import os
import shlex
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any, Iterable
from arenyxa import __display_version__ as __version__
from arenyxa.application.developer_safety import authorization_from_settings
from arenyxa.application.scheduler import ScheduleRule
from arenyxa.compat import UTC
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.models import NetworkEvent, new_id
from arenyxa.application.extraction_studio import ExtractionDryRun, ExtractionField, ExtractionLivePicker, ExtractionStudioService
from arenyxa.application.autopilot_validation import AutopilotProductionValidator
from arenyxa.application.terminal import TerminalMode
from arenyxa.application.terminal_workspace import TerminalWorkspaceManager
from arenyxa.application.workflow_inspector import WorkflowExecutionInspector
from arenyxa.application.workflow_trace import WorkflowRuntimeTrace
from arenyxa.application.extraction_recipe import ExtractionRecipeCompiler
from arenyxa.application.extraction_runtime import ExtractionRecipeExecutor
from arenyxa.application.proxy_deep_inspector import ProxyDeepInspector
from arenyxa.application.packet_analytics import PacketAdvancedAnalyzer
from arenyxa.application.mitm_analytics import MitmFlowAnalyzer
from arenyxa.application.windows_conpty import WindowsConPtySession
from arenyxa.infrastructure.capture.bodies import NetworkBodyStore
from arenyxa.enterprise.fleet_telemetry import FleetTelemetryAnalyzer
from arenyxa.enterprise.fleet_live import FleetLiveTelemetry

from arenyxa.application.command_runtime_base import CommandRuntimeError
from arenyxa.application.command_runtime_core import CommandCoreMixin
from arenyxa.application.command_runtime_professional import CommandProfessionalMixin
from arenyxa.application.command_runtime_platform import CommandPlatformMixin
from arenyxa.application.command_runtime_terminal import CommandTerminalMixin
from arenyxa.application.command_runtime_render import CommandRenderMixin
from arenyxa.application.command_runtime_v8 import CommandV8Mixin

class ArenyxaCommandRuntime(
    CommandCoreMixin,
    CommandProfessionalMixin,
    CommandPlatformMixin,
    CommandTerminalMixin,
    CommandV8Mixin,
    CommandRenderMixin,
):
    """Shared command runtime used by GUI, headless CLI, and automation callers."""
    COMMAND_TREE: dict[str, tuple[str, ...]] = {
        "status": (),
        "permissions": (),
        "whoami": (),
        "version": (),
        "health-check": (),
        "diagnostics": ("export",),
        "resilience": ("status", "refresh", "drills", "performance"),
        "job": ("list", "show", "wait", "cancel"),
        "traffic": ("status", "protocols", "fields", "decode", "analyze", "proxy-status", "mitm-status"),
        "task": ("list", "show", "run"),
        "run": ("list", "show", "cancel", "pause", "resume", "export"),
        "capture": ("start", "browser", "har-import", "pcap-import", "stop", "list", "status", "events", "intelligence", "alerts", "rules", "rule-load", "stream-stats"),
        "packet": ("sessions", "events", "http", "hosts", "summary", "conversations", "analytics", "detect", "hunt", "build", "protocols", "fields"),
        "pivot": ("request", "event"),
        "extraction": ("analyze", "dry-run", "pick", "recipe-validate", "recipe-compile", "recipe-run"),
        "web": ("autopilot-status", "autopilot-validate"),
        "automation": ("list", "show", "add", "enable", "disable", "remove", "run-now"),
        "dataset": ("list", "show", "revisions"),
        "flow": ("list", "show", "executions", "inspect-execution", "trace", "step-plan", "safe-debug", "run"),
        "fleet": ("status", "workers", "jobs", "health", "metrics", "live", "events", "export-snapshot"),
        "proxy": (
            "status", "start", "stop", "history", "inspect", "sessions", "history-health", "cleanup", "summary", "deep-inspect", "compare", "timeline", "pending", "resolve", "replay", "intercept", "export-har",
            "autoresponder-list", "autoresponder-add", "autoresponder-remove",
            "match-list", "match-add", "match-remove",
        ),
        "tls": ("status", "certificates", "export-root"),
        "api": ("analyze", "openapi"),
        "analyze": ("traffic",),
        "export": ("session",),
        "enterprise": ("status", "governance", "enrollment", "storage", "workers", "jobs", "worker-drain", "worker-resume", "worker-revoke", "retry-job", "recover-leases", "server-authority-start", "server-authority-stop", "audit"),
        "platform": ("status", "windows", "service-status", "service-install", "service-start", "service-stop", "service-remove", "event"),
        "recovery": ("check", "repair"),
        "traffic-automation": ("list", "add", "remove", "run"),
        "mitm": ("status", "start", "stop", "flows", "analytics", "pending", "resolve", "export", "replay-current"),
        "plugin": ("list", "health"),
        "terminal": (
            "permissions", "whoami", "capabilities", "net-capabilities", "net-resolve", "net-reverse", "net-dns", "net-tcp", "net-tls",
            "net-interfaces", "net-sockets", "net-service", "net-protocol",
            "packet-capabilities", "packet-protocols", "packet-fields", "packet-decode",
            "packet-info", "packet-summary", "packet-frame", "packet-stats", "run",
            "session-list", "session-create", "session-send", "session-output", "session-rename",
            "session-move", "session-resize", "session-interrupt", "session-stop", "session-close",
        ),
    }

    def __init__(self, context: Any) -> None:
        self.context = context

    def _terminal_workspace(self) -> TerminalWorkspaceManager:
        workspace = getattr(self.context, "terminal_workspace", None)
        if workspace is None:
            workspace = TerminalWorkspaceManager(self.context.paths.projects)
            self.context.terminal_workspace = workspace
        return workspace

    def developer_authorized(self) -> bool:
        manager = getattr(self.context, "developer_access", None)
        try:
            status = manager.status() if manager is not None else None
        except (ArenyxaError, OSError, RuntimeError, ValueError, TypeError):
            status = None
        if status is not None and status.authenticated:
            if bool(getattr(self.context, "root_developer_workstation", False)):
                if "platform.root" in status.capabilities:
                    return True
                # A stale process marker must never outlive Root cryptographic authority.
                self.context.root_developer_workstation = False
            else:
                # Official Developer sessions are sufficient for the professional command
                # plane; individual privileged operations still enforce capabilities.
                return True
        elif bool(getattr(self.context, "root_developer_workstation", False)):
            self.context.root_developer_workstation = False
        return bool(authorization_from_settings(self.context.settings).valid)

    def require_developer(self) -> None:
        if not self.developer_authorized():
            raise CommandRuntimeError(
                "DEVELOPER_MODE_REQUIRED",
                "Developer Mode is required and its risk agreement must be accepted before using the Arenyxa command runtime.",
                exit_code=3,
            )
