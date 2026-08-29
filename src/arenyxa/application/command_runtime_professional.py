from __future__ import annotations
from arenyxa.application.command_runtime_packet import CommandPacketMixin
from arenyxa.application.command_runtime_automation import CommandAutomationMixin
from arenyxa.application.command_runtime_proxy import CommandProxyMixin
from arenyxa.recoverable import record_current_exception

import json
import hashlib
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
from arenyxa.domain.models import CaptureSession, NetworkEvent, Workflow, WorkflowNode, new_id
from arenyxa.application.extraction_studio import ExtractionDryRun, ExtractionField, ExtractionLivePicker, ExtractionStudioService
from arenyxa.application.autopilot_validation import AutopilotProductionValidator
from arenyxa.application.terminal import TerminalMode
from arenyxa.application.terminal_workspace import TerminalWorkspaceManager
from arenyxa.application.workflow_inspector import WorkflowExecutionInspector
from arenyxa.application.workflow_trace import WorkflowRuntimeTrace
from arenyxa.application.workflow_debugger import WorkflowSafeDebugger
from arenyxa.application.extraction_recipe import ExtractionRecipeCompiler
from arenyxa.application.extraction_runtime import ExtractionRecipeExecutor
from arenyxa.application.proxy_deep_inspector import ProxyDeepInspector
from arenyxa.application.packet_analytics import PacketAdvancedAnalyzer
from arenyxa.application.professional_pivot import ProfessionalPivotService
from arenyxa.application.mitm_analytics import MitmFlowAnalyzer
from arenyxa.application.windows_conpty import WindowsConPtySession
from arenyxa.infrastructure.capture.bodies import NetworkBodyStore
from arenyxa.infrastructure.capture.proxy_transport import _header, _parse_raw_message
from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine
from arenyxa.infrastructure.capture.packet_lab import OfflinePacketLab
from arenyxa.infrastructure.capture.detection import PassiveDetectionEngine, ThreatHunter
from arenyxa.enterprise.fleet_telemetry import FleetTelemetryAnalyzer
from arenyxa.enterprise.fleet_live import FleetLiveTelemetry

from arenyxa.application.command_runtime_base import CommandRuntimeError

class CommandProfessionalMixin(CommandPacketMixin, CommandAutomationMixin, CommandProxyMixin):
    def _pivot(self, args: list[str]) -> Any:
        action = self._action(args, "pivot")
        source_id = self._one_id(args, f"pivot {action} <id>")
        service = ProfessionalPivotService(self.context.store)
        if action == "request":
            artifact = service.from_request(source_id)
        elif action == "event":
            artifact = service.from_event(source_id)
        else:
            raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown pivot action: {action}")
        if artifact is None:
            raise CommandRuntimeError("PIVOT_SOURCE_NOT_FOUND", f"Captured HTTP {action} not found: {source_id}", exit_code=4)
        return artifact.snapshot()









