from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import json
import hashlib
import os
import shlex
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any, Iterable
from arenyxa import __version__
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


class CommandAutomationMixin:
    def _automation(self, args: list[str]) -> Any:
        action = self._action(args, "automation")
        if action == "list":
            self._expect_count(args, 0, 0, "automation list")
            return self.context.store.list_schedules()
        if action == "show":
            schedule_id = self._one_id(args, "automation show <schedule_id>")
            return self._schedule_row(schedule_id)
        if action == "add":
            task_id = self._required_option(args, "--task")
            task = self.context.store.get_task(task_id)
            if task is None:
                raise CommandRuntimeError("TASK_NOT_FOUND", f"Task not found: {task_id}", exit_code=4)
            kind = self._option(args, "--kind", default="interval").casefold()
            timezone = self._option(args, "--timezone", default="UTC")
            interval_raw = self._option(args, "--minutes", default="60")
            hour_raw = self._option(args, "--hour", default="2")
            minute_raw = self._option(args, "--minute", default="0")
            weekdays_raw = self._option(args, "--weekdays", default="0,1,2,3,4,5,6")
            disabled = self._pop_flag(args, "--disabled")
            self._expect_count(args, 0, 0, "automation add")
            try:
                interval_minutes = int(interval_raw)
                hour = int(hour_raw)
                minute = int(minute_raw)
                weekdays = tuple(int(item.strip()) for item in weekdays_raw.split(",") if item.strip())
            except ValueError as exc:
                raise CommandRuntimeError("USAGE", "Automation numeric options must contain integers") from exc
            rule = ScheduleRule(
                kind=kind, interval_minutes=interval_minutes, hour=hour, minute=minute,
                weekdays=weekdays, timezone=timezone,
            )
            try:
                rule.validate()
                next_run = rule.next_after(datetime.now(UTC))
            except ValueError as exc:
                raise CommandRuntimeError("USAGE", str(exc)) from exc
            schedule_id = new_id("schedule")
            enabled = not disabled
            row = {
                "id": schedule_id, "task_id": task_id, "rule": asdict(rule), "timezone": rule.timezone,
                "enabled": enabled, "next_run_at": next_run.isoformat(),
            }
            self.context.store.save_schedule(row)
            self.context.scheduler.add(
                schedule_id, rule, self._schedule_callback(task_id, schedule_id),
                enabled=enabled, next_run=next_run,
            )
            return self._schedule_row(schedule_id)
        if action in {"enable", "disable"}:
            schedule_id = self._one_id(args, f"automation {action} <schedule_id>")
            self._schedule_row(schedule_id)
            enabled = action == "enable"
            try:
                self.context.scheduler.set_enabled(schedule_id, enabled)
            except KeyError as exc:
                raise CommandRuntimeError("SCHEDULE_NOT_LOADED", f"Schedule is not loaded: {schedule_id}", exit_code=5) from exc
            self.context.store.update_schedule_enabled(schedule_id, enabled)
            return self._schedule_row(schedule_id)
        if action == "remove":
            schedule_id = self._one_id(args, "automation remove <schedule_id>")
            self._schedule_row(schedule_id)
            self.context.scheduler.remove(schedule_id)
            removed = self.context.store.delete_schedule(schedule_id)
            return {"schedule_id": schedule_id, "removed": bool(removed)}
        if action == "run-now":
            schedule_id = self._one_id(args, "automation run-now <schedule_id>")
            row = self._schedule_row(schedule_id)
            task_id = str(row.get("task_id") or "")
            task = self.context.store.get_task(task_id)
            if task is None:
                raise CommandRuntimeError("TASK_NOT_FOUND", f"Task not found: {task_id}", exit_code=4)
            operations = getattr(self.context, "enterprise_operations", None)
            if operations is not None:
                operations.authorize_if_bound(
                    "schedule", schedule_id, "schedule.manage", correlation_id=f"schedule-cli:{schedule_id}",
                )
            handle = self.context.runner.submit(task)
            return {"schedule_id": schedule_id, "task_id": task_id, "run_id": handle.run.id, "status": handle.run.status.value}
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown automation action: {action}")

    def _dataset(self, args: list[str]) -> Any:
        action = self._action(args, "dataset")
        if action == "list":
            return self.context.store.list_datasets(limit=self._limit(args, default=100, maximum=500))
        if action == "show":
            dataset_id = self._one_id(args, "dataset show <dataset_id>")
            row = self.context.store.get_dataset(dataset_id)
            if row is None:
                raise CommandRuntimeError("DATASET_NOT_FOUND", f"Dataset not found: {dataset_id}", exit_code=4)
            return row
        if action == "revisions":
            dataset_id = self._one_id_allow_flags(args, "dataset revisions <dataset_id> [--limit N]")
            limit = self._limit(args, default=100, maximum=500)
            rows = self.context.store.list_revisions(dataset_id)
            return rows[:limit]
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown dataset action: {action}")

    def _flow(self, args: list[str]) -> Any:
        action = self._action(args, "flow")
        if action == "list":
            self._expect_count(args, 0, 0, "flow list")
            return self.context.store.list_workflows()
        if action == "show":
            workflow_id = self._one_id(args, "flow show <workflow_id>")
            row = self.context.store.get_workflow(workflow_id)
            if row is None:
                raise CommandRuntimeError("FLOW_NOT_FOUND", f"Flow not found: {workflow_id}", exit_code=4)
            return row
        if action == "executions":
            workflow_id = args.pop(0) if args and not args[0].startswith("--") else None
            limit = self._limit(args, default=100, maximum=500)
            return self.context.store.list_workflow_executions(workflow_id=workflow_id, limit=limit)
        if action == "inspect-execution":
            execution_id = self._one_id(args, "flow inspect-execution <execution_id>")
            try:
                return WorkflowExecutionInspector(self.context.store).inspect(execution_id).snapshot()
            except KeyError as exc:
                raise CommandRuntimeError("FLOW_EXECUTION_NOT_FOUND", str(exc), exit_code=4) from exc
        if action in {"trace", "step-plan"}:
            execution_id = self._one_id(args, f"flow {action} <execution_id>")
            try:
                runtime_trace = WorkflowRuntimeTrace(self.context.store)
                return runtime_trace.trace(execution_id) if action == "trace" else runtime_trace.step_plan(execution_id)
            except KeyError as exc:
                raise CommandRuntimeError("FLOW_EXECUTION_NOT_FOUND", str(exc), exit_code=4) from exc
        if action == "safe-debug":
            if not args or args[0].startswith("--"):
                raise CommandRuntimeError(
                    "USAGE",
                    "Usage: flow safe-debug <workflow_id> --input-json <json-array> [--breakpoints a,b] [--max-steps N]",
                )
            workflow_id = args.pop(0)
            raw_inputs = self._required_option(args, "--input-json")
            breakpoints_raw = self._option(args, "--breakpoints", default="")
            max_steps_raw = self._option(args, "--max-steps", default="5000")
            self._expect_count(args, 0, 0, "flow safe-debug")
            row = self.context.store.get_workflow(workflow_id)
            if row is None:
                raise CommandRuntimeError("FLOW_NOT_FOUND", f"Flow not found: {workflow_id}", exit_code=4)
            try:
                decoded = json.loads(raw_inputs)
                if not isinstance(decoded, list) or any(not isinstance(item, dict) for item in decoded):
                    raise ValueError("--input-json must decode to an array of objects")
                max_steps = int(max_steps_raw)
                nodes = [
                    WorkflowNode(
                        kind=str(item.get("kind") or ""),
                        config=dict(item.get("config") or {}),
                        id=str(item.get("id") or ""),
                        next_ids=[str(value) for value in list(item.get("next_ids") or [])],
                        failure_ids=[str(value) for value in list(item.get("failure_ids") or [])],
                    )
                    for item in list(row.get("nodes") or []) if isinstance(item, dict)
                ]
                workflow = Workflow(
                    name=str(row.get("name") or "Workflow"),
                    nodes=nodes,
                    id=str(row.get("id") or workflow_id),
                    version=str(row.get("version") or "1.0.0"),
                )
                breakpoints = [value.strip() for value in breakpoints_raw.split(",") if value.strip()]
                return WorkflowSafeDebugger(self.context.workflows).simulate(
                    workflow, decoded, breakpoints=breakpoints, max_steps=max_steps
                ).snapshot()
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise CommandRuntimeError("USAGE", f"Invalid safe-debug input: {exc}") from exc
        if action == "run":
            if len([item for item in args if not item.startswith("--")]) < 3:
                raise CommandRuntimeError(
                    "USAGE",
                    "Usage: flow run <workflow_id> <source_revision_id> <output_dataset_id> [--max-outputs N]",
                )
            workflow_id = args.pop(0)
            source_revision_id = args.pop(0)
            output_dataset_id = args.pop(0)
            max_outputs_raw = self._option(args, "--max-outputs", default="")
            self._expect_count(args, 0, 0, "flow run")
            max_outputs = None
            if max_outputs_raw:
                try:
                    max_outputs = int(max_outputs_raw)
                except ValueError as exc:
                    raise CommandRuntimeError("USAGE", "--max-outputs must be an integer") from exc
                if not 1 <= max_outputs <= 1_000_000:
                    raise CommandRuntimeError("USAGE", "--max-outputs must be between 1 and 1000000")
            result = self.context.workflow_runtime.execute_saved_workflow(
                workflow_id, source_revision_id, output_dataset_id, max_outputs=max_outputs
            )
            return self._normalize(result)
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown flow action: {action}")

    def _fleet(self, args: list[str]) -> Any:
        action = self._action(args, "fleet")
        server = getattr(self.context, "enterprise_server", None)
        if server is None:
            raise CommandRuntimeError("FLEET_UNAVAILABLE", "Enterprise Server runtime is unavailable", exit_code=5)
        if action in {"status", "health"}:
            self._expect_count(args, 0, 0, f"fleet {action}")
            snapshot = server.remote_ops_snapshot()
            if action == "health":
                return {"queue": snapshot.get("queue"), "workers": snapshot.get("workers", [])}
            return snapshot
        if action == "metrics":
            self._expect_count(args, 0, 0, "fleet metrics")
            return FleetTelemetryAnalyzer().analyze(server.remote_ops_snapshot()).snapshot()
        if action in {"live", "events"}:
            self._expect_count(args, 0, 0, f"fleet {action}")
            live = getattr(self.context, "fleet_live_telemetry", None)
            if live is None:
                live = FleetLiveTelemetry()
                self.context.fleet_live_telemetry = live
            live.ingest(server.remote_ops_snapshot())
            snapshot = live.snapshot()
            return snapshot if action == "live" else snapshot["events"]
        if action == "workers":
            limit = self._limit(args, default=100, maximum=1000)
            snapshot = server.remote_ops_snapshot()
            return list(snapshot.get("workers", []))[:limit]
        if action == "jobs":
            state = self._option(args, "--state", default="")
            limit = self._limit(args, default=100, maximum=1000)
            snapshot = server.remote_ops_snapshot()
            rows = list(snapshot.get("jobs", []))
            if state:
                rows = [row for row in rows if str(row.get("state", "")).casefold() == state.casefold()]
            return rows[:limit]
        if action == "export-snapshot":
            if not args or args[0].startswith("--"):
                raise CommandRuntimeError("USAGE", "Usage: fleet export-snapshot <path>")
            destination = self._confined_export_path(args.pop(0))
            self._expect_count(args, 0, 0, "fleet export-snapshot")
            snapshot = server.remote_ops_snapshot()
            payload = json.dumps(snapshot, ensure_ascii=False, indent=2, default=str) + "\n"
            if len(payload.encode("utf-8")) > 8 * 1024 * 1024:
                raise CommandRuntimeError("EXPORT_TOO_LARGE", "Fleet snapshot exceeds the 8 MiB export budget", exit_code=5)
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(f".{destination.name}.tmp")
            try:
                temporary.write_text(payload, encoding="utf-8")
                os.replace(temporary, destination)
            finally:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    record_current_exception(__name__, 'CommandProfessionalMixin._fleet:618')
            return {"path": str(destination), "bytes": len(payload.encode("utf-8")), "workers": len(snapshot.get("workers", [])), "jobs": len(snapshot.get("jobs", []))}
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown fleet action: {action}")
