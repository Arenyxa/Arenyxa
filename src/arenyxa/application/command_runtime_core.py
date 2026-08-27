from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import json
import os
import shlex
import shutil
import sqlite3
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any, Iterable
from arenyxa import __version__
from arenyxa.application.developer_safety import authorization_from_settings
from arenyxa.application.scheduler import ScheduleRule
from arenyxa.compat import UTC
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.models import CaptureSession, NetworkEvent, new_id, utc_now
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
from arenyxa.infrastructure.capture.adapters import TsharkPacketAdapter
from arenyxa.infrastructure.capture.browser_adapter import BrowserCaptureAdapter
from arenyxa.infrastructure.capture.har import HarAnalyzer
from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine
from arenyxa.infrastructure.capture.live_intelligence import LiveIntelligencePipeline
from arenyxa.infrastructure.capture.event_stream import BoundedEventStream
from arenyxa.infrastructure.atomic_io import read_text_limited
from arenyxa.enterprise.fleet_telemetry import FleetTelemetryAnalyzer
from arenyxa.enterprise.fleet_live import FleetLiveTelemetry

from arenyxa.application.command_runtime_base import CommandRuntimeError

class CommandCoreMixin:
    def execute(self, command: str) -> dict[str, Any]:
        raw = str(command or "").strip()
        if not raw:
            raise CommandRuntimeError("COMMAND_EMPTY", "Command is empty")
        pipeline = self._split_pipeline(raw)
        base = pipeline[0]
        tokens = self._split(base)
        if tokens and tokens[0].casefold() in {"arenyxa", "arenyxa-cli"}:
            tokens = tokens[1:]
        if not tokens:
            raise CommandRuntimeError("COMMAND_EMPTY", "Command is empty")
        json_output = self._pop_flag(tokens, "--json") or any("--json" in self._split(stage) for stage in pipeline[1:])
        if tokens[0].casefold() in {"help", "?"}:
            payload = self.help(tokens[1] if len(tokens) > 1 else "")
            return self._result(raw, payload, json_output=json_output)
        if tokens[0].casefold() == "version":
            return self._result(raw, {"product": "Arenyxa", "version": __version__}, json_output=json_output)
        if tokens[0].casefold() in {"permissions", "whoami"}:
            command_name = tokens.pop(0).casefold()
            self._expect_count(tokens, 0, 0, command_name)
            return self._result(raw, self._permission_status(), json_output=json_output)
        self.require_developer()
        group = tokens.pop(0).casefold()
        try:
            payload = self._dispatch(group, tokens)
            for stage in pipeline[1:]:
                payload = self._apply_pipeline(payload, stage)
        except CommandRuntimeError:
            raise
        except ArenyxaError as exc:
            raise CommandRuntimeError(str(exc.code), str(exc.message), exit_code=5) from exc
        except (KeyError, ValueError, TypeError, OSError, RuntimeError) as exc:
            raise CommandRuntimeError(type(exc).__name__.upper(), str(exc)) from exc
        return self._result(raw, payload, json_output=json_output)

    def complete(self, prefix: str) -> list[str]:
        text = str(prefix or "")
        tokens = self._split_completion(text)
        trailing_space = bool(text and text[-1].isspace())
        if not tokens:
            return sorted(["help", "version", *self.COMMAND_TREE])
        if len(tokens) == 1 and not trailing_space:
            needle = tokens[0].casefold()
            return [item for item in sorted(["help", "version", *self.COMMAND_TREE]) if item.startswith(needle)]
        group = tokens[0].casefold()
        children = list(self.COMMAND_TREE.get(group, ()))
        if not children:
            return []
        if len(tokens) == 1 and trailing_space:
            return children
        if len(tokens) == 2 and not trailing_space:
            needle = tokens[1].casefold()
            return [item for item in children if item.startswith(needle)]
        return []

    def help(self, topic: str = "") -> dict[str, Any]:
        selected = str(topic or "").casefold().strip()
        if selected and selected not in self.COMMAND_TREE:
            raise CommandRuntimeError("UNKNOWN_HELP_TOPIC", f"Unknown help topic: {selected}")
        if selected:
            return {
                "topic": selected,
                "commands": list(self.COMMAND_TREE[selected]),
                "developer_mode_required": selected not in {"version", "permissions", "whoami"},
            }
        return {
            "product": "Arenyxa Terminal-First Professional Control Plane",
            "developer_mode_required": True,
            "syntax": "arenyxa <group> <action> [arguments] [--json]",
            "groups": {name: list(children) for name, children in self.COMMAND_TREE.items()},
            "external_shells": ["direct", "powershell", "cmd", "python", "powershell-session", "cmd-session", "python-session"],
        }

    def _dispatch(self, group: str, args: list[str]) -> Any:
        if group == "status":
            self._expect_count(args, 0, 0, "status")
            return self._status()
        if group == "health-check":
            return self._health_check(args)
        if group == "diagnostics":
            return self._diagnostics(args)
        if group == "resilience":
            return self._resilience(args)
        if group == "job":
            return self._job(args)
        if group == "traffic":
            return self._traffic(args)
        if group == "task":
            return self._task(args)
        if group == "run":
            return self._run(args)
        if group == "capture":
            return self._capture(args)
        if group == "packet":
            return self._packet(args)
        if group == "pivot":
            return self._pivot(args)
        if group == "extraction":
            return self._extraction(args)
        if group == "web":
            return self._web(args)
        if group == "automation":
            return self._automation(args)
        if group == "dataset":
            return self._dataset(args)
        if group == "flow":
            return self._flow(args)
        if group == "fleet":
            return self._fleet(args)
        if group == "proxy":
            return self._proxy(args)
        if group == "tls":
            return self._tls(args)
        if group == "api":
            return self._api(args)
        if group == "analyze":
            return self._analyze(args)
        if group == "export":
            return self._export_professional(args)
        if group == "enterprise":
            return self._enterprise(args)
        if group == "platform":
            return self._platform(args)
        if group == "recovery":
            return self._recovery(args)
        if group == "traffic-automation":
            return self._traffic_automation(args)
        if group == "mitm":
            return self._mitm(args)
        if group == "plugin":
            return self._plugin(args)
        if group == "terminal":
            return self._terminal(args)
        raise CommandRuntimeError("UNKNOWN_COMMAND", f"Unknown Arenyxa command group: {group}")

    def _permission_status(self) -> dict[str, Any]:
        """Return the live authority projection without granting or changing permission."""
        from arenyxa.navigation.factory import NavigationContextFactory

        navigation = NavigationContextFactory.from_application(self.context)

        manager = getattr(self.context, "developer_access", None)
        try:
            developer_status = manager.status() if manager is not None else None
        except (ArenyxaError, OSError, RuntimeError, TypeError, ValueError):
            developer_status = None

        enterprise_service = getattr(self.context, "enterprise_identity", None)
        try:
            enterprise_status = enterprise_service.status() if enterprise_service is not None else None
        except (AttributeError, ArenyxaError, OSError, RuntimeError, TypeError, ValueError):
            enterprise_status = None

        developer_authenticated = bool(
            developer_status is not None and getattr(developer_status, "authenticated", False)
        )
        developer_kind = str(getattr(developer_status, "kind", "") or "")
        root_active = bool(
            developer_authenticated
            and developer_kind == "root_owner"
            and "platform.root" in set(getattr(developer_status, "capabilities", ()))
            and bool(getattr(self.context, "root_developer_workstation", False))
        )

        return {
            "experience_mode": navigation.experience_mode.value,
            "runtime_mode": navigation.runtime_mode.value,
            "account_role": navigation.account_role.value,
            "effective_capabilities": sorted(navigation.effective_capabilities),
            "developer": {
                "authenticated": developer_authenticated,
                "kind": developer_kind,
                "principal_id": str(getattr(developer_status, "developer_id", "") or ""),
                "capabilities": sorted(str(item) for item in getattr(developer_status, "capabilities", ())),
                "session_expires_at": str(getattr(developer_status, "session_expires_at", "") or ""),
            },
            "root": {
                "active": root_active,
                "platform_root": root_active,
            },
            "enterprise": {
                "configured": bool(getattr(enterprise_status, "configured", False)),
                "authenticated": bool(getattr(enterprise_status, "authenticated", False)),
                "enterprise_id": str(getattr(enterprise_status, "enterprise_id", "") or ""),
                "account_id": str(getattr(enterprise_status, "account_id", "") or ""),
                "roles": sorted(str(item) for item in getattr(enterprise_status, "roles", ())),
                "permissions": sorted(str(item) for item in getattr(enterprise_status, "permissions", ())),
            },
        }

    def _status(self) -> dict[str, Any]:
        capture = self.context.capture.session
        enterprise = getattr(self.context, "enterprise_server", None)
        return {
            "version": __version__,
            "developer_mode": bool(self.context.settings.developer_mode),
            "developer_authorized": self.developer_authorized(),
            "safe_mode": bool(getattr(self.context, "safe_mode", False)),
            "performance_mode": self.context.performance.mode,
            "active_runs": len(self.context.runner.active_handles()),
            "capture": None if capture is None else {"id": capture.id, "state": capture.state.value},
            "proxy": self._snapshot(getattr(self.context, "proxy_engine", None), "status"),
            "mitm": self._snapshot(getattr(self.context, "mitm_engine", None), "status"),
            "fleet": self._safe_fleet_snapshot(enterprise),
            "resource_governance": self.context.runner.resource_snapshot(),
        }

    def _task(self, args: list[str]) -> Any:
        action = self._action(args, "task")
        if action == "list":
            limit = self._limit(args, default=100, maximum=500)
            return [self._normalize(item) for item in self.context.store.list_tasks(True, limit=limit)]
        if action == "show":
            task_id = self._one_id(args, "task show <task_id>")
            task = self.context.store.get_task(task_id)
            if task is None:
                raise CommandRuntimeError("TASK_NOT_FOUND", f"Task not found: {task_id}", exit_code=4)
            return self._normalize(task)
        if action == "run":
            task_id = self._one_id(args, "task run <task_id>")
            task = self.context.store.get_task(task_id)
            if task is None:
                raise CommandRuntimeError("TASK_NOT_FOUND", f"Task not found: {task_id}", exit_code=4)
            handle = self.context.runner.submit(task)
            return {"task_id": task_id, "run_id": handle.run.id, "status": handle.run.status.value}
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown task action: {action}")

    def _run(self, args: list[str]) -> Any:
        action = self._action(args, "run")
        if action == "list":
            return self.context.store.list_runs(limit=self._limit(args, default=100, maximum=1000))
        if action == "show":
            run_id = self._one_id(args, "run show <run_id>")
            row = self.context.store.get_run(run_id)
            if row is None:
                raise CommandRuntimeError("RUN_NOT_FOUND", f"Run not found: {run_id}", exit_code=4)
            return row
        if action in {"cancel", "pause", "resume"}:
            run_id = self._one_id(args, f"run {action} <run_id>")
            handle = next((item for item in self.context.runner.active_handles() if item.run.id == run_id), None)
            if handle is None:
                raise CommandRuntimeError("ACTIVE_RUN_NOT_FOUND", f"Active run not found: {run_id}", exit_code=4)
            getattr(handle, action)()
            return {"run_id": run_id, "action": action, "status": handle.run.status.value}
        if action == "export":
            if not args or args[0].startswith("--"):
                raise CommandRuntimeError("USAGE", "Usage: run export <run_id> <path> [--format csv|json|jsonl|xlsx]")
            run_id = args.pop(0)
            if not args or args[0].startswith("--"):
                raise CommandRuntimeError("USAGE", "Usage: run export <run_id> <path> [--format csv|json|jsonl|xlsx]")
            destination = self._confined_export_path(args.pop(0))
            format_name = self._option(args, "--format", default=destination.suffix.lstrip(".") or "jsonl").casefold()
            self._expect_count(args, 0, 0, "run export")
            if self.context.store.get_run(run_id) is None:
                raise CommandRuntimeError("RUN_NOT_FOUND", f"Run not found: {run_id}", exit_code=4)
            if format_name not in {"csv", "json", "jsonl", "ndjson", "xlsx", "excel"}:
                raise CommandRuntimeError("USAGE", f"Unsupported export format: {format_name}")
            count = self.context.exporter.export_run(run_id, destination, format_name)
            return {"run_id": run_id, "path": str(destination), "format": format_name, "records": count}
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown run action: {action}")

    def _capture(self, args: list[str]) -> Any:
        action = self._action(args, "capture")
        if action == "start":
            return self._capture_start_system(args)
        if action == "browser":
            return self._capture_start_browser(args)
        if action == "har-import":
            return self._capture_import_har(args)
        if action == "pcap-import":
            return self._capture_import_pcap(args)
        if action == "stop":
            self._expect_count(args, 0, 0, "capture stop")
            if self.context.capture.session is None:
                raise CommandRuntimeError("CAPTURE_NOT_ACTIVE", "No capture session is active", exit_code=4)
            try:
                session = self.context.capture.stop(cancelled=False)
            except (ArenyxaError, OSError, RuntimeError, ValueError) as exc:
                raise CommandRuntimeError("CAPTURE_STOP_FAILED", str(exc), exit_code=5) from exc
            return {"stopped": True, "session": self._normalize(session)}
        if action == "list":
            return self.context.store.list_captures(limit=self._limit(args, default=100, maximum=1000))
        if action == "status":
            self._expect_count(args, 0, 0, "capture status")
            session = self.context.capture.session
            return {
                "active": session is not None,
                "session": None if session is None else self._normalize(session),
                "intelligence": self._network_intelligence().live_snapshot(session.id if session is not None else ""),
            }
        if action == "events":
            if not args:
                raise CommandRuntimeError("USAGE", "Usage: capture events <session_id> [--limit N]")
            session_id = args.pop(0)
            limit = self._limit(args, default=1000, maximum=10000)
            return list(self.context.store.iter_network_events(session_id, limit))
        if action in {"intelligence", "alerts"}:
            return self._capture_intelligence(action, args)
        if action == "rules":
            self._expect_count(args, 0, 0, "capture rules")
            rules = self._network_intelligence().detector.rules()
            return {"count": len(rules), "rules": rules}
        if action == "rule-load":
            return self._capture_rule_load(args)
        if action == "stream-stats":
            self._expect_count(args, 0, 0, "capture stream-stats")
            return self._network_intelligence().stream.stats()
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown capture action: {action}")

    def _capture_start_system(self, args: list[str]) -> dict[str, Any]:
        interface = self._option(args, "--interface", default="1")
        capture_filter = self._option(args, "--capture-filter", default="")
        event_filter = self._option(args, "--filter", default="")
        name = self._option(args, "--name", default=f"CLI Capture {utc_now()[0:19]}")
        self._expect_count(args, 0, 0, "capture start")
        session = CaptureSession(name=name, source_type=CaptureSource.SYSTEM, filter_expression=event_filter)
        adapter = TsharkPacketAdapter(
            interface,
            capture_filter=capture_filter,
            raw_dir=self.context.paths.captures / session.id,
        )
        try:
            self.context.capture.prepare(session, adapter)
            self.context.capture.start()
        except (ArenyxaError, OSError, RuntimeError, ValueError) as exc:
            raise CommandRuntimeError("CAPTURE_START_FAILED", str(exc), exit_code=5) from exc
        return {"started": True, "source": "system", "session": self._normalize(session), "interface": interface}

    def _capture_start_browser(self, args: list[str]) -> dict[str, Any]:
        url = self._required_option(args, "--url")
        event_filter = self._option(args, "--filter", default="")
        name = self._option(args, "--name", default=f"CLI Browser Capture {utc_now()[0:19]}")
        headless = not self._pop_flag(args, "--headed")
        self._expect_count(args, 0, 0, "capture browser")
        session = CaptureSession(name=name, source_type=CaptureSource.BROWSER, filter_expression=event_filter)
        body_store = NetworkBodyStore.for_capture(self.context.paths.captures, session.id)
        adapter = BrowserCaptureAdapter(
            url,
            self.context.paths.profiles / session.id,
            headless=headless,
            body_store=body_store,
            browser_pool=getattr(self.context, "browser_pool", None),
        )
        try:
            self.context.capture.prepare(session, adapter)
            self.context.capture.start()
        except (ArenyxaError, OSError, RuntimeError, ValueError) as exc:
            raise CommandRuntimeError("BROWSER_CAPTURE_START_FAILED", str(exc), exit_code=5) from exc
        return {
            "started": True, "source": "browser", "url": url, "headless": headless,
            "session": self._normalize(session),
        }

    def _capture_import_har(self, args: list[str]) -> dict[str, Any]:
        raw_path = self._required_option(args, "--file")
        name = self._option(args, "--name", default=f"CLI HAR Import {utc_now()[0:19]}")
        self._expect_count(args, 0, 0, "capture har-import")
        path = self._confined_project_path(raw_path)
        session = CaptureSession(name=name, source_type=CaptureSource.HAR_IMPORT)
        body_store = NetworkBodyStore.for_capture(self.context.paths.captures, session.id)
        try:
            events, summary = HarAnalyzer.load(path, session, body_store=body_store)
            from arenyxa.domain.enums import CaptureState
            session.started_at = utc_now()
            session.finished_at = session.started_at
            session.event_count = len(events)
            session.bytes_captured = sum(max(0, int(event.size or 0)) for event in events)
            session.state = CaptureState.COMPLETED
            self.context.store.append_capture_events(session, events)
            self._network_intelligence().on_capture_batch(events)
        except (ArenyxaError, OSError, RuntimeError, ValueError) as exc:
            raise CommandRuntimeError("HAR_IMPORT_FAILED", str(exc), exit_code=5) from exc
        return {"imported": True, "session": self._normalize(session), "summary": self._normalize(summary)}

    def _capture_import_pcap(self, args: list[str]) -> dict[str, Any]:
        raw_path = self._required_option(args, "--file")
        display_filter = self._option(args, "--filter", default="")
        name = self._option(args, "--name", default=f"CLI PCAP Import {utc_now()[0:19]}")
        limit_raw = self._option(args, "--limit", default="200000")
        self._expect_count(args, 0, 0, "capture pcap-import")
        try:
            limit = max(1, min(1_000_000, int(limit_raw)))
        except ValueError as exc:
            raise CommandRuntimeError("USAGE", "--limit must be an integer") from exc
        source = self._confined_project_path(raw_path)
        session = CaptureSession(name=name, source_type=CaptureSource.PCAP_IMPORT, filter_expression=display_filter)
        capture_dir = self.context.paths.captures / session.id
        capture_dir.mkdir(parents=True, exist_ok=True)
        target = capture_dir / source.name
        from arenyxa.domain.enums import CaptureState
        session.started_at = utc_now()
        session.state = CaptureState.CAPTURING
        try:
            if source.resolve() != target.resolve():
                shutil.copy2(source, target)
            session.permission_state = "offline_capture"
            session.bytes_captured = target.stat().st_size
            self.context.store.save_capture(session)
            engine = PacketAnalysisEngine()
            decoded = 0
            batch: list[NetworkEvent] = []
            intelligence = self._network_intelligence()
            for event in engine.iter_network_events(target, session, display_filter=display_filter, limit=limit):
                batch.append(event)
                decoded += 1
                if len(batch) >= 1000:
                    self.context.store.append_network_events(batch)
                    intelligence.on_capture_batch(batch)
                    batch = []
            if batch:
                self.context.store.append_network_events(batch)
                intelligence.on_capture_batch(batch)
            session.event_count = decoded
            session.finished_at = utc_now()
            session.state = CaptureState.COMPLETED
            self.context.store.save_capture(session)
        except (ArenyxaError, OSError, RuntimeError, ValueError) as exc:
            session.finished_at = utc_now()
            session.state = CaptureState.FAILED
            try:
                self.context.store.save_capture(session)
            except (OSError, RuntimeError, ValueError, TypeError, sqlite3.Error):
                record_current_exception(__name__, 'CommandCoreMixin._capture_import_pcap:402')
            raise CommandRuntimeError("PCAP_IMPORT_FAILED", str(exc), exit_code=5) from exc
        return {
            "imported": True, "session": self._normalize(session), "capture": str(target),
            "decoded_packets": session.event_count, "display_filter": display_filter,
        }

    def _capture_intelligence(self, action: str, args: list[str]) -> Any:
        if not args:
            raise CommandRuntimeError("USAGE", f"Usage: capture {action} <session_id> [--limit N]")
        session_id = args.pop(0)
        limit = self._limit(args, default=50000 if action == "intelligence" else 1000, maximum=200000)
        intelligence = self._network_intelligence()
        if action == "alerts":
            live = intelligence.alerts(session_id, limit=limit)
            if live:
                return {"session_id": session_id, "alert_count": len(live), "alerts": live}
            rows = list(self.context.store.iter_network_events(session_id, limit))
            analysis = intelligence.analyze_events(session_id, rows, limit=limit)
            return {"session_id": session_id, "alert_count": analysis["alert_count"], "alerts": analysis["alerts"]}
        return intelligence.analyze_events(
            session_id, self.context.store.iter_network_events(session_id, limit), limit=limit
        )

    def _capture_rule_load(self, args: list[str]) -> dict[str, Any]:
        raw_path = self._required_option(args, "--file")
        replace = not self._pop_flag(args, "--no-replace")
        self._expect_count(args, 0, 0, "capture rule-load")
        path = self._confined_project_path(raw_path)
        try:
            payload = json.loads(read_text_limited(path, 2 * 1024 * 1024, encoding="utf-8-sig"))
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise CommandRuntimeError("DETECTION_RULES_INVALID", str(exc), exit_code=5) from exc
        rows = payload.get("rules") if isinstance(payload, dict) else payload
        if not isinstance(rows, list):
            raise CommandRuntimeError(
                "DETECTION_RULES_INVALID",
                "Rule catalog must be an array or an object containing a rules array",
                exit_code=5,
            )
        try:
            loaded = self._network_intelligence().detector.load_rule_catalog(rows, replace=replace, limit=10_000)
        except (TypeError, ValueError) as exc:
            raise CommandRuntimeError("DETECTION_RULES_INVALID", str(exc), exit_code=5) from exc
        return {
            "loaded": loaded,
            "replace": replace,
            "source": str(path),
            "rules": self._network_intelligence().detector.rules(),
        }

    def _network_intelligence(self) -> LiveIntelligencePipeline:
        intelligence = getattr(self.context, "network_intelligence", None)
        if intelligence is None:
            intelligence = LiveIntelligencePipeline(BoundedEventStream(capacity=50_000))
            self.context.network_intelligence = intelligence
            capture = getattr(self.context, "capture", None)
            if capture is not None and hasattr(capture, "add_listener"):
                capture.add_listener(intelligence.on_capture_batch)
        return intelligence
