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


class CommandProxyMixin:
    def _proxy(self, args: list[str]) -> Any:
        action = self._action(args, "proxy")
        engine = getattr(self.context, "proxy_engine", None)
        if engine is None:
            raise CommandRuntimeError("PROXY_UNAVAILABLE", "Proxy runtime is unavailable", exit_code=5)
        if action == "status":
            self._expect_count(args, 0, 0, "proxy status")
            traffic = getattr(self.context, "traffic_control", None)
            if traffic is not None and getattr(self.context, "local_control_session", None) is not None:
                return traffic.proxy_status(
                    session=self.context.local_control_session, surface="cli"
                )
            return self._normalize(engine.status())
        if action == "start":
            self._expect_count(args, 0, 0, "proxy start")
            host, port = engine.start()
            return {"running": True, "host": host, "port": port}
        if action == "stop":
            self._expect_count(args, 0, 0, "proxy stop")
            engine.stop()
            return self._normalize(engine.status())
        if action == "history":
            page_raw = self._option(args, "--page", default="1")
            size_raw = self._option(args, "--page-size", default="100")
            query = self._option(args, "--query", default="")
            session_id = self._option(args, "--session", default="")
            legacy_limit = self._option(args, "--limit", default="")
            self._expect_count(args, 0, 0, "proxy history")
            try:
                page = int(page_raw)
                page_size = int(legacy_limit or size_raw)
            except ValueError as exc:
                raise CommandRuntimeError("USAGE", "--page and --page-size must be integers") from exc
            result = engine.history_page(page=page, page_size=page_size, query=query, session_id=session_id)
            result["items"] = [self._normalize(item) for item in result["items"]]
            return result
        if action == "sessions":
            limit = self._limit(args, default=100, maximum=10000)
            return engine.sessions(limit=limit)
        if action == "history-health":
            self._expect_count(args, 0, 0, "proxy history-health")
            return engine.history_health()
        if action == "cleanup":
            max_records_raw = self._option(args, "--max-records", default="1000000")
            batch_raw = self._option(args, "--batch", default="5000")
            self._expect_count(args, 0, 0, "proxy cleanup")
            try:
                removed = engine.cleanup_history(max_records=int(max_records_raw), batch_size=int(batch_raw))
            except ValueError as exc:
                raise CommandRuntimeError("USAGE", "--max-records and --batch must be integers") from exc
            return {"removed": removed, "health": engine.history_health()}
        if action == "summary":
            limit = self._limit(args, default=2000, maximum=10000)
            return engine.session_summary(limit=limit)
        if action == "deep-inspect":
            flow_id = self._one_id(args, "proxy deep-inspect <flow_id>")
            flow = engine.get_flow(flow_id)
            if flow is None:
                raise CommandRuntimeError("FLOW_NOT_FOUND", f"Proxy flow not found: {flow_id}", exit_code=4)
            return ProxyDeepInspector().inspect(flow).snapshot()
        if action == "compare":
            if len(args) != 2:
                raise CommandRuntimeError("USAGE", "Usage: proxy compare <left_flow_id> <right_flow_id>")
            left_id, right_id = args
            left = engine.get_flow(left_id)
            right = engine.get_flow(right_id)
            if left is None or right is None:
                raise CommandRuntimeError("FLOW_NOT_FOUND", "One or both Proxy flows were not found", exit_code=4)
            return ProxyDeepInspector().compare(left, right)
        if action == "timeline":
            limit = self._limit(args, default=500, maximum=5000)
            return ProxyDeepInspector().timeline(engine.history()[-limit:], limit=limit)
        if action == "inspect":
            flow_id = self._one_id(args, "proxy inspect <flow_id>")
            return engine.inspect_flow(flow_id)
        if action == "pending":
            self._expect_count(args, 0, 0, "proxy pending")
            return engine.pending()
        if action == "resolve":
            if len(args) != 2:
                raise CommandRuntimeError("USAGE", "Usage: proxy resolve <intercept_id> <forward|drop>")
            intercept_id, decision = args
            if decision.casefold() not in {"forward", "drop"}:
                raise CommandRuntimeError("USAGE", "Proxy intercept decision must be forward or drop")
            changed = engine.resolve(intercept_id, decision)
            if not changed:
                raise CommandRuntimeError("INTERCEPT_NOT_FOUND", f"Proxy intercept not found: {intercept_id}", exit_code=4)
            return {"intercept_id": intercept_id, "action": decision.casefold(), "resolved": True}
        if action == "intercept":
            subaction = self._action(args, "proxy intercept")
            if subaction in {"enable", "disable"}:
                responses = self._pop_flag(args, "--responses")
                self._expect_count(args, 0, 0, f"proxy intercept {subaction}")
                enabled = subaction == "enable"
                engine.update_policy(enabled, enabled and responses)
                return {
                    "enabled": enabled,
                    "requests": bool(engine.settings.intercept_requests),
                    "responses": bool(engine.settings.intercept_responses),
                }
            if subaction == "list":
                self._expect_count(args, 0, 0, "proxy intercept list")
                return {"pending": engine.pending(), "rules": engine.intercept_rules()}
            if subaction == "add":
                name = self._required_option(args, "--name")
                rule_action = self._required_option(args, "--action")
                phase = self._option(args, "--phase", default="both")
                priority_raw = self._option(args, "--priority", default="100")
                host = self._option(args, "--host", default="*")
                url = self._option(args, "--url", default="*")
                method = self._option(args, "--method", default="*")
                header = self._option(args, "--header", default="*")
                body = self._option(args, "--body", default="*")
                replacement = self._option(args, "--replace", default="")
                self._expect_count(args, 0, 0, "proxy intercept add")
                try:
                    return engine.add_intercept_rule(
                        name,
                        rule_action,
                        phase=phase,
                        priority=int(priority_raw),
                        host_pattern=host,
                        url_pattern=url,
                        method_pattern=method,
                        header_pattern=header,
                        body_pattern=body,
                        replacement=replacement,
                    )
                except ValueError as exc:
                    raise CommandRuntimeError("INTERCEPT_RULE_INVALID", str(exc)) from exc
            if subaction == "remove":
                rule_id = self._one_id(args, "proxy intercept remove <rule_id>")
                if not engine.remove_intercept_rule(rule_id):
                    raise CommandRuntimeError("INTERCEPT_RULE_NOT_FOUND", f"InterceptRule not found: {rule_id}", exit_code=4)
                return {"rule_id": rule_id, "removed": True}
            if subaction in {"forward", "drop", "modify"}:
                if not args or args[0].startswith("--"):
                    raise CommandRuntimeError("USAGE", f"Usage: proxy intercept {subaction} <intercept_id>")
                intercept_id = args.pop(0)
                raw = self._option(args, "--raw", default="") if subaction == "modify" else None
                self._expect_count(args, 0, 0, f"proxy intercept {subaction}")
                decision = "forward" if subaction in {"forward", "modify"} else "drop"
                changed = engine.resolve(intercept_id, decision, raw=raw if subaction == "modify" else None)
                if not changed:
                    raise CommandRuntimeError("INTERCEPT_NOT_FOUND", f"Proxy intercept not found: {intercept_id}", exit_code=4)
                return {"intercept_id": intercept_id, "action": subaction, "resolved": True}
            raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown proxy intercept action: {subaction}")
        if action == "replay":
            if not args or args[0].startswith("--"):
                raise CommandRuntimeError("USAGE", "Usage: proxy replay <flow_id> [--confirm-side-effect]")
            flow_id = args.pop(0)
            confirmed = self._pop_flag(args, "--confirm-side-effect")
            self._expect_count(args, 0, 0, "proxy replay")
            flow = engine.get_flow(flow_id)
            if flow is None:
                raise CommandRuntimeError("FLOW_NOT_FOUND", f"Proxy flow not found: {flow_id}", exit_code=4)
            if flow.method.upper() in {"POST", "PUT", "PATCH", "DELETE"} and not confirmed:
                raise CommandRuntimeError(
                    "REPLAY_SIDE_EFFECT_CONFIRMATION",
                    "Replay of a potentially mutating request requires --confirm-side-effect.",
                    exit_code=3,
                )
            response = engine.repeat_raw(flow.scheme, flow.host, flow.port, flow.request_raw)
            try:
                response_line, response_headers, response_body = _parse_raw_message(response)
                parts = response_line.split(" ", 2)
                status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
            except ValueError:
                response_headers, response_body, status = [], b"", None
            try:
                _original_line, original_headers, original_body = _parse_raw_message(flow.response_raw)
            except ValueError:
                original_headers, original_body = [], b""
            return {
                "source_flow_id": flow.id,
                "method": flow.method,
                "url": flow.url,
                "status": {"before": flow.status, "after": status, "equal": flow.status == status},
                "headers": {
                    "before": len(original_headers),
                    "after": len(response_headers),
                    "equal": original_headers == response_headers,
                },
                "body_hash": {
                    "before": hashlib.sha256(original_body).hexdigest(),
                    "after": hashlib.sha256(response_body).hexdigest(),
                    "equal": hashlib.sha256(original_body).digest() == hashlib.sha256(response_body).digest(),
                },
                "size": {"before": len(flow.response_raw), "after": len(response)},
            }
        if action == "export-har":
            if not args or args[0].startswith("--"):
                raise CommandRuntimeError("USAGE", "Usage: proxy export-har <path> [--unredacted]")
            destination = self._confined_export_path(args.pop(0))
            unredacted = self._pop_flag(args, "--unredacted")
            self._expect_count(args, 0, 0, "proxy export-har")
            exported = engine.export_har(destination, redact_sensitive=not unredacted)
            return {"path": str(exported), "redacted": not unredacted}
        if action == "autoresponder-list":
            self._expect_count(args, 0, 0, "proxy autoresponder-list")
            return engine.autoresponder_rules()
        if action == "autoresponder-add":
            host = self._required_option(args, "--host")
            path = self._option(args, "--path", default="/*")
            method = self._option(args, "--method", default="*")
            body = self._option(args, "--body", default="{}")
            content_type = self._option(args, "--content-type", default="application/json; charset=utf-8")
            status_raw = self._option(args, "--status", default="200")
            self._expect_count(args, 0, 0, "proxy autoresponder-add")
            try:
                status = int(status_raw)
            except ValueError as exc:
                raise CommandRuntimeError("USAGE", "--status must be an integer") from exc
            return engine.add_autoresponder_rule(
                host, path, method=method, status=status, content_type=content_type, body=body
            )
        if action == "autoresponder-remove":
            rule_id = self._one_id(args, "proxy autoresponder-remove <rule_id>")
            if not engine.remove_autoresponder_rule(rule_id):
                raise CommandRuntimeError("RULE_NOT_FOUND", f"AutoResponder rule not found: {rule_id}", exit_code=4)
            return {"rule_id": rule_id, "removed": True}
        if action == "match-list":
            self._expect_count(args, 0, 0, "proxy match-list")
            return engine.match_replace_rules()
        if action == "match-add":
            phase = self._required_option(args, "--phase")
            scope = self._required_option(args, "--scope")
            match = self._required_option(args, "--match")
            replacement = self._option(args, "--replace", default="")
            host = self._option(args, "--host", default="*")
            path = self._option(args, "--path", default="/*")
            method = self._option(args, "--method", default="*")
            header = self._option(args, "--header", default="*")
            self._expect_count(args, 0, 0, "proxy match-add")
            return engine.add_match_replace_rule(
                phase, scope, match, replacement, host_pattern=host, path_pattern=path, method=method, header_name=header
            )
        if action == "match-remove":
            rule_id = self._one_id(args, "proxy match-remove <rule_id>")
            if not engine.remove_match_replace_rule(rule_id):
                raise CommandRuntimeError("RULE_NOT_FOUND", f"Match/Replace rule not found: {rule_id}", exit_code=4)
            return {"rule_id": rule_id, "removed": True}
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown proxy action: {action}")

    def _mitm(self, args: list[str]) -> Any:
        action = self._action(args, "mitm")
        engine = getattr(self.context, "mitm_engine", None)
        if engine is None:
            raise CommandRuntimeError("MITM_UNAVAILABLE", "MITM Proxy runtime is unavailable", exit_code=5)
        if action == "status":
            self._expect_count(args, 0, 0, "mitm status")
            traffic = getattr(self.context, "traffic_control", None)
            if traffic is not None and getattr(self.context, "local_control_session", None) is not None:
                return traffic.mitm_status(
                    session=self.context.local_control_session, surface="cli"
                )
            return self._normalize(engine.status())
        if action == "start":
            self._expect_count(args, 0, 0, "mitm start")
            return self._normalize(engine.start())
        if action == "stop":
            self._expect_count(args, 0, 0, "mitm stop")
            engine.stop()
            return self._normalize(engine.status())
        if action == "flows":
            query = self._option(args, "--query", default="")
            protocol = self._option(args, "--protocol", default="")
            limit = self._limit(args, default=100, maximum=5000)
            rows = engine.events(query=query, protocol=protocol)
            return [self._normalize(item) for item in rows[-limit:]]
        if action == "analytics":
            query = self._option(args, "--query", default="")
            protocol = self._option(args, "--protocol", default="")
            limit = self._limit(args, default=50000, maximum=100000)
            rows = engine.events(query=query, protocol=protocol)
            return MitmFlowAnalyzer().analyze(rows[-limit:], limit=limit).snapshot()
        if action == "pending":
            self._expect_count(args, 0, 0, "mitm pending")
            return engine.pending()
        if action == "resolve":
            if len(args) != 2:
                raise CommandRuntimeError("USAGE", "Usage: mitm resolve <token> <forward|drop>")
            token, decision = args
            if decision.casefold() not in {"forward", "drop"}:
                raise CommandRuntimeError("USAGE", "MITM intercept decision must be forward or drop")
            try:
                changed = engine.resolve(token, decision.casefold())
            except ValueError as exc:
                raise CommandRuntimeError("MITM_RESOLVE_FAILED", str(exc), exit_code=5) from exc
            if not changed:
                raise CommandRuntimeError("MITM_INTERCEPT_NOT_FOUND", f"MITM intercept not found: {token}", exit_code=4)
            return {"token": token, "action": decision.casefold(), "resolved": True}
        if action == "export":
            if not args or args[0].startswith("--"):
                raise CommandRuntimeError("USAGE", "Usage: mitm export <path>")
            destination = self._confined_export_path(args.pop(0))
            self._expect_count(args, 0, 0, "mitm export")
            try:
                exported = engine.export_flows(destination)
            except (FileNotFoundError, OSError) as exc:
                raise CommandRuntimeError("MITM_EXPORT_FAILED", str(exc), exit_code=5) from exc
            return {"path": str(exported)}
        if action == "replay-current":
            direction = self._option(args, "--direction", default="client").casefold()
            timeout_raw = self._option(args, "--timeout", default="120")
            self._expect_count(args, 0, 0, "mitm replay-current")
            if direction not in {"client", "server"}:
                raise CommandRuntimeError("USAGE", "--direction must be client or server")
            try:
                timeout = float(timeout_raw)
            except ValueError as exc:
                raise CommandRuntimeError("USAGE", "--timeout must be numeric") from exc
            if not 1 <= timeout <= 600:
                raise CommandRuntimeError("USAGE", "--timeout must be between 1 and 600 seconds")
            try:
                completed = engine.run_replay(engine.flow_path, direction=direction, timeout=timeout)
            except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
                raise CommandRuntimeError("MITM_REPLAY_FAILED", str(exc), exit_code=5) from exc
            return {
                "direction": direction,
                "exit_code": int(completed.returncode),
                "stdout": str(completed.stdout or "")[-200000:],
                "stderr": str(completed.stderr or "")[-200000:],
            }
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown mitm action: {action}")

    def _plugin(self, args: list[str]) -> Any:
        action = self._action(args, "plugin")
        if action == "list":
            self._expect_count(args, 0, 0, "plugin list")
            return [{"manifest": self._normalize(manifest), "path": str(path)} for manifest, path in self.context.plugins.discover()]
        if action == "health":
            self._expect_count(args, 0, 0, "plugin health")
            return [self._normalize(item) for item in self.context.plugin_sandbox.health_snapshot()]
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown plugin action: {action}")
