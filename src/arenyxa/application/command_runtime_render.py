from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import json
import os
import shlex
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from arenyxa import __version__
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

class CommandRenderMixin:
    @staticmethod
    def _network_event(row: dict[str, Any]) -> NetworkEvent:
        source = CaptureSource(str(row.get("source_type") or CaptureSource.HTTP_RUNNER.value))
        return NetworkEvent(
            session_id=str(row.get("session_id") or ""),
            source_type=source,
            protocol=str(row.get("protocol") or ""),
            direction=str(row.get("direction") or ""),
            size=int(row.get("size") or 0),
            id=str(row.get("id") or ""),
            timestamp=str(row.get("timestamp") or ""),
            process_ref=row.get("process_ref"),
            flow_ref=row.get("flow_ref"),
            request_ref=row.get("request_ref"),
            method=row.get("method"),
            url=row.get("url"),
            status=row.get("status"),
            host=row.get("host"),
            timing=dict(row.get("timing") or {}),
            request_headers=dict(row.get("request_headers") or {}),
            response_headers=dict(row.get("response_headers") or {}),
            request_body_ref=row.get("request_body_ref"),
            response_body_ref=row.get("response_body_ref"),
            sensitivity_flags=list(row.get("sensitivity") or []),
            initiator=row.get("initiator"),
            metadata=dict(row.get("metadata") or {}),
        )

    @staticmethod
    def _field_spec(value: str) -> ExtractionField:
        name, separator, remainder = str(value).partition(":")
        selector_type, separator2, selector = remainder.partition(":")
        if not separator or not separator2:
            raise CommandRuntimeError("USAGE", "--field format is name:type:selector")
        return ExtractionField(name=name, selector_type=selector_type, selector=selector).normalized()

    @classmethod
    def _apply_pipeline(cls, payload: Any, stage: str) -> Any:
        tokens = [token for token in cls._split(stage) if token != "--json"]
        if not tokens:
            return payload
        action = tokens.pop(0).casefold()
        if action == "take":
            if len(tokens) != 1:
                raise CommandRuntimeError("USAGE", "Pipeline usage: | take <count>")
            try:
                count = int(tokens[0])
            except ValueError as exc:
                raise CommandRuntimeError("USAGE", "take count must be an integer") from exc
            if not 0 <= count <= 10000:
                raise CommandRuntimeError("USAGE", "take count must be between 0 and 10000")
            return list(payload)[:count] if isinstance(payload, (list, tuple)) else payload
        if action == "where":
            if len(tokens) != 1 or "=" not in tokens[0]:
                raise CommandRuntimeError("USAGE", "Pipeline usage: | where field=value")
            key, value = tokens[0].split("=", 1)
            if not isinstance(payload, list):
                raise CommandRuntimeError("PIPELINE_TYPE", "where requires a list result")
            return [row for row in payload if isinstance(row, dict) and str(row.get(key, "")).casefold() == value.casefold()]
        if action == "select":
            if not tokens:
                raise CommandRuntimeError("USAGE", "Pipeline usage: | select field1,field2")
            fields = [item.strip() for item in " ".join(tokens).split(",") if item.strip()]
            if not isinstance(payload, list):
                raise CommandRuntimeError("PIPELINE_TYPE", "select requires a list result")
            return [{key: row.get(key) for key in fields} for row in payload if isinstance(row, dict)]
        if action == "sort":
            if len(tokens) not in {1, 2}:
                raise CommandRuntimeError("USAGE", "Pipeline usage: | sort <field> [desc]")
            if not isinstance(payload, list):
                raise CommandRuntimeError("PIPELINE_TYPE", "sort requires a list result")
            field = tokens[0]
            reverse = len(tokens) == 2 and tokens[1].casefold() == "desc"
            return sorted(payload, key=lambda row: cls._sort_value(row.get(field) if isinstance(row, dict) else None), reverse=reverse)
        if action == "count":
            if tokens:
                raise CommandRuntimeError("USAGE", "Pipeline usage: | count")
            if isinstance(payload, (list, tuple, dict, str)):
                return {"count": len(payload)}
            raise CommandRuntimeError("PIPELINE_TYPE", "count requires a collection result")
        if action == "unique":
            if len(tokens) != 1:
                raise CommandRuntimeError("USAGE", "Pipeline usage: | unique <field>")
            if not isinstance(payload, list):
                raise CommandRuntimeError("PIPELINE_TYPE", "unique requires a list result")
            field = tokens[0]
            seen: set[str] = set()
            rows: list[Any] = []
            for row in payload:
                if not isinstance(row, dict):
                    continue
                key = json.dumps(row.get(field), ensure_ascii=False, sort_keys=True, default=str)
                if key in seen:
                    continue
                seen.add(key)
                rows.append(row)
            return rows
        raise CommandRuntimeError("UNKNOWN_PIPELINE_STAGE", f"Unknown pipeline stage: {action}")

    @staticmethod
    def _sort_value(value: Any) -> tuple[int, Any]:
        if value is None:
            return (2, "")
        if isinstance(value, (int, float)):
            return (0, value)
        return (1, str(value).casefold())

    @staticmethod
    def _split_pipeline(command: str) -> list[str]:
        parts: list[str] = []
        current: list[str] = []
        quote = ""
        escaped = False
        for char in command:
            if escaped:
                current.append(char)
                escaped = False
                continue
            if char == "\\" and quote:
                current.append(char)
                escaped = True
                continue
            if char in {"\"", "'"}:
                if quote == char:
                    quote = ""
                elif not quote:
                    quote = char
                current.append(char)
                continue
            if char == "|" and not quote:
                part = "".join(current).strip()
                if not part:
                    raise CommandRuntimeError("COMMAND_PARSE_FAILED", "Empty pipeline stage")
                parts.append(part)
                current = []
                continue
            current.append(char)
        if quote:
            raise CommandRuntimeError("COMMAND_PARSE_FAILED", "Unterminated quote in command pipeline")
        final = "".join(current).strip()
        if not final:
            raise CommandRuntimeError("COMMAND_PARSE_FAILED", "Empty pipeline stage")
        parts.append(final)
        return parts

    @staticmethod
    def _options(args: list[str], name: str) -> list[str]:
        values: list[str] = []
        index = 0
        while index < len(args):
            if args[index] != name:
                index += 1
                continue
            if index + 1 >= len(args):
                raise CommandRuntimeError("USAGE", f"{name} requires a value")
            values.append(args[index + 1])
            del args[index:index + 2]
        return values

    def _confined_project_path(self, raw: str) -> Path:
        root = Path(self.context.paths.projects).expanduser().resolve()
        candidate = Path(str(raw)).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        resolved = candidate.resolve()
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise CommandRuntimeError("PATH_OUTSIDE_PROJECTS", "Path must remain inside the Arenyxa Projects directory", exit_code=3) from exc
        return resolved

    @staticmethod
    def _safe_fleet_snapshot(server: Any) -> Any:
        if server is None:
            return None
        try:
            return CommandRenderMixin._normalize(server.remote_ops_snapshot())
        except ArenyxaError as exc:
            return {"available": True, "authorized": False, "error": {"code": exc.code, "message": exc.message}}

    @staticmethod
    def _result(command: str, data: Any, *, json_output: bool) -> dict[str, Any]:
        normalized = CommandRenderMixin._normalize(data)
        return {
            "ok": True,
            "command": command,
            "exit_code": 0,
            "format": "json" if json_output else "text",
            "data": normalized,
        }

    @staticmethod
    def render(result: dict[str, Any], *, force_json: bool | None = None) -> str:
        use_json = bool(force_json) if force_json is not None else result.get("format") == "json"
        if use_json:
            return json.dumps(result, ensure_ascii=False, indent=2, default=str)
        data = result.get("data")
        if isinstance(data, list):
            return CommandRenderMixin._render_rows(data)
        if isinstance(data, dict):
            return CommandRenderMixin._render_mapping(data)
        return str(data)

    @staticmethod
    def error_result(command: str, exc: CommandRuntimeError, *, json_output: bool = False) -> dict[str, Any]:
        return {
            "ok": False,
            "command": command,
            "exit_code": exc.exit_code,
            "format": "json" if json_output else "text",
            "error": {"code": exc.code, "message": exc.message},
        }

    @staticmethod
    def render_error(result: dict[str, Any]) -> str:
        if result.get("format") == "json":
            return json.dumps(result, ensure_ascii=False, indent=2)
        error = result.get("error") or {}
        return f"{error.get('code', 'COMMAND_FAILED')}: {error.get('message', 'Command failed')}"

    @staticmethod
    def _render_mapping(data: dict[str, Any]) -> str:
        scalar = all(not isinstance(value, (dict, list, tuple)) for value in data.values())
        if scalar:
            width = max([len(str(key)) for key in data] or [1])
            return "\n".join(f"{str(key):<{width}}  {value}" for key, value in data.items())
        return json.dumps(data, ensure_ascii=False, indent=2, default=str)

    @staticmethod
    def _render_rows(data: list[Any]) -> str:
        if not data:
            return "<empty>"
        if not all(isinstance(item, dict) for item in data):
            return "\n".join(str(item) for item in data)
        keys: list[str] = []
        preferred = ["id", "name", "state", "status", "worker_id", "task_id", "run_id", "method", "host", "url"]
        available = {str(key) for row in data for key in row.keys()}
        for key in preferred:
            if key in available and key not in keys:
                keys.append(key)
        for key in sorted(available):
            if key not in keys and len(keys) < 8:
                keys.append(key)
        rows = [[CommandRenderMixin._cell(row.get(key)) for key in keys] for row in data]
        widths = [min(48, max(len(key), *(len(row[index]) for row in rows))) for index, key in enumerate(keys)]
        header = "  ".join(key.upper().ljust(widths[index]) for index, key in enumerate(keys))
        separator = "  ".join("-" * width for width in widths)
        lines = [header, separator]
        for row in rows:
            lines.append("  ".join(row[index][: widths[index]].ljust(widths[index]) for index in range(len(keys))))
        return "\n".join(lines)

    @staticmethod
    def _cell(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (dict, list, tuple)):
            return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
        return str(value).replace("\r", " ").replace("\n", " ")

    @staticmethod
    def _normalize(value: Any) -> Any:
        if is_dataclass(value):
            return {key: CommandRenderMixin._normalize(item) for key, item in asdict(value).items()}
        if hasattr(value, "to_dict") and callable(value.to_dict):
            return CommandRenderMixin._normalize(value.to_dict())
        if hasattr(value, "value") and value.__class__.__module__ != "builtins":
            try:
                return value.value
            except (AttributeError, TypeError):
                record_current_exception(__name__, 'CommandRenderMixin._normalize:307')
        if isinstance(value, dict):
            return {str(key): CommandRenderMixin._normalize(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [CommandRenderMixin._normalize(item) for item in value]
        return value

    @staticmethod
    def _snapshot(target: Any, method: str) -> Any:
        if target is None:
            return None
        return CommandRenderMixin._normalize(getattr(target, method)())

    @staticmethod
    def _split(command: str) -> list[str]:
        try:
            return shlex.split(command, posix=os.name != "nt")
        except ValueError as exc:
            raise CommandRuntimeError("COMMAND_PARSE_FAILED", str(exc)) from exc

    @staticmethod
    def _split_completion(command: str) -> list[str]:
        try:
            return shlex.split(command, posix=os.name != "nt")
        except ValueError:
            return command.split()

    @staticmethod
    def _pop_flag(args: list[str], flag: str) -> bool:
        found = False
        while flag in args:
            args.remove(flag)
            found = True
        return found

    @staticmethod
    def _option(args: list[str], name: str, *, default: str = "") -> str:
        if name not in args:
            return default
        index = args.index(name)
        if index + 1 >= len(args):
            raise CommandRuntimeError("USAGE", f"{name} requires a value")
        value = args[index + 1]
        del args[index:index + 2]
        return value

    @classmethod
    def _limit(cls, args: list[str], *, default: int, maximum: int) -> int:
        raw = cls._option(args, "--limit", default=str(default))
        try:
            value = int(raw)
        except ValueError as exc:
            raise CommandRuntimeError("USAGE", "--limit must be an integer") from exc
        if not 1 <= value <= maximum:
            raise CommandRuntimeError("USAGE", f"--limit must be between 1 and {maximum}")
        if args:
            raise CommandRuntimeError("USAGE", f"Unexpected arguments: {' '.join(args)}")
        return value

    @staticmethod
    def _action(args: list[str], group: str) -> str:
        if not args:
            raise CommandRuntimeError("USAGE", f"{group} requires an action")
        return args.pop(0).casefold()

    @staticmethod
    def _expect_count(args: list[str], low: int, high: int, usage: str) -> None:
        if not low <= len(args) <= high:
            raise CommandRuntimeError("USAGE", f"Usage: {usage}")

    @staticmethod
    def _one_id(args: list[str], usage: str) -> str:
        if len(args) != 1:
            raise CommandRuntimeError("USAGE", f"Usage: {usage}")
        return args.pop(0)

    @staticmethod
    def _one_id_allow_flags(args: list[str], usage: str) -> str:
        if not args or args[0].startswith("--"):
            raise CommandRuntimeError("USAGE", f"Usage: {usage}")
        return args.pop(0)

