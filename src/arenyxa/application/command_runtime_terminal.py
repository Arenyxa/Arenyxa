from __future__ import annotations

import json
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
from arenyxa.domain.models import NetworkEvent, new_id
from arenyxa.application.extraction_studio import ExtractionDryRun, ExtractionField, ExtractionLivePicker, ExtractionStudioService
from arenyxa.application.autopilot_validation import AutopilotProductionValidator
from arenyxa.application.terminal import TerminalMode
from arenyxa.application.network_terminal import NetworkTerminalToolkit
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
from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine
from arenyxa.infrastructure.capture.inspectors import DnsAnalyzer
from arenyxa.enterprise.fleet_telemetry import FleetTelemetryAnalyzer
from arenyxa.enterprise.fleet_live import FleetLiveTelemetry

from arenyxa.application.command_runtime_base import CommandRuntimeError


_TERMINAL_UNHANDLED = object()

class CommandTerminalMixin:
    """Expose bounded terminal, network-diagnostic, packet-analysis, and session commands."""
    def _terminal(self, args: list[str]) -> Any:
        """Dispatch terminal commands to focused command-family handlers."""
        action = self._action(args, "terminal")
        handlers = (
            self._terminal_capabilities_action,
            self._terminal_network_action,
            self._terminal_packet_action,
            self._terminal_session_action,
            self._terminal_run_action,
        )
        for handler in handlers:
            result = handler(action, args)
            if result is not _TERMINAL_UNHANDLED:
                return result
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown terminal action: {action}")

    def _terminal_capabilities_action(self, action: str, args: list[str]) -> Any:
        """Handle one bounded terminal command family without growing the top-level dispatcher."""
        if action in {"permissions", "whoami"}:
            self._expect_count(args, 0, 0, f"terminal {action}")
            return self._permission_status()
        if action == "capabilities":
            self._expect_count(args, 0, 0, "terminal capabilities")
            terminal = self.context.terminal
            return {
                "cwd": str(terminal.cwd),
                "timeout_seconds": terminal.timeout_seconds,
                "running": terminal.is_running,
                "direct_shell_enabled": bool(getattr(self.context.settings, "developer_direct_shell_enabled", False)),
                "powershell": terminal.which("pwsh") or terminal.which("powershell.exe") or terminal.which("powershell"),
                "cmd": terminal.which("cmd.exe") if os.name == "nt" else None,
                "python": terminal.which(os.path.basename(os.sys.executable)) or os.sys.executable,
                "persistent_shell_modes": ["powershell-session", "cmd-session", "python-session"],
                "native_conpty_backend": WindowsConPtySession.supported(),
                "interactive_backend": "windows-conpty" if WindowsConPtySession.supported() else "persistent-pipes",
                "workspace_sessions": self._terminal_workspace().list(),
                "workspace_session_limit": self._terminal_workspace().MAX_SESSIONS,
                "network_diagnostics": NetworkTerminalToolkit.capabilities(),
            }
        return _TERMINAL_UNHANDLED

    def _terminal_network_action(self, action: str, args: list[str]) -> Any:
        """Handle one bounded terminal command family without growing the top-level dispatcher."""
        if action == "net-capabilities":
            self._expect_count(args, 0, 0, "terminal net-capabilities")
            return NetworkTerminalToolkit.capabilities()
        if action == "net-resolve":
            if not args or args[0].startswith("--"):
                raise CommandRuntimeError("USAGE", "Usage: terminal net-resolve <host> [--port N] [--family any|ipv4|ipv6] [--type any|stream|datagram]")
            host = args.pop(0)
            port_raw = self._option(args, "--port", default="0")
            family = self._option(args, "--family", default="any")
            socktype = self._option(args, "--type", default="stream")
            self._expect_count(args, 0, 0, "terminal net-resolve")
            try:
                return NetworkTerminalToolkit.resolve(host, port=int(port_raw), family=family, socktype=socktype)
            except (OSError, RuntimeError, ValueError) as exc:
                raise CommandRuntimeError("NETWORK_RESOLVE_FAILED", str(exc), exit_code=5) from exc
        if action == "net-reverse":
            address = self._one_id(args, "terminal net-reverse <address>")
            try:
                return NetworkTerminalToolkit.reverse(address)
            except (OSError, RuntimeError, ValueError) as exc:
                raise CommandRuntimeError("NETWORK_REVERSE_FAILED", str(exc), exit_code=5) from exc
        if action == "net-dns":
            if not args or args[0].startswith("--"):
                raise CommandRuntimeError("USAGE", "Usage: terminal net-dns <host> [--port N]")
            host = args.pop(0)
            port_raw = self._option(args, "--port", default="443")
            self._expect_count(args, 0, 0, "terminal net-dns")
            try:
                return asdict(DnsAnalyzer.resolve(host, port=int(port_raw)))
            except (OSError, RuntimeError, ValueError) as exc:
                raise CommandRuntimeError("NETWORK_DNS_FAILED", str(exc), exit_code=5) from exc
        if action in {"net-tcp", "net-tls"}:
            if not args or args[0].startswith("--"):
                raise CommandRuntimeError("USAGE", f"Usage: terminal {action} <host> [--port N] [--timeout SECONDS]")
            host = args.pop(0)
            default_port = "443" if action == "net-tls" else ""
            port_raw = self._option(args, "--port", default=default_port)
            timeout_raw = self._option(args, "--timeout", default="5" if action == "net-tls" else "3")
            self._expect_count(args, 0, 0, f"terminal {action}")
            if not port_raw:
                raise CommandRuntimeError("USAGE", "--port is required for terminal net-tcp")
            try:
                if action == "net-tls":
                    return NetworkTerminalToolkit.tls_probe(host, int(port_raw), timeout=float(timeout_raw))
                return NetworkTerminalToolkit.tcp_probe(host, int(port_raw), timeout=float(timeout_raw))
            except (OSError, RuntimeError, ValueError) as exc:
                raise CommandRuntimeError("NETWORK_PROBE_FAILED", str(exc), exit_code=5) from exc
        if action == "net-interfaces":
            self._expect_count(args, 0, 0, "terminal net-interfaces")
            try:
                return NetworkTerminalToolkit.interfaces()
            except (OSError, RuntimeError, ValueError) as exc:
                raise CommandRuntimeError("NETWORK_INTERFACES_FAILED", str(exc), exit_code=5) from exc
        if action == "net-sockets":
            kind = self._option(args, "--kind", default="inet")
            limit_raw = self._option(args, "--limit", default="500")
            self._expect_count(args, 0, 0, "terminal net-sockets")
            try:
                return NetworkTerminalToolkit.sockets(kind=kind, limit=int(limit_raw))
            except (OSError, RuntimeError, ValueError) as exc:
                raise CommandRuntimeError("NETWORK_SOCKETS_FAILED", str(exc), exit_code=5) from exc
        if action == "net-service":
            port_raw = self._required_option(args, "--port")
            protocol = self._option(args, "--protocol", default="tcp")
            self._expect_count(args, 0, 0, "terminal net-service")
            try:
                return NetworkTerminalToolkit.service(int(port_raw), protocol=protocol)
            except (OSError, RuntimeError, ValueError) as exc:
                raise CommandRuntimeError("NETWORK_SERVICE_FAILED", str(exc), exit_code=5) from exc
        if action == "net-protocol":
            protocol_name = self._one_id(args, "terminal net-protocol <name>")
            try:
                return NetworkTerminalToolkit.protocol(protocol_name)
            except (OSError, RuntimeError, ValueError) as exc:
                raise CommandRuntimeError("NETWORK_PROTOCOL_FAILED", str(exc), exit_code=5) from exc
        return _TERMINAL_UNHANDLED

    def _terminal_packet_action(self, action: str, args: list[str]) -> Any:
        """Dispatch packet commands between catalog/decode and capture-analysis handlers."""
        for handler in (self._terminal_packet_catalog_action, self._terminal_packet_capture_action):
            result = handler(action, args)
            if result is not _TERMINAL_UNHANDLED:
                return result
        return _TERMINAL_UNHANDLED

    def _terminal_packet_catalog_action(self, action: str, args: list[str]) -> Any:
        """Handle packet capability, catalog, field, and raw-frame decode commands."""
        if action == "packet-capabilities":
            self._expect_count(args, 0, 0, "terminal packet-capabilities")
            engine = PacketAnalysisEngine()
            capabilities = asdict(engine.capabilities())
            capabilities["coverage"] = engine.protocol_coverage()
            return capabilities
        if action == "packet-protocols":
            contains = self._option(args, "--contains", default="").casefold()
            limit_raw = self._option(args, "--limit", default="500")
            self._expect_count(args, 0, 0, "terminal packet-protocols")
            try:
                limit = max(1, min(int(limit_raw), 5000))
            except ValueError as exc:
                raise CommandRuntimeError("USAGE", "--limit must be an integer") from exc
            engine = PacketAnalysisEngine()
            rows = engine.unified_protocol_catalog(contains=contains, limit=limit)
            return {
                "external_available": engine.available,
                "registry": engine.unified_protocol_registry(field_limit=limit).snapshot(),
                "count": len(rows),
                "protocols": rows,
            }
        if action == "packet-fields":
            contains = self._option(args, "--contains", default="").casefold()
            limit_raw = self._option(args, "--limit", default="500")
            self._expect_count(args, 0, 0, "terminal packet-fields")
            try:
                limit = max(1, min(int(limit_raw), 5000))
            except ValueError as exc:
                raise CommandRuntimeError("USAGE", "--limit must be an integer") from exc
            engine = PacketAnalysisEngine()
            rows = engine.unified_field_catalog(contains=contains, limit=limit)
            return {
                "external_available": engine.available,
                "registry": engine.unified_protocol_registry(field_limit=limit).snapshot(),
                "count": len(rows),
                "fields": rows,
            }
        if action == "packet-decode":
            raw_hex = self._required_option(args, "--hex")
            link_type = self._option(args, "--link", default="ethernet")
            self._expect_count(args, 0, 0, "terminal packet-decode")
            if len(raw_hex) > 524288:
                raise CommandRuntimeError("PACKET_INPUT_TOO_LARGE", "Terminal packet hex input is limited to 256 KiB.", exit_code=3)
            try:
                frame = bytes.fromhex(raw_hex)
                return asdict(PacketAnalysisEngine.decode_raw_frame(frame, link_type=link_type))
            except ValueError as exc:
                raise CommandRuntimeError("PACKET_DECODE_FAILED", str(exc), exit_code=5) from exc
        return _TERMINAL_UNHANDLED

    def _terminal_packet_capture_action(self, action: str, args: list[str]) -> Any:
        """Handle capture-file metadata, summary, frame, and statistics commands."""
        if action == "packet-info":
            capture = self._one_id(args, "terminal packet-info <capture>")
            try:
                info = PacketAnalysisEngine().capture_info(capture)
                return {"path": info.path, "info": info.output}
            except (ArenyxaError, OSError, RuntimeError, ValueError) as exc:
                raise CommandRuntimeError("PACKET_INFO_FAILED", str(exc), exit_code=5) from exc
        if action == "packet-summary":
            if not args or args[0].startswith("--"):
                raise CommandRuntimeError("USAGE", "Usage: terminal packet-summary <capture> [--limit N]")
            capture = args.pop(0)
            limit_raw = self._option(args, "--limit", default="1000")
            self._expect_count(args, 0, 0, "terminal packet-summary")
            try:
                limit = max(1, min(int(limit_raw), 10000))
                rows = [asdict(row) for row in PacketAnalysisEngine().iter_packet_summaries(capture, limit=limit)]
                return {"count": len(rows), "limit": limit, "packets": rows}
            except (ArenyxaError, OSError, RuntimeError, ValueError) as exc:
                raise CommandRuntimeError("PACKET_SUMMARY_FAILED", str(exc), exit_code=5) from exc
        if action == "packet-frame":
            if not args or args[0].startswith("--"):
                raise CommandRuntimeError("USAGE", "Usage: terminal packet-frame <capture> --number N")
            capture = args.pop(0)
            number_raw = self._required_option(args, "--number")
            include_raw = not self._pop_flag(args, "--no-raw")
            self._expect_count(args, 0, 0, "terminal packet-frame")
            try:
                number = int(number_raw)
                if number < 1 or number > 100_000_000:
                    raise ValueError("frame number is out of bounds")
                return PacketAnalysisEngine().packet_tree(capture, number, include_raw=include_raw)
            except (ArenyxaError, OSError, RuntimeError, ValueError) as exc:
                raise CommandRuntimeError("PACKET_FRAME_FAILED", str(exc), exit_code=5) from exc
        if action == "packet-stats":
            capture = self._one_id(args, "terminal packet-stats <capture>")
            try:
                stats = PacketAnalysisEngine().full_statistics(capture)
                return asdict(stats)
            except (ArenyxaError, OSError, RuntimeError, ValueError) as exc:
                raise CommandRuntimeError("PACKET_STATS_FAILED", str(exc), exit_code=5) from exc
        return _TERMINAL_UNHANDLED

    def _terminal_session_action(self, action: str, args: list[str]) -> Any:
        """Handle one bounded terminal command family without growing the top-level dispatcher."""
        if action == "session-list":
            self._expect_count(args, 0, 0, "terminal session-list")
            return self._terminal_workspace().list()
        if action == "session-create":
            mode = self._option(args, "--mode", default="powershell-session")
            title = self._option(args, "--title", default="Terminal")
            pane = self._option(args, "--pane", default="primary")
            self._expect_count(args, 0, 0, "terminal session-create")
            if mode in {"powershell-session", "cmd-session"} and not bool(
                getattr(self.context.settings, "developer_direct_shell_enabled", False)
            ):
                raise CommandRuntimeError(
                    "DIRECT_SHELL_DISABLED",
                    "PowerShell/CMD persistent sessions require the Developer Mode Direct Shell setting.",
                    exit_code=3,
                )
            try:
                session = self._terminal_workspace().create(title=title, mode=mode, pane=pane)
                self._terminal_workspace().start(str(session["id"]))
                return self._terminal_workspace().snapshot(str(session["id"]))
            except (KeyError, OSError, RuntimeError, ValueError) as exc:
                raise CommandRuntimeError("TERMINAL_SESSION_CREATE_FAILED", str(exc), exit_code=5) from exc
        if action == "session-send":
            if not args or args[0].startswith("--"):
                raise CommandRuntimeError("USAGE", "Usage: terminal session-send <session_id> --text <text>")
            session_id = args.pop(0)
            text = self._required_option(args, "--text")
            no_newline = self._pop_flag(args, "--no-newline")
            self._expect_count(args, 0, 0, "terminal session-send")
            try:
                return self._terminal_workspace().send(session_id, text, newline=not no_newline)
            except (KeyError, OSError, RuntimeError, ValueError) as exc:
                raise CommandRuntimeError("TERMINAL_SESSION_SEND_FAILED", str(exc), exit_code=5) from exc
        if action == "session-output":
            if not args or args[0].startswith("--"):
                raise CommandRuntimeError("USAGE", "Usage: terminal session-output <session_id> [--tail N]")
            session_id = args.pop(0)
            tail_raw = self._option(args, "--tail", default="200000")
            self._expect_count(args, 0, 0, "terminal session-output")
            try:
                tail = int(tail_raw)
            except ValueError as exc:
                raise CommandRuntimeError("USAGE", "--tail must be an integer") from exc
            try:
                return {"session": self._terminal_workspace().snapshot(session_id), "output": self._terminal_workspace().output(session_id, tail_chars=tail)}
            except KeyError as exc:
                raise CommandRuntimeError("TERMINAL_SESSION_NOT_FOUND", str(exc), exit_code=4) from exc
        if action == "session-rename":
            if not args or args[0].startswith("--"):
                raise CommandRuntimeError("USAGE", "Usage: terminal session-rename <session_id> --title <title>")
            session_id = args.pop(0)
            title = self._required_option(args, "--title")
            self._expect_count(args, 0, 0, "terminal session-rename")
            return self._terminal_workspace().rename(session_id, title)
        if action == "session-move":
            if not args or args[0].startswith("--"):
                raise CommandRuntimeError("USAGE", "Usage: terminal session-move <session_id> --pane <primary|secondary|bottom>")
            session_id = args.pop(0)
            pane = self._required_option(args, "--pane")
            self._expect_count(args, 0, 0, "terminal session-move")
            return self._terminal_workspace().move(session_id, pane)
        if action == "session-resize":
            if not args or args[0].startswith("--"):
                raise CommandRuntimeError("USAGE", "Usage: terminal session-resize <session_id> --columns N --rows N")
            session_id = args.pop(0)
            columns_raw = self._required_option(args, "--columns")
            rows_raw = self._required_option(args, "--rows")
            self._expect_count(args, 0, 0, "terminal session-resize")
            try:
                return self._terminal_workspace().resize(session_id, int(columns_raw), int(rows_raw))
            except ValueError as exc:
                raise CommandRuntimeError("TERMINAL_SESSION_RESIZE_FAILED", str(exc), exit_code=5) from exc
        if action == "session-interrupt":
            session_id = self._one_id(args, "terminal session-interrupt <session_id>")
            try:
                return self._terminal_workspace().interrupt(session_id)
            except KeyError as exc:
                raise CommandRuntimeError("TERMINAL_SESSION_NOT_FOUND", str(exc), exit_code=4) from exc
        if action == "session-stop":
            session_id = self._one_id(args, "terminal session-stop <session_id>")
            try:
                return self._terminal_workspace().stop(session_id)
            except KeyError as exc:
                raise CommandRuntimeError("TERMINAL_SESSION_NOT_FOUND", str(exc), exit_code=4) from exc
        if action == "session-close":
            session_id = self._one_id(args, "terminal session-close <session_id>")
            if not self._terminal_workspace().close(session_id):
                raise CommandRuntimeError("TERMINAL_SESSION_NOT_FOUND", f"Terminal session not found: {session_id}", exit_code=4)
            return {"session_id": session_id, "closed": True}
        return _TERMINAL_UNHANDLED

    def _terminal_run_action(self, action: str, args: list[str]) -> Any:
        """Handle one bounded terminal command family without growing the top-level dispatcher."""
        if action == "run":
            if not args:
                raise CommandRuntimeError(
                    "USAGE",
                    "Usage: terminal run <direct|powershell|cmd|python> --confirm-external --command <command>",
                )
            mode_name = args.pop(0).casefold()
            mode_map = {
                "direct": TerminalMode.DIRECT,
                "powershell": TerminalMode.POWERSHELL,
                "cmd": TerminalMode.CMD,
                "python": TerminalMode.PYTHON,
            }
            mode = mode_map.get(mode_name)
            if mode is None:
                raise CommandRuntimeError("USAGE", f"Unsupported one-shot terminal mode: {mode_name}")
            confirmed = self._pop_flag(args, "--confirm-external")
            command = self._required_option(args, "--command")
            if len(command) >= 2 and command[0] == command[-1] and command[0] in {"\"", "'"}:
                command = command[1:-1]
            self._expect_count(args, 0, 0, "terminal run")
            if not confirmed:
                raise CommandRuntimeError(
                    "EXTERNAL_CONFIRMATION_REQUIRED",
                    "Headless external execution requires --confirm-external for every command.",
                    exit_code=3,
                )
            if mode in {TerminalMode.POWERSHELL, TerminalMode.CMD} and not bool(
                getattr(self.context.settings, "developer_direct_shell_enabled", False)
            ):
                raise CommandRuntimeError(
                    "DIRECT_SHELL_DISABLED",
                    "PowerShell/CMD execution requires the Developer Mode Direct Shell setting.",
                    exit_code=3,
                )
            terminal = self.context.terminal
            if terminal.is_running:
                raise CommandRuntimeError("TERMINAL_BUSY", "Another external terminal process is already running", exit_code=5)
            try:
                launch = terminal.build_launch(command, mode)
            except (OSError, ValueError) as exc:
                raise CommandRuntimeError("TERMINAL_LAUNCH_FAILED", str(exc), exit_code=5) from exc
            chunks: list[str] = []
            results: list[Any] = []
            terminal.start(launch, chunks.append, results.append)
            wait_budget = min(3605.0, float(terminal.timeout_seconds) + 5.0)
            if not terminal.wait(wait_budget):
                terminal.stop()
                terminal.wait(5.0)
                raise CommandRuntimeError("TERMINAL_WAIT_FAILED", "External command did not terminate cleanly", exit_code=5)
            if not results:
                raise CommandRuntimeError("TERMINAL_RESULT_MISSING", "External command completed without a result", exit_code=5)
            result = results[0]
            return {
                "mode": mode.value,
                "display": terminal.redact_command(command),
                "exit_code": result.exit_code,
                "duration_seconds": result.duration_seconds,
                "timed_out": result.timed_out,
                "cancelled": result.cancelled,
                "output_truncated": result.output_truncated,
                "output": "".join(chunks),
            }
        return _TERMINAL_UNHANDLED

    def _schedule_row(self, schedule_id: str) -> dict[str, Any]:
        row = next((item for item in self.context.store.list_schedules() if str(item.get("id")) == schedule_id), None)
        if row is None:
            raise CommandRuntimeError("SCHEDULE_NOT_FOUND", f"Schedule not found: {schedule_id}", exit_code=4)
        return row

    def _schedule_callback(self, task_id: str, schedule_id: str) -> Any:
        def run_scheduled() -> None:
            operations = getattr(self.context, "enterprise_operations", None)
            if operations is not None:
                operations.authorize_if_bound(
                    "schedule", schedule_id, "schedule.manage", correlation_id=f"schedule-run:{schedule_id}",
                )
            task = self.context.store.get_task(task_id)
            if task is None:
                return
            active = [
                item for item in self.context.runner.active_handles()
                if str(getattr(item.run, "task_id", "")) == task_id and not item.future.done()
            ]
            if active:
                return
            self.context.runner.submit(task)
        return run_scheduled

    def _confined_export_path(self, value: str) -> Any:
        from pathlib import Path

        candidate = Path(str(value)).expanduser()
        if not candidate.is_absolute():
            candidate = self.context.paths.exports / candidate
        resolved = candidate.resolve(strict=False)
        exports_root = self.context.paths.exports.resolve(strict=False)
        try:
            resolved.relative_to(exports_root)
        except ValueError as exc:
            raise CommandRuntimeError(
                "EXPORT_PATH_DENIED",
                f"CLI exports are confined to the Arenyxa exports directory: {exports_root}",
                exit_code=3,
            ) from exc
        return resolved

    def _required_option(self, args: list[str], name: str) -> str:
        value = self._option(args, name, default="")
        if not value:
            raise CommandRuntimeError("USAGE", f"Missing required option: {name}")
        return value
