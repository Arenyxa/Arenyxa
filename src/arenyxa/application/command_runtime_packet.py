from __future__ import annotations
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


class CommandPacketMixin:
    def _packet(self, args: list[str]) -> Any:
        action = self._action(args, "packet")
        if action == "sessions":
            return self.context.store.list_captures(limit=self._limit(args, default=100, maximum=1000))
        if action in {"events", "http", "hosts", "summary", "conversations"}:
            if not args:
                raise CommandRuntimeError("USAGE", f"Usage: packet {action} <session_id> [--limit N]")
            session_id = args.pop(0)
            limit = self._limit(args, default=1000, maximum=10000)
            rows = list(self.context.store.iter_network_events(session_id, limit))
            if action == "events":
                return rows
            http_rows = [row for row in rows if row.get("method") or row.get("status") is not None or str(row.get("protocol", "")).casefold() in {"http", "https", "http2", "http3"}]
            if action == "http":
                return http_rows
            hosts: dict[str, dict[str, Any]] = {}
            protocols: dict[str, dict[str, Any]] = {}
            conversations: dict[str, dict[str, Any]] = {}
            total_bytes = 0
            error_events = 0
            for row in rows:
                size = max(0, int(row.get("size") or 0))
                total_bytes += size
                protocol = str(row.get("protocol") or "unknown").strip().casefold() or "unknown"
                proto = protocols.setdefault(protocol, {"protocol": protocol, "events": 0, "bytes": 0, "errors": 0})
                proto["events"] += 1
                proto["bytes"] += size
                status = row.get("status")
                is_error = isinstance(status, int) and status >= 400
                if is_error:
                    proto["errors"] += 1
                    error_events += 1
                host = str(row.get("host") or "").strip()
                if host:
                    item = hosts.setdefault(host, {"host": host, "events": 0, "bytes": 0, "http": 0, "errors": 0})
                    item["events"] += 1
                    item["bytes"] += size
                    if row.get("method"):
                        item["http"] += 1
                    if is_error:
                        item["errors"] += 1
                flow_ref = str(row.get("flow_ref") or "").strip()
                if not flow_ref:
                    flow_ref = f"{protocol}:{host or 'unknown'}:{str(row.get('direction') or '')}"
                convo = conversations.setdefault(flow_ref, {
                    "flow_ref": flow_ref, "protocol": protocol, "host": host, "events": 0, "bytes": 0,
                    "requests": 0, "responses": 0, "errors": 0,
                })
                convo["events"] += 1
                convo["bytes"] += size
                if row.get("method"):
                    convo["requests"] += 1
                if status is not None:
                    convo["responses"] += 1
                if is_error:
                    convo["errors"] += 1
            if action == "hosts":
                return sorted(hosts.values(), key=lambda item: (-int(item["events"]), str(item["host"])))
            if action == "conversations":
                return sorted(conversations.values(), key=lambda item: (-int(item["bytes"]), -int(item["events"]), str(item["flow_ref"])))[:2000]
            return {
                "session_id": session_id,
                "events": len(rows),
                "bytes": total_bytes,
                "http_events": len(http_rows),
                "error_events": error_events,
                "protocols": sorted(protocols.values(), key=lambda item: (-int(item["events"]), str(item["protocol"]))),
                "top_hosts": sorted(hosts.values(), key=lambda item: (-int(item["bytes"]), str(item["host"])))[:20],
                "conversation_count": len(conversations),
            }
        if action == "analytics":
            if not args:
                raise CommandRuntimeError("USAGE", "Usage: packet analytics <session_id> [--limit N]")
            session_id = args.pop(0)
            limit = self._limit(args, default=50000, maximum=100000)
            events = [self._network_event(row) for row in self.context.store.iter_network_events(session_id, limit)]
            return PacketAdvancedAnalyzer().analyze(events, limit=limit).snapshot()
        if action in {"detect", "hunt"}:
            if not args:
                raise CommandRuntimeError("USAGE", f"Usage: packet {action} <capture-file> [--limit N] [--filter EXPR]")
            raw_path = args.pop(0)
            display_filter = self._option(args, "--filter", default="")
            limit = self._limit(args, default=100000, maximum=1000000)
            capture_path = self._confined_project_path(raw_path)
            session = CaptureSession(name=f"Offline {action}", source_type=CaptureSource.PCAP_IMPORT)
            engine = PacketAnalysisEngine()
            try:
                events = list(engine.iter_network_events(capture_path, session, display_filter=display_filter, limit=limit))
            except (ArenyxaError, OSError, RuntimeError, ValueError) as exc:
                raise CommandRuntimeError("PACKET_ANALYSIS_FAILED", str(exc), exit_code=5) from exc
            if action == "detect":
                detector = PassiveDetectionEngine()
                alerts = [alert.snapshot() for event in events for alert in detector.inspect(event)]
                return {
                    "capture": str(capture_path), "events_analyzed": len(events),
                    "alert_count": len(alerts), "alerts": alerts[:5000],
                }
            return {"capture": str(capture_path), **ThreatHunter().hunt(events, limit=limit)}
        if action == "protocols":
            contains = self._option(args, "--contains", default="")
            limit = self._limit(args, default=500, maximum=5000)
            self._expect_count(args, 0, 0, "packet protocols")
            traffic = getattr(self.context, "traffic_control", None)
            if traffic is not None and getattr(self.context, "local_control_session", None) is not None:
                return traffic.protocol_catalog(
                    session=self.context.local_control_session, surface="cli", contains=contains, limit=limit
                )
            engine = PacketAnalysisEngine()
            rows = engine.unified_protocol_catalog(contains=contains, limit=limit)
            return {
                "external_available": engine.available,
                "registry": engine.unified_protocol_registry(field_limit=limit).snapshot(),
                "count": len(rows), "protocols": rows,
            }
        if action == "fields":
            contains = self._option(args, "--contains", default="")
            protocol = self._option(args, "--protocol", default="")
            limit = self._limit(args, default=500, maximum=5000)
            self._expect_count(args, 0, 0, "packet fields")
            traffic = getattr(self.context, "traffic_control", None)
            if traffic is not None and getattr(self.context, "local_control_session", None) is not None:
                return traffic.protocol_fields(
                    session=self.context.local_control_session, surface="cli",
                    contains=contains, protocol=protocol, limit=limit
                )
            engine = PacketAnalysisEngine()
            rows = engine.unified_field_catalog(contains=contains, protocol=protocol, limit=limit)
            return {
                "external_available": engine.available,
                "registry": engine.unified_protocol_registry(field_limit=limit).snapshot(),
                "count": len(rows), "fields": rows,
            }
        if action == "build":
            protocol = self._option(args, "--protocol", default="udp").casefold()
            payload = self._option(args, "--payload", default="")
            output = self._option(args, "--output", default="")
            try:
                if protocol in {"udp", "tcp", "icmp", "udp6", "tcp6", "icmp6", "dns", "http", "tls-client-hello"}:
                    src_ip = self._required_option(args, "--src-ip")
                    dst_ip = self._required_option(args, "--dst-ip")
                if protocol == "udp":
                    artifact = OfflinePacketLab.ipv4_udp(
                        src_ip=src_ip, dst_ip=dst_ip,
                        src_port=int(self._required_option(args, "--src-port")),
                        dst_port=int(self._required_option(args, "--dst-port")),
                        payload=payload,
                    )
                elif protocol == "tcp":
                    flags = int(self._option(args, "--flags", default="2"), 0)
                    artifact = OfflinePacketLab.ipv4_tcp(
                        src_ip=src_ip, dst_ip=dst_ip,
                        src_port=int(self._required_option(args, "--src-port")),
                        dst_port=int(self._required_option(args, "--dst-port")),
                        payload=payload, flags=flags,
                    )
                elif protocol == "icmp":
                    artifact = OfflinePacketLab.ipv4_icmp_echo(src_ip=src_ip, dst_ip=dst_ip, payload=payload)
                elif protocol == "udp6":
                    artifact = OfflinePacketLab.ipv6_udp(
                        src_ip=src_ip, dst_ip=dst_ip,
                        src_port=int(self._required_option(args, "--src-port")),
                        dst_port=int(self._required_option(args, "--dst-port")), payload=payload,
                    )
                elif protocol == "tcp6":
                    flags = int(self._option(args, "--flags", default="2"), 0)
                    artifact = OfflinePacketLab.ipv6_tcp(
                        src_ip=src_ip, dst_ip=dst_ip,
                        src_port=int(self._required_option(args, "--src-port")),
                        dst_port=int(self._required_option(args, "--dst-port")), payload=payload, flags=flags,
                    )
                elif protocol == "icmp6":
                    artifact = OfflinePacketLab.ipv6_icmp_echo(src_ip=src_ip, dst_ip=dst_ip, payload=payload)
                elif protocol == "arp":
                    artifact = OfflinePacketLab.arp_request(
                        src_mac=self._required_option(args, "--src-mac"),
                        src_ip=self._required_option(args, "--src-ip"),
                        target_ip=self._required_option(args, "--target-ip"),
                    )
                elif protocol == "dns":
                    artifact = OfflinePacketLab.dns_query(
                        src_ip=src_ip, dst_ip=dst_ip, name=self._required_option(args, "--name"),
                        src_port=int(self._option(args, "--src-port", default="53000")),
                        dst_port=int(self._option(args, "--dst-port", default="53")),
                        query_type=int(self._option(args, "--query-type", default="1"), 0),
                    )
                elif protocol == "dhcp":
                    artifact = OfflinePacketLab.dhcp_discover(
                        client_mac=self._required_option(args, "--client-mac"),
                        hostname=self._option(args, "--hostname", default="arenyxa-lab"),
                    )
                elif protocol == "http":
                    artifact = OfflinePacketLab.http_request(
                        src_ip=src_ip, dst_ip=dst_ip, host=self._required_option(args, "--host"),
                        target=self._option(args, "--target", default="/"),
                        method=self._option(args, "--method", default="GET"),
                        src_port=int(self._option(args, "--src-port", default="49152")),
                        dst_port=int(self._option(args, "--dst-port", default="80")), body=payload,
                    )
                elif protocol == "tls-client-hello":
                    artifact = OfflinePacketLab.tls_client_hello(
                        src_ip=src_ip, dst_ip=dst_ip, server_name=self._required_option(args, "--server-name"),
                        src_port=int(self._option(args, "--src-port", default="49152")),
                        dst_port=int(self._option(args, "--dst-port", default="443")),
                    )
                else:
                    raise CommandRuntimeError(
                        "USAGE",
                        "packet build --protocol must be udp, tcp, icmp, udp6, tcp6, icmp6, arp, dns, dhcp, http, or tls-client-hello",
                    )
                self._expect_count(args, 0, 0, "packet build")
                result = artifact.snapshot()
                if output:
                    destination = self._confined_export_path(output)
                    linktype = 1 if artifact.link_type == "ethernet" else 101
                    OfflinePacketLab.write_pcap(destination, artifact, linktype=linktype)
                    result["pcap_path"] = str(destination)
                return result
            except CommandRuntimeError:
                raise
            except (OSError, TypeError, ValueError) as exc:
                raise CommandRuntimeError("PACKET_BUILD_FAILED", str(exc), exit_code=5) from exc
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown packet action: {action}")

    def _extraction(self, args: list[str]) -> Any:
        action = self._action(args, "extraction")
        if action == "pick":
            url = self._required_option(args, "--url")
            timeout_raw = self._option(args, "--timeout", default="120")
            self._expect_count(args, 0, 0, "extraction pick")
            try:
                timeout_seconds = int(timeout_raw)
            except ValueError as exc:
                raise CommandRuntimeError("USAGE", "--timeout must be an integer") from exc
            try:
                return self._normalize(ExtractionLivePicker().pick(url, timeout_seconds=timeout_seconds, headless=False))
            except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
                raise CommandRuntimeError("EXTRACTION_PICK_FAILED", str(exc), exit_code=5) from exc
        if action in {"recipe-validate", "recipe-compile", "recipe-run"}:
            recipe_path = self._required_option(args, "--file")
            headed = self._pop_flag(args, "--headed") if action == "recipe-run" else False
            output_raw = self._option(args, "--output", default="") if action == "recipe-run" else ""
            self._expect_count(args, 0, 0, f"extraction {action}")
            path = self._confined_project_path(recipe_path)
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                raise CommandRuntimeError("EXTRACTION_RECIPE_INVALID", str(exc), exit_code=5) from exc
            if not isinstance(payload, dict):
                raise CommandRuntimeError("EXTRACTION_RECIPE_INVALID", "Extraction recipe must be a JSON object", exit_code=5)
            compiler = ExtractionRecipeCompiler()
            try:
                recipe = compiler.from_mapping(payload)
                warnings = compiler.validate(recipe)
                if action == "recipe-validate":
                    return {"valid": True, "warnings": warnings, "recipe": recipe.snapshot()}
                if action == "recipe-compile":
                    return {"workflow": compiler.compile(recipe), "warnings": warnings}
                vault = getattr(getattr(self.context, "nextgen", None), "vault", None)
                resolver = getattr(vault, "get", None) if vault is not None else None
                result = ExtractionRecipeExecutor().execute(
                    recipe, headless=not headed, secret_resolver=resolver if callable(resolver) else None
                ).snapshot()
                if output_raw:
                    destination = self._confined_export_path(output_raw)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    payload_text = json.dumps(result, ensure_ascii=False, indent=2, default=str) + "\n"
                    if len(payload_text.encode("utf-8")) > 64 * 1024 * 1024:
                        raise CommandRuntimeError("EXPORT_TOO_LARGE", "Extraction result exceeds the 64 MiB export budget", exit_code=5)
                    destination.write_text(payload_text, encoding="utf-8")
                    result["export_path"] = str(destination)
                return result
            except (TypeError, ValueError) as exc:
                raise CommandRuntimeError("EXTRACTION_RECIPE_INVALID", str(exc), exit_code=5) from exc
        if not args:
            raise CommandRuntimeError("USAGE", f"Usage: extraction {action} <session_id> ...")
        session_id = args.pop(0)
        source_url = self._option(args, "--source-url", default="")
        field_specs = self._options(args, "--field")
        limit = self._limit(args, default=5000, maximum=20000)
        rows = list(self.context.store.iter_network_events(session_id, limit))
        events = [self._network_event(row) for row in rows]
        fields = [self._field_spec(value) for value in field_specs]
        if action == "analyze":
            result = ExtractionStudioService().analyze(events, source_url=source_url, fields=fields)
            return self._normalize(result)
        if action == "dry-run":
            if not fields:
                raise CommandRuntimeError("USAGE", "extraction dry-run requires at least one --field name:type:selector")
            store = NetworkBodyStore.for_capture(self.context.paths.captures, session_id)
            def resolve(body_id: str, max_bytes: int) -> bytes | None:
                artifact = self.context.store.get_network_body(body_id)
                if artifact is None:
                    return None
                return store.read(artifact, max_bytes=max_bytes)
            result = ExtractionDryRun().preview(events, fields, resolve)
            return self._normalize(result)
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown extraction action: {action}")

    def _web(self, args: list[str]) -> Any:
        action = self._action(args, "web")
        if action == "autopilot-status":
            self._expect_count(args, 0, 0, "web autopilot-status")
            autopilot = getattr(self.context.nextgen, "autopilot", None)
            if autopilot is None:
                return {"available": False}
            experience = getattr(autopilot, "experience", None) or getattr(autopilot, "store", None)
            stats = experience.stats() if experience is not None and hasattr(experience, "stats") else {}
            return {"available": True, "mode": "local-advisory", "production_override": False, "experience": stats}
        if action == "autopilot-validate":
            samples_raw = self._option(args, "--samples", default="200")
            self._expect_count(args, 0, 0, "web autopilot-validate [--samples N]")
            try:
                samples = int(samples_raw)
            except ValueError as exc:
                raise CommandRuntimeError("USAGE", "--samples must be an integer") from exc
            return AutopilotProductionValidator(samples=samples).run().to_dict()
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown web action: {action}")
