from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from arenyxa.application.api_security_lab import ApiSecurityLab
from arenyxa.application.command_runtime_base import CommandRuntimeError
from arenyxa.application.runtime_recovery import RuntimeRecoveryService
from arenyxa.application.traffic_automation import (
    TrafficAutomationEngine,
    TrafficEvent,
    configure_default_traffic_handlers,
)
from arenyxa.application.traffic_intelligence import TrafficIntelligenceAnalyzer


class CommandPlatformMixin:
    """Professional platform commands shared by the standalone and embedded terminal."""

    def _platform_proxy(self) -> Any:
        engine = getattr(self.context, "proxy_engine", None)
        if engine is None:
            raise CommandRuntimeError("PROXY_UNAVAILABLE", "Proxy runtime is unavailable", exit_code=5)
        return engine

    def _durable_proxy_flows(self, limit: int) -> list[Any]:
        engine = self._platform_proxy()
        bounded = max(1, min(int(limit), 100_000))
        rows: list[Any] = []
        page = 1
        while len(rows) < bounded:
            result = engine.history_page(page=page, page_size=min(1000, bounded - len(rows)))
            batch = list(result.get("items", []))
            rows.extend(batch)
            if not batch or not result.get("has_next"):
                break
            page += 1
        return rows

    def _tls(self, args: list[str]) -> Any:
        action = self._action(args, "tls")
        engine = self._platform_proxy()
        if action == "status":
            self._expect_count(args, 0, 0, "tls status")
            value = engine.ca.status()
            value["proxy_running"] = bool(engine.running)
            value["tls_interception"] = bool(engine.settings.tls_interception)
            return value
        if action == "certificates":
            limit = self._limit(args, default=100, maximum=10000)
            return engine.ca.certificates(limit=limit)
        if action == "export-root":
            if not args or args[0].startswith("--"):
                raise CommandRuntimeError("USAGE", "Usage: tls export-root <path>")
            destination = self._confined_export_path(args.pop(0))
            self._expect_count(args, 0, 0, "tls export-root")
            return {"path": str(engine.export_ca_certificate(destination)), "private_key_exported": False}
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown tls action: {action}")

    def _api(self, args: list[str]) -> Any:
        action = self._action(args, "api")
        lab = ApiSecurityLab()
        if action == "analyze":
            limit = self._limit(args, default=10_000, maximum=100_000)
            return lab.analyze(self._durable_proxy_flows(limit)).snapshot()
        if action == "openapi":
            if not args or args[0].startswith("--"):
                raise CommandRuntimeError("USAGE", "Usage: api openapi <document.json>")
            path = Path(args.pop(0)).expanduser().resolve()
            self._expect_count(args, 0, 0, "api openapi")
            try:
                if path.stat().st_size > 16 * 1024 * 1024:
                    raise ValueError("OpenAPI document exceeds the 16 MiB safety limit")
                rows = lab.import_openapi_json(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
                raise CommandRuntimeError("OPENAPI_IMPORT_FAILED", str(exc), exit_code=5) from exc
            return {
                "path": str(path),
                "endpoint_count": len(rows),
                "endpoints": [asdict(item) for item in rows],
            }
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown api action: {action}")

    def _analyze(self, args: list[str]) -> Any:
        action = self._action(args, "analyze")
        if action != "traffic":
            raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown analyze action: {action}")
        limit = self._limit(args, default=10_000, maximum=100_000)
        return TrafficIntelligenceAnalyzer().analyze(self._durable_proxy_flows(limit)).snapshot()

    def _export_professional(self, args: list[str]) -> Any:
        action = self._action(args, "export")
        if action != "session":
            raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown export action: {action}")
        if not args or args[0].startswith("--"):
            raise CommandRuntimeError("USAGE", "Usage: export session <path> [--unredacted]")
        destination = self._confined_export_path(args.pop(0))
        unredacted = self._pop_flag(args, "--unredacted")
        self._expect_count(args, 0, 0, "export session")
        exported = self._platform_proxy().export_har(destination, redact_sensitive=not unredacted)
        return {"path": str(exported), "format": "har", "redacted": not unredacted}

    def _enterprise(self, args: list[str]) -> Any:
        action = self._action(args, "enterprise")
        control = getattr(self.context, "control_plane", None)
        session = getattr(self.context, "local_control_session", None)
        if control is None or session is None:
            raise CommandRuntimeError("CONTROL_PLANE_UNAVAILABLE", "Arenyxa v8 Application Control Plane is unavailable", exit_code=5)
        if action == "status":
            self._expect_count(args, 0, 0, "enterprise status")
            return control.enterprise_status(session=session, surface="cli", include_fleet=True)
        if action == "governance":
            self._expect_count(args, 0, 0, "enterprise governance")
            return control.enterprise_governance(session=session, surface="cli")
        if action == "enrollment":
            self._expect_count(args, 0, 0, "enterprise enrollment")
            return control.enterprise_enrollment(session=session, surface="cli")
        if action == "storage":
            self._expect_count(args, 0, 0, "enterprise storage")
            return control.enterprise_storage(session=session, surface="cli")
        if action in {"workers", "jobs"}:
            state = self._option(args, "--state", default="")
            limit = self._limit(args, default=100, maximum=1000)
            self._expect_count(args, 0, 0, f"enterprise {action} [--state STATE] [--limit N]")
            if action == "workers":
                return control.enterprise_workers(session=session, surface="cli", limit=limit, state=state)
            return control.enterprise_jobs(session=session, surface="cli", limit=limit, state=state)
        if action in {"worker-drain", "worker-resume", "worker-revoke"}:
            worker_id = self._one_id(args, f"enterprise {action} <worker_id>")
            if action == "worker-revoke":
                return control.enterprise_worker_revoke(worker_id, session=session, surface="cli")
            return control.enterprise_worker_drain(
                worker_id, drain=action == "worker-drain", session=session, surface="cli"
            )
        if action == "retry-job":
            job_id = self._one_id(args, "enterprise retry-job <job_id>")
            return control.enterprise_retry_job(job_id, session=session, surface="cli")
        if action == "recover-leases":
            self._expect_count(args, 0, 0, "enterprise recover-leases")
            return control.enterprise_recover_leases(session=session, surface="cli")
        if action in {"server-authority-start", "server-authority-stop"}:
            ttl_raw = self._option(args, "--ttl", default="86400") if action == "server-authority-start" else "86400"
            self._expect_count(args, 0, 0, f"enterprise {action}")
            try:
                ttl = max(300, min(86400, int(ttl_raw)))
            except ValueError as exc:
                raise CommandRuntimeError("USAGE", "--ttl must be an integer number of seconds") from exc
            return control.enterprise_server_authority(
                "start" if action == "server-authority-start" else "stop",
                session=session, surface="cli", ttl_seconds=ttl,
            )
        if action == "audit":
            limit = self._limit(args, default=100, maximum=500)
            self._expect_count(args, 0, 0, "enterprise audit [--limit N]")
            return control.enterprise_audit(session=session, surface="cli", limit=limit)
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown enterprise action: {action}")

    def _recovery(self, args: list[str]) -> Any:
        action = self._action(args, "recovery")
        service = RuntimeRecoveryService(self.context.store)
        if action == "check":
            self._expect_count(args, 0, 0, "recovery check")
            audit = service.audit()
            return {
                "healthy": not audit.has_stale_active_state and not audit.has_invalid_state,
                "stale_active_state": audit.has_stale_active_state,
                "invalid_state": audit.has_invalid_state,
                "audit": audit.to_dict(),
                "proxy_history": self._platform_proxy().history_health(),
            }
        if action == "repair":
            self._expect_count(args, 0, 0, "recovery repair")
            result = service.recover()
            return result.to_dict()
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown recovery action: {action}")

    def _traffic_automation_engine(self) -> TrafficAutomationEngine:
        engine = getattr(self.context, "traffic_automation", None)
        if engine is None:
            engine = TrafficAutomationEngine(Path(self.context.paths.captures) / "automation" / "traffic-rules.json")
            configure_default_traffic_handlers(engine, Path(self.context.paths.captures) / "automation")
            self.context.traffic_automation = engine
        return engine

    def _traffic_automation(self, args: list[str]) -> Any:
        action = self._action(args, "traffic-automation")
        engine = self._traffic_automation_engine()
        if action == "list":
            self._expect_count(args, 0, 0, "traffic-automation list")
            return engine.list()
        if action == "add":
            name = self._required_option(args, "--name")
            event = self._required_option(args, "--event")
            actions_raw = self._required_option(args, "--actions")
            host = self._option(args, "--host", default="*")
            url = self._option(args, "--url", default="*")
            method = self._option(args, "--method", default="*")
            status = self._option(args, "--status", default="*")
            self._expect_count(args, 0, 0, "traffic-automation add")
            try:
                return engine.add(
                    name,
                    event,
                    [item.strip() for item in actions_raw.split(",") if item.strip()],
                    host_pattern=host,
                    url_pattern=url,
                    method_pattern=method,
                    status_pattern=status,
                )
            except ValueError as exc:
                raise CommandRuntimeError("TRAFFIC_AUTOMATION_RULE_INVALID", str(exc)) from exc
        if action == "remove":
            rule_id = self._one_id(args, "traffic-automation remove <rule_id>")
            if not engine.remove(rule_id):
                raise CommandRuntimeError("TRAFFIC_AUTOMATION_RULE_NOT_FOUND", f"Rule not found: {rule_id}", exit_code=4)
            return {"rule_id": rule_id, "removed": True}
        if action == "run":
            event_name = self._required_option(args, "--event")
            payload_raw = self._required_option(args, "--payload")
            self._expect_count(args, 0, 0, "traffic-automation run")
            try:
                payload = json.loads(payload_raw)
                if not isinstance(payload, dict):
                    raise ValueError("payload must be a JSON object")
                event = TrafficEvent(event_name.upper())
            except (json.JSONDecodeError, ValueError) as exc:
                raise CommandRuntimeError("TRAFFIC_AUTOMATION_EVENT_INVALID", str(exc)) from exc
            return engine.process(event, payload)
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown traffic-automation action: {action}")


__all__ = ["CommandPlatformMixin"]
