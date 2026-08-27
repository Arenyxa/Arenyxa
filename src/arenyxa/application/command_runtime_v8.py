from __future__ import annotations

from pathlib import Path
from typing import Any

from arenyxa.application.command_runtime_base import CommandRuntimeError


class CommandV8Mixin:
    """Canonical v8 CLI adapters over the shared PlatformControlPlane service."""

    def _v8_control_plane(self) -> Any:
        control_plane = getattr(self.context, "control_plane", None)
        if control_plane is None:
            raise CommandRuntimeError(
                "CONTROL_PLANE_UNAVAILABLE",
                "the Arenyxa v8 Application Control Plane is unavailable",
                exit_code=5,
            )
        return control_plane

    def _v8_traffic_control(self) -> Any:
        control = getattr(self.context, "traffic_control", None)
        if control is None:
            raise CommandRuntimeError(
                "TRAFFIC_CONTROL_UNAVAILABLE",
                "the Arenyxa v8 Network/Protocol/Proxy control plane is unavailable",
                exit_code=5,
            )
        return control

    def _v8_session(self) -> Any:
        session = getattr(self.context, "local_control_session", None)
        if session is None:
            raise CommandRuntimeError(
                "CONTROL_SESSION_UNAVAILABLE",
                "the local v8 Security Kernel session is unavailable",
                exit_code=3,
            )
        return session

    def _health_check(self, args: list[str]) -> dict[str, Any]:
        deep = self._pop_flag(args, "--deep")
        self._expect_count(args, 0, 0, "health-check [--deep]")
        return self._v8_control_plane().health(deep=deep)

    def _diagnostics(self, args: list[str]) -> dict[str, Any]:
        action = self._action(args, "diagnostics")
        if action != "export":
            raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown diagnostics action: {action}")
        output = self._option(args, "--output", default="")
        timeout_raw = self._option(args, "--timeout", default="120")
        no_wait = self._pop_flag(args, "--no-wait")
        self._expect_count(
            args,
            0,
            0,
            "diagnostics export [--output FILE.zip] [--timeout SECONDS] [--no-wait]",
        )
        try:
            timeout = max(1.0, min(3600.0, float(timeout_raw)))
        except ValueError as exc:
            raise CommandRuntimeError("USAGE", "--timeout must be a number") from exc
        job = self._v8_control_plane().submit_diagnostics_export(
            destination=None if not output else Path(output),
            session=self._v8_session(),
            surface="cli",
            timeout_seconds=timeout,
        )
        if no_wait:
            return job
        completed = self._v8_control_plane().wait_job(
            str(job["id"]),
            session=self._v8_session(),
            surface="cli",
            timeout_seconds=timeout + 10.0,
        )
        if completed["state"] != "succeeded":
            raise CommandRuntimeError(
                str(completed.get("error_code") or "DIAGNOSTICS_EXPORT_FAILED"),
                str(completed.get("error_message") or completed.get("message") or "diagnostics export failed"),
                exit_code=5,
            )
        return completed

    def _resilience(self, args: list[str]) -> Any:
        action = self._action(args, "resilience")
        control = self._v8_control_plane()
        session = self._v8_session()
        if action in {"status", "refresh"}:
            self._expect_count(args, 0, 0, f"resilience {action}")
            return control.survivability_status(
                session=session, surface="cli", refresh=action == "refresh"
            )
        if action == "performance":
            self._expect_count(args, 0, 0, "resilience performance")
            return control.performance_status(session=session, surface="cli")
        if action == "drills":
            timeout_raw = self._option(args, "--timeout", default="120")
            no_wait = self._pop_flag(args, "--no-wait")
            self._expect_count(args, 0, 0, "resilience drills [--timeout SECONDS] [--no-wait]")
            try:
                timeout = max(10.0, min(3600.0, float(timeout_raw)))
            except ValueError as exc:
                raise CommandRuntimeError("USAGE", "--timeout must be a number") from exc
            job = control.submit_resilience_drills(
                session=session, surface="cli", timeout_seconds=timeout
            )
            if no_wait:
                return job
            completed = control.wait_job(
                str(job["id"]), session=session, surface="cli", timeout_seconds=timeout + 10.0
            )
            if completed.get("state") != "succeeded":
                raise CommandRuntimeError(
                    str(completed.get("error_code") or "RESILIENCE_DRILLS_FAILED"),
                    str(completed.get("error_message") or "resilience drills failed"),
                    exit_code=5,
                )
            return completed
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown resilience action: {action}")

    def _job(self, args: list[str]) -> Any:
        action = self._action(args, "job")
        control_plane = self._v8_control_plane()
        session = self._v8_session()
        if action == "list":
            state = self._option(args, "--state", default="")
            limit = self._limit(args, default=100, maximum=1000)
            return control_plane.list_jobs(
                session=session, surface="cli", limit=limit, state=state
            )
        if action in {"show", "cancel", "wait"}:
            timeout_raw = self._option(args, "--timeout", default="300") if action == "wait" else ""
            job_id = self._one_id(args, f"job {action} <job_id>")
            if action == "show":
                return control_plane.get_job(job_id, session=session, surface="cli")
            if action == "cancel":
                return control_plane.cancel_job(job_id, session=session, surface="cli")
            try:
                timeout = max(0.0, min(3600.0, float(timeout_raw)))
            except ValueError as exc:
                raise CommandRuntimeError("USAGE", "--timeout must be a number") from exc
            return control_plane.wait_job(
                job_id,
                session=session,
                surface="cli",
                timeout_seconds=timeout,
            )
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown job action: {action}")
    def _platform(self, args: list[str]) -> Any:
        action = self._action(args, "platform")
        control = self._v8_control_plane()
        session = self._v8_session()
        if action == "status":
            deep = self._pop_flag(args, "--deep")
            self._expect_count(args, 0, 0, "platform status [--deep]")
            return {
                "health": control.health(deep=deep),
                "windows": control.windows_status(session=session, surface="cli", deep=deep),
                "enterprise": control.enterprise_status(session=session, surface="cli", include_fleet=False),
            }
        if action == "windows":
            deep = self._pop_flag(args, "--deep")
            self._expect_count(args, 0, 0, "platform windows [--deep]")
            return control.windows_status(session=session, surface="cli", deep=deep)
        if action in {"service-status", "service-install", "service-start", "service-stop", "service-remove"}:
            name = self._option(args, "--name", default="Arenyxa")
            start_mode = self._option(args, "--start", default="auto") if action == "service-install" else "auto"
            self._expect_count(args, 0, 0, f"platform {action} [--name SERVICE]")
            if action == "service-status":
                return control.windows_service_status(session=session, surface="cli", service_name=name)
            if action == "service-install":
                return control.windows_service_install(
                    session=session, surface="cli", service_name=name, start=start_mode
                )
            if action == "service-remove":
                return control.windows_service_remove(session=session, surface="cli", service_name=name)
            return control.windows_service_control(
                "start" if action == "service-start" else "stop",
                session=session, surface="cli", service_name=name,
            )
        if action == "event":
            level = self._option(args, "--level", default="INFORMATION")
            if not args:
                raise CommandRuntimeError("USAGE", "Usage: platform event <message> [--level INFORMATION|WARNING|ERROR]")
            message = " ".join(args)
            args.clear()
            return control.windows_event(message, session=session, surface="cli", level=level)
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown platform action: {action}")

    def _traffic(self, args: list[str]) -> Any:
        action = self._action(args, "traffic")
        control = self._v8_traffic_control()
        session = self._v8_session()
        if action == "status":
            self._expect_count(args, 0, 0, "traffic status")
            return control.status(session=session, surface="cli")
        if action == "protocols":
            contains = self._option(args, "--contains", default="")
            limit = self._limit(args, default=500, maximum=5000)
            self._expect_count(args, 0, 0, "traffic protocols")
            return control.protocol_catalog(
                session=session, surface="cli", contains=contains, limit=limit
            )
        if action == "fields":
            contains = self._option(args, "--contains", default="")
            protocol = self._option(args, "--protocol", default="")
            limit = self._limit(args, default=500, maximum=10000)
            self._expect_count(args, 0, 0, "traffic fields")
            return control.protocol_fields(
                session=session, surface="cli", contains=contains, protocol=protocol, limit=limit
            )
        if action == "decode":
            protocol = self._required_option(args, "--protocol")
            payload_hex = self._required_option(args, "--hex")
            self._expect_count(args, 0, 0, "traffic decode --protocol NAME --hex HEX")
            try:
                payload = bytes.fromhex(payload_hex)
            except ValueError as exc:
                raise CommandRuntimeError("USAGE", "--hex must contain valid hexadecimal bytes") from exc
            return control.decode_protocol(
                protocol, payload, session=session, surface="cli"
            )
        if action == "analyze":
            if not args or args[0].startswith("--"):
                raise CommandRuntimeError(
                    "USAGE",
                    "Usage: traffic analyze <capture-file> [--filter EXPR] [--timeout SECONDS] [--wait]",
                )
            capture_path = args.pop(0)
            display_filter = self._option(args, "--filter", default="")
            timeout_raw = self._option(args, "--timeout", default="300")
            wait = self._pop_flag(args, "--wait")
            self._expect_count(args, 0, 0, "traffic analyze")
            try:
                timeout = max(1.0, min(3600.0, float(timeout_raw)))
            except ValueError as exc:
                raise CommandRuntimeError("USAGE", "--timeout must be numeric") from exc
            job = control.submit_capture_analysis(
                capture_path,
                session=session,
                surface="cli",
                display_filter=display_filter,
                timeout_seconds=timeout,
            )
            if not wait:
                return job
            return self._v8_control_plane().wait_job(
                str(job["id"]), session=session, surface="cli", timeout_seconds=timeout + 10.0
            )
        if action == "proxy-status":
            self._expect_count(args, 0, 0, "traffic proxy-status")
            return control.proxy_status(session=session, surface="cli")
        if action == "mitm-status":
            self._expect_count(args, 0, 0, "traffic mitm-status")
            return control.mitm_status(session=session, surface="cli")
        raise CommandRuntimeError("UNKNOWN_ACTION", f"Unknown traffic action: {action}")

