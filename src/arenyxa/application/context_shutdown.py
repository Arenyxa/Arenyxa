from __future__ import annotations

import inspect
from typing import Any, Callable

from arenyxa.infrastructure.shutdown import ShutdownDeadline


def build_shutdown_actions(self: Any, deadline: ShutdownDeadline, shutdown_logging: Callable[[], None]) -> dict[str, Callable[[], bool | None]]:
    def bounded(action: Callable[..., Any]) -> Any:
        # Preserve no-argument close implementations supplied by embedders.
        if "timeout" in inspect.signature(action).parameters:
            return action(timeout=deadline.remaining())
        return action()

    def stop_scheduler() -> None:
        return self.scheduler.stop(timeout=deadline.remaining())

    def stop_runtime_supervisor() -> None:
        if self.runtime_supervisor is not None:
            return bounded(self.runtime_supervisor.stop)

    def stop_survivability() -> None:
        if self.survivability is not None:
            return bounded(self.survivability.stop)

    def stop_job_system() -> None:
        if self.job_system is not None:
            return self.job_system.shutdown(wait=True, timeout=deadline.remaining())

    def stop_resilience_scheduler() -> None:
        if self.resilience_scheduler is not None:
            return bounded(self.resilience_scheduler.shutdown)

    def stop_enterprise_server() -> None:
        if self.enterprise_server is not None:
            return self.enterprise_server.close(reason="APPLICATION_SHUTDOWN")

    def stop_office_coordinator() -> None:
        if self.office_coordinator is not None:
            return bounded(self.office_coordinator.stop)

    def stop_workflow_runtime() -> None:
        return self.workflow_runtime.shutdown(wait=True, timeout=deadline.remaining())

    def finalize_capture() -> None:
        if self.capture.session and self.capture.session.state.value in {
            "preparing",
            "capturing",
            "paused",
            "finalizing",
            "failed",
        }:
            return self.capture.stop(cancelled=True)

    def stop_proxy() -> None:
        if self.proxy_engine is not None:
            return bounded(self.proxy_engine.close)

    def stop_mitm() -> None:
        if self.mitm_engine is not None:
            return bounded(self.mitm_engine.stop)

    def stop_runner() -> None:
        return self.runner.shutdown(wait=True, timeout=deadline.remaining())

    def close_terminal() -> None:
        self.terminal.close()
        if self.terminal_workspace is not None:
            self.terminal_workspace.close_all()

    def logout_developer() -> None:
        if self.developer_access is not None:
            self.developer_access.logout(reason="APPLICATION_SHUTDOWN")

    def retire_local_control_session() -> None:
        if self.security is None or self.local_control_session is None:
            return
        session = self.local_control_session
        self.security.state.revoke_session(session.id)
        self.security.state.remove_identity(session.identity_id)
        self.security.state.forget_session_revocation(session.id)
        self.local_control_session = None

    def close_enterprise_identity() -> None:
        if self.enterprise_identity is not None:
            self.enterprise_identity.close()

    def save_settings() -> None:
        self.settings.save(self.paths.root / "settings.json")

    def checkpoint_database() -> None:
        self.store.checkpoint("PASSIVE")

    def optimize_database() -> None:
        self.store.optimize()

    def stop_logging() -> None:
        shutdown_logging()

    return {
        "runtime_supervisor": stop_runtime_supervisor, "survivability": stop_survivability,
        "scheduler": stop_scheduler, "resilience_scheduler": stop_resilience_scheduler,
        "job_system": stop_job_system, "enterprise_server": stop_enterprise_server,
        "office_coordinator": stop_office_coordinator, "workflow_runtime": stop_workflow_runtime,
        "capture": finalize_capture, "proxy": stop_proxy, "mitm": stop_mitm,
        "runner": stop_runner, "terminal": close_terminal, "developer_access": logout_developer,
        "local_control_session": retire_local_control_session, "enterprise_identity": close_enterprise_identity,
        "settings": save_settings, "database_checkpoint": checkpoint_database,
        "database_optimize": optimize_database, "logging": stop_logging,
    }
