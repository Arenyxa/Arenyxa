from __future__ import annotations

from arenyxa.domain.enums import WorkspaceRole

ROLE_PERMISSIONS: dict[WorkspaceRole, frozenset[str]] = {
    WorkspaceRole.ADMIN: frozenset(
        {
            "project.read",
            "project.write",
            "task.run",
            "data.read",
            "data.write",
            "data.export",
            "capture.run",
            "replay.run",
            "secrets.use",
            "plugin.install",
            "plugin.run",
            "logs.read",
            "workspace.manage",
            "system.configure",
        }
    ),
    WorkspaceRole.DEVELOPER: frozenset(
        {
            "project.read",
            "project.write",
            "task.run",
            "data.read",
            "data.write",
            "data.export",
            "capture.run",
            "replay.run",
            "secrets.use",
            "plugin.run",
            "logs.read",
        }
    ),
    WorkspaceRole.VIEWER: frozenset({"project.read", "data.read", "logs.read"}),
}


def authorize(role: WorkspaceRole, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS[role]
