"""Pure navigation capability models with no Qt or persistence dependencies."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Iterable

from arenyxa.compat import StrEnum, dataclass


class ExperienceMode(StrEnum):
    PERSONAL = "personal"
    PROFESSIONAL = "professional"
    DEVELOPER = "developer"
    ENTERPRISE = "enterprise"
    ROOT_DEVELOPER = "root_developer"

    # Source-compatible aliases retained for the legacy navigation API.
    GUIDED = "personal"
    ADVANCED = "professional"


DEVELOPER_SURFACE_CAPABILITY = "developer.surface"


class RuntimeMode(StrEnum):
    DESKTOP = "desktop"
    SERVER = "server"
    WORKER = "worker"


class AccountRole(StrEnum):
    PERSONAL = "personal"
    ENTERPRISE_MEMBER = "enterprise_member"
    ENTERPRISE_ADMIN = "enterprise_admin"
    LOCAL_SUPER_ADMIN = "local_super_admin"


def _parse_utc(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class DeveloperAuthority:
    """Verified developer credential state, independent from Experience Mode."""

    authenticated: bool = False
    credential_valid: bool = False
    revoked: bool = False
    expires_at: str = ""
    capabilities: frozenset[str] = frozenset()
    principal_id: str = ""

    def is_expired(self, *, now: datetime | None = None) -> bool:
        expiry = _parse_utc(self.expires_at)
        if expiry is None:
            return bool(self.expires_at)
        current = now or datetime.now(UTC)
        current = current.replace(tzinfo=UTC) if current.tzinfo is None else current.astimezone(UTC)
        return current >= expiry

    @property
    def active(self) -> bool:
        return bool(
            self.authenticated
            and self.credential_valid
            and not self.revoked
            and not self.is_expired()
        )


@dataclass(frozen=True, slots=True)
class ActiveRootSession:
    """Ephemeral Root session state. This model must never be serialized to settings."""

    authenticated: bool = False
    revoked: bool = False
    expires_at: str = ""
    session_id: str = ""
    capabilities: frozenset[str] = frozenset()

    def is_expired(self, *, now: datetime | None = None) -> bool:
        expiry = _parse_utc(self.expires_at)
        if expiry is None:
            return bool(self.expires_at)
        current = now or datetime.now(UTC)
        current = current.replace(tzinfo=UTC) if current.tzinfo is None else current.astimezone(UTC)
        return current >= expiry

    @property
    def active(self) -> bool:
        return bool(
            self.authenticated
            and not self.revoked
            and not self.is_expired()
            and "platform.root" in self.capabilities
        )


@dataclass(frozen=True, slots=True)
class NavigationContext:
    experience_mode: ExperienceMode
    runtime_mode: RuntimeMode
    account_role: AccountRole
    developer_authority: DeveloperAuthority = DeveloperAuthority()
    root_session: ActiveRootSession = ActiveRootSession()
    capabilities: frozenset[str] = frozenset()

    @property
    def effective_capabilities(self) -> frozenset[str]:
        # Persisted/application-projected capabilities are process state.
        # Credential/session capabilities are ephemeral authority and must
        # disappear the instant that authority expires or is revoked.
        effective = set(self.capabilities)
        if self.developer_authority.active:
            effective.update(self.developer_authority.capabilities)
        if self.root_session.active:
            effective.update(self.root_session.capabilities)

        # This token controls Developer navigation surfaces only. An active
        # Official Developer or Root session must retain the pre-existing
        # ability to see those surfaces even when the public Developer Mode
        # preference is off; it does not grant any privileged command
        # capability by itself.
        if self.developer_authority.active or self.root_session.active:
            effective.add(DEVELOPER_SURFACE_CAPABILITY)
        return frozenset(effective)


@dataclass(frozen=True, slots=True)
class ExperienceIdentity:
    """Identity posture exposed to workspace selection without granting authority."""

    account_role: AccountRole = AccountRole.PERSONAL
    enterprise_configured: bool = False
    enterprise_authenticated: bool = False
    enterprise_id: str = ""
    principal_id: str = ""
    developer_authenticated: bool = False
    root_authenticated: bool = False


@dataclass(frozen=True, slots=True)
class WorkspacePolicy:
    """Mode-owned workspace navigation. Existing pages remain registered as secondary pages."""

    id: str
    landing_page: str
    primary_pages: tuple[str, ...]
    secondary_pages: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.id.strip() or not self.landing_page.strip():
            raise ValueError("workspace id and landing page are required")
        if len(self.primary_pages) > 8:
            raise ValueError("workspace primary navigation cannot exceed eight entries")

    @property
    def page_ids(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((*self.primary_pages, *self.secondary_pages)))


@dataclass(frozen=True, slots=True)
class ExperienceContext:
    """Unified identity-driven context consumed by navigation and the desktop shell."""

    mode: ExperienceMode
    identity: ExperienceIdentity
    permissions: frozenset[str]
    capabilities: frozenset[str]
    workspace: WorkspacePolicy
    navigation: NavigationContext


@dataclass(frozen=True, slots=True)
class ModeChangedEvent:
    previous: ExperienceContext
    current: ExperienceContext
    occurred_at: str


@dataclass(frozen=True, slots=True)
class PageManifest:
    id: str
    group: str = "core"
    experience_modes: frozenset[ExperienceMode] = frozenset(ExperienceMode)
    runtime_modes: frozenset[RuntimeMode] = frozenset(RuntimeMode)
    required_roles: frozenset[AccountRole] = frozenset()
    required_capabilities: frozenset[str] = frozenset()
    requires_developer_authority: bool = False
    root_only: bool = False
    import_path: str = ""


@dataclass(frozen=True, slots=True)
class NavigationDecision:
    page_id: str
    allowed: bool
    reason: str


@dataclass(frozen=True, slots=True)
class ResolvedNavigation:
    page_ids: tuple[str, ...]
    decisions: tuple[NavigationDecision, ...]

    @property
    def visible(self) -> frozenset[str]:
        return frozenset(self.page_ids)


@dataclass(frozen=True, slots=True)
class NavigationDiff:
    added_pages: tuple[str, ...] = ()
    removed_pages: tuple[str, ...] = ()
    updated_pages: tuple[str, ...] = ()

    @classmethod
    def between(
        cls,
        previous: Iterable[str],
        current: Iterable[str],
        *,
        updated: Iterable[str] = (),
    ) -> "NavigationDiff":
        before = tuple(dict.fromkeys(str(item) for item in previous))
        after = tuple(dict.fromkeys(str(item) for item in current))
        before_set = set(before)
        after_set = set(after)
        return cls(
            added_pages=tuple(item for item in after if item not in before_set),
            removed_pages=tuple(item for item in before if item not in after_set),
            updated_pages=tuple(
                item for item in dict.fromkeys(str(value) for value in updated) if item in after_set
            ),
        )

    @property
    def changed(self) -> bool:
        return bool(self.added_pages or self.removed_pages or self.updated_pages)
