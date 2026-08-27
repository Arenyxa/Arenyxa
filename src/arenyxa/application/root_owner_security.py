"""Pure Root Owner workstation security state and startup-attempt policy."""

from __future__ import annotations

from arenyxa.compat import dataclass


@dataclass(frozen=True, slots=True)
class RootWorkstationStatus:
    active: bool
    owner_id: str = ""
    root_key_id: str = ""
    certificate_sha256: str = ""
    fingerprint: str = ""
    reason: str = ""
    root_fingerprint: str = ""


@dataclass(frozen=True, slots=True)
class RootCapabilityState:
    """Read-only projection of Root workstation health and process authority.

    ``available`` means the durable workstation binding and its Root trust
    anchor are valid enough to begin the mandatory Root Owner challenge.  It
    never means that ``platform.root`` has been granted to this process.
    ``authority_active`` becomes true only after a fresh private-key proof.
    """

    registered: bool
    binding_valid: bool
    root_key_present: bool
    device_binding_valid: bool
    available: bool
    authority_active: bool
    authentication_required: bool
    owner_id: str = ""
    root_key_id: str = ""
    root_fingerprint: str = ""
    certificate_sha256: str = ""
    owner_fingerprint: str = ""
    reason: str = ""
    # Phase 2 read-only integrity projection. These fields never grant authority.
    integrity_valid: bool = False
    hardware_root: bool = False
    hardware_proof_required: bool = False
    root_artifact_sha256: str = ""
    integrity_reason: str = ""


@dataclass(frozen=True, slots=True)
class RootStartupSecurityStatus:
    registered: bool
    locked: bool
    failed_attempts: int
    max_attempts: int
    reason: str = ""


def root_owner_startup_attempt_budget(status: RootStartupSecurityStatus) -> int:
    """Return the strong-auth attempts allowed for the current desktop launch.

    A locked workstation receives exactly one recovery proof opportunity per
    launch.  An unlocked workstation inherits the durable failure counter, so
    process restarts cannot reset the three-attempt security boundary.
    """
    if not status.registered:
        return 0
    maximum = max(1, int(status.max_attempts))
    failures = max(0, min(int(status.failed_attempts), maximum))
    if status.locked or failures >= maximum:
        return 1
    return max(1, maximum - failures)


