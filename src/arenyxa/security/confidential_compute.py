from __future__ import annotations

import os
import platform
import sys
import time
from dataclasses import field
from typing import Any, Callable, Mapping

from arenyxa.compat import dataclass
from arenyxa.domain.errors import ArenyxaError


@dataclass(frozen=True, slots=True)
class ConfidentialComputeStatus:
    provider: str
    supported: bool
    ready: bool
    attested: bool
    hardware_backed: bool
    isolation: str
    reason: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "supported": self.supported,
            "ready": self.ready,
            "attested": self.attested,
            "hardware_backed": self.hardware_backed,
            "isolation": self.isolation,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }


class ConfidentialComputeProvider:
    """Execution boundary for sensitive operations.

    Providers must not report ``ready=True`` until code actually crosses a
    trusted execution boundary and an attestation decision has succeeded.
    Capability detection alone is deliberately insufficient.
    """

    name = "unavailable"

    def status(self) -> ConfidentialComputeStatus:
        return ConfidentialComputeStatus(
            provider=self.name,
            supported=False,
            ready=False,
            attested=False,
            hardware_backed=False,
            isolation="none",
            reason="provider is unavailable",
        )

    def execute(self, operation: str, payload: bytes) -> bytes:
        raise ArenyxaError(
            "CONFIDENTIAL_COMPUTE_UNAVAILABLE",
            "Confidential-compute execution is unavailable for this provider.",
            domain="SECURITY",
            context={"provider": self.name, "operation": str(operation)},
        )


class CallbackConfidentialComputeProvider(ConfidentialComputeProvider):
    """Bridge to a separately built/signed native enclave or confidential VM host."""

    def __init__(
        self,
        name: str,
        *,
        executor: Callable[[str, bytes], bytes] | None,
        attestation: Callable[[], Mapping[str, Any]] | None,
        hardware_backed: bool,
        isolation: str,
        supported_probe: Callable[[], tuple[bool, Mapping[str, Any], str]] | None = None,
    ) -> None:
        self.name = str(name)
        self._executor = executor
        self._attestation = attestation
        self._hardware_backed = bool(hardware_backed)
        self._isolation = str(isolation)
        self._supported_probe = supported_probe

    def status(self) -> ConfidentialComputeStatus:
        supported = True
        metadata: dict[str, Any] = {}
        reason = ""
        if self._supported_probe is not None:
            supported, probe_metadata, reason = self._supported_probe()
            metadata.update(dict(probe_metadata))
        if not supported:
            return ConfidentialComputeStatus(
                self.name, False, False, False, self._hardware_backed, self._isolation, reason, metadata
            )
        if self._executor is None or self._attestation is None:
            return ConfidentialComputeStatus(
                self.name,
                True,
                False,
                False,
                self._hardware_backed,
                self._isolation,
                reason or "native confidential-compute bridge is not configured",
                metadata,
            )
        try:
            attestation = dict(self._attestation())
        except (OSError, RuntimeError, ValueError, TypeError) as exc:
            return ConfidentialComputeStatus(
                self.name,
                True,
                False,
                False,
                self._hardware_backed,
                self._isolation,
                f"attestation failed: {type(exc).__name__}",
                metadata,
            )
        metadata.update(attestation)
        verified = attestation.get("verified") is True
        return ConfidentialComputeStatus(
            self.name,
            True,
            bool(verified),
            bool(verified),
            self._hardware_backed,
            self._isolation,
            "" if verified else "attestation was not verified",
            metadata,
        )

    def execute(self, operation: str, payload: bytes) -> bytes:
        status = self.status()
        if not status.ready or self._executor is None:
            return super().execute(operation, payload)
        raw = bytes(payload)
        if len(raw) > 16 * 1024 * 1024:
            raise ArenyxaError(
                "CONFIDENTIAL_COMPUTE_PAYLOAD_TOO_LARGE",
                "Sensitive-operation payload exceeds the enclave bridge safety limit.",
                domain="SECURITY",
                context={"bytes": len(raw)},
            )
        return bytes(self._executor(str(operation), raw))


def _windows_vbs_probe() -> tuple[bool, Mapping[str, Any], str]:
    if os.name != "nt":
        return False, {"platform": platform.system()}, "Windows VBS enclaves require Windows"
    version = sys.getwindowsversion()
    metadata: dict[str, Any] = {"windows_build": int(version.build), "hvci_enabled": False}
    if int(version.build) < 26100:
        return False, metadata, "Windows build is older than the VBS enclave baseline"
    try:
        import winreg

        path = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            value, _kind = winreg.QueryValueEx(key, "Enabled")
            metadata["hvci_enabled"] = int(value) == 1
    except (FileNotFoundError, OSError, ValueError):
        metadata["hvci_enabled"] = False
    if not metadata["hvci_enabled"]:
        return True, metadata, "VBS-capable OS detected, but HVCI/VBS readiness was not confirmed"
    return True, metadata, ""


class WindowsVBSEnclaveProvider(CallbackConfidentialComputeProvider):
    def __init__(
        self,
        *,
        executor: Callable[[str, bytes], bytes] | None = None,
        attestation: Callable[[], Mapping[str, Any]] | None = None,
    ) -> None:
        super().__init__(
            "windows-vbs-enclave",
            executor=executor,
            attestation=attestation,
            hardware_backed=False,
            isolation="hypervisor-isolated VBS enclave",
            supported_probe=_windows_vbs_probe,
        )


@dataclass(frozen=True, slots=True)
class ConfidentialComputePolicy:
    mode: str = "off"  # off | prefer | require
    operations: tuple[str, ...] = (
        "enterprise.vault.decrypt",
        "enterprise.worker.verify",
        "enterprise.root.sign",
    )
    # Attestation hardening. A provider that reports an explicit stale timestamp,
    # debug-enabled state, or an unapproved code measurement is never considered
    # active for protected operations. Missing optional metadata remains compatible
    # with older native bridges unless an allow-list is configured.
    max_attestation_age_seconds: int = 5 * 60
    require_debug_disabled: bool = True
    allowed_measurements: tuple[str, ...] = ()
    require_hardware_backed: bool = False

    def normalized_mode(self) -> str:
        mode = str(self.mode).strip().casefold()
        return mode if mode in {"off", "prefer", "require"} else "off"


class ConfidentialComputeManager:
    def __init__(
        self,
        providers: tuple[ConfidentialComputeProvider, ...] | None = None,
        policy: ConfidentialComputePolicy | None = None,
    ) -> None:
        self.providers = tuple(providers or (WindowsVBSEnclaveProvider(),))
        self.policy = policy or ConfidentialComputePolicy()

    def _effective_status(self, provider: ConfidentialComputeProvider) -> ConfidentialComputeStatus:
        status = provider.status()
        if not status.ready or not status.attested:
            return status
        metadata = dict(status.metadata)
        reason = ""
        if self.policy.require_hardware_backed and not status.hardware_backed:
            reason = "policy requires a hardware-backed confidential-compute provider"
        if not reason and self.policy.require_debug_disabled and metadata.get("debug_enabled") is True:
            reason = "attested enclave is running with debugger access enabled"
        measurement = str(metadata.get("measurement") or metadata.get("code_measurement") or "").casefold()
        allowed = {str(item).strip().casefold() for item in self.policy.allowed_measurements if str(item).strip()}
        if not reason and allowed and measurement not in allowed:
            reason = "attested enclave code measurement is not allow-listed"
        attested_at = metadata.get("attested_at_epoch")
        if not reason and attested_at is not None:
            try:
                age = max(0.0, time.time() - float(attested_at))
            except (TypeError, ValueError, OverflowError):
                reason = "attestation timestamp is invalid"
            else:
                metadata["attestation_age_seconds"] = round(age, 3)
                maximum = max(1, min(24 * 60 * 60, int(self.policy.max_attestation_age_seconds)))
                if age > maximum:
                    reason = "attestation is stale"
        if not reason:
            return ConfidentialComputeStatus(
                status.provider, status.supported, status.ready, status.attested, status.hardware_backed,
                status.isolation, status.reason, metadata,
            )
        return ConfidentialComputeStatus(
            status.provider, status.supported, False, False, status.hardware_backed, status.isolation, reason, metadata
        )

    def statuses(self) -> tuple[ConfidentialComputeStatus, ...]:
        return tuple(self._effective_status(provider) for provider in self.providers)

    def active_provider(self) -> ConfidentialComputeProvider | None:
        for provider in self.providers:
            if self._effective_status(provider).ready:
                return provider
        return None

    def execute(self, operation: str, payload: bytes, *, fallback: Callable[[bytes], bytes]) -> bytes:
        operation_id = str(operation)
        mode = self.policy.normalized_mode()
        protected = operation_id in set(self.policy.operations)
        if mode == "off" or not protected:
            return bytes(fallback(bytes(payload)))
        provider = self.active_provider()
        if provider is not None:
            return provider.execute(operation_id, bytes(payload))
        if mode == "require":
            raise ArenyxaError(
                "CONFIDENTIAL_COMPUTE_REQUIRED",
                "This sensitive operation requires an attested confidential-compute provider.",
                domain="SECURITY",
                context={"operation": operation_id},
            )
        return bytes(fallback(bytes(payload)))
