from __future__ import annotations

import ctypes
import hashlib
import os
import threading
import time
from ctypes import wintypes
from dataclasses import field
from typing import Any, Mapping

from arenyxa.compat import dataclass
from arenyxa.domain.errors import ArenyxaError
from arenyxa.security.developer_crypto import ECDSA_P256_SHA256, validate_public_key_raw, verify_signature_raw


@dataclass(frozen=True, slots=True)
class HardwareSigningStatus:
    provider: str
    available: bool
    hardware_backed: bool
    non_exportable: bool
    algorithms: tuple[str, ...] = field(default_factory=tuple)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "available": self.available,
            "hardware_backed": self.hardware_backed,
            "non_exportable": self.non_exportable,
            "algorithms": list(self.algorithms),
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class HardwareKeyHealth:
    provider: str
    key_name: str
    available: bool
    hardware_backed: bool
    policy_valid: bool
    proof_of_possession: bool
    latency_ms: float | None
    public_key_sha256: str = ""
    reason: str = ""
    key_binding_sha256: str = ""

    @property
    def healthy(self) -> bool:
        return self.available and self.hardware_backed and self.policy_valid and self.proof_of_possession

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "key_name": self.key_name,
            "available": self.available,
            "hardware_backed": self.hardware_backed,
            "policy_valid": self.policy_valid,
            "proof_of_possession": self.proof_of_possession,
            "healthy": self.healthy,
            "latency_ms": self.latency_ms,
            "public_key_sha256": self.public_key_sha256,
            "reason": self.reason,
            "key_binding_sha256": self.key_binding_sha256,
        }


class HardwareSigningProvider:
    name = "unavailable"

    def status(self) -> HardwareSigningStatus:
        return HardwareSigningStatus(self.name, False, False, False, (), "provider unavailable")

    def create_key(self, key_name: str) -> Mapping[str, Any]:
        raise ArenyxaError("HARDWARE_SIGNING_UNAVAILABLE", "Hardware signing is unavailable.", domain="SECURITY")

    def sign_sha256(self, key_name: str, digest: bytes) -> bytes:
        raise ArenyxaError("HARDWARE_SIGNING_UNAVAILABLE", "Hardware signing is unavailable.", domain="SECURITY")


class _NCRYPT_UI_POLICY(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("pszCreationTitle", wintypes.LPCWSTR),
        ("pszFriendlyName", wintypes.LPCWSTR),
        ("pszDescription", wintypes.LPCWSTR),
    ]


class WindowsTPMEcdsaP256Provider(HardwareSigningProvider):
    """Windows TPM-backed ECDSA P-256 signer using Microsoft Platform Crypto Provider.

    The private key is created by the Windows CNG key-storage provider and this
    adapter only exports the public point. Root provisioning uses an explicit
    machine-scoped, non-exportable, signing-only, high-protection profile.
    """

    name = "windows-tpm-cng"
    _PROVIDER = "Microsoft Platform Crypto Provider"
    _ALGORITHM = "ECDSA_P256"
    _PUBLIC_BLOB = "ECCPUBLICBLOB"
    _ECDSA_P256_PUBLIC_MAGIC = b"ECS1"

    _EXPORT_POLICY = "Export Policy"
    _KEY_USAGE = "Key Usage"
    _KEY_TYPE = "Key Type"
    _IMPL_TYPE = "Impl Type"
    _UNIQUE_NAME = "Unique Name"
    _ALGORITHM_NAME = "Algorithm Name"
    _UI_POLICY = "UI Policy"

    _NCRYPT_MACHINE_KEY_FLAG = 0x00000020
    _NCRYPT_ALLOW_SIGNING_FLAG = 0x00000002
    _NCRYPT_IMPL_HARDWARE_FLAG = 0x00000001
    _NCRYPT_UI_PROTECT_KEY_FLAG = 0x00000001
    _NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG = 0x00000002
    _NTE_BAD_KEYSET = 0x80090016
    _STATUS_CACHE_SECONDS = 5.0

    def __init__(self) -> None:
        self._ncrypt = None
        self._lock = threading.RLock()
        self._status_cache: tuple[float, HardwareSigningStatus] | None = None
        if os.name == "nt":
            try:
                self._ncrypt = ctypes.WinDLL("ncrypt.dll")
                self._configure()
            except OSError:
                self._ncrypt = None

    def _configure(self) -> None:
        assert self._ncrypt is not None
        self._ncrypt.NCryptOpenStorageProvider.argtypes = [ctypes.POINTER(wintypes.HANDLE), wintypes.LPCWSTR, wintypes.DWORD]
        self._ncrypt.NCryptOpenStorageProvider.restype = wintypes.ULONG
        self._ncrypt.NCryptOpenKey.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE), wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        self._ncrypt.NCryptOpenKey.restype = wintypes.ULONG
        self._ncrypt.NCryptCreatePersistedKey.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE), wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        self._ncrypt.NCryptCreatePersistedKey.restype = wintypes.ULONG
        self._ncrypt.NCryptSetProperty.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
        self._ncrypt.NCryptSetProperty.restype = wintypes.ULONG
        self._ncrypt.NCryptGetProperty.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
        self._ncrypt.NCryptGetProperty.restype = wintypes.ULONG
        self._ncrypt.NCryptFinalizeKey.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self._ncrypt.NCryptFinalizeKey.restype = wintypes.ULONG
        self._ncrypt.NCryptDeleteKey.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self._ncrypt.NCryptDeleteKey.restype = wintypes.ULONG
        self._ncrypt.NCryptExportKey.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
        self._ncrypt.NCryptExportKey.restype = wintypes.ULONG
        self._ncrypt.NCryptSignHash.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
        self._ncrypt.NCryptSignHash.restype = wintypes.ULONG
        self._ncrypt.NCryptFreeObject.argtypes = [wintypes.HANDLE]
        self._ncrypt.NCryptFreeObject.restype = wintypes.ULONG

    @staticmethod
    def _error(code: int, action: str) -> ArenyxaError:
        return ArenyxaError(
            "TPM_CNG_FAILED",
            f"Windows TPM provider failed while attempting to {action}.",
            domain="SECURITY",
            context={"status": int(code)},
        )

    def _open_provider(self) -> wintypes.HANDLE:
        if self._ncrypt is None:
            raise ArenyxaError("TPM_CNG_UNAVAILABLE", "Windows TPM Platform Crypto Provider is unavailable.", domain="SECURITY")
        handle = wintypes.HANDLE()
        status = int(self._ncrypt.NCryptOpenStorageProvider(ctypes.byref(handle), self._PROVIDER, 0))
        if status != 0:
            raise self._error(status, "open the platform provider")
        return handle

    def _get_property(self, handle: wintypes.HANDLE, name: str, *, max_bytes: int = 16_384) -> bytes:
        assert self._ncrypt is not None
        required = wintypes.DWORD()
        status = int(self._ncrypt.NCryptGetProperty(handle, name, None, 0, ctypes.byref(required), 0))
        if status != 0 or required.value <= 0 or required.value > max_bytes:
            raise self._error(status, f"measure CNG property {name}")
        buffer = (ctypes.c_ubyte * required.value)()
        status = int(self._ncrypt.NCryptGetProperty(handle, name, buffer, required.value, ctypes.byref(required), 0))
        if status != 0:
            raise self._error(status, f"read CNG property {name}")
        return bytes(buffer[: required.value])

    def _get_dword(self, handle: wintypes.HANDLE, name: str) -> int:
        raw = self._get_property(handle, name, max_bytes=16)
        if len(raw) < 4:
            raise ArenyxaError("TPM_CNG_PROPERTY_INVALID", f"CNG property {name} was not a DWORD.", domain="SECURITY")
        return int.from_bytes(raw[:4], "little")

    def _get_wstring(self, handle: wintypes.HANDLE, name: str) -> str:
        raw = self._get_property(handle, name, max_bytes=8192)
        try:
            return raw.decode("utf-16-le").rstrip("\x00")
        except UnicodeError as exc:
            raise ArenyxaError("TPM_CNG_PROPERTY_INVALID", f"CNG property {name} was not valid UTF-16.", domain="SECURITY") from exc

    def _get_ui_policy_flags(self, handle: wintypes.HANDLE) -> int:
        raw = self._get_property(handle, self._UI_POLICY, max_bytes=4096)
        if len(raw) < 8:
            raise ArenyxaError("TPM_CNG_PROPERTY_INVALID", "CNG UI policy was truncated.", domain="SECURITY")
        version = int.from_bytes(raw[:4], "little")
        flags = int.from_bytes(raw[4:8], "little")
        if version != 1:
            raise ArenyxaError("TPM_CNG_PROPERTY_INVALID", "CNG UI policy version is unsupported.", domain="SECURITY")
        return flags

    def _set_dword(self, handle: wintypes.HANDLE, name: str, value: int) -> None:
        assert self._ncrypt is not None
        dword = wintypes.DWORD(int(value))
        status = int(self._ncrypt.NCryptSetProperty(handle, name, ctypes.byref(dword), ctypes.sizeof(dword), 0))
        if status != 0:
            raise self._error(status, f"set CNG property {name}")

    def _set_high_protection_ui(self, handle: wintypes.HANDLE) -> None:
        assert self._ncrypt is not None
        policy = _NCRYPT_UI_POLICY(
            1,
            self._NCRYPT_UI_PROTECT_KEY_FLAG | self._NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG,
            "Arenyxa Hardware Root",
            "Arenyxa Developer Hardware Root",
            "High-protection TPM signing key for Arenyxa Developer Root authority.",
        )
        status = int(self._ncrypt.NCryptSetProperty(handle, self._UI_POLICY, ctypes.byref(policy), ctypes.sizeof(policy), 0))
        if status != 0:
            raise self._error(status, "set high-protection Root UI policy")

    def status(self, *, refresh: bool = False) -> HardwareSigningStatus:
        with self._lock:
            now = time.monotonic()
            if not refresh and self._status_cache is not None and now - self._status_cache[0] <= self._STATUS_CACHE_SECONDS:
                return self._status_cache[1]
            if self._ncrypt is None:
                result = HardwareSigningStatus(self.name, False, False, True, (ECDSA_P256_SHA256,), "Windows CNG is unavailable")
                self._status_cache = (now, result)
                return result
            try:
                provider = self._open_provider()
                try:
                    result = self._status_from_provider(provider)
                finally:
                    self._ncrypt.NCryptFreeObject(provider)
            except ArenyxaError as exc:
                result = HardwareSigningStatus(self.name, False, False, True, (ECDSA_P256_SHA256,), exc.code)
                self._status_cache = (now, result)
                return result
            self._status_cache = (now, result)
            return result

    def _status_from_provider(self, provider: wintypes.HANDLE) -> HardwareSigningStatus:
        impl_type = self._get_dword(provider, self._IMPL_TYPE)
        hardware = bool(impl_type & self._NCRYPT_IMPL_HARDWARE_FLAG)
        reason = "" if hardware else "provider-not-hardware-backed"
        return HardwareSigningStatus(self.name, True, hardware, True, (ECDSA_P256_SHA256,), reason)

    def _open_key(self, provider: wintypes.HANDLE, key_name: str, *, machine_scope: bool = False) -> wintypes.HANDLE | None:
        assert self._ncrypt is not None
        key = wintypes.HANDLE()
        flags = self._NCRYPT_MACHINE_KEY_FLAG if machine_scope else 0
        status = int(self._ncrypt.NCryptOpenKey(provider, ctypes.byref(key), str(key_name), 0, flags))
        if status == 0:
            return key
        if status == self._NTE_BAD_KEYSET:
            return None
        raise self._error(status, "open a TPM-backed identity key")

    def _export_public(self, key: wintypes.HANDLE) -> bytes:
        assert self._ncrypt is not None
        required = wintypes.DWORD()
        status = int(self._ncrypt.NCryptExportKey(key, wintypes.HANDLE(), self._PUBLIC_BLOB, None, None, 0, ctypes.byref(required), 0))
        if status != 0 or required.value <= 8 or required.value > 4096:
            raise self._error(status, "measure the TPM public key")
        buffer = (ctypes.c_ubyte * required.value)()
        status = int(self._ncrypt.NCryptExportKey(key, wintypes.HANDLE(), self._PUBLIC_BLOB, None, buffer, required.value, ctypes.byref(required), 0))
        if status != 0:
            raise self._error(status, "export the TPM public key")
        raw = bytes(buffer[: required.value])
        if len(raw) < 8 or raw[:4] != self._ECDSA_P256_PUBLIC_MAGIC:
            raise ArenyxaError(
                "TPM_PUBLIC_KEY_INVALID",
                "TPM returned a public key blob that is not ECDSA P-256.",
                domain="SECURITY",
            )
        cb_key = int.from_bytes(raw[4:8], "little")
        if cb_key != 32 or len(raw) != 8 + 2 * cb_key:
            raise ArenyxaError("TPM_PUBLIC_KEY_INVALID", "TPM returned an unexpected P-256 public key blob.", domain="SECURITY")
        return b"\x04" + raw[8 : 8 + cb_key] + raw[8 + cb_key : 8 + 2 * cb_key]

    def _configure_new_key(self, key: wintypes.HANDLE, *, high_protection: bool) -> None:
        # Export-policy zero means no private-key export/archival flags are granted.
        self._set_dword(key, self._EXPORT_POLICY, 0)
        self._set_dword(key, self._KEY_USAGE, self._NCRYPT_ALLOW_SIGNING_FLAG)
        if high_protection:
            self._set_high_protection_ui(key)

    def inspect_key(self, key_name: str, *, machine_scope: bool = False) -> Mapping[str, Any]:
        provider = self._open_provider()
        try:
            key = self._open_key(provider, str(key_name), machine_scope=machine_scope)
            if key is None:
                raise ArenyxaError("TPM_KEY_NOT_FOUND", "TPM identity key was not found.", domain="SECURITY")
            try:
                return self._inspect_open_key(provider, key, str(key_name))
            finally:
                assert self._ncrypt is not None
                self._ncrypt.NCryptFreeObject(key)
        finally:
            assert self._ncrypt is not None
            self._ncrypt.NCryptFreeObject(provider)

    def _inspect_open_key(
        self,
        provider: wintypes.HANDLE,
        key: wintypes.HANDLE,
        key_name: str,
    ) -> dict[str, Any]:
        export_policy = self._get_dword(key, self._EXPORT_POLICY)
        usage = self._get_dword(key, self._KEY_USAGE)
        key_type = self._get_dword(key, self._KEY_TYPE)
        ui_policy_flags = self._get_ui_policy_flags(key)
        algorithm = self._get_wstring(key, self._ALGORITHM_NAME)
        if algorithm != self._ALGORITHM:
            raise ArenyxaError(
                "TPM_KEY_ALGORITHM_INVALID",
                "TPM key algorithm is not ECDSA P-256.",
                domain="SECURITY",
                context={"algorithm": algorithm},
            )
        provider_status = self._status_from_provider(provider)
        return {
            "provider": self.name,
            "provider_available": provider_status.available,
            "hardware_backed": provider_status.hardware_backed,
            "algorithm": algorithm,
            "key_name": str(key_name),
            "unique_name": self._get_wstring(key, self._UNIQUE_NAME),
            "machine_scope": bool(key_type & self._NCRYPT_MACHINE_KEY_FLAG),
            "export_policy": export_policy,
            "private_exportable": bool(export_policy),
            "key_usage": usage,
            "signing_only": usage == self._NCRYPT_ALLOW_SIGNING_FLAG,
            "ui_policy_flags": ui_policy_flags,
            "high_protection": bool(ui_policy_flags & self._NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG),
            "public_key_uncompressed": self._export_public(key),
        }

    def _create_or_open(
        self,
        key_name: str,
        *,
        machine_scope: bool,
        high_protection: bool,
    ) -> Mapping[str, Any]:
        name = str(key_name).strip()
        if not name or len(name) > 180:
            raise ValueError("invalid TPM key name")
        provider = self._open_provider()
        try:
            key = self._open_key(provider, name, machine_scope=machine_scope)
            created = False
            if key is None:
                key = wintypes.HANDLE()
                assert self._ncrypt is not None
                flags = self._NCRYPT_MACHINE_KEY_FLAG if machine_scope else 0
                status = int(self._ncrypt.NCryptCreatePersistedKey(provider, ctypes.byref(key), self._ALGORITHM, name, 0, flags))
                if status != 0:
                    raise self._error(status, "create a TPM-backed identity key")
                try:
                    self._configure_new_key(key, high_protection=high_protection)
                    status = int(self._ncrypt.NCryptFinalizeKey(key, 0))
                    if status != 0:
                        raise self._error(status, "finalize a TPM-backed identity key")
                except ArenyxaError as exc:
                    rollback_status = int(self._ncrypt.NCryptDeleteKey(key, 0))
                    if rollback_status != 0:
                        raise ArenyxaError(
                            "TPM_KEY_ROLLBACK_FAILED",
                            "TPM key creation failed and Windows could not delete the incomplete persisted key.",
                            domain="SECURITY",
                            context={
                                "creation_status": int(exc.context.get("status", 0)),
                                "rollback_status": rollback_status,
                            },
                            suggested_action="Inspect the TPM/CNG key container before retrying provisioning.",
                        ) from exc
                    raise
                created = True
            try:
                properties = self._inspect_open_key(provider, key, name)
                public = bytes(properties["public_key_uncompressed"])
            finally:
                assert self._ncrypt is not None
                self._ncrypt.NCryptFreeObject(key)
        finally:
            assert self._ncrypt is not None
            self._ncrypt.NCryptFreeObject(provider)
        if properties.get("private_exportable") or not properties.get("signing_only"):
            raise ArenyxaError("TPM_KEY_POLICY_INVALID", "TPM key does not satisfy the non-exportable signing-only policy.", domain="SECURITY")
        if bool(properties.get("machine_scope")) != bool(machine_scope):
            raise ArenyxaError("TPM_KEY_SCOPE_INVALID", "TPM key scope does not match the requested persistence scope.", domain="SECURITY")
        if high_protection and not bool(properties.get("high_protection")):
            raise ArenyxaError("TPM_KEY_UI_POLICY_INVALID", "TPM key does not retain the required high-protection UI policy.", domain="SECURITY")
        return {
            **properties,
            "created": created,
            "public_key_uncompressed": public,
            "high_protection_requested": bool(high_protection),
        }

    def create_key(self, key_name: str) -> Mapping[str, Any]:
        return self._create_or_open(key_name, machine_scope=False, high_protection=False)

    def create_protected_key(
        self, key_name: str, *, machine_scope: bool, high_protection: bool, require_hardware: bool = False,
    ) -> Mapping[str, Any]:
        """Create/open a protected TPM key without assigning any application trust role."""
        status = self.status()
        if require_hardware and (not status.available or not status.hardware_backed):
            raise ArenyxaError("TPM_HARDWARE_REQUIRED", "A hardware-backed Microsoft Platform Crypto Provider is required.", domain="SECURITY")
        return self._create_or_open(key_name, machine_scope=machine_scope, high_protection=high_protection)

    def _sign_with_key(self, key: wintypes.HANDLE, digest: bytes) -> bytes:
        assert self._ncrypt is not None
        required = wintypes.DWORD()
        source = ctypes.create_string_buffer(digest, len(digest))
        status = int(self._ncrypt.NCryptSignHash(key, None, source, len(digest), None, 0, ctypes.byref(required), 0))
        if status != 0 or required.value <= 0 or required.value > 512:
            raise self._error(status, "measure a TPM signature")
        signature = (ctypes.c_ubyte * required.value)()
        status = int(
            self._ncrypt.NCryptSignHash(
                key, None, source, len(digest), signature, required.value, ctypes.byref(required), 0
            )
        )
        if status != 0:
            raise self._error(status, "sign with a TPM identity key")
        return bytes(signature[: required.value])

    def sign_sha256(self, key_name: str, digest: bytes, *, machine_scope: bool = False) -> bytes:
        raw = bytes(digest)
        if len(raw) != 32:
            raise ValueError("ECDSA P-256 TPM signing requires a SHA-256 digest")
        with self._lock:
            provider = self._open_provider()
            try:
                key = self._open_key(provider, str(key_name), machine_scope=machine_scope)
                if key is None:
                    raise ArenyxaError("TPM_KEY_NOT_FOUND", "TPM identity key was not found.", domain="SECURITY")
                try:
                    return self._sign_with_key(key, raw)
                finally:
                    assert self._ncrypt is not None
                    self._ncrypt.NCryptFreeObject(key)
            finally:
                assert self._ncrypt is not None
                self._ncrypt.NCryptFreeObject(provider)

    def sign_checked_sha256(
        self,
        key_name: str,
        digest: bytes,
        *,
        machine_scope: bool = False,
        expected_public_key: bytes,
        expected_key_binding_sha256: str = "",
    ) -> bytes:
        """Validate hardware policy/binding and sign using one CNG key handle."""
        raw = bytes(digest)
        expected_public = bytes(expected_public_key)
        if len(raw) != 32:
            raise ValueError("ECDSA P-256 TPM signing requires a SHA-256 digest")
        validate_public_key_raw(ECDSA_P256_SHA256, expected_public)
        expected_binding = str(expected_key_binding_sha256).strip().casefold()
        if expected_binding and (
            len(expected_binding) != 64 or any(ch not in "0123456789abcdef" for ch in expected_binding)
        ):
            raise ValueError("expected TPM key binding must be a SHA-256 hex digest")
        with self._lock:
            provider = self._open_provider()
            try:
                key = self._open_key(provider, str(key_name), machine_scope=machine_scope)
                if key is None:
                    raise ArenyxaError("TPM_KEY_NOT_FOUND", "TPM identity key was not found.", domain="SECURITY")
                try:
                    metadata = self._inspect_open_key(provider, key, str(key_name))
                    public = bytes(metadata["public_key_uncompressed"])
                    if public != expected_public:
                        raise ArenyxaError(
                            "TPM_KEY_PUBLIC_BINDING_INVALID",
                            "The opened TPM key does not match the expected public key.",
                            domain="SECURITY",
                        )
                    if (
                        not bool(metadata.get("hardware_backed"))
                        or bool(metadata.get("private_exportable"))
                        or not bool(metadata.get("signing_only"))
                        or bool(metadata.get("machine_scope")) != bool(machine_scope)
                        or (machine_scope and not bool(metadata.get("high_protection")))
                    ):
                        raise ArenyxaError(
                            "TPM_KEY_POLICY_INVALID",
                            "The opened TPM key no longer satisfies the required hardware policy.",
                            domain="SECURITY",
                        )
                    if expected_binding:
                        unique_name = str(metadata.get("unique_name") or "").strip()
                        observed = hashlib.sha256(unique_name.encode("utf-8")).hexdigest() if unique_name else ""
                        if observed != expected_binding:
                            raise ArenyxaError(
                                "TPM_KEY_UNIQUE_BINDING_INVALID",
                                "The opened TPM key unique binding does not match the expected Root artifact.",
                                domain="SECURITY",
                            )
                    return self._sign_with_key(key, raw)
                finally:
                    assert self._ncrypt is not None
                    self._ncrypt.NCryptFreeObject(key)
            finally:
                assert self._ncrypt is not None
                self._ncrypt.NCryptFreeObject(provider)

    def sign_many_sha256(
        self, key_name: str, digests: list[bytes] | tuple[bytes, ...], *, machine_scope: bool = False, max_items: int = 256,
    ) -> tuple[bytes, ...]:
        limit = int(max_items)
        if not 1 <= limit <= 256:
            raise ValueError("TPM batch signing max_items must be between 1 and 256")
        items = tuple(bytes(item) for item in digests)
        if len(items) > limit:
            raise ValueError("TPM batch signing request exceeds its bounded item limit")
        if any(len(item) != 32 for item in items):
            raise ValueError("every TPM batch item must be a SHA-256 digest")
        if not items:
            return ()
        with self._lock:
            provider = self._open_provider()
            try:
                key = self._open_key(provider, str(key_name), machine_scope=machine_scope)
                if key is None:
                    raise ArenyxaError("TPM_KEY_NOT_FOUND", "TPM identity key was not found.", domain="SECURITY")
                try:
                    return tuple(self._sign_with_key(key, digest) for digest in items)
                finally:
                    assert self._ncrypt is not None
                    self._ncrypt.NCryptFreeObject(key)
            finally:
                assert self._ncrypt is not None
                self._ncrypt.NCryptFreeObject(provider)

    def probe_key(self, key_name: str, *, machine_scope: bool = False) -> HardwareKeyHealth:
        started = time.perf_counter()
        try:
            with self._lock:
                provider = self._open_provider()
                try:
                    key = self._open_key(provider, str(key_name), machine_scope=machine_scope)
                    if key is None:
                        raise ArenyxaError("TPM_KEY_NOT_FOUND", "TPM identity key was not found.", domain="SECURITY")
                    try:
                        metadata = self._inspect_open_key(provider, key, str(key_name))
                        public = bytes(metadata["public_key_uncompressed"])
                        policy_valid = (
                            bool(metadata.get("hardware_backed"))
                            and not bool(metadata.get("private_exportable"))
                            and bool(metadata.get("signing_only"))
                            and bool(metadata.get("machine_scope")) == bool(machine_scope)
                            and (not machine_scope or bool(metadata.get("high_protection")))
                        )
                        nonce = os.urandom(32)
                        signature = self._sign_with_key(key, hashlib.sha256(nonce).digest())
                    finally:
                        assert self._ncrypt is not None
                        self._ncrypt.NCryptFreeObject(key)
                finally:
                    assert self._ncrypt is not None
                    self._ncrypt.NCryptFreeObject(provider)
            verify_signature_raw(ECDSA_P256_SHA256, public, signature, nonce)
            unique_name = str(metadata.get("unique_name") or "").strip()
            binding = hashlib.sha256(unique_name.encode("utf-8")).hexdigest() if unique_name else ""
            return HardwareKeyHealth(
                self.name, str(key_name), True, bool(metadata.get("hardware_backed")), policy_valid, True,
                round((time.perf_counter() - started) * 1000.0, 3), hashlib.sha256(public).hexdigest(), "", binding,
            )
        except (ArenyxaError, ValueError, KeyError) as exc:
            code = exc.code if isinstance(exc, ArenyxaError) else type(exc).__name__
            return HardwareKeyHealth(
                self.name, str(key_name), False, False, False, False,
                round((time.perf_counter() - started) * 1000.0, 3), "", str(code),
            )
