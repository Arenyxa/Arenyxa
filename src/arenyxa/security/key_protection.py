from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import logging
import os
import secrets
from enum import Enum
from ctypes import wintypes
from typing import Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from arenyxa.domain.errors import ArenyxaError

LOGGER = logging.getLogger(__name__)


class SecretBuffer:
    





    def __init__(self, value: bytes | bytearray | memoryview) -> None:
        self._buffer = bytearray(value)
        self._cleared = False

    def view(self) -> memoryview:
        if self._cleared:
            raise RuntimeError("secret buffer was cleared")
        return memoryview(self._buffer)

    def copy_bytes(self) -> bytes:
        if self._cleared:
            raise RuntimeError("secret buffer was cleared")
        return bytes(self._buffer)

    def zeroize(self) -> None:
        for index in range(len(self._buffer)):
            self._buffer[index] = 0
        self._cleared = True

    def __enter__(self) -> "SecretBuffer":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.zeroize()

    def __del__(self) -> None:
                                                                                             
                                                  
        try:
            if not self._cleared:
                self.zeroize()
        except (AttributeError, TypeError) as exc:
            LOGGER.debug("SecretBuffer finalizer could not zeroize an incomplete buffer: %s", exc)


class KeyProtectionAdapter:
    name = "abstract"

    def available(self) -> bool:
        return False

    def protect(self, plaintext: bytes, *, purpose: str = "Arenyxa") -> bytes:
        raise ArenyxaError("KEY_PROTECTION_UNAVAILABLE", "key protection adapter is unavailable", domain="SECURITY")

    def unprotect(self, ciphertext: bytes, *, purpose: str = "Arenyxa") -> bytes:
        raise ArenyxaError("KEY_PROTECTION_UNAVAILABLE", "key protection adapter is unavailable", domain="SECURITY")


class DPAPIScope(str, Enum):
    AUTO = "auto"
    USER = "user"
    MACHINE = "machine"


def detect_dpapi_scope() -> DPAPIScope:
    """Select DPAPI scope from explicit policy and runtime context.

    Desktop/interactive runtimes stay user-scoped.  Windows Service runtimes use
    machine scope so secrets remain available after service-account rotation.
    """

    configured = os.getenv("ARENYXA_DPAPI_SCOPE", "auto").strip().casefold()
    try:
        requested = DPAPIScope(configured)
    except ValueError as exc:
        raise ArenyxaError(
            "DPAPI_SCOPE_INVALID",
            "ARENYXA_DPAPI_SCOPE must be auto, user, or machine",
            domain="SECURITY",
            context={"value": configured[:64]},
        ) from exc
    if requested is not DPAPIScope.AUTO:
        return requested
    runtime_mode = os.getenv("ARENYXA_RUNTIME_MODE", "desktop").strip().casefold()
    if runtime_mode in {"service", "windows-service", "machine"}:
        return DPAPIScope.MACHINE
    return DPAPIScope.USER


class DPAPIKeyProtectionAdapter(KeyProtectionAdapter):
    name = "windows-dpapi"
    _MAGIC = b"ARXDPAPI1:"
    _UI_FORBIDDEN = 0x1
    _LOCAL_MACHINE = 0x4

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    def __init__(self, *, scope: DPAPIScope | str = DPAPIScope.AUTO) -> None:
        self._scope = DPAPIScope(str(scope).casefold()) if not isinstance(scope, DPAPIScope) else scope

    @property
    def scope(self) -> DPAPIScope:
        return detect_dpapi_scope() if self._scope is DPAPIScope.AUTO else self._scope

    def available(self) -> bool:
        return os.name == "nt" and hasattr(ctypes, "windll")

    @classmethod
    def _blob(cls, value: bytes) -> tuple["DPAPIKeyProtectionAdapter.DATA_BLOB", ctypes.Array[ctypes.c_char]]:
        buffer = ctypes.create_string_buffer(value, max(1, len(value)))
        blob = cls.DATA_BLOB(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
        return blob, buffer

    @staticmethod
    def _zero_buffer(buffer: ctypes.Array[ctypes.c_char]) -> None:
        try:
            ctypes.memset(ctypes.addressof(buffer), 0, ctypes.sizeof(buffer))
        except (TypeError, ValueError) as exc:
            LOGGER.warning("DPAPI temporary buffer zeroization failed: %s", exc)

    @classmethod
    def _encode_envelope(cls, scope: DPAPIScope, ciphertext: bytes) -> bytes:
        return cls._MAGIC + scope.value.encode("ascii") + b":" + ciphertext

    @classmethod
    def _decode_envelope(cls, value: bytes) -> tuple[DPAPIScope | None, bytes]:
        if not value.startswith(cls._MAGIC):
            return None, value
        remainder = value[len(cls._MAGIC):]
        scope_raw, separator, ciphertext = remainder.partition(b":")
        if not separator or not ciphertext:
            raise ArenyxaError("DPAPI_ENVELOPE_INVALID", "DPAPI protected value envelope is malformed", domain="SECURITY")
        try:
            scope = DPAPIScope(scope_raw.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ArenyxaError("DPAPI_ENVELOPE_SCOPE_INVALID", "DPAPI protected value has an invalid scope", domain="SECURITY") from exc
        if scope is DPAPIScope.AUTO:
            raise ArenyxaError("DPAPI_ENVELOPE_SCOPE_INVALID", "Persisted DPAPI values cannot use auto scope", domain="SECURITY")
        return scope, ciphertext

    def protect(self, plaintext: bytes, *, purpose: str = "Arenyxa") -> bytes:
        if not self.available():
            return super().protect(plaintext, purpose=purpose)
        scope = self.scope
        source, source_buffer = self._blob(bytes(plaintext))
        entropy, entropy_buffer = self._blob(purpose.encode("utf-8"))
        output = self.DATA_BLOB()
        flags = self._UI_FORBIDDEN | (self._LOCAL_MACHINE if scope is DPAPIScope.MACHINE else 0)
        try:
            ok = ctypes.windll.crypt32.CryptProtectData(
                ctypes.byref(source), None, ctypes.byref(entropy), None, None, flags, ctypes.byref(output)
            )
            if not ok:
                raise ArenyxaError("DPAPI_PROTECT_FAILED", "Windows DPAPI failed to protect secret", domain="SECURITY")
            try:
                ciphertext = ctypes.string_at(output.pbData, output.cbData)
                return self._encode_envelope(scope, ciphertext)
            finally:
                if output.pbData and output.cbData:
                    ctypes.memset(output.pbData, 0, output.cbData)
                if output.pbData:
                    ctypes.windll.kernel32.LocalFree(output.pbData)
        finally:
            self._zero_buffer(source_buffer)
            self._zero_buffer(entropy_buffer)

    def unprotect(self, ciphertext: bytes, *, purpose: str = "Arenyxa") -> bytes:
        if not self.available():
            return super().unprotect(ciphertext, purpose=purpose)
        persisted_scope, protected_value = self._decode_envelope(bytes(ciphertext))
        # Legacy v7/v8 values had no Arenyxa envelope. DPAPI itself retains the original
        # user/machine binding, so direct decryption preserves backwards compatibility.
        source, source_buffer = self._blob(protected_value)
        entropy, entropy_buffer = self._blob(purpose.encode("utf-8"))
        output = self.DATA_BLOB()
        flags = self._UI_FORBIDDEN
        try:
            ok = ctypes.windll.crypt32.CryptUnprotectData(
                ctypes.byref(source), None, ctypes.byref(entropy), None, None, flags, ctypes.byref(output)
            )
            if not ok:
                raise ArenyxaError(
                    "DPAPI_UNPROTECT_FAILED",
                    "Windows DPAPI failed to unprotect secret",
                    domain="SECURITY",
                    context={"persisted_scope": persisted_scope.value if persisted_scope else "legacy"},
                )
            try:
                return ctypes.string_at(output.pbData, output.cbData)
            finally:
                if output.pbData and output.cbData:
                    ctypes.memset(output.pbData, 0, output.cbData)
                if output.pbData:
                    ctypes.windll.kernel32.LocalFree(output.pbData)
        finally:
            self._zero_buffer(source_buffer)
            self._zero_buffer(entropy_buffer)


class _DelegatingHardwareAdapter(KeyProtectionAdapter):
    def __init__(
        self,
        name: str,
        protect_callback: Callable[[bytes, str], bytes] | None = None,
        unprotect_callback: Callable[[bytes, str], bytes] | None = None,
    ) -> None:
        self.name = name
        self._protect = protect_callback
        self._unprotect = unprotect_callback

    def available(self) -> bool:
        return self._protect is not None and self._unprotect is not None

    def protect(self, plaintext: bytes, *, purpose: str = "Arenyxa") -> bytes:
        if self._protect is None:
            raise ArenyxaError(
                "KEY_PROTECTION_NOT_CONFIGURED",
                f"{self.name} adapter requires a platform key provider before use",
                domain="SECURITY",
            )
        return bytes(self._protect(bytes(plaintext), str(purpose)))

    def unprotect(self, ciphertext: bytes, *, purpose: str = "Arenyxa") -> bytes:
        if self._unprotect is None:
            raise ArenyxaError(
                "KEY_PROTECTION_NOT_CONFIGURED",
                f"{self.name} adapter requires a platform key provider before use",
                domain="SECURITY",
            )
        return bytes(self._unprotect(bytes(ciphertext), str(purpose)))


class CNGKeyProtectionAdapter(_DelegatingHardwareAdapter):
    

    def __init__(
        self,
        protect_callback: Callable[[bytes, str], bytes] | None = None,
        unprotect_callback: Callable[[bytes, str], bytes] | None = None,
    ) -> None:
        super().__init__("windows-cng", protect_callback, unprotect_callback)


class TPMKeyProtectionAdapter(_DelegatingHardwareAdapter):
    """Windows TPM-backed envelope encryption using Microsoft Platform Crypto Provider.

    A non-exportable RSA wrapping key is persisted in the TPM. Each protected value gets a
    fresh AES-256-GCM data key; only that small data key is RSA-OAEP wrapped by the TPM key.
    Callback injection remains supported for test/platform overrides.
    """

    PROVIDER_NAME = "Microsoft Platform Crypto Provider"
    _MAGIC = b"ARXTPM1:"
    _RSA_ALGORITHM = "RSA"
    _NCRYPT_MACHINE_KEY_FLAG = 0x00000020
    _NCRYPT_ALLOW_DECRYPT_FLAG = 0x00000001
    _NCRYPT_PAD_OAEP_FLAG = 0x00000004
    _NCRYPT_IMPL_HARDWARE_FLAG = 0x00000001
    _NTE_BAD_KEYSET = 0x80090016

    class _OAEP_INFO(ctypes.Structure):
        _fields_ = [
            ("pszAlgId", wintypes.LPCWSTR),
            ("pbLabel", ctypes.c_void_p),
            ("cbLabel", wintypes.ULONG),
        ]

    def __init__(
        self,
        protect_callback: Callable[[bytes, str], bytes] | None = None,
        unprotect_callback: Callable[[bytes, str], bytes] | None = None,
    ) -> None:
        super().__init__("tpm", protect_callback, unprotect_callback)
        self._native = None
        if os.name == "nt":
            try:
                self._native = ctypes.WinDLL("ncrypt.dll")
                self._configure_native()
            except (AttributeError, OSError):
                self._native = None

    def _configure_native(self) -> None:
        assert self._native is not None
        ncrypt = self._native
        ncrypt.NCryptOpenStorageProvider.argtypes = [ctypes.POINTER(wintypes.HANDLE), wintypes.LPCWSTR, wintypes.DWORD]
        ncrypt.NCryptOpenStorageProvider.restype = wintypes.ULONG
        ncrypt.NCryptOpenKey.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE), wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        ncrypt.NCryptOpenKey.restype = wintypes.ULONG
        ncrypt.NCryptCreatePersistedKey.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE), wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        ncrypt.NCryptCreatePersistedKey.restype = wintypes.ULONG
        ncrypt.NCryptSetProperty.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
        ncrypt.NCryptSetProperty.restype = wintypes.ULONG
        ncrypt.NCryptGetProperty.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
        ncrypt.NCryptGetProperty.restype = wintypes.ULONG
        ncrypt.NCryptFinalizeKey.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        ncrypt.NCryptFinalizeKey.restype = wintypes.ULONG
        ncrypt.NCryptDeleteKey.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        ncrypt.NCryptDeleteKey.restype = wintypes.ULONG
        ncrypt.NCryptEncrypt.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
        ncrypt.NCryptEncrypt.restype = wintypes.ULONG
        ncrypt.NCryptDecrypt.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
        ncrypt.NCryptDecrypt.restype = wintypes.ULONG
        ncrypt.NCryptFreeObject.argtypes = [wintypes.HANDLE]
        ncrypt.NCryptFreeObject.restype = wintypes.ULONG

    @staticmethod
    def _native_error(status: int, action: str) -> ArenyxaError:
        return ArenyxaError(
            "TPM_KEY_PROTECTION_FAILED",
            f"Windows TPM provider failed while attempting to {action}",
            domain="SECURITY",
            context={"status": int(status)},
        )

    @staticmethod
    def _scope_flags() -> int:
        configured = os.getenv("ARENYXA_TPM_SCOPE", "auto").strip().casefold()
        if configured not in {"auto", "user", "machine"}:
            raise ArenyxaError(
                "TPM_SCOPE_INVALID", "ARENYXA_TPM_SCOPE must be auto, user, or machine", domain="SECURITY"
            )
        if configured == "machine" or (
            configured == "auto" and os.getenv("ARENYXA_RUNTIME_MODE", "desktop").strip().casefold() in {"service", "windows-service", "machine"}
        ):
            return TPMKeyProtectionAdapter._NCRYPT_MACHINE_KEY_FLAG
        return 0

    @staticmethod
    def _key_name(purpose: str) -> str:
        digest = hashlib.sha256(str(purpose).encode("utf-8", errors="replace")).hexdigest()[:40]
        return f"Arenyxa-KeyProtection-{digest}"

    def _get_dword(self, handle: wintypes.HANDLE, name: str) -> int:
        assert self._native is not None
        required = wintypes.DWORD()
        status = int(self._native.NCryptGetProperty(handle, name, None, 0, ctypes.byref(required), 0))
        if status != 0 or required.value < 4 or required.value > 16:
            raise self._native_error(status, f"read {name}")
        buf = (ctypes.c_ubyte * required.value)()
        status = int(self._native.NCryptGetProperty(handle, name, buf, required.value, ctypes.byref(required), 0))
        if status != 0:
            raise self._native_error(status, f"read {name}")
        return int.from_bytes(bytes(buf[:4]), "little")

    def _set_dword(self, handle: wintypes.HANDLE, name: str, value: int) -> None:
        assert self._native is not None
        dword = wintypes.DWORD(int(value))
        status = int(self._native.NCryptSetProperty(handle, name, ctypes.byref(dword), ctypes.sizeof(dword), 0))
        if status != 0:
            raise self._native_error(status, f"set {name}")

    def _open_provider(self) -> wintypes.HANDLE:
        if self._native is None:
            raise ArenyxaError("TPM_KEY_PROTECTION_UNAVAILABLE", "Windows TPM provider is unavailable", domain="SECURITY")
        provider = wintypes.HANDLE()
        status = int(self._native.NCryptOpenStorageProvider(ctypes.byref(provider), self.PROVIDER_NAME, 0))
        if status != 0:
            raise self._native_error(status, "open the Platform Crypto Provider")
        if not (self._get_dword(provider, "Impl Type") & self._NCRYPT_IMPL_HARDWARE_FLAG):
            self._native.NCryptFreeObject(provider)
            raise ArenyxaError("TPM_PROVIDER_NOT_HARDWARE", "Platform Crypto Provider is not hardware-backed", domain="SECURITY")
        return provider

    def _open_or_create_key(self, provider: wintypes.HANDLE, purpose: str) -> wintypes.HANDLE:
        assert self._native is not None
        key = wintypes.HANDLE()
        flags = self._scope_flags()
        name = self._key_name(purpose)
        status = int(self._native.NCryptOpenKey(provider, ctypes.byref(key), name, 0, flags))
        if status == 0:
            export_policy = self._get_dword(key, "Export Policy")
            usage = self._get_dword(key, "Key Usage")
            if export_policy != 0 or not (usage & self._NCRYPT_ALLOW_DECRYPT_FLAG):
                self._native.NCryptFreeObject(key)
                raise ArenyxaError(
                    "TPM_KEY_POLICY_INVALID",
                    "Existing TPM wrapping key does not satisfy non-exportable decrypt policy",
                    domain="SECURITY",
                    context={"export_policy": export_policy, "key_usage": usage},
                )
            return key
        if status != self._NTE_BAD_KEYSET:
            raise self._native_error(status, "open the TPM wrapping key")
        status = int(self._native.NCryptCreatePersistedKey(provider, ctypes.byref(key), self._RSA_ALGORITHM, name, 0, flags))
        if status != 0:
            raise self._native_error(status, "create the TPM wrapping key")
        try:
            self._set_dword(key, "Length", 2048)
            self._set_dword(key, "Export Policy", 0)
            self._set_dword(key, "Key Usage", self._NCRYPT_ALLOW_DECRYPT_FLAG)
            status = int(self._native.NCryptFinalizeKey(key, 0))
            if status != 0:
                raise self._native_error(status, "finalize the TPM wrapping key")
            return key
        except (ArenyxaError, AttributeError, OSError, TypeError, ValueError) as exc:
            delete_status = int(self._native.NCryptDeleteKey(key, 0))
            if delete_status != 0:
                LOGGER.critical(
                    "TPM wrapping key rollback failed status=%d after %s", delete_status, type(exc).__name__
                )
            raise

    def _rsa_oaep(self, key: wintypes.HANDLE, value: bytes, *, decrypt: bool) -> bytes:
        assert self._native is not None
        operation = self._native.NCryptDecrypt if decrypt else self._native.NCryptEncrypt
        source = ctypes.create_string_buffer(bytes(value), max(1, len(value)))
        oaep = self._OAEP_INFO("SHA256", None, 0)
        required = wintypes.DWORD()
        status = int(operation(
            key, source, len(value), ctypes.byref(oaep), None, 0, ctypes.byref(required), self._NCRYPT_PAD_OAEP_FLAG
        ))
        if status != 0 or required.value <= 0 or required.value > 16_384:
            raise self._native_error(status, "measure TPM RSA-OAEP operation")
        output = (ctypes.c_ubyte * required.value)()
        status = int(operation(
            key, source, len(value), ctypes.byref(oaep), output, required.value, ctypes.byref(required), self._NCRYPT_PAD_OAEP_FLAG
        ))
        if status != 0:
            raise self._native_error(status, "perform TPM RSA-OAEP operation")
        return bytes(output[: required.value])

    @classmethod
    def hardware_present(cls) -> bool:
        if os.name != "nt" or not hasattr(ctypes, "WinDLL"):
            return False
        try:
            provider = cls()
            if provider._native is None:
                return False
            handle = provider._open_provider()
            provider._native.NCryptFreeObject(handle)
            return True
        except ArenyxaError:
            return False

    def _native_available(self) -> bool:
        if self._native is None:
            return False
        try:
            provider = self._open_provider()
            self._native.NCryptFreeObject(provider)
            return True
        except ArenyxaError:
            return False

    def capability_status(self) -> dict[str, object]:
        injected = super().available()
        native = self._native_available()
        return {
            "provider": self.PROVIDER_NAME,
            "hardware_present": self.hardware_present(),
            "sealing_provider_configured": bool(injected or native),
            "native_sealing_available": native,
            "available": bool(injected or native),
            "scope": "machine" if self._scope_flags() & self._NCRYPT_MACHINE_KEY_FLAG else "user",
        }

    def available(self) -> bool:
        return super().available() or self._native_available()

    def protect(self, plaintext: bytes, *, purpose: str = "Arenyxa") -> bytes:
        if super().available():
            return super().protect(plaintext, purpose=purpose)
        if not self._native_available():
            return KeyProtectionAdapter.protect(self, plaintext, purpose=purpose)
        provider = self._open_provider()
        key = None
        try:
            key = self._open_or_create_key(provider, purpose)
            with SecretBuffer(secrets.token_bytes(32)) as data_key:
                nonce = secrets.token_bytes(12)
                ciphertext = AESGCM(data_key.copy_bytes()).encrypt(nonce, bytes(plaintext), str(purpose).encode("utf-8"))
                wrapped = self._rsa_oaep(key, data_key.copy_bytes(), decrypt=False)
            envelope = {
                "v": 1,
                "k": base64.urlsafe_b64encode(wrapped).decode("ascii"),
                "n": base64.urlsafe_b64encode(nonce).decode("ascii"),
                "c": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
            }
            return self._MAGIC + json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("ascii")
        finally:
            assert self._native is not None
            if key is not None:
                self._native.NCryptFreeObject(key)
            self._native.NCryptFreeObject(provider)

    def unprotect(self, ciphertext: bytes, *, purpose: str = "Arenyxa") -> bytes:
        if super().available():
            return super().unprotect(ciphertext, purpose=purpose)
        if not self._native_available():
            return KeyProtectionAdapter.unprotect(self, ciphertext, purpose=purpose)
        raw = bytes(ciphertext)
        if not raw.startswith(self._MAGIC):
            raise ArenyxaError("TPM_ENVELOPE_INVALID", "TPM protected value envelope is invalid", domain="SECURITY")
        try:
            envelope = json.loads(raw[len(self._MAGIC):].decode("ascii"))
            if not isinstance(envelope, dict) or int(envelope.get("v", 0)) != 1:
                raise ValueError("unsupported envelope")
            wrapped = base64.urlsafe_b64decode(str(envelope["k"]).encode("ascii"))
            nonce = base64.urlsafe_b64decode(str(envelope["n"]).encode("ascii"))
            sealed = base64.urlsafe_b64decode(str(envelope["c"]).encode("ascii"))
        except (KeyError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise ArenyxaError("TPM_ENVELOPE_INVALID", "TPM protected value envelope is malformed", domain="SECURITY") from exc
        if len(nonce) != 12 or len(wrapped) > 16_384 or len(sealed) > 1_048_576:
            raise ArenyxaError("TPM_ENVELOPE_INVALID", "TPM protected value envelope exceeds safety bounds", domain="SECURITY")
        provider = self._open_provider()
        key = None
        try:
            key = self._open_or_create_key(provider, purpose)
            unwrapped = self._rsa_oaep(key, wrapped, decrypt=True)
            if len(unwrapped) != 32:
                raise ArenyxaError("TPM_UNWRAP_INVALID", "TPM returned an invalid AES wrapping key", domain="SECURITY")
            with SecretBuffer(unwrapped) as data_key:
                return AESGCM(data_key.copy_bytes()).decrypt(nonce, sealed, str(purpose).encode("utf-8"))
        finally:
            assert self._native is not None
            if key is not None:
                self._native.NCryptFreeObject(key)
            self._native.NCryptFreeObject(provider)


class KeyProtectionRegistry:
    def __init__(self) -> None:
        self.adapters: dict[str, KeyProtectionAdapter] = {
            "dpapi": DPAPIKeyProtectionAdapter(),
            "cng": CNGKeyProtectionAdapter(),
            "tpm": TPMKeyProtectionAdapter(),
        }

    def get(self, name: str) -> KeyProtectionAdapter:
        try:
            return self.adapters[str(name).casefold()]
        except KeyError as exc:
            raise KeyError(f"unknown key protection adapter: {name}") from exc

    def available(self) -> tuple[str, ...]:
        return tuple(name for name, adapter in self.adapters.items() if adapter.available())

    def diagnostics(self) -> dict[str, object]:
        tpm = self.adapters.get("tpm")
        tpm_status = tpm.capability_status() if isinstance(tpm, TPMKeyProtectionAdapter) else {"available": False}
        return {
            "available": self.available(),
            "tpm": tpm_status,
            "dpapi_scope": self.adapters["dpapi"].scope.value if isinstance(self.adapters.get("dpapi"), DPAPIKeyProtectionAdapter) else "unknown",
        }
