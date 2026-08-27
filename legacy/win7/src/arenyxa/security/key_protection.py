from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from typing import Callable

from arenyxa.domain.errors import ArenyxaError


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

    def __exit__(self, exc_type, exc, tb) -> None:
        self.zeroize()

    def __del__(self) -> None:
                                                                                             
                                                  
        try:
            if not self._cleared:
                self.zeroize()
        except Exception:
            pass


class KeyProtectionAdapter:
    name = "abstract"

    def available(self) -> bool:
        return False

    def protect(self, plaintext: bytes, *, purpose: str = "Arenyxa") -> bytes:
        raise ArenyxaError("KEY_PROTECTION_UNAVAILABLE", "key protection adapter is unavailable", domain="SECURITY")

    def unprotect(self, ciphertext: bytes, *, purpose: str = "Arenyxa") -> bytes:
        raise ArenyxaError("KEY_PROTECTION_UNAVAILABLE", "key protection adapter is unavailable", domain="SECURITY")


class DPAPIKeyProtectionAdapter(KeyProtectionAdapter):
    name = "windows-dpapi"

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

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
        except (TypeError, ValueError):
            pass

    def protect(self, plaintext: bytes, *, purpose: str = "Arenyxa") -> bytes:
        if not self.available():
            return super().protect(plaintext, purpose=purpose)
        source, source_buffer = self._blob(bytes(plaintext))
        entropy, entropy_buffer = self._blob(purpose.encode("utf-8"))
        output = self.DATA_BLOB()
        flags = 0x1                             
        try:
            ok = ctypes.windll.crypt32.CryptProtectData(
                ctypes.byref(source), None, ctypes.byref(entropy), None, None, flags, ctypes.byref(output)
            )
            if not ok:
                raise ArenyxaError("DPAPI_PROTECT_FAILED", "Windows DPAPI failed to protect secret", domain="SECURITY")
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

    def unprotect(self, ciphertext: bytes, *, purpose: str = "Arenyxa") -> bytes:
        if not self.available():
            return super().unprotect(ciphertext, purpose=purpose)
        source, source_buffer = self._blob(bytes(ciphertext))
        entropy, entropy_buffer = self._blob(purpose.encode("utf-8"))
        output = self.DATA_BLOB()
        flags = 0x1
        try:
            ok = ctypes.windll.crypt32.CryptUnprotectData(
                ctypes.byref(source), None, ctypes.byref(entropy), None, None, flags, ctypes.byref(output)
            )
            if not ok:
                raise ArenyxaError("DPAPI_UNPROTECT_FAILED", "Windows DPAPI failed to unprotect secret", domain="SECURITY")
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
    

    def __init__(self, protect_callback=None, unprotect_callback=None) -> None:
        super().__init__("windows-cng", protect_callback, unprotect_callback)


class TPMKeyProtectionAdapter(_DelegatingHardwareAdapter):
    

    def __init__(self, protect_callback=None, unprotect_callback=None) -> None:
        super().__init__("tpm", protect_callback, unprotect_callback)


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
