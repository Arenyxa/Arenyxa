from __future__ import annotations
import logging

import ctypes
import os
from ctypes import wintypes
from typing import Any

from arenyxa.qt_compat.QtWidgets import QMainWindow


class WindowsTaskbarProgress:
    





    TBPF_NOPROGRESS = 0x0
    TBPF_INDETERMINATE = 0x1
    TBPF_NORMAL = 0x2
    TBPF_ERROR = 0x4
    TBPF_PAUSED = 0x8

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

        @classmethod
        def parse(cls, text: str) -> "WindowsTaskbarProgress.GUID":
            import uuid
            value = uuid.UUID(text)
            data4 = (ctypes.c_ubyte * 8).from_buffer_copy(value.bytes[8:])
            return cls(value.time_low, value.time_mid, value.time_hi_version, data4)

    def __init__(self, window: QMainWindow) -> None:
        self.window = window
        self._object: ctypes.c_void_p | None = None
        self._available = False
        self._last_state: int | None = None
        self._last_progress: tuple[int, int, int] | None = None
        self._hwnd: wintypes.HWND | None = None
        self._com_initialized = False
        if os.name != "nt":
            return
        try:
            hr_init = int(ctypes.windll.ole32.CoInitialize(None))
            self._com_initialized = hr_init in (0, 1)
            clsid = self.GUID.parse("56FDF344-FD6D-11d0-958A-006097C9A090")
            iid = self.GUID.parse("EA1AFB91-9E28-4B86-90E9-9E9F8A5EEA84")
            obj = ctypes.c_void_p()
            hr = ctypes.windll.ole32.CoCreateInstance(ctypes.byref(clsid), None, 1, ctypes.byref(iid), ctypes.byref(obj))
            if hr != 0 or not obj.value:
                return
            self._object = obj
            hr_taskbar = self._call(3, ctypes.c_long, [])          
            if hr_taskbar is not None and int(hr_taskbar) < 0:
                self.close()
                return
            self._available = True
        except Exception:
                                                                                                
                                                                                         
            self.close()
            self._available = False

    def _call(self, index: int, restype: Any, args: list[tuple[Any, Any]]) -> Any:
        if not self._object:
            return None
        vtbl = ctypes.cast(self._object, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        prototype = ctypes.WINFUNCTYPE(restype, ctypes.c_void_p, *[kind for kind, _ in args])
        fn = prototype(vtbl[index])
        return fn(self._object, *[value for _, value in args])

    def clear(self) -> None:
        self.set_state(self.TBPF_NOPROGRESS)

    def _window_handle(self) -> wintypes.HWND:
        if self._hwnd is None:
            self._hwnd = wintypes.HWND(int(self.window.winId()))
        return self._hwnd

    def set_state(self, state: int) -> None:
        if not self._available or self._last_state == int(state):
            return
        try:
            hwnd = self._window_handle()
            self._call(10, ctypes.c_long, [(wintypes.HWND, hwnd), (wintypes.DWORD, wintypes.DWORD(state))])
            self._last_state = int(state)
            if state == self.TBPF_NOPROGRESS:
                self._last_progress = None
        except Exception:
            self._available = False

    def set_progress(self, completed: int, total: int, state: int = TBPF_NORMAL) -> None:
        if not self._available:
            return
        total = max(1, int(total))
        completed = max(0, min(total, int(completed)))
        progress = (completed, total, int(state))
        if self._last_progress == progress:
            return
        try:
            hwnd = self._window_handle()
            if self._last_state != int(state):
                self._call(10, ctypes.c_long, [(wintypes.HWND, hwnd), (wintypes.DWORD, wintypes.DWORD(state))])
                self._last_state = int(state)
            self._call(9, ctypes.c_long, [(wintypes.HWND, hwnd), (ctypes.c_ulonglong, ctypes.c_ulonglong(completed)), (ctypes.c_ulonglong, ctypes.c_ulonglong(total))])
            self._last_progress = progress
        except Exception:
            self._available = False

    def close(self) -> None:
        if self._object:
            try:
                self._call(2, ctypes.c_ulong, [])           
            except Exception:
                logging.getLogger(__name__).debug("Suppressed non-fatal exception", exc_info=True)
            self._object = None
            self._hwnd = None
            self._last_state = None
            self._last_progress = None
        if self._com_initialized and os.name == "nt":
            try:
                ctypes.windll.ole32.CoUninitialize()
            except Exception:
                logging.getLogger(__name__).debug("Suppressed non-fatal exception", exc_info=True)
            self._com_initialized = False
