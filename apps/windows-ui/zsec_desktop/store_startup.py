"""Use the package's Windows StartupTask without a registry workaround.

The WinRT ABI is projected with ctypes so frozen Store builds need no optional
Python WinRT package. Creation, polling and disposal stay on the Tk UI thread;
RequestEnableAsync is never invoked by a worker or an external PowerShell host.
Interface layouts: Microsoft's windows-rs Windows/ApplicationModel bindings.
"""

from __future__ import annotations

import ctypes
import os
import threading
import uuid
from enum import IntEnum
from typing import Literal

TASK_ID = "ZSECAntivirusStartup"


class StoreStartupState(IntEnum):
    DISABLED = 0
    DISABLED_BY_USER = 1
    ENABLED = 2
    DISABLED_BY_POLICY = 3
    ENABLED_BY_POLICY = 4

    @property
    def enabled(self) -> bool:
        return self in (self.ENABLED, self.ENABLED_BY_POLICY)

    @property
    def description(self) -> str:
        return {
            self.DISABLED: "Off — enable this option to start monitoring when you sign in.",
            self.DISABLED_BY_USER: (
                "Off in Windows — open Startup apps, turn on ZSEC Antivirus, then refresh. "
                "Windows requires you to change this setting yourself."
            ),
            self.ENABLED: "On — Windows will start ZSEC in the notification area at sign-in.",
            self.DISABLED_BY_POLICY: "Off — your Windows administrator policy prevents startup.",
            self.ENABLED_BY_POLICY: (
                "On — startup is required by your Windows administrator policy."
            ),
        }[self]


class _Guid(ctypes.Structure):
    _fields_ = [
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def parse(cls, value: str) -> _Guid:
        return cls.from_buffer_copy(uuid.UUID(value).bytes_le)


def _check(result: int, operation: str) -> None:
    if result < 0:
        raise OSError(f"Windows startup {operation} failed (0x{result & 0xFFFFFFFF:08X}).")


def _call(
    pointer: ctypes.c_void_p, slot: int, *args: object, argtypes: tuple[object, ...] = ()
) -> int:
    if not pointer.value:
        raise OSError("Windows startup returned an empty interface.")
    table = ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    method = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, *argtypes)(table[slot])
    return method(pointer, *args)


def _release(pointer: ctypes.c_void_p) -> None:
    if pointer.value:
        _call(pointer, 2)
        pointer.value = None


class StoreStartupOperation:
    """One asynchronous status/read or explicit enable/disable request.

    poll() returns None while Windows is working, then the authoritative state.
    A request blocked by user choice or policy returns that state without trying
    a registry/task-scheduler fallback. close() releases every WinRT reference.
    """

    def __init__(self, action: Literal["query", "enable", "disable"] = "query") -> None:
        if os.name != "nt":
            raise OSError("Store startup is available only on Windows.")
        if action not in ("query", "enable", "disable"):
            raise ValueError("Invalid Windows startup action.")
        self.action = action
        self.thread = threading.get_ident()
        self.runtime_initialized = False
        self.factory = ctypes.c_void_p()
        self.operation = ctypes.c_void_p()
        self.info = ctypes.c_void_p()
        self.task = ctypes.c_void_p()
        self.requesting = False
        self.closed = False
        # Load only Windows' system DLL, never a working-directory DLL.
        self.runtime = ctypes.WinDLL("combase.dll", winmode=0x00000800)
        self.runtime.RoInitialize.argtypes = [ctypes.c_uint32]
        self.runtime.RoInitialize.restype = ctypes.c_int32
        self.runtime.RoUninitialize.argtypes = []
        self.runtime.RoUninitialize.restype = None
        self.runtime.WindowsCreateString.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.runtime.WindowsCreateString.restype = ctypes.c_int32
        self.runtime.WindowsDeleteString.argtypes = [ctypes.c_void_p]
        self.runtime.WindowsDeleteString.restype = ctypes.c_int32
        self.runtime.RoGetActivationFactory.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_Guid),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.runtime.RoGetActivationFactory.restype = ctypes.c_int32
        try:
            initialized = self.runtime.RoInitialize(0)  # STA; Tk keeps pumping messages.
            if initialized >= 0:
                self.runtime_initialized = True
            elif (initialized & 0xFFFFFFFF) != 0x80010106:  # already initialized as MTA
                _check(initialized, "initialization")
            name = self._string("Windows.ApplicationModel.StartupTask")
            try:
                iid = _Guid.parse("ee5b60bd-a148-41a7-b26e-e8b88a1e62f8")
                _check(
                    self.runtime.RoGetActivationFactory(
                        name, ctypes.byref(iid), ctypes.byref(self.factory)
                    ),
                    "activation",
                )
            finally:
                self.runtime.WindowsDeleteString(name)
            identifier = self._string(TASK_ID)
            try:
                _check(
                    _call(
                        self.factory,
                        7,
                        identifier,
                        ctypes.byref(self.operation),
                        argtypes=(ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)),
                    ),
                    "lookup",
                )
            finally:
                self.runtime.WindowsDeleteString(identifier)
            self._get_async_info()
        except BaseException:
            self.close()
            raise

    def _string(self, value: str) -> ctypes.c_void_p:
        result = ctypes.c_void_p()
        _check(
            self.runtime.WindowsCreateString(value, len(value), ctypes.byref(result)),
            "string creation",
        )
        return result

    def _ensure_thread(self) -> None:
        if threading.get_ident() != self.thread:
            raise RuntimeError("Windows startup must stay on its originating UI thread.")

    def _get_async_info(self) -> None:
        iid = _Guid.parse("00000036-0000-0000-c000-000000000046")
        _check(
            _call(
                self.operation,
                0,
                ctypes.byref(iid),
                ctypes.byref(self.info),
                argtypes=(ctypes.POINTER(_Guid), ctypes.POINTER(ctypes.c_void_p)),
            ),
            "async status",
        )

    def _state(self) -> StoreStartupState:
        state = ctypes.c_int32()
        _check(
            _call(self.task, 8, ctypes.byref(state), argtypes=(ctypes.POINTER(ctypes.c_int32),)),
            "state read",
        )
        return StoreStartupState(state.value)

    def poll(self) -> StoreStartupState | None:
        self._ensure_thread()
        if self.closed:
            raise OSError("Windows startup operation is closed.")
        status = ctypes.c_int32()
        _check(
            _call(self.info, 7, ctypes.byref(status), argtypes=(ctypes.POINTER(ctypes.c_int32),)),
            "async status read",
        )
        if status.value == 0:
            return None
        if status.value != 1:
            error = ctypes.c_int32()
            _check(
                _call(
                    self.info, 8, ctypes.byref(error), argtypes=(ctypes.POINTER(ctypes.c_int32),)
                ),
                "async error read",
            )
            _check(error.value, "request")
            raise OSError("Windows startup request was cancelled.")
        if self.requesting:
            result = ctypes.c_int32()
            _check(
                _call(
                    self.operation,
                    8,
                    ctypes.byref(result),
                    argtypes=(ctypes.POINTER(ctypes.c_int32),),
                ),
                "enable result",
            )
            # Read back the task; the returned enabled result alone is not evidence.
            return self._state()
        _check(
            _call(
                self.operation,
                8,
                ctypes.byref(self.task),
                argtypes=(ctypes.POINTER(ctypes.c_void_p),),
            ),
            "lookup result",
        )
        state = self._state()
        if self.action == "enable" and state == StoreStartupState.DISABLED:
            _release(self.info)
            _release(self.operation)
            _check(
                _call(
                    self.task,
                    6,
                    ctypes.byref(self.operation),
                    argtypes=(ctypes.POINTER(ctypes.c_void_p),),
                ),
                "enable request",
            )
            self._get_async_info()
            self.requesting = True
            return None
        if self.action == "disable" and state == StoreStartupState.ENABLED:
            _check(_call(self.task, 7), "disable request")
            return self._state()
        return state

    def close(self) -> None:
        self._ensure_thread()
        if self.closed:
            return
        self.closed = True
        if self.info.value:
            # Cancel a pending request before releasing it. Cancel is best-effort;
            # Windows may already have completed a user-initiated enable request.
            _call(self.info, 9)
        for pointer in (self.info, self.operation, self.task, self.factory):
            _release(pointer)
        if self.runtime_initialized:
            self.runtime.RoUninitialize()
            self.runtime_initialized = False
