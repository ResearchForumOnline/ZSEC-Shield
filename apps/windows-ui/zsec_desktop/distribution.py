"""Runtime distribution detection without trusting user-controlled environment values."""

from __future__ import annotations

import ctypes
import os


APPMODEL_ERROR_NO_PACKAGE = 15700
ERROR_INSUFFICIENT_BUFFER = 122


def is_windows_store_package() -> bool:
    """Return whether this process has an MSIX package identity."""

    if os.name != "nt":
        return False
    try:
        length = ctypes.c_uint32(0)
        result = int(ctypes.windll.kernel32.GetCurrentPackageFullName(ctypes.byref(length), None))
    except (AttributeError, OSError):
        return False
    if result == ERROR_INSUFFICIENT_BUFFER:
        return True
    if result == APPMODEL_ERROR_NO_PACKAGE:
        return False
    return False


__all__ = ["is_windows_store_package"]
