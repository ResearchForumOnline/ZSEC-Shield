"""Cache-only Windows Authenticode verification for already-hashed PE files."""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import Any


def _status_name(status: int) -> str:
    unsigned = {0x800B0100, 0x800B0003, 0x800B0004}
    if status == 0:
        return "trusted"
    if status & 0xFFFFFFFF in unsigned:
        return "unsigned"
    if status & 0xFFFFFFFF == 0x800B0111:
        return "explicitly_distrusted"
    return "untrusted_or_unverifiable"


def verify_authenticode(path: Path, expected: os.stat_result) -> dict[str, Any] | None:
    """Return review-only cache-only trust evidence, or ``None`` off Windows.

    Network retrieval is disabled. File identity is checked before and after the
    WinVerifyTrust call so a path replacement cannot inherit the hashed file's
    evidence.
    """

    if os.name != "nt":
        return None

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", ctypes.c_ulong),
            ("Data2", ctypes.c_ushort),
            ("Data3", ctypes.c_ushort),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.c_ulong),
            ("pcwszFilePath", ctypes.c_wchar_p),
            ("hFile", ctypes.c_void_p),
            ("pgKnownSubject", ctypes.c_void_p),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.c_ulong),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", ctypes.c_ulong),
            ("fdwRevocationChecks", ctypes.c_ulong),
            ("dwUnionChoice", ctypes.c_ulong),
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", ctypes.c_ulong),
            ("hWVTStateData", ctypes.c_void_p),
            ("pwszURLReference", ctypes.c_wchar_p),
            ("dwProvFlags", ctypes.c_ulong),
            ("dwUIContext", ctypes.c_ulong),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    before = path.stat()
    identity = (
        before.st_dev,
        getattr(before, "st_ino", 0),
        before.st_size,
        before.st_mtime_ns,
    )
    expected_identity = (
        expected.st_dev,
        getattr(expected, "st_ino", 0),
        expected.st_size,
        expected.st_mtime_ns,
    )
    if identity != expected_identity:
        return {
            "provider": "authenticode",
            "category": "identity_changed",
            "severity": "medium",
            "summary": "File identity changed before Authenticode verification",
            "evidence": {"cache_only": True},
            "quarantine_eligible": False,
        }

    action = GUID(
        0x00AAC56B,
        0xCD44,
        0x11D0,
        (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )
    file_info = WINTRUST_FILE_INFO(
        ctypes.sizeof(WINTRUST_FILE_INFO), str(path), None, None
    )
    trust_data = WINTRUST_DATA(
        ctypes.sizeof(WINTRUST_DATA),
        None,
        None,
        2,  # WTD_UI_NONE
        0,  # WTD_REVOKE_NONE
        1,  # WTD_CHOICE_FILE
        ctypes.pointer(file_info),
        1,  # WTD_STATEACTION_VERIFY
        None,
        None,
        0x1000,  # WTD_CACHE_ONLY_URL_RETRIEVAL
        0,
        None,
    )
    win_verify_trust = ctypes.windll.wintrust.WinVerifyTrust  # type: ignore[attr-defined]
    win_verify_trust.argtypes = [ctypes.c_void_p, ctypes.POINTER(GUID), ctypes.c_void_p]
    win_verify_trust.restype = ctypes.c_long
    status = int(
        win_verify_trust(
            ctypes.c_void_p(-1), ctypes.byref(action), ctypes.byref(trust_data)
        )
    )
    trust_data.dwStateAction = 2  # WTD_STATEACTION_CLOSE
    win_verify_trust(ctypes.c_void_p(-1), ctypes.byref(action), ctypes.byref(trust_data))

    after = path.stat()
    after_identity = (
        after.st_dev,
        getattr(after, "st_ino", 0),
        after.st_size,
        after.st_mtime_ns,
    )
    if after_identity != expected_identity:
        return {
            "provider": "authenticode",
            "category": "identity_changed",
            "severity": "medium",
            "summary": "File identity changed during Authenticode verification",
            "evidence": {"cache_only": True},
            "quarantine_eligible": False,
        }
    name = _status_name(status)
    severity = "info" if name in {"trusted", "unsigned"} else "medium"
    return {
        "provider": "authenticode",
        "category": name,
        "severity": severity,
        "summary": f"Windows Authenticode cache-only status: {name.replace('_', ' ')}",
        "evidence": {"cache_only": True, "winverifytrust_status": f"0x{status & 0xFFFFFFFF:08x}"},
        "quarantine_eligible": False,
    }


__all__ = ["verify_authenticode"]
