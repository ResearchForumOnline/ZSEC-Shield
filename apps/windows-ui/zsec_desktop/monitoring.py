"""Local monitoring preference and Windows-resolved standard user folders.

The preference controls this app's observer only. It never changes Defender,
starts a privileged service, or persists automatic quarantine authorization.
"""

from __future__ import annotations

import ctypes
import json
import os
import stat
import tempfile
import uuid
from pathlib import Path

MONITORING_SCHEMA = "zsec.antivirus.monitoring-preference.v1"
KNOWN_FOLDERS = (
    ("Downloads", "374de290-123f-4565-9164-39c4925e467b"),
    ("Documents", "fdd39ad0-238f-46af-adb4-6c85480369c7"),
    ("Desktop", "b4bfcc3a-db2c-424c-b029-7fe99a87c641"),
)


def load_monitoring_enabled(state_dir: Path) -> tuple[bool, str | None]:
    path = state_dir / "desktop" / "monitoring.json"
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4096:
            raise ValueError("monitoring preference is not a bounded regular file")
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
            raise ValueError("monitoring preference may not be a link")
        value = json.loads(path.read_text(encoding="utf-8"))
        if (
            not isinstance(value, dict)
            or set(value) != {"schema", "enabled"}
            or value["schema"] != MONITORING_SCHEMA
            or type(value["enabled"]) is not bool
        ):
            raise ValueError("monitoring preference fields are invalid")
        return value["enabled"], None
    except FileNotFoundError:
        return True, None
    except (OSError, UnicodeError, ValueError) as exc:
        # A corrupt preference is visible and does not silently turn protection off.
        return True, str(exc)[:300]


def save_monitoring_enabled(state_dir: Path, enabled: bool) -> None:
    if type(enabled) is not bool:
        raise ValueError("monitoring preference must be boolean")
    directory = state_dir / "desktop"
    directory.mkdir(parents=True, exist_ok=True)
    metadata = directory.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or getattr(metadata, "st_file_attributes", 0) & 0x400
    ):
        raise ValueError("monitoring preference directory may not be a link")
    descriptor, name = tempfile.mkstemp(prefix=".monitoring-", suffix=".tmp", dir=directory)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump({"schema": MONITORING_SCHEMA, "enabled": enabled}, handle)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, directory / "monitoring.json")
    finally:
        temporary.unlink(missing_ok=True)


def standard_monitoring_roots() -> tuple[Path, ...]:
    """Resolve redirected folders through Windows, never traverse root links.

    SHGetKnownFolderPath uses the current user's configured location, including
    a local OneDrive relocation. UNC locations are excluded from automatic scope.
    The observer and scanner independently retain their own path checks.
    """
    roots: list[Path] = []
    for name, identifier in KNOWN_FOLDERS:
        candidate = Path.home() / name
        if os.name == "nt":
            try:
                shell = ctypes.WinDLL("shell32.dll", use_last_error=True, winmode=0x800)
                ole = ctypes.WinDLL("ole32.dll", use_last_error=True, winmode=0x800)
                get_path = shell.SHGetKnownFolderPath
                get_path.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_uint32,
                    ctypes.c_void_p,
                    ctypes.POINTER(ctypes.c_void_p),
                ]
                get_path.restype = ctypes.c_long
                ole.CoTaskMemFree.argtypes = [ctypes.c_void_p]
                ole.CoTaskMemFree.restype = None
                folder_id = ctypes.create_string_buffer(uuid.UUID(identifier).bytes_le)
                allocated = ctypes.c_void_p()
                try:
                    result = get_path(ctypes.byref(folder_id), 0, None, ctypes.byref(allocated))
                    if result != 0 or not allocated.value:
                        continue
                    candidate = Path(ctypes.wstring_at(allocated))
                finally:
                    if allocated.value:
                        ole.CoTaskMemFree(allocated)
            except (OSError, AttributeError, ValueError):
                continue
        try:
            if str(candidate).startswith("\\\\"):
                continue
            metadata = candidate.lstat()
            if (
                stat.S_ISDIR(metadata.st_mode)
                and not stat.S_ISLNK(metadata.st_mode)
                and not getattr(metadata, "st_file_attributes", 0) & 0x400
                and candidate not in roots
            ):
                roots.append(candidate)
        except OSError:
            continue
    return tuple(roots)
