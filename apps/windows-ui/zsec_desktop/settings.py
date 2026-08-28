"""Strict local desktop preferences and owned Windows startup registration."""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from zsec_desktop.distribution import is_windows_store_package

SETTINGS_SCHEMA = "zsec.antivirus.desktop-settings.v1"
STARTUP_VALUE_NAME = "ZSEC Antivirus Desktop"


@dataclass(frozen=True, slots=True)
class DesktopSettings:
    close_to_tray: bool = True
    start_with_windows: bool = False
    reduce_motion: bool = False
    max_file_mebibytes: int = 64


def settings_path(state_dir: Path) -> Path:
    return state_dir / "desktop" / "settings.json"


def _validate(value: Any) -> DesktopSettings:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "close_to_tray",
        "start_with_windows",
        "reduce_motion",
        "max_file_mebibytes",
    }:
        raise ValueError("desktop settings fields are invalid")
    if value["schema"] != SETTINGS_SCHEMA:
        raise ValueError("desktop settings schema is invalid")
    for field in ("close_to_tray", "start_with_windows", "reduce_motion"):
        if not isinstance(value[field], bool):
            raise ValueError(f"desktop setting {field} must be boolean")
    maximum = value["max_file_mebibytes"]
    if isinstance(maximum, bool) or not isinstance(maximum, int) or not 1 <= maximum <= 16384:
        raise ValueError("desktop maximum file size is invalid")
    return DesktopSettings(
        close_to_tray=value["close_to_tray"],
        start_with_windows=value["start_with_windows"],
        reduce_motion=value["reduce_motion"],
        max_file_mebibytes=maximum,
    )


def load_settings(state_dir: Path) -> tuple[DesktopSettings, str | None]:
    path = settings_path(state_dir)
    if not path.exists():
        return DesktopSettings(), None
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ValueError("desktop settings path is not a regular file")
        if metadata.st_size > 16 * 1024:
            raise ValueError("desktop settings file is unexpectedly large")
        return _validate(json.loads(path.read_text(encoding="utf-8"))), None
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return DesktopSettings(), str(exc)[:500]


def save_settings(state_dir: Path, settings: DesktopSettings) -> None:
    path = settings_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise ValueError("desktop settings directory may not be a link")
    payload = {"schema": SETTINGS_SCHEMA, **asdict(settings)}
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".settings-", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def startup_command(executable: Path | None = None) -> str:
    target = (executable or Path(sys.executable)).absolute()
    return f'"{target}" --startup'


class StartupRegistration:
    """Own only the exact current-user startup value created by this app."""

    def __init__(
        self, executable: Path | None = None, *, store_managed: bool | None = None
    ) -> None:
        self.executable = (executable or Path(sys.executable)).absolute()
        self.command = startup_command(self.executable)
        self.store_managed = (
            is_windows_store_package() if store_managed is None else store_managed
        )

    def _installed_command_is_owned(self, value: str) -> bool:
        """Recognize a prior versioned installer path without trusting arbitrary values."""

        prefix, suffix = '"', '" --startup'
        if not value.startswith(prefix) or not value.endswith(suffix):
            return False
        raw_path = value[len(prefix) : -len(suffix)]
        local = os.environ.get("LOCALAPPDATA")
        if not local:
            return False
        try:
            candidate = Path(raw_path).resolve(strict=True)
            product = (Path(local) / "TalkToAI" / "ZSEC Antivirus" / "App").resolve(strict=True)
            relative = candidate.relative_to(product)
            # Installer layout: App/<version>/App/ZSEC Antivirus.exe.
            if len(relative.parts) != 3 or relative.parts[1:] != (
                "App",
                "ZSEC Antivirus.exe",
            ):
                return False
            metadata = candidate.lstat()
            return stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)
        except (OSError, RuntimeError, ValueError):
            return False

    def _read_value(self) -> tuple[str | None, str | None]:
        import winreg

        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_QUERY_VALUE,
            ) as key:
                value, kind = winreg.QueryValueEx(key, STARTUP_VALUE_NAME)
        except FileNotFoundError:
            return None, None
        if kind != winreg.REG_SZ or not isinstance(value, str):
            return None, "The ZSEC startup value has an unexpected registry type"
        if value != self.command and not self._installed_command_is_owned(value):
            return None, "The ZSEC startup value is not owned by this installation"
        return value, None

    def current(self) -> tuple[bool, str | None]:
        if os.name != "nt":
            return False, "Windows startup registration is available only on Windows"
        if self.store_managed:
            return False, None
        value, error = self._read_value()
        return value is not None, error

    def set_enabled(self, enabled: bool) -> None:
        if os.name != "nt":
            raise OSError("Windows startup registration is available only on Windows")
        if self.store_managed:
            if enabled:
                raise OSError("Windows manages startup for this Store installation")
            return
        import winreg

        path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        current_value, error = self._read_value()
        current = current_value is not None
        if enabled:
            if self.executable.name.casefold() != "zsec antivirus.exe":
                raise OSError(
                    "Windows startup is available only from the installed ZSEC Antivirus app"
                )
            if error is not None:
                raise OSError(error)
            if current_value == self.command:
                return
            with winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE
            ) as key:
                winreg.SetValueEx(key, STARTUP_VALUE_NAME, 0, winreg.REG_SZ, self.command)
            verified, verification_error = self.current()
            if not verified or verification_error is not None:
                raise OSError(verification_error or "startup registration read-back failed")
            return
        if error is not None:
            raise OSError(error)
        if not current:
            return
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.DeleteValue(key, STARTUP_VALUE_NAME)


__all__ = [
    "SETTINGS_SCHEMA",
    "STARTUP_VALUE_NAME",
    "DesktopSettings",
    "StartupRegistration",
    "load_settings",
    "save_settings",
    "settings_path",
    "startup_command",
]
