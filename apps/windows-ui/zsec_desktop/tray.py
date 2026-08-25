"""Windows notification-area integration with thread-safe Tk callbacks."""

from __future__ import annotations

import threading
import unicodedata
from collections.abc import Callable
from typing import Any

from zsec_desktop.brand import render_mark


def _single_line(value: str, *, maximum: int) -> str:
    """Return bounded tray text that cannot create deceptive extra lines."""

    if not isinstance(value, str):
        raise TypeError("tray text must be a string")
    cleaned = "".join(
        " " if unicodedata.category(character) == "Cc" else character
        for character in value
    ).split()
    return " ".join(cleaned)[:maximum].rstrip()


class TrayController:
    def __init__(
        self,
        *,
        dispatch: Callable[[Callable[[], None]], None],
        open_window: Callable[[], None],
        scan_protected_folders: Callable[[], None],
        open_settings: Callable[[], None],
        exit_application: Callable[[], None],
    ) -> None:
        self._dispatch = dispatch
        self._open_window = open_window
        self._scan_protected_folders = scan_protected_folders
        self._open_settings = open_settings
        self._exit_application = exit_application
        self._protection_status = "Checking Windows protection…"
        self._monitoring_status = "Checking ZSEC monitoring…"
        self._last_scan_status = "Checking scan evidence…"
        self._icon: Any = None
        self._thread: threading.Thread | None = None

    @property
    def active(self) -> bool:
        return self._icon is not None

    def start(self) -> bool:
        try:
            import pystray  # type: ignore[import-untyped]
            image = render_mark(64)

            def dispatch(callback: Callable[[], None]) -> Callable[..., None]:
                return lambda *_args: self._dispatch(callback)

            menu = pystray.Menu(
                pystray.MenuItem("Open ZSEC Antivirus", dispatch(self._open_window), default=True),
                pystray.MenuItem(
                    lambda _item: f"Protection: {self._protection_status}",
                    None,
                    enabled=False,
                ),
                pystray.MenuItem(
                    lambda _item: f"Monitoring: {self._monitoring_status}",
                    None,
                    enabled=False,
                ),
                pystray.MenuItem(
                    lambda _item: f"Last scan: {self._last_scan_status}",
                    None,
                    enabled=False,
                ),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem(
                    "Scan protected folders now",
                    dispatch(self._scan_protected_folders),
                ),
                pystray.MenuItem("Settings", dispatch(self._open_settings)),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Exit ZSEC Antivirus", dispatch(self._exit_application)),
            )
            self._icon = pystray.Icon("zsec-antivirus", image, "ZSEC Antivirus", menu)
            self._thread = threading.Thread(
                target=self._icon.run, name="zsec-notification-area", daemon=True
            )
            self._thread.start()
            return True
        except (ImportError, OSError, RuntimeError):
            self._icon = None
            self._thread = None
            return False

    def set_status(self, *, protection: str, monitoring: str, last_scan: str) -> None:
        self._protection_status = (
            _single_line(protection, maximum=72) or "Protection evidence unavailable"
        )
        self._monitoring_status = (
            _single_line(monitoring, maximum=72) or "Monitoring evidence unavailable"
        )
        self._last_scan_status = _single_line(last_scan, maximum=96) or "Scan evidence unavailable"
        icon = self._icon
        if icon is not None:
            with suppress_tray_errors():
                # Historical scan observations stay in the menu and never become the
                # primary protection tooltip.
                icon.title = (
                    f"ZSEC Antivirus — {self._protection_status}; {self._monitoring_status}"
                )[:127]
                icon.update_menu()

    def notify(self, message: str, title: str = "ZSEC Antivirus") -> None:
        icon = self._icon
        if icon is not None:
            with suppress_tray_errors():
                safe_message = _single_line(message, maximum=240) or "Open ZSEC Antivirus."
                safe_title = _single_line(title, maximum=64) or "ZSEC Antivirus"
                icon.notify(safe_message, safe_title)

    def stop(self) -> None:
        icon = self._icon
        self._icon = None
        if icon is not None:
            with suppress_tray_errors():
                icon.stop()


class suppress_tray_errors:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *_exc: object) -> bool:
        return True


__all__ = ["TrayController"]
