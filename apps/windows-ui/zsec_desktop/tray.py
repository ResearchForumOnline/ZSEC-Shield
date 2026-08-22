"""Windows notification-area integration with thread-safe Tk callbacks."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any


class TrayController:
    def __init__(
        self,
        *,
        dispatch: Callable[[Callable[[], None]], None],
        open_window: Callable[[], None],
        scan_downloads: Callable[[], None],
        open_settings: Callable[[], None],
        exit_application: Callable[[], None],
    ) -> None:
        self._dispatch = dispatch
        self._open_window = open_window
        self._scan_downloads = scan_downloads
        self._open_settings = open_settings
        self._exit_application = exit_application
        self._status = "Starting local evidence checks…"
        self._icon: Any = None
        self._thread: threading.Thread | None = None

    @property
    def active(self) -> bool:
        return self._icon is not None

    def start(self) -> bool:
        try:
            import pystray
            from PIL import Image, ImageDraw

            image = Image.new("RGBA", (64, 64), (8, 17, 31, 255))
            draw = ImageDraw.Draw(image)
            draw.rounded_rectangle((4, 4, 60, 60), radius=14, fill=(15, 35, 52, 255))
            draw.polygon(
                ((32, 8), (53, 16), (50, 41), (32, 56), (14, 41), (11, 16)),
                fill=(16, 185, 175, 255),
            )
            draw.text((20, 18), "Z", fill=(255, 255, 255, 255), stroke_width=1)

            def dispatch(callback: Callable[[], None]) -> Callable[..., None]:
                return lambda *_args: self._dispatch(callback)

            menu = pystray.Menu(
                pystray.MenuItem("Open ZSEC Antivirus", dispatch(self._open_window), default=True),
                pystray.MenuItem(lambda _item: f"Status: {self._status}", None, enabled=False),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Scan Downloads", dispatch(self._scan_downloads)),
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

    def set_status(self, value: str) -> None:
        self._status = value[:120]
        icon = self._icon
        if icon is not None:
            with suppress_tray_errors():
                icon.title = f"ZSEC Antivirus — {self._status}"[:127]
                icon.update_menu()

    def notify(self, message: str, title: str = "ZSEC Antivirus") -> None:
        icon = self._icon
        if icon is not None:
            with suppress_tray_errors():
                icon.notify(message[:240], title[:64])

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
