from __future__ import annotations

import os
import sys
import types
from pathlib import Path
from typing import ClassVar

import pytest

GUI_ROOT = Path(__file__).resolve().parents[1] / "apps" / "windows-ui"
if str(GUI_ROOT) not in sys.path:
    sys.path.insert(0, str(GUI_ROOT))

from zsec_desktop.settings import (  # noqa: E402
    DesktopSettings,
    StartupRegistration,
    load_settings,
    save_settings,
    startup_command,
)
from zsec_desktop.tray import TrayController  # noqa: E402


def test_desktop_settings_round_trip_and_corrupt_recovery(tmp_path: Path) -> None:
    expected = DesktopSettings(False, True, True, 256)
    save_settings(tmp_path, expected)
    loaded, error = load_settings(tmp_path)
    assert error is None
    assert loaded == expected

    path = tmp_path / "desktop" / "settings.json"
    path.write_text("{not json", encoding="utf-8")
    loaded, error = load_settings(tmp_path)
    assert loaded == DesktopSettings()
    assert error is not None


def test_startup_command_quotes_exact_executable() -> None:
    executable = Path(r"C:\Program Files\TalkToAI\ZSEC Antivirus.exe")
    assert startup_command(executable) == f'"{executable.absolute()}" --startup'


@pytest.mark.skipif(os.name != "nt", reason="Windows startup registration")
def test_source_python_cannot_be_registered_as_the_desktop_startup_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registration = StartupRegistration(Path(r"C:\Python312\python.exe"))
    monkeypatch.setattr(registration, "_read_value", lambda: (None, None))
    with pytest.raises(OSError, match="installed ZSEC Antivirus app"):
        registration.set_enabled(True)


def test_tray_menu_dispatches_ui_actions_and_updates_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    callbacks: list[str] = []
    dispatched: list[object] = []

    class FakeMenuItem:
        def __init__(self, text: object, action: object, **kwargs: object) -> None:
            self.text = text
            self.action = action
            self.kwargs = kwargs

    class FakeMenu:
        SEPARATOR = object()

        def __init__(self, *items: object) -> None:
            self.items = items

    class FakeIcon:
        instances: ClassVar[list[FakeIcon]] = []

        def __init__(self, name: str, image: object, title: str, menu: FakeMenu) -> None:
            self.name = name
            self.image = image
            self.title = title
            self.menu = menu
            self.notifications: list[tuple[str, str]] = []
            self.updated = False
            self.stopped = False
            self.instances.append(self)

        def run(self) -> None:
            return None

        def update_menu(self) -> None:
            self.updated = True

        def notify(self, message: str, title: str) -> None:
            self.notifications.append((message, title))

        def stop(self) -> None:
            self.stopped = True

    pystray = types.SimpleNamespace(Menu=FakeMenu, MenuItem=FakeMenuItem, Icon=FakeIcon)
    monkeypatch.setitem(sys.modules, "pystray", pystray)

    controller = TrayController(
        dispatch=lambda callback: dispatched.append(callback),
        open_window=lambda: callbacks.append("open"),
        scan_protected_folders=lambda: callbacks.append("scan"),
        open_settings=lambda: callbacks.append("settings"),
        exit_application=lambda: callbacks.append("exit"),
    )
    assert controller.start()
    icon = FakeIcon.instances[-1]
    assert controller.active
    assert len(icon.menu.items) == 7

    open_item = icon.menu.items[0]
    assert isinstance(open_item, FakeMenuItem)
    assert callable(open_item.action)
    open_item.action()
    assert len(dispatched) == 1
    callback = dispatched.pop()
    assert callable(callback)
    callback()
    assert callbacks == ["open"]

    controller.set_status("Review-only observations")
    assert icon.updated
    assert "Review-only observations" in icon.title
    controller.notify("Scan completed")
    assert icon.notifications == [("Scan completed", "ZSEC Antivirus")]
    controller.stop()
    assert icon.stopped
    assert not controller.active
