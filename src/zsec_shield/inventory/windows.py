"""Read-only Windows 10/11 inventory adapter."""

from __future__ import annotations

import importlib
import platform
from typing import Any, Protocol, cast

from zsec_shield.inventory.base import BaseInventoryAdapter


class _WinregModule(Protocol):
    KEY_READ: int
    KEY_WOW64_64KEY: int
    HKEY_LOCAL_MACHINE: Any

    def OpenKey(self, key: Any, sub_key: str, reserved: int = 0, access: int = 0) -> Any: ...

    def QueryValueEx(self, key: Any, value_name: str, /) -> tuple[Any, int]: ...


def windows_marketing_name(build: int | None) -> str:
    if build is None:
        return "Windows (version unknown)"
    return "Windows 11" if build >= 22000 else "Windows 10"


class WindowsInventoryAdapter(BaseInventoryAdapter):
    def __init__(self) -> None:
        super().__init__(adapter_name="windows", supported=True)

    def platform_details(self) -> dict[str, Any]:
        registry: dict[str, Any] = {}
        registry_error: str | None = None
        try:
            winreg = cast(_WinregModule, importlib.import_module("winreg"))

            access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            location = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, location, 0, access) as key:
                for name in (
                    "ProductName",
                    "EditionID",
                    "DisplayVersion",
                    "CurrentBuildNumber",
                    "UBR",
                ):
                    try:
                        registry[name] = winreg.QueryValueEx(key, name)[0]
                    except OSError:
                        continue
        except (ImportError, OSError) as exc:
            registry_error = str(exc)[:300]
        raw_build = registry.get("CurrentBuildNumber")
        try:
            build = (
                int(raw_build) if raw_build is not None else int(platform.version().split(".")[-1])
            )
        except (TypeError, ValueError, IndexError):
            build = None
        details: dict[str, Any] = {
            "product": windows_marketing_name(build),
            "edition": registry.get("EditionID", "unknown"),
            "display_version": registry.get("DisplayVersion", "unknown"),
            "build": build,
            "update_build_revision": registry.get("UBR"),
            "registry_product_name": registry.get("ProductName"),
        }
        if registry_error:
            details["registry_read_error"] = registry_error
        return details

    def observations(self) -> list[str]:
        return [
            (
                "Windows version metadata was read from the CurrentVersion registry key "
                "when available."
            ),
            (
                "A build number of 22000 or newer is labelled Windows 11; older Windows "
                "10-family builds are labelled Windows 10."
            ),
            (
                "Microsoft Defender configuration and health are not asserted by this "
                "inventory adapter."
            ),
        ]
