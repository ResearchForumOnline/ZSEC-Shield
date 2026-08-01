"""Read-only macOS inventory adapter."""

from __future__ import annotations

import platform
from typing import Any

from zsec_shield.inventory.base import BaseInventoryAdapter


class MacOSInventoryAdapter(BaseInventoryAdapter):
    def __init__(self) -> None:
        super().__init__(adapter_name="macos", supported=True)

    def platform_details(self) -> dict[str, Any]:
        version, version_info, architecture = platform.mac_ver()
        return {
            "product": "macOS",
            "product_version": version or "unknown",
            "version_components": list(version_info),
            "architecture": architecture or platform.machine(),
        }

    def observations(self) -> list[str]:
        return [
            "macOS product and architecture information came from Python platform APIs.",
            (
                "System Integrity Protection, Gatekeeper, and XProtect status are not "
                "asserted by this MVP."
            ),
        ]
