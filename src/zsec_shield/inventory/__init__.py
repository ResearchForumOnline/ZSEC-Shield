"""Read-only platform inventory adapter selection."""

from __future__ import annotations

import platform
from typing import Any

from zsec_shield.inventory.base import BaseInventoryAdapter
from zsec_shield.inventory.linux import LinuxInventoryAdapter
from zsec_shield.inventory.macos import MacOSInventoryAdapter
from zsec_shield.inventory.windows import WindowsInventoryAdapter


def select_adapter(system: str | None = None) -> BaseInventoryAdapter:
    detected = system or platform.system()
    if detected == "Windows":
        return WindowsInventoryAdapter()
    if detected == "Darwin":
        return MacOSInventoryAdapter()
    if detected == "Linux":
        return LinuxInventoryAdapter()
    return BaseInventoryAdapter(adapter_name="generic", supported=False)


def collect_inventory() -> dict[str, Any]:
    return select_adapter().collect()


__all__ = ["collect_inventory", "select_adapter"]
