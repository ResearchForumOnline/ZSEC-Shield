"""Base inventory model shared by platform-specific read-only adapters."""

from __future__ import annotations

import platform
import socket
import sys
from dataclasses import dataclass
from typing import Any

from zsec_shield.util import format_utc


@dataclass(slots=True)
class BaseInventoryAdapter:
    adapter_name: str = "generic"
    supported: bool = False

    def platform_details(self) -> dict[str, Any]:
        return {}

    def observations(self) -> list[str]:
        return ["No platform-specific inventory adapter is available."]

    def collect(self) -> dict[str, Any]:
        try:
            hostname = socket.gethostname()
        except OSError:
            hostname = "unknown"
        return {
            "schema": "zsec.shield.inventory.v1",
            "collected_at": format_utc(),
            "adapter": self.adapter_name,
            "supported": self.supported,
            "read_only": True,
            "host": {
                "hostname": hostname,
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "python": platform.python_version(),
                "python_implementation": platform.python_implementation(),
                "pointer_bits": 64 if sys.maxsize > 2**32 else 32,
            },
            "platform": self.platform_details(),
            "observations": self.observations(),
            "limitations": [
                "Inventory is a point-in-time, unprivileged, read-only observation.",
                "It does not prove patch status, compromise state, or security compliance.",
            ],
        }
