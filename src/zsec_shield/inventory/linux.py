"""Read-only Linux inventory adapter."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

from zsec_shield.inventory.base import BaseInventoryAdapter


def _read_small_text(path: Path, maximum: int = 65536) -> str:
    try:
        with path.open("rb") as handle:
            raw = handle.read(maximum + 1)
    except OSError:
        return ""
    if len(raw) > maximum:
        return ""
    return raw.decode("utf-8", "replace")


def read_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in _read_small_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.replace("_", "").isalnum():
            values[key] = value.strip().strip('"').strip("'")[:500]
    return values


class LinuxInventoryAdapter(BaseInventoryAdapter):
    def __init__(self) -> None:
        super().__init__(adapter_name="linux", supported=True)

    def platform_details(self) -> dict[str, Any]:
        release = read_os_release()
        managers = [
            executable
            for executable in ("apt-get", "dnf", "yum", "zypper", "pacman", "apk")
            if shutil.which(executable)
        ]
        virtualization_signals: list[str] = []
        if (
            os.environ.get("WSL_INTEROP")
            or "microsoft" in _read_small_text(Path("/proc/version")).lower()
        ):
            virtualization_signals.append("wsl")
        if Path("/.dockerenv").exists():
            virtualization_signals.append("docker-marker")
        container = _read_small_text(Path("/proc/1/cgroup")).lower()
        if any(marker in container for marker in ("docker", "containerd", "kubepods", "lxc")):
            virtualization_signals.append("container-cgroup")
        return {
            "distribution_id": release.get("ID", "unknown"),
            "distribution_name": release.get("PRETTY_NAME", release.get("NAME", "unknown")),
            "version_id": release.get("VERSION_ID", "unknown"),
            "id_like": release.get("ID_LIKE", ""),
            "package_managers_detected": managers,
            "virtualization_signals": sorted(set(virtualization_signals)),
        }

    def observations(self) -> list[str]:
        return [
            "Linux distribution metadata was read from /etc/os-release when available.",
            (
                "Package-manager names are capability signals, not an update or "
                "vulnerability assessment."
            ),
        ]
