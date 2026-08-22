"""Privacy-bounded support snapshot derived from validated desktop evidence."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .contracts import validate_companion_status, validate_status


def build_support_snapshot(
    status_payload: Any,
    companion_payload: Any,
    *,
    desktop_version: str,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Build a path-free support summary; reject evidence before summarising it."""

    if not isinstance(desktop_version, str) or not 1 <= len(desktop_version) <= 32:
        raise ValueError("desktop version must be a bounded string")
    status = validate_status(status_payload)
    companion = validate_companion_status(companion_payload)
    created = (generated_at or datetime.now(UTC)).astimezone(UTC)
    if created.utcoffset() is None:
        raise ValueError("support snapshot time must include a timezone")

    update = status.get("update_status")
    defender = companion["existing_primary_protection"]["defender"]
    health = companion.get("health") or {}
    last_record = health.get("last_record") or {}
    roots = last_record.get("roots") if isinstance(last_record, dict) else None
    protected_root_count = len(roots) if isinstance(roots, list) else 0

    return {
        "schema": "zsec.antivirus.support-snapshot.v1",
        "generated_at": created.isoformat().replace("+00:00", "Z"),
        "desktop_version": desktop_version,
        "privacy": {
            "file_paths_included": False,
            "quarantine_contents_included": False,
            "user_or_device_identifiers_included": False,
        },
        "scan": {
            "outcome": status["last_scan_outcome"],
            "findings": status["findings"],
            "observations": status["observations"],
            "errors": status["last_scan_errors"],
            "last_completed_at": status["last_scan"],
        },
        "intelligence": {
            "feed_state": status["feed"]["state"],
            "update_state": update["state"] if update is not None else "unavailable",
            "feed_sequence": update["feed_sequence"] if update is not None else None,
            "last_success_at": update["last_success_at"] if update is not None else None,
        },
        "recovery": {"quarantine_entries": status["quarantine_count"]},
        "automation": {
            "decision": companion["decision"],
            "healthy": companion["healthy"],
            "protected_root_count": protected_root_count,
            "heartbeat_fresh": health.get("fresh") if isinstance(health, dict) else None,
            "process_verified": (
                health.get("process_verified") if isinstance(health, dict) else None
            ),
        },
        "windows_protection": {
            "aggregate_health": companion["existing_primary_protection"]["aggregate_health"],
            "defender_confirmed_active": defender["confirmed_active"],
            "defender_baseline_confirmed": defender["baseline_features_confirmed"],
            "defender_signatures_current": defender["signatures_current"],
            "tamper_protection": defender["tamper_protection"],
            "reboot_required": defender["reboot_required"],
        },
        "boundary": {
            "zsec_primary_antivirus": False,
            "zsec_real_time_protection": False,
            "existing_provider_must_remain_active": True,
        },
    }


def save_support_snapshot(destination: Path, snapshot: dict[str, Any]) -> None:
    """Atomically save a locally generated snapshot to a user-selected path."""

    if snapshot.get("schema") != "zsec.antivirus.support-snapshot.v1":
        raise ValueError("support snapshot schema is invalid")
    target = destination.absolute()
    if target.suffix.casefold() != ".json":
        raise ValueError("support snapshot destination must end in .json")
    if not target.parent.is_dir():
        raise OSError("support snapshot destination directory does not exist")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".zsec-support-", suffix=".tmp", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(snapshot, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()


__all__ = ["build_support_snapshot", "save_support_snapshot"]
