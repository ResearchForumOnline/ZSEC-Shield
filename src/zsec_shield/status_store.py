"""Small local summary used by the desktop status bridge."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from zsec_shield.errors import FeedError
from zsec_shield.util import atomic_write_json, strict_json_loads

LAST_SCAN_SCHEMA = "zsec.shield.last-scan.v1"


def last_scan_path(state_dir: Path) -> Path:
    return state_dir / "status" / "last-scan.json"


def save_last_scan(
    state_dir: Path,
    *,
    completed_at: str,
    findings: int,
    issues: int,
    outcome: str,
) -> None:
    atomic_write_json(
        last_scan_path(state_dir),
        {
            "schema": LAST_SCAN_SCHEMA,
            "completed_at": completed_at,
            "findings": findings,
            "issues": issues,
            "outcome": outcome,
        },
        mode=0o600,
    )


def load_last_scan(state_dir: Path) -> tuple[dict[str, Any] | None, str | None]:
    path = last_scan_path(state_dir)
    if not path.exists():
        return None, None
    try:
        if path.stat().st_size > 32 * 1024:
            return None, "last-scan summary is unexpectedly large"
        value = strict_json_loads(path.read_bytes())
    except (OSError, FeedError) as exc:
        return None, f"cannot read last-scan summary: {exc}"
    if not isinstance(value, dict):
        return None, "last-scan summary is not an object"
    if set(value) != {"schema", "completed_at", "findings", "issues", "outcome"}:
        return None, "last-scan summary fields are invalid"
    if value.get("schema") != LAST_SCAN_SCHEMA:
        return None, "last-scan summary schema is invalid"
    findings = value.get("findings")
    issues = value.get("issues")
    if (
        isinstance(findings, bool)
        or not isinstance(findings, int)
        or findings < 0
        or isinstance(issues, bool)
        or not isinstance(issues, int)
        or issues < 0
    ):
        return None, "last-scan summary counters are invalid"
    if not isinstance(value.get("completed_at"), str) or not isinstance(value.get("outcome"), str):
        return None, "last-scan summary text fields are invalid"
    return value, None
