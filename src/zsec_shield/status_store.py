"""Small local summary used by the desktop status bridge."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from zsec_shield.errors import FeedError
from zsec_shield.util import atomic_write_json, strict_json_loads

LAST_SCAN_SCHEMA = "zsec.shield.last-scan.v2"
LEGACY_LAST_SCAN_SCHEMA = "zsec.shield.last-scan.v1"


def last_scan_path(state_dir: Path) -> Path:
    return state_dir / "status" / "last-scan.json"


def save_last_scan(
    state_dir: Path,
    *,
    completed_at: str,
    findings: int,
    issues: int,
    files_hashed: int,
    bytes_hashed: int,
    outcome: str,
) -> None:
    atomic_write_json(
        last_scan_path(state_dir),
        {
            "schema": LAST_SCAN_SCHEMA,
            "completed_at": completed_at,
            "findings": findings,
            "issues": issues,
            "files_hashed": files_hashed,
            "bytes_hashed": bytes_hashed,
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
    schema = value.get("schema")
    if schema == LEGACY_LAST_SCAN_SCHEMA:
        expected_fields = {"schema", "completed_at", "findings", "issues", "outcome"}
    elif schema == LAST_SCAN_SCHEMA:
        expected_fields = {
            "schema",
            "completed_at",
            "findings",
            "issues",
            "files_hashed",
            "bytes_hashed",
            "outcome",
        }
    else:
        return None, "last-scan summary schema is invalid"
    if set(value) != expected_fields:
        return None, "last-scan summary fields are invalid"
    findings = value.get("findings")
    issues = value.get("issues")
    files_hashed = value.get("files_hashed")
    bytes_hashed = value.get("bytes_hashed")
    counters: tuple[Any, ...] = (findings, issues)
    if schema == LAST_SCAN_SCHEMA:
        counters += (files_hashed, bytes_hashed)
    if any(
        isinstance(counter, bool) or not isinstance(counter, int) or counter < 0
        for counter in counters
    ):
        return None, "last-scan summary counters are invalid"
    completed_at = value.get("completed_at")
    outcome = value.get("outcome")
    if not isinstance(completed_at, str) or not completed_at:
        return None, "last-scan summary text fields are invalid"
    allowed_outcomes = {
        "no_configured_rule_matches",
        "configured_rule_matches_detected",
        "incomplete",
    }
    if not isinstance(outcome, str) or outcome not in allowed_outcomes:
        return None, "last-scan summary outcome is invalid"
    if outcome == "no_configured_rule_matches" and (findings != 0 or issues != 0):
        return None, "last-scan summary clean outcome is inconsistent"
    if outcome == "configured_rule_matches_detected" and (findings == 0 or issues != 0):
        return None, "last-scan summary finding outcome is inconsistent"
    if schema == LEGACY_LAST_SCAN_SCHEMA:
        value = {**value, "files_hashed": None, "bytes_hashed": None}
    return value, None
