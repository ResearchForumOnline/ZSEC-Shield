"""Strict consumer validation for the ZSEC Antivirus desktop CLI contracts.

The desktop must not turn malformed, incomplete, or future/unknown payloads
into a green state. These validators are intentionally narrower than a JSON
Schema library so the source client adds no runtime dependency.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, TypeGuard


class ContractError(ValueError):
    """A CLI payload cannot safely be rendered by this desktop version."""


def _is_object(value: Any) -> TypeGuard[dict[str, Any]]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


def _object(value: Any, field: str) -> dict[str, Any]:
    if not _is_object(value):
        raise ContractError(f"{field} must be an object")
    return value


def _list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise ContractError(f"{field} must be an array")
    return value


def _string(value: Any, field: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ContractError(f"{field} must be a non-empty bounded string")
    return value


def _optional_string(value: Any, field: str, *, maximum: int = 4096) -> str | None:
    if value is None:
        return None
    return _string(value, field, maximum=maximum)


def _bool(value: Any, field: str) -> bool:
    if type(value) is not bool:
        raise ContractError(f"{field} must be a boolean")
    return value


def _integer(value: Any, field: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ContractError(f"{field} must be an integer >= {minimum}")
    return value


def _schema(payload: Any, expected: str) -> dict[str, Any]:
    root = _object(payload, "payload")
    if root.get("schema") != expected:
        raise ContractError(f"unsupported schema; expected {expected}")
    return root


@dataclass(frozen=True, slots=True)
class ScanPresentation:
    state: str
    headline: str
    detail: str
    accent: str


def validate_status(payload: Any) -> dict[str, Any]:
    root = _schema(payload, "zsec.shield.status.v2")
    if root.get("contract_version") != 2:
        raise ContractError("unsupported status contract_version")
    _string(root.get("version"), "version", maximum=80)
    _string(root.get("generated_at"), "generated_at", maximum=80)
    _string(root.get("platform"), "platform", maximum=80)
    if root.get("scanner_mode") != "on-demand":
        raise ContractError("status scanner_mode is inconsistent with this desktop build")
    if _bool(root.get("real_time_protection"), "real_time_protection"):
        raise ContractError("desktop status unexpectedly asserts real-time protection")
    findings = _integer(root.get("findings"), "findings")
    errors = _integer(root.get("last_scan_errors"), "last_scan_errors")
    diagnostic = _object(root.get("last_scan_diagnostic"), "last_scan_diagnostic")
    available = _bool(diagnostic.get("available"), "last_scan_diagnostic.available")
    diagnostic_error = _optional_string(
        diagnostic.get("error"), "last_scan_diagnostic.error", maximum=1000
    )
    last_scan = root.get("last_scan")
    if last_scan is not None:
        _string(last_scan, "last_scan", maximum=80)
    outcome = root.get("last_scan_outcome")
    if outcome not in {
        None,
        "no_configured_rule_matches",
        "configured_rule_matches_detected",
        "incomplete",
    }:
        raise ContractError("last_scan_outcome is unknown")
    if available != (last_scan is not None):
        raise ContractError("last-scan availability and timestamp are inconsistent")
    if outcome == "no_configured_rule_matches" and (findings != 0 or errors != 0):
        raise ContractError("no-match outcome has inconsistent counters")
    if outcome == "configured_rule_matches_detected" and findings == 0:
        raise ContractError("finding outcome has a zero finding counter")
    if diagnostic_error is not None and available:
        raise ContractError("validated last-scan state cannot also have a diagnostic error")
    feed = _object(root.get("feed"), "feed")
    if feed.get("state") not in {"absent", "valid", "invalid"}:
        raise ContractError("feed.state is unknown")
    _integer(root.get("quarantine_count"), "quarantine_count")
    quarantine = _object(root.get("quarantine"), "quarantine")
    if _integer(quarantine.get("entries"), "quarantine.entries") != root["quarantine_count"]:
        raise ContractError("quarantine counters are inconsistent")
    _list(quarantine.get("metadata_errors"), "quarantine.metadata_errors")
    return root


def status_presentation(status: Mapping[str, Any]) -> ScanPresentation:
    diagnostic = status["last_scan_diagnostic"]
    outcome = status["last_scan_outcome"]
    if diagnostic["error"] is not None:
        return ScanPresentation(
            "unavailable", "Scan evidence unavailable", str(diagnostic["error"]), "#ef4444"
        )
    if not diagnostic["available"] or status["last_scan"] is None:
        return ScanPresentation(
            "not_run",
            "No completed scan",
            "Run an on-demand scan to create local evidence.",
            "#f59e0b",
        )
    if outcome == "incomplete":
        return ScanPresentation(
            "incomplete",
            "Last scan incomplete",
            f"{status['last_scan_errors']} issue(s) prevented a complete result.",
            "#ef4444",
        )
    if outcome == "configured_rule_matches_detected":
        return ScanPresentation(
            "matches",
            "Configured rules matched",
            f"{status['findings']} file finding(s) require review.",
            "#ef4444",
        )
    if outcome == "no_configured_rule_matches":
        return ScanPresentation(
            "no_matches",
            "No configured rule matches",
            "This completed scan is not proof that the computer is clean.",
            "#22c55e",
        )
    return ScanPresentation(
        "unknown", "Scan state unavailable", "The last-scan outcome is unavailable.", "#f59e0b"
    )


def validate_readiness(payload: Any) -> dict[str, Any]:
    root = _schema(payload, "zero.security.replacement-readiness.v1")
    if root.get("decision") != "keep_existing_protection":
        raise ContractError("this desktop build only supports the blocking readiness decision")
    if _bool(root.get("eligible_for_primary_replacement"), "eligible_for_primary_replacement"):
        raise ContractError("desktop build cannot assert primary-replacement eligibility")
    if not _bool(
        root.get("existing_provider_must_remain_active"), "existing_provider_must_remain_active"
    ):
        raise ContractError("desktop build must require the existing provider")
    if _bool(root.get("automatic_uninstall_available"), "automatic_uninstall_available"):
        raise ContractError("desktop build cannot expose automatic antivirus uninstall")
    if _bool(root.get("manual_override_available"), "manual_override_available"):
        raise ContractError("desktop build cannot expose a replacement override")
    blockers = _list(root.get("blocking_gates"), "blocking_gates")
    seen: set[str] = set()
    for index, value in enumerate(blockers):
        gate = _object(value, f"blocking_gates[{index}]")
        gate_id = _string(gate.get("id"), f"blocking_gates[{index}].id", maximum=100)
        if gate_id in seen:
            raise ContractError("replacement blocker identifiers must be unique")
        seen.add(gate_id)
        _string(gate.get("title"), f"blocking_gates[{index}].title", maximum=200)
        if gate.get("state") != "not_met":
            raise ContractError("a replacement blocker unexpectedly claims to be met")
        _string(
            gate.get("evidence_required"),
            f"blocking_gates[{index}].evidence_required",
            maximum=2000,
        )
    counts = _object(root.get("gate_counts"), "gate_counts")
    if (
        _integer(counts.get("met"), "gate_counts.met") != 0
        or _integer(counts.get("not_met"), "gate_counts.not_met") != len(blockers)
        or _integer(counts.get("total"), "gate_counts.total") != len(blockers)
    ):
        raise ContractError("replacement gate counters are inconsistent")
    return root


def validate_quarantine_list(payload: Any) -> dict[str, Any]:
    root = _schema(payload, "zsec.shield.quarantine-list.v1")
    entries = _list(root.get("entries"), "entries")
    _list(root.get("errors"), "errors")
    seen: set[str] = set()
    for index, value in enumerate(entries):
        entry = _object(value, f"entries[{index}]")
        entry_id = _string(entry.get("id"), f"entries[{index}].id", maximum=40)
        try:
            if str(uuid.UUID(entry_id)) != entry_id.lower():
                raise ValueError
        except ValueError as exc:
            raise ContractError(f"entries[{index}].id is not a canonical UUID") from exc
        if entry_id in seen:
            raise ContractError("duplicate quarantine entry identifier")
        seen.add(entry_id)
        if entry.get("state") not in {"quarantined", "copy_only", "restored"}:
            raise ContractError(f"entries[{index}].state is unknown")
        _string(entry.get("original_path"), f"entries[{index}].original_path", maximum=32768)
        digest = _string(entry.get("sha256"), f"entries[{index}].sha256", maximum=64)
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ContractError(f"entries[{index}].sha256 is invalid")
    return root


def validate_scan_report(payload: Any) -> dict[str, Any]:
    root = _schema(payload, "zsec.shield.report.v1")
    if root.get("outcome") not in {
        "no_configured_rule_matches",
        "configured_rule_matches_detected",
        "incomplete",
    }:
        raise ContractError("scan outcome is unknown")
    policy = _object(root.get("policy"), "policy")
    if _bool(policy.get("real_time_protection"), "policy.real_time_protection"):
        raise ContractError("on-demand report unexpectedly asserts real-time protection")
    scan = _object(root.get("scan"), "scan")
    _list(scan.get("findings"), "scan.findings")
    _list(scan.get("issues"), "scan.issues")
    _object(scan.get("stats"), "scan.stats")
    _list(root.get("quarantine"), "quarantine")
    return root


def validate_feed_update(payload: Any) -> dict[str, Any]:
    root = _schema(payload, "zsec.shield.update-result.v1")
    if root.get("outcome") not in {"installed", "unchanged"}:
        raise ContractError("feed update outcome is unknown")
    _integer(root.get("sequence"), "sequence", minimum=1)
    _integer(root.get("rules_count"), "rules_count")
    digest = _string(root.get("payload_sha256"), "payload_sha256", maximum=64)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ContractError("feed payload digest is invalid")
    if root.get("policy") != "signed data-only rules; no command fields are accepted":
        raise ContractError("feed update policy is inconsistent")
    return root


def validate_companion_status(payload: Any) -> dict[str, Any]:
    root = _schema(payload, "zsec.antivirus.windows-companion-status.v1")
    for field in ("primary_antivirus", "real_time_protection", "pre_access_enforcement"):
        if _bool(root.get(field), field):
            raise ContractError(f"companion unexpectedly asserts {field}")
    if not _bool(
        root.get("existing_protection_must_remain_active"),
        "existing_protection_must_remain_active",
    ):
        raise ContractError("companion must preserve existing protection")
    if _bool(root.get("primary_provider_uninstall_allowed"), "primary_provider_uninstall_allowed"):
        raise ContractError("companion cannot authorize provider uninstall")
    if _bool(root.get("cutover_allowed"), "cutover_allowed"):
        raise ContractError("companion cannot authorize cutover")
    _bool(root.get("installed"), "installed")
    _bool(root.get("healthy"), "healthy")
    if root.get("decision") not in {"not_installed", "degraded", "healthy_companion"}:
        raise ContractError("companion decision is unknown")
    _list(root.get("reasons"), "reasons")
    _object(root.get("existing_primary_protection"), "existing_primary_protection")
    return root


def validate_watch_event(payload: Any) -> dict[str, Any]:
    root = _schema(payload, "zsec.shield.watch-event.v1")
    if root.get("event") not in {
        "session_started",
        "backend_fallback",
        "scan_completed",
        "health_issue",
        "health_heartbeat",
        "session_completed",
    }:
        raise ContractError("watch event is unknown")
    _string(root.get("session_id"), "session_id", maximum=80)
    _integer(root.get("sequence"), "sequence", minimum=1)
    policy = root.get("policy")
    if policy is not None:
        policy_object = _object(policy, "policy")
        if _bool(policy_object.get("real_time_protection"), "policy.real_time_protection"):
            raise ContractError("watch event unexpectedly asserts real-time protection")
        if _bool(policy_object.get("pre_access_enforcement"), "policy.pre_access_enforcement"):
            raise ContractError("watch event unexpectedly asserts pre-access enforcement")
    return root


__all__ = [
    "ContractError",
    "ScanPresentation",
    "status_presentation",
    "validate_companion_status",
    "validate_feed_update",
    "validate_quarantine_list",
    "validate_readiness",
    "validate_scan_report",
    "validate_status",
    "validate_watch_event",
]
