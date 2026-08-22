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


RECOVERY_DRILL_CHECK_IDS = frozenset(
    {
        "encrypted_authenticated_copy",
        "authenticated_restore",
        "no_overwrite_restore",
        "ciphertext_tamper_rejected",
        "device_key_loss_and_recovery",
    }
)


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


@dataclass(frozen=True, slots=True)
class CompanionPresentation:
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
    worker = _object(root.get("content_worker"), "content_worker")
    if worker.get("mode") != "bounded_out_of_process_rules_and_review_providers":
        raise ContractError("status content_worker mode is unsupported")
    if _bool(worker.get("path_disclosure"), "content_worker.path_disclosure"):
        raise ContractError("content worker unexpectedly receives a source path")
    if not _bool(
        worker.get("broker_digest_verification"),
        "content_worker.broker_digest_verification",
    ):
        raise ContractError("content worker must retain broker digest verification")
    if _bool(worker.get("reduced_privilege"), "content_worker.reduced_privilege"):
        raise ContractError("this build cannot assert a reduced-privilege worker")
    if _bool(
        worker.get("hostile_format_parser_gate_met"),
        "content_worker.hostile_format_parser_gate_met",
    ):
        raise ContractError("this build cannot assert the hostile-parser gate")
    if _bool(root.get("real_time_protection"), "real_time_protection"):
        raise ContractError("desktop status unexpectedly asserts real-time protection")
    findings = _integer(root.get("findings"), "findings")
    observations = _integer(root.get("observations"), "observations")
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
        "review_observations",
        "incomplete",
    }:
        raise ContractError("last_scan_outcome is unknown")
    if available != (last_scan is not None):
        raise ContractError("last-scan availability and timestamp are inconsistent")
    if outcome == "no_configured_rule_matches" and (
        findings != 0 or observations != 0 or errors != 0
    ):
        raise ContractError("no-match outcome has inconsistent counters")
    if outcome == "configured_rule_matches_detected" and findings == 0:
        raise ContractError("finding outcome has a zero finding counter")
    if outcome == "review_observations" and (
        observations == 0 or findings != 0 or errors != 0
    ):
        raise ContractError("review-observation outcome has inconsistent counters")
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
    if outcome == "review_observations":
        return ScanPresentation(
            "review",
            "Review-only signals found",
            (
                f"{status['observations']} conservative user-mode observation(s); "
                "none authorized automatic quarantine."
            ),
            "#f59e0b",
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


def validate_recovery_drill(payload: Any) -> dict[str, Any]:
    root = _schema(payload, "zsec.antivirus.recovery-drill.v1")
    if root.get("product") != "ZSEC Antivirus":
        raise ContractError("recovery drill product identity is invalid")
    _string(root.get("started_at"), "started_at", maximum=80)
    _string(root.get("completed_at"), "completed_at", maximum=80)
    if root.get("scope") != "isolated synthetic data only":
        raise ContractError("recovery drill scope is not isolated synthetic data")
    if _bool(root.get("independent_certification"), "independent_certification"):
        raise ContractError("local recovery drill cannot assert independent certification")
    passed = _bool(root.get("passed"), "passed")
    checks = _list(root.get("checks"), "checks")
    if not checks or len(checks) > 32:
        raise ContractError("recovery drill check count is invalid")
    seen: set[str] = set()
    passed_count = 0
    for index, value in enumerate(checks):
        check = _object(value, f"checks[{index}]")
        check_id = _string(check.get("id"), f"checks[{index}].id", maximum=100)
        if check_id in seen:
            raise ContractError("recovery drill check identifiers must be unique")
        seen.add(check_id)
        check_passed = _bool(check.get("passed"), f"checks[{index}].passed")
        error = check.get("error")
        if check_passed:
            passed_count += 1
            if error is not None:
                raise ContractError("passing recovery drill check cannot contain an error")
        else:
            _string(error, f"checks[{index}].error", maximum=2000)
    if seen != RECOVERY_DRILL_CHECK_IDS:
        raise ContractError("recovery drill does not contain the exact v1 control set")
    summary = _object(root.get("summary"), "summary")
    failed_count = len(checks) - passed_count
    if (
        _integer(summary.get("passed"), "summary.passed") != passed_count
        or _integer(summary.get("failed"), "summary.failed") != failed_count
        or _integer(summary.get("total"), "summary.total") != len(checks)
        or passed != (failed_count == 0)
    ):
        raise ContractError("recovery drill summary is inconsistent")
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
        "review_observations",
        "incomplete",
    }:
        raise ContractError("scan outcome is unknown")
    policy = _object(root.get("policy"), "policy")
    if _bool(policy.get("real_time_protection"), "policy.real_time_protection"):
        raise ContractError("on-demand report unexpectedly asserts real-time protection")
    if "heuristic_observations_quarantine_eligible" in policy and _bool(
        policy["heuristic_observations_quarantine_eligible"],
        "policy.heuristic_observations_quarantine_eligible",
    ):
        raise ContractError("review providers unexpectedly authorize quarantine")
    scan = _object(root.get("scan"), "scan")
    _list(scan.get("findings"), "scan.findings")
    observations = _list(scan.get("observations"), "scan.observations")
    for index, observation_value in enumerate(observations):
        observation = _object(observation_value, f"scan.observations[{index}]")
        _string(observation.get("path"), f"scan.observations[{index}].path", maximum=32768)
        _string(observation.get("provider"), f"scan.observations[{index}].provider", maximum=40)
        _string(observation.get("category"), f"scan.observations[{index}].category", maximum=80)
        if observation.get("severity") not in {"info", "low", "medium", "high", "critical"}:
            raise ContractError(f"scan.observations[{index}].severity is invalid")
        _string(observation.get("summary"), f"scan.observations[{index}].summary", maximum=300)
        _object(observation.get("evidence"), f"scan.observations[{index}].evidence")
        if _bool(
            observation.get("quarantine_eligible"),
            f"scan.observations[{index}].quarantine_eligible",
        ):
            raise ContractError("review-only observation cannot authorize quarantine")
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
    installed = _bool(root.get("installed"), "installed")
    healthy = _bool(root.get("healthy"), "healthy")
    decision = root.get("decision")
    if decision not in {"not_installed", "degraded", "healthy_companion"}:
        raise ContractError("companion decision is unknown")
    _list(root.get("reasons"), "reasons")
    existing = _object(root.get("existing_primary_protection"), "existing_primary_protection")
    aggregate_good = _bool(
        existing.get("aggregate_good"),
        "existing_primary_protection.aggregate_good",
    )

    if decision == "not_installed":
        if installed or healthy:
            raise ContractError(
                "not_installed companion decision contradicts installed/healthy state"
            )
    elif decision == "degraded":
        if healthy:
            raise ContractError("degraded companion decision contradicts healthy state")
    else:
        if not installed or not healthy or not aggregate_good:
            raise ContractError("healthy companion decision lacks required protection evidence")
        supervisor = _object(root.get("supervisor"), "supervisor")
        if not _bool(supervisor.get("registration_verified"), "supervisor.registration_verified"):
            raise ContractError("healthy companion supervisor registration is unverified")
        if supervisor.get("state") not in {"registered_for_logon", "registered_and_running"}:
            raise ContractError("healthy companion supervisor state is unsupported")
        integrity = _object(root.get("integrity"), "integrity")
        for field in ("cli_hash_verified", "runtime_hash_verified", "launcher_hash_verified"):
            if not _bool(integrity.get(field), f"integrity.{field}"):
                raise ContractError(f"healthy companion lacks {field}")
        health = _object(root.get("health"), "health")
        for field in ("schema_valid", "fresh", "process_verified"):
            if not _bool(health.get(field), f"health.{field}"):
                raise ContractError(f"healthy companion lacks {field}")
    return root


def companion_presentation(payload: dict[str, Any]) -> CompanionPresentation:
    decision = payload["decision"]
    if decision == "healthy_companion":
        return CompanionPresentation(
            state="healthy",
            headline="Automatic companion active",
            detail=(
                "Verified process, hashes, heartbeat, logon supervisor and existing "
                "antivirus health."
            ),
            accent="green",
        )
    if decision == "not_installed":
        return CompanionPresentation(
            state="not_installed",
            headline="Automatic companion not installed",
            detail="Existing Windows antivirus remains required.",
            accent="amber",
        )
    reasons = "; ".join(str(value) for value in payload["reasons"][:3])
    return CompanionPresentation(
        state="degraded",
        headline="Automatic companion degraded",
        detail=reasons or "Protection evidence is incomplete.",
        accent="red",
    )


def validate_watch_event(payload: Any) -> dict[str, Any]:
    root = _schema(payload, "zsec.shield.watch-event.v1")
    if root.get("event") not in {
        "session_started",
        "backend_fallback",
        "scan_completed",
        "reconciliation_completed",
        "health_issue",
        "health_heartbeat",
        "session_completed",
    }:
        raise ContractError("watch event is unknown")
    _string(root.get("session_id"), "session_id", maximum=80)
    _integer(root.get("sequence"), "sequence", minimum=1)
    generated_at = _string(root.get("generated_at"), "generated_at", maximum=80)
    if not generated_at.endswith("Z") or "T" not in generated_at:
        raise ContractError("watch event generated_at must be a UTC timestamp")
    if root.get("event") == "health_heartbeat":
        if root.get("backend_active") not in {"native", "polling"}:
            raise ContractError("watch heartbeat backend is unsupported")
        _bool(root.get("operational_incomplete"), "operational_incomplete")
    policy = root.get("policy")
    if policy is not None:
        policy_object = _object(policy, "policy")
        if _bool(policy_object.get("real_time_protection"), "policy.real_time_protection"):
            raise ContractError("watch event unexpectedly asserts real-time protection")
        if _bool(policy_object.get("pre_access_enforcement"), "policy.pre_access_enforcement"):
            raise ContractError("watch event unexpectedly asserts pre-access enforcement")
    return root


__all__ = [
    "CompanionPresentation",
    "ContractError",
    "ScanPresentation",
    "companion_presentation",
    "status_presentation",
    "validate_companion_status",
    "validate_feed_update",
    "validate_quarantine_list",
    "validate_readiness",
    "validate_scan_report",
    "validate_status",
    "validate_watch_event",
]
