from __future__ import annotations

import copy
import json
import os
import queue
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

GUI_ROOT = Path(__file__).resolve().parents[1] / "apps" / "windows-ui"
if str(GUI_ROOT) not in sys.path:
    sys.path.insert(0, str(GUI_ROOT))

from zsec_desktop.app import ZsecDesktop, scan_completion_notification  # noqa: E402
from zsec_desktop.bridge import BridgeError, CommandResult, ZsecBridge, discover_cli  # noqa: E402
from zsec_desktop.contracts import (  # noqa: E402
    ContractError,
    companion_presentation,
    status_presentation,
    update_presentation,
    validate_companion_status,
    validate_quarantine_list,
    validate_readiness,
    validate_recovery_drill,
    validate_scan_report,
    validate_status,
    validate_watch_event,
    validate_windows_protection_action,
    windows_cutover_presentation,
)


def valid_status() -> dict[str, object]:
    return {
        "schema": "zsec.shield.status.v2",
        "contract_version": 2,
        "version": "0.3.1",
        "generated_at": "2026-08-21T20:00:00Z",
        "platform": "windows",
        "definitions": "built-in:0.3.1;feed:absent",
        "last_scan": "2026-08-21T19:00:00Z",
        "findings": 0,
        "observations": 0,
        "last_scan_outcome": "no_configured_rule_matches",
        "last_scan_errors": 0,
        "last_scan_files_hashed": 1,
        "last_scan_bytes_hashed": 10,
        "last_scan_diagnostic": {"available": True, "error": None},
        "quarantine_count": 0,
        "scanner_mode": "on-demand",
        "content_worker": {
            "mode": "bounded_out_of_process_rules_and_review_providers",
            "path_disclosure": False,
            "broker_digest_verification": True,
            "reduced_privilege": False,
            "hostile_format_parser_gate_met": False,
        },
        "real_time_protection": False,
        "state_dir": r"C:\Users\example\AppData\Local\ZSEC\Shield",
        "built_in_rules": 2,
        "feed": {
            "state": "absent",
            "path": "current.json",
            "keyring_path": "trusted_keys.json",
            "sequence": None,
            "key_id": None,
            "rules_count": 0,
            "generated_at": None,
            "expires_at": None,
            "payload_sha256": None,
            "error": None,
        },
        "quarantine": {"entries": 0, "states": {}, "metadata_errors": []},
        "inventory": {},
    }


def valid_readiness() -> dict[str, object]:
    blockers = [
        {
            "id": "publisher_signed_release",
            "title": "Publisher-signed production release",
            "state": "not_met",
            "evidence_required": "Signed exact release evidence is required.",
        }
    ]
    return {
        "schema": "zero.security.replacement-readiness.v1",
        "decision": "keep_existing_protection",
        "eligible_for_primary_replacement": False,
        "existing_provider_must_remain_active": True,
        "automatic_uninstall_available": False,
        "manual_override_available": False,
        "blocking_gates": blockers,
        "gate_counts": {"met": 0, "not_met": 1, "total": 1},
    }


def valid_companion() -> dict[str, object]:
    return {
        "schema": "zsec.antivirus.windows-companion-status.v1",
        "primary_antivirus": False,
        "real_time_protection": False,
        "pre_access_enforcement": False,
        "existing_protection_must_remain_active": True,
        "primary_provider_uninstall_allowed": False,
        "cutover_allowed": False,
        "installed": False,
        "healthy": False,
        "decision": "not_installed",
        "reasons": ["installation marker is absent"],
        "existing_primary_protection": {
            "method": "WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_ANTIVIRUS)",
            "aggregate_health": "GOOD",
            "aggregate_good": True,
            "registered_products": [
                {
                    "display_name": "Example AV",
                    "product_state_raw": 397568,
                    "product_state_interpreted": False,
                    "instance_guid": "{00000000-0000-0000-0000-000000000001}",
                }
            ],
            "registration_inventory_complete": True,
            "registration_inventory_error": None,
            "security_services": [
                {"name": "WinDefend", "available": True, "status": "Stopped"},
                {"name": "WdNisSvc", "available": True, "status": "Stopped"},
                {"name": "MDCoreSvc", "available": True, "status": "Stopped"},
                {"name": "wscsvc", "available": True, "status": "Running"},
                {"name": "SecurityHealthService", "available": True, "status": "Running"},
            ],
            "defender": {
                "available": True,
                "source": "Get-MpComputerStatus",
                "antivirus_enabled": False,
                "real_time_protection_enabled": False,
                "antispyware_enabled": False,
                "service_enabled": False,
                "behavior_monitor_enabled": False,
                "ioav_protection_enabled": False,
                "on_access_protection_enabled": False,
                "network_inspection_enabled": False,
                "network_protection": {
                    "state": "disabled",
                    "raw_value": 0,
                    "source": "Get-MpPreference.EnableNetworkProtection",
                    "note": "Defender Network Protection is disabled.",
                },
                "tamper_protection": "enabled",
                "reboot_required": False,
                "signatures": {
                    "engine_version": "1.1.25080.5",
                    "product_version": "4.18.25080.5",
                    "antivirus_version": "1.437.1.0",
                    "antivirus_last_updated": "2026-08-22T05:00:00Z",
                    "antivirus_age_days": 0,
                    "defender_reports_out_of_date": False,
                },
                "scans": {
                    "quick_scan_age_days": 1,
                    "quick_scan_end": "2026-08-21T05:00:00Z",
                    "full_scan_age_days": 4,
                    "full_scan_end": "2026-08-18T05:00:00Z",
                },
                "confirmed_active": False,
                "baseline_features_confirmed": False,
                "signatures_current": True,
                "update_recommended": False,
                "note": "Defender is installed but not active.",
            },
        },
    }


def valid_healthy_companion() -> dict[str, object]:
    value = valid_companion()
    value.update(
        {
            "installed": True,
            "healthy": True,
            "decision": "healthy_companion",
            "reasons": [],
            "supervisor": {
                "registration_verified": True,
                "state": "registered_for_logon",
            },
            "integrity": {
                "cli_hash_verified": True,
                "runtime_hash_verified": True,
                "launcher_hash_verified": True,
            },
            "health": {
                "schema_valid": True,
                "fresh": True,
                "process_verified": True,
            },
        }
    )
    return value


def valid_baselining_companion() -> dict[str, object]:
    value = valid_healthy_companion()
    value.update(
        {
            "healthy": False,
            "decision": "baseline_in_progress",
            "reasons": ["initial protected-folder baseline is in progress"],
        }
    )
    value["health"]["last_record"] = {"operational_state": "baselining"}
    return value


def valid_metadata_inventory_companion() -> dict[str, object]:
    value = valid_healthy_companion()
    value.update(
        {
            "healthy": False,
            "decision": "metadata_inventory_in_progress",
            "reasons": ["initial protected-folder metadata inventory is in progress"],
        }
    )
    value["health"]["last_record"] = {"operational_state": "inventorying_metadata"}
    return value


def test_companion_refresh_never_supersedes_a_still_running_evidence_check() -> None:
    class FakeButton:
        def __init__(self) -> None:
            self.states: list[str] = []

        def configure(self, *, state: str) -> None:
            self.states.append(state)

    desktop = object.__new__(ZsecDesktop)
    desktop.companion_refresh_inflight = False
    desktop.companion_refresh_generation = 0
    buttons = [FakeButton(), FakeButton()]
    desktop.companion_refresh_buttons = buttons
    desktop.bridge = type("FakeBridge", (), {"companion_status": lambda self: None})()
    submissions: list[tuple[object, object, object]] = []
    desktop._run_async = lambda operation, success, failure: submissions.append(  # type: ignore[method-assign]
        (operation, success, failure)
    )

    assert desktop.refresh_companion() is True
    assert desktop.companion_refresh_generation == 1
    assert desktop.companion_refresh_inflight is True
    assert len(submissions) == 1
    assert all(button.states == ["disabled"] for button in buttons)

    assert desktop.refresh_companion() is False
    assert desktop.companion_refresh_generation == 1
    assert len(submissions) == 1
    assert desktop._finish_companion_refresh(0) is False
    assert desktop.companion_refresh_inflight is True

    assert desktop._finish_companion_refresh(1) is True
    assert desktop.companion_refresh_inflight is False
    assert all(button.states == ["disabled", "normal"] for button in buttons)


def test_worker_completion_queue_is_drained_without_cross_thread_tk_calls() -> None:
    class FakeRoot:
        def __init__(self) -> None:
            self.after_calls: list[tuple[int, object]] = []
            self.callback_errors: list[tuple[type[BaseException], BaseException]] = []

        def after(self, delay: int, callback: object) -> str:
            self.after_calls.append((delay, callback))
            return "next-drain"

        def report_callback_exception(
            self,
            error_type: type[BaseException],
            error: BaseException,
            traceback: object,
        ) -> None:
            del traceback
            self.callback_errors.append((error_type, error))

    desktop = object.__new__(ZsecDesktop)
    desktop.closing = False
    desktop.root = FakeRoot()
    desktop.ui_queue = queue.SimpleQueue()
    desktop.ui_queue_job = None
    delivered: list[tuple[str, int]] = []

    def broken_callback() -> None:
        raise ValueError("synthetic callback failure")

    desktop._post(broken_callback)
    desktop._post(lambda name, value: delivered.append((name, value)), "companion", 19)
    assert delivered == []
    assert desktop.root.after_calls == []

    desktop._drain_ui_queue()
    assert delivered == [("companion", 19)]
    assert desktop.ui_queue_job == "next-drain"
    assert desktop.root.after_calls == [(20, desktop._drain_ui_queue)]
    assert len(desktop.root.callback_errors) == 1
    assert desktop.root.callback_errors[0][0] is ValueError


def valid_recovery_drill() -> dict[str, object]:
    return {
        "schema": "zsec.antivirus.recovery-drill.v1",
        "product": "ZSEC Antivirus",
        "started_at": "2026-08-22T02:00:00Z",
        "completed_at": "2026-08-22T02:00:01Z",
        "passed": True,
        "scope": "isolated synthetic data only",
        "independent_certification": False,
        "checks": [
            {"id": check_id, "passed": True, "error": None}
            for check_id in (
                "encrypted_authenticated_copy",
                "authenticated_restore",
                "no_overwrite_restore",
                "ciphertext_tamper_rejected",
                "device_key_loss_and_recovery",
            )
        ],
        "summary": {"passed": 5, "failed": 0, "total": 5},
    }


def valid_windows_protection_action() -> dict[str, object]:
    return {
        "schema": "zsec.antivirus.windows-protection-action.v1",
        "product": "ZSEC Antivirus",
        "provider": "Microsoft Defender Antivirus",
        "action": "QuickScan",
        "started_at": "2026-08-22T05:00:00Z",
        "completed_at": "2026-08-22T05:01:00Z",
        "outcome": "completed",
        "provider_configuration_changed": False,
        "exclusions_changed": False,
        "security_center_registration_changed": False,
        "existing_provider_removed": False,
        "evidence": {
            "source": "Get-MpComputerStatus",
            "antivirus_enabled": True,
            "real_time_protection_enabled": True,
            "service_enabled": True,
            "behavior_monitor_enabled": True,
            "ioav_protection_enabled": True,
            "on_access_protection_enabled": True,
            "signature_version": "1.437.1.0",
            "signature_last_updated": "2026-08-22T05:00:00Z",
            "signatures_out_of_date": False,
            "quick_scan_end": "2026-08-22T05:01:00Z",
            "full_scan_end": None,
        },
        "error": None,
    }


def test_watch_contract_accepts_metadata_reconciliation_without_overclaiming() -> None:
    event = {
        "schema": "zsec.shield.watch-event.v1",
        "event": "reconciliation_completed",
        "session_id": str(uuid.uuid4()),
        "sequence": 2,
        "generated_at": "2026-08-22T03:00:00Z",
        "policy": {"real_time_protection": False, "pre_access_enforcement": False},
    }
    assert validate_watch_event(event)["event"] == "reconciliation_completed"

    event["policy"] = {"real_time_protection": True, "pre_access_enforcement": False}
    with pytest.raises(ContractError, match="real-time protection"):
        validate_watch_event(event)


def test_status_contract_never_turns_incomplete_or_inconsistent_evidence_green() -> None:
    status = validate_status(valid_status())
    presentation = status_presentation(status)
    assert presentation.state == "no_matches"
    assert "not proof" in presentation.detail

    incomplete = copy.deepcopy(status)
    incomplete["last_scan_outcome"] = "incomplete"
    incomplete["last_scan_errors"] = 1
    assert status_presentation(validate_status(incomplete)).state == "incomplete"

    review = copy.deepcopy(status)
    review["last_scan_outcome"] = "review_observations"
    review["observations"] = 3
    review_view = status_presentation(validate_status(review))
    assert review_view.state == "review"
    assert review_view.headline == "No malware rule matches"
    assert review_view.accent == "#26d9d1"
    assert "3 item(s)" in review_view.detail
    assert "not malware detections" in review_view.detail

    inconsistent = copy.deepcopy(status)
    inconsistent["findings"] = 1
    with pytest.raises(ContractError, match="inconsistent counters"):
        validate_status(inconsistent)

    overclaim = copy.deepcopy(status)
    overclaim["real_time_protection"] = True
    with pytest.raises(ContractError, match="real-time protection"):
        validate_status(overclaim)


def test_advisory_update_presentation_exposes_failures_retention_and_overdue_state() -> None:
    update = {
        "state": "current",
        "last_checked_at": "2026-08-24T08:00:00Z",
        "last_success_at": "2026-08-24T08:00:00Z",
        "next_check_at": "2026-08-25T08:00:00Z",
        "feed_sequence": 12,
        "feed_expires_at": "2026-09-01T08:00:00Z",
        "source": "https://talktoai.org/zsec/intelligence/v1/feed.json",
        "error": None,
    }
    status = valid_status()
    status["update_status"] = update
    validate_status(status)
    current = update_presentation(update, now=datetime(2026, 8, 24, 12, tzinfo=UTC))
    assert current.state == "current" and "creates no detection rule" in current.detail

    failed = dict(update, state="error", error="FeedError: offline")
    retained = update_presentation(failed, now=datetime(2026, 8, 24, 12, tzinfo=UTC))
    assert retained.state == "degraded_retained"
    assert "prior catalog retained" in retained.headline
    assert "offline" in retained.detail

    never_succeeded = update_presentation(
        dict(failed, last_success_at=None), now=datetime(2026, 8, 24, 12, tzinfo=UTC)
    )
    assert never_succeeded.state == "failed" and never_succeeded.accent == "red"

    overdue = update_presentation(update, now=datetime(2026, 8, 25, 11, 1, tzinfo=UTC))
    assert overdue.state == "overdue" and overdue.accent == "amber"

    unowned = copy.deepcopy(status)
    unowned["update_status"]["source"] = "https://example.invalid/feed.json"
    with pytest.raises(ContractError, match="release-owned"):
        validate_status(unowned)

    malformed_schedule = copy.deepcopy(status)
    malformed_schedule["update_status"]["next_check_at"] = "tomorrow"
    with pytest.raises(ContractError, match="UTC timestamp"):
        validate_status(malformed_schedule)


def test_scan_contract_keeps_review_observations_ineligible_for_quarantine() -> None:
    payload = {
        "schema": "zsec.shield.report.v1",
        "outcome": "review_observations",
        "policy": {
            "real_time_protection": False,
            "heuristic_observations_quarantine_eligible": False,
        },
        "scan": {
            "findings": [],
            "observations": [
                {
                    "path": r"C:\Users\example\Downloads\review.ps1",
                    "provider": "script",
                    "category": "download_execute_chain",
                    "severity": "high",
                    "summary": "Conservative review signal",
                    "evidence": {},
                    "quarantine_eligible": False,
                }
            ],
            "issues": [],
            "stats": {},
        },
        "quarantine": [],
    }
    validate_scan_report(payload)

    payload["scan"]["observations"][0]["quarantine_eligible"] = True  # type: ignore[index]
    with pytest.raises(ContractError, match="cannot authorize quarantine"):
        validate_scan_report(payload)


def test_replacement_and_companion_contracts_are_hard_interlocks() -> None:
    validate_readiness(valid_readiness())
    validate_companion_status(valid_companion())

    for field in (
        "eligible_for_primary_replacement",
        "automatic_uninstall_available",
        "manual_override_available",
    ):
        value = copy.deepcopy(valid_readiness())
        value[field] = True
        with pytest.raises(ContractError):
            validate_readiness(value)

    for field in ("primary_antivirus", "real_time_protection", "cutover_allowed"):
        value = copy.deepcopy(valid_companion())
        value[field] = True
        with pytest.raises(ContractError):
            validate_companion_status(value)


def test_companion_truth_table_rejects_false_green_decisions() -> None:
    healthy = validate_companion_status(valid_healthy_companion())
    assert companion_presentation(healthy).state == "healthy"

    baselining = validate_companion_status(valid_baselining_companion())
    baseline_view = companion_presentation(baselining)
    assert baseline_view.state == "baselining"
    assert baseline_view.accent == "cyan"
    assert baseline_view.headline == "Automatic protection is live"
    assert "one-time coverage inventory completes automatically" in baseline_view.detail
    assert baseline_view.detail.startswith("Windows antivirus protection")
    assert "Microsoft Defender" not in baseline_view.detail

    inventory = validate_companion_status(valid_metadata_inventory_companion())
    inventory_view = companion_presentation(inventory)
    assert inventory_view.state == "inventorying"
    assert inventory_view.accent == "cyan"
    assert inventory_view.headline == "Automatic protection is live"
    assert "metadata inventory completes automatically" in inventory_view.detail
    assert inventory_view.detail.startswith("Windows antivirus protection")

    degraded_with_defender = valid_companion()
    degraded_with_defender.update(
        {"decision": "degraded", "installed": True, "healthy": False}
    )
    degraded_view = companion_presentation(
        validate_companion_status(degraded_with_defender)
    )
    assert degraded_view.state == "degraded"
    assert degraded_view.accent == "amber"
    assert degraded_view.headline.startswith("Windows antivirus protection active")
    assert "Microsoft Defender" not in degraded_view.headline
    assert "ZSEC monitoring degraded" in degraded_view.headline
    assert "not currently verified" in degraded_view.detail

    stale_inventory = valid_metadata_inventory_companion()
    stale_inventory["decision"] = "degraded"
    stale_inventory["reasons"] = ["health heartbeat is stale or from the future"]
    stale_inventory["health"]["fresh"] = False
    stale_view = companion_presentation(validate_companion_status(stale_inventory))
    assert stale_view.state == "stale"
    assert stale_view.accent == "amber"
    assert "monitoring evidence stale" in stale_view.headline
    assert stale_view.headline != inventory_view.headline
    assert "fresh ZSEC monitoring heartbeat is not currently verified" in stale_view.detail

    restarted_inventory = valid_metadata_inventory_companion()
    restarted_inventory["decision"] = "degraded"
    restarted_inventory["reasons"] = [
        "heartbeat process is absent or does not match the configured CLI runtime"
    ]
    restarted_inventory["health"]["process_verified"] = False
    restarted_view = companion_presentation(validate_companion_status(restarted_inventory))
    assert restarted_view.state == "recovering"
    assert restarted_view.accent == "amber"
    assert "ZSEC monitoring restarting" in restarted_view.headline
    assert "verified ZSEC supervisor" in restarted_view.detail

    forged_inventory = valid_metadata_inventory_companion()
    forged_inventory["health"]["fresh"] = False
    with pytest.raises(ContractError, match="initializing companion lacks fresh"):
        validate_companion_status(forged_inventory)

    degraded_with_active_defender = copy.deepcopy(degraded_with_defender)
    active_defender = degraded_with_active_defender["existing_primary_protection"][  # type: ignore[index]
        "defender"
    ]
    for field in (
        "antivirus_enabled",
        "real_time_protection_enabled",
        "service_enabled",
        "behavior_monitor_enabled",
        "ioav_protection_enabled",
        "on_access_protection_enabled",
        "network_inspection_enabled",
    ):
        active_defender[field] = True  # type: ignore[index]
    active_defender["confirmed_active"] = True  # type: ignore[index]
    active_defender["baseline_features_confirmed"] = True  # type: ignore[index]
    defender_view = companion_presentation(
        validate_companion_status(degraded_with_active_defender)
    )
    assert defender_view.headline.startswith("Microsoft Defender protection active")

    degraded_without_verified_primary = copy.deepcopy(degraded_with_defender)
    degraded_without_verified_primary["existing_primary_protection"][
        "aggregate_good"
    ] = False
    red_view = companion_presentation(
        validate_companion_status(degraded_without_verified_primary)
    )
    assert red_view.state == "degraded"
    assert red_view.accent == "red"

    degraded_integrity_failure = copy.deepcopy(degraded_with_defender)
    degraded_integrity_failure["integrity"] = {
        "cli_hash_verified": True,
        "runtime_hash_verified": False,
        "launcher_hash_verified": True,
    }
    integrity_view = companion_presentation(degraded_integrity_failure)
    assert integrity_view.state == "degraded"
    assert integrity_view.accent == "red"


def test_scan_completion_notifications_use_user_copy_and_preserve_severity() -> None:
    assert scan_completion_notification(
        {"outcome": "no_configured_rule_matches", "findings": 0, "observations": 0}
    ) == "Scan complete — no malware rule matches."
    review = scan_completion_notification(
        {"outcome": "review_observations", "findings": 0, "observations": 2}
    )
    assert "2 items available for review" in review
    assert "Nothing was quarantined" in review
    detected = scan_completion_notification(
        {"outcome": "configured_rule_matches_detected", "findings": 1, "observations": 0}
    )
    assert detected.startswith("Action recommended — 1 malware rule match.")
    assert scan_completion_notification({"outcome": "incomplete"}).startswith(
        "Scan incomplete"
    )


def test_network_protection_posture_is_validated_without_changing_health() -> None:
    payload = valid_companion()
    validated = validate_companion_status(payload)
    assert validated["existing_primary_protection"]["defender"]["network_protection"][
        "state"
    ] == "disabled"

    for state, raw_value in (("active", 1), ("audit", 2), ("unavailable", None)):
        candidate = copy.deepcopy(payload)
        posture = candidate["existing_primary_protection"]["defender"][  # type: ignore[index]
            "network_protection"
        ]
        posture["state"] = state  # type: ignore[index]
        posture["raw_value"] = raw_value  # type: ignore[index]
        assert validate_companion_status(candidate)["decision"] == "not_installed"

    invalid = copy.deepcopy(payload)
    invalid["existing_primary_protection"]["defender"]["network_protection"][  # type: ignore[index]
        "raw_value"
    ] = 9
    with pytest.raises(ContractError, match="raw value"):
        validate_companion_status(invalid)

    contradictory_baseline = valid_baselining_companion()
    contradictory_baseline["integrity"]["runtime_hash_verified"] = False
    with pytest.raises(ContractError, match="initializing companion"):
        validate_companion_status(contradictory_baseline)

    for field, replacement in (
        ("installed", False),
        ("healthy", False),
    ):
        contradictory = valid_healthy_companion()
        contradictory[field] = replacement
        with pytest.raises(ContractError, match="healthy companion"):
            validate_companion_status(contradictory)

    aggregate = valid_healthy_companion()
    aggregate["existing_primary_protection"]["aggregate_good"] = False  # type: ignore[index]
    with pytest.raises(ContractError, match="required protection evidence"):
        validate_companion_status(aggregate)

    for section, field in (
        ("supervisor", "registration_verified"),
        ("integrity", "runtime_hash_verified"),
        ("health", "fresh"),
        ("health", "process_verified"),
    ):
        contradictory = valid_healthy_companion()
        contradictory[section][field] = False  # type: ignore[index]
        with pytest.raises(ContractError, match="healthy companion"):
            validate_companion_status(contradictory)

    not_installed = valid_companion()
    not_installed["installed"] = True
    with pytest.raises(ContractError, match="not_installed"):
        validate_companion_status(not_installed)

    degraded = valid_companion()
    degraded.update({"decision": "degraded", "installed": True, "healthy": True})
    with pytest.raises(ContractError, match="degraded"):
        validate_companion_status(degraded)


def test_companion_reasons_are_bounded_strings_before_ui_rendering() -> None:
    wrong_type = valid_companion()
    wrong_type["reasons"] = [{"headline": "forged"}]
    with pytest.raises(ContractError, match=r"reasons\[0\]"):
        validate_companion_status(wrong_type)

    oversized = valid_companion()
    oversized["reasons"] = ["x"] * 33
    with pytest.raises(ContractError, match="exceed their bound"):
        validate_companion_status(oversized)

    too_long = valid_companion()
    too_long["reasons"] = ["x" * 501]
    with pytest.raises(ContractError, match=r"reasons\[0\]"):
        validate_companion_status(too_long)


def test_watch_heartbeat_contract_exposes_incomplete_state() -> None:
    heartbeat = {
        "schema": "zsec.shield.watch-event.v1",
        "event": "health_heartbeat",
        "session_id": str(uuid.uuid4()),
        "sequence": 3,
        "generated_at": "2026-08-22T03:00:00Z",
        "backend_active": "native",
        "operational_incomplete": True,
        "policy": {"real_time_protection": False, "pre_access_enforcement": False},
    }
    assert validate_watch_event(heartbeat)["operational_incomplete"] is True
    heartbeat["backend_active"] = "unknown"
    with pytest.raises(ContractError, match="backend"):
        validate_watch_event(heartbeat)


def test_recovery_drill_contract_rejects_certification_and_counter_overclaims() -> None:
    validate_recovery_drill(valid_recovery_drill())

    certification = copy.deepcopy(valid_recovery_drill())
    certification["independent_certification"] = True
    with pytest.raises(ContractError, match="independent certification"):
        validate_recovery_drill(certification)

    inconsistent = copy.deepcopy(valid_recovery_drill())
    inconsistent["summary"]["passed"] = 0
    with pytest.raises(ContractError, match="summary is inconsistent"):
        validate_recovery_drill(inconsistent)

    missing_control = copy.deepcopy(valid_recovery_drill())
    missing_control["checks"].pop()
    missing_control["summary"] = {"passed": 4, "failed": 0, "total": 4}
    with pytest.raises(ContractError, match="exact v1 control set"):
        validate_recovery_drill(missing_control)


def test_windows_protection_action_is_fixed_bounded_and_non_mutating() -> None:
    payload = valid_windows_protection_action()
    assert validate_windows_protection_action(payload)["outcome"] == "completed"

    for field in (
        "provider_configuration_changed",
        "exclusions_changed",
        "security_center_registration_changed",
        "existing_provider_removed",
    ):
        mutated = copy.deepcopy(payload)
        mutated[field] = True
        with pytest.raises(ContractError, match=field):
            validate_windows_protection_action(mutated)

    failed = copy.deepcopy(payload)
    failed.update({"outcome": "failed", "evidence": None, "error": "Defender unavailable"})
    assert validate_windows_protection_action(failed)["outcome"] == "failed"

    contradictory = copy.deepcopy(failed)
    contradictory["error"] = None
    with pytest.raises(ContractError, match="contradictory"):
        validate_windows_protection_action(contradictory)


def test_windows_cutover_state_is_derived_from_provider_and_defender_evidence() -> None:
    blocked = validate_companion_status(valid_companion())
    blocked_view = windows_cutover_presentation(blocked)
    assert blocked_view.state == "blocked"
    assert "Defender real-time enforcement inactive" in blocked_view.detail

    eligible = valid_companion()
    existing = eligible["existing_primary_protection"]  # type: ignore[index]
    existing["registered_products"][0]["display_name"] = "Malwarebytes"  # type: ignore[index]
    defender = existing["defender"]  # type: ignore[index]
    defender.update(  # type: ignore[union-attr]
        {
            "antivirus_enabled": True,
            "real_time_protection_enabled": True,
            "service_enabled": True,
            "behavior_monitor_enabled": True,
            "ioav_protection_enabled": True,
            "on_access_protection_enabled": True,
            "network_inspection_enabled": True,
            "confirmed_active": True,
            "baseline_features_confirmed": True,
        }
    )
    eligible_view = windows_cutover_presentation(validate_companion_status(eligible))
    assert eligible_view.state == "eligible_operator_cutover"
    assert "Defender must remain" in eligible_view.detail

    verified = copy.deepcopy(eligible)
    verified["existing_primary_protection"]["registered_products"] = []  # type: ignore[index]
    verified_view = windows_cutover_presentation(validate_companion_status(verified))
    assert verified_view.state == "cutover_verified"


def test_missing_defender_signature_material_cannot_be_current() -> None:
    missing = valid_companion()
    defender = missing["existing_primary_protection"]["defender"]  # type: ignore[index]
    signatures = defender["signatures"]  # type: ignore[index]
    signatures["antivirus_version"] = None  # type: ignore[index]
    signatures["antivirus_last_updated"] = None  # type: ignore[index]
    defender["signatures_current"] = False  # type: ignore[index]
    defender["update_recommended"] = True  # type: ignore[index]
    validate_companion_status(missing)

    contradictory = copy.deepcopy(missing)
    contradictory["existing_primary_protection"]["defender"][  # type: ignore[index]
        "signatures_current"
    ] = True
    with pytest.raises(ContractError, match="signature summary"):
        validate_companion_status(contradictory)


def test_recovery_drill_bridge_binds_exit_code_to_validated_outcome(tmp_path: Path) -> None:
    bridge = _source_bridge(tmp_path / "state")
    payload = validate_recovery_drill(valid_recovery_drill())
    contradictory = CommandResult(("zsec-shield",), 2, payload, "")
    with (
        patch.object(bridge, "_run_json", return_value=contradictory),
        pytest.raises(BridgeError, match="exit code and validated outcome disagree"),
    ):
        bridge.recovery_drill()


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell path validation")
def test_windows_action_bridge_binds_exit_code_to_validated_outcome(tmp_path: Path) -> None:
    script = (
        Path(__file__).resolve().parents[1]
        / "windows"
        / "companion"
        / "Invoke-ZsecWindowsProtectionAction.ps1"
    )
    prefix = (sys.executable, "-m", "zsec_shield")
    with patch("zsec_desktop.bridge.discover_cli", return_value=prefix):
        bridge = ZsecBridge(
            state_dir=tmp_path / "state",
            windows_protection_action_script=script,
        )
    payload = validate_windows_protection_action(valid_windows_protection_action())
    contradictory = CommandResult(("powershell.exe",), 2, payload, "")
    with (
        patch.object(bridge, "_run_json", return_value=contradictory),
        pytest.raises(BridgeError, match="exit code and outcome disagree"),
    ):
        bridge.windows_protection_action("QuickScan")


def test_quarantine_contract_rejects_noncanonical_or_duplicate_entries() -> None:
    entry_id = str(uuid.uuid4())
    entry = {
        "id": entry_id,
        "state": "quarantined",
        "original_path": r"C:\Users\example\Downloads\fixture.bin",
        "sha256": "a" * 64,
    }
    payload = {
        "schema": "zsec.shield.quarantine-list.v1",
        "entries": [entry],
        "errors": [],
    }
    validate_quarantine_list(payload)

    duplicate = copy.deepcopy(payload)
    duplicate["entries"] = [entry, copy.deepcopy(entry)]
    with pytest.raises(ContractError, match="duplicate"):
        validate_quarantine_list(duplicate)

    malformed = copy.deepcopy(payload)
    malformed["entries"][0]["id"] = "../../outside"
    with pytest.raises(ContractError, match="canonical UUID"):
        validate_quarantine_list(malformed)


def _source_bridge(state_dir: Path) -> ZsecBridge:
    prefix = (sys.executable, "-m", "zsec_shield")
    with patch("zsec_desktop.bridge.discover_cli", return_value=prefix):
        return ZsecBridge(state_dir=state_dir)


def test_bridge_consumes_live_status_and_readiness_contracts_without_shell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = Path(__file__).resolve().parents[1] / "src"
    existing = os.environ.get("PYTHONPATH")
    pythonpath = str(source_root) if not existing else os.pathsep.join((str(source_root), existing))
    monkeypatch.setenv("PYTHONPATH", pythonpath)
    bridge = _source_bridge(tmp_path / "state")

    status = bridge.status()
    assert status.exit_code == 0
    assert status.payload["schema"] == "zsec.shield.status.v2"
    assert status.payload["real_time_protection"] is False

    readiness = bridge.replacement_readiness()
    assert readiness.exit_code == 2
    assert readiness.payload["decision"] == "keep_existing_protection"
    assert readiness.payload["automatic_uninstall_available"] is False

    recovery = bridge.recovery_drill()
    assert recovery.exit_code == 0
    assert recovery.payload["passed"] is True
    assert recovery.payload["independent_certification"] is False


def test_bridge_scan_writes_and_revalidates_only_bounded_local_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = Path(__file__).resolve().parents[1] / "src"
    existing = os.environ.get("PYTHONPATH")
    pythonpath = str(source_root) if not existing else os.pathsep.join((str(source_root), existing))
    monkeypatch.setenv("PYTHONPATH", pythonpath)
    state = tmp_path / "state"
    fixture = tmp_path / "benign.txt"
    fixture.write_text("bounded benign desktop GUI fixture", encoding="utf-8")
    bridge = _source_bridge(state)
    report_path = bridge.new_report_path()

    result = bridge.scan(
        [fixture],
        quarantine=False,
        max_file_bytes=1024 * 1024,
        report_path=report_path,
    )

    assert result.exit_code == 0
    assert result.payload["outcome"] == "no_configured_rule_matches"
    assert report_path.is_file()
    listed = bridge.list_reports()
    assert [value["path"] for value in listed] == [str(report_path)]
    assert bridge.read_report(report_path)["schema"] == "zsec.shield.report.v1"

    report_path.write_text(json.dumps({"schema": "future.unknown"}), encoding="utf-8")
    with pytest.raises(BridgeError, match="unsafe scan report"):
        bridge.read_report(report_path)


def test_bridge_has_no_remote_feed_or_provider_removal_surface(tmp_path: Path) -> None:
    public_methods = {name for name in dir(ZsecBridge) if not name.startswith("_")}
    assert "update_feed_file" in public_methods
    assert "windows_protection_action" in public_methods
    assert "update_feed_url" not in public_methods
    assert not any(
        "uninstall" in name or "disable" in name or "exclusion" in name for name in public_methods
    )
    bridge = _source_bridge(tmp_path / "state")
    with pytest.raises(BridgeError, match="unsupported Windows protection action"):
        bridge.windows_protection_action("DisableDefender")


@pytest.mark.skipif(os.name != "nt", reason="Windows packaged-layout discovery")
def test_packaged_gui_prefers_its_bundled_engine_over_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gui = tmp_path / "App" / "ZSEC Antivirus.exe"
    engine = tmp_path / "Engine" / "zsec-shield.exe"
    gui.parent.mkdir()
    engine.parent.mkdir()
    gui.write_bytes(b"gui")
    engine.write_bytes(b"engine")

    monkeypatch.setattr(sys, "executable", str(gui))
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.delenv("ZSEC_GUI_CLI", raising=False)

    assert discover_cli() == (str(engine.resolve()),)
