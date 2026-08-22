from __future__ import annotations

import copy
import json
import os
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

GUI_ROOT = Path(__file__).resolve().parents[1] / "apps" / "windows-ui"
if str(GUI_ROOT) not in sys.path:
    sys.path.insert(0, str(GUI_ROOT))

from zsec_desktop.bridge import BridgeError, CommandResult, ZsecBridge, discover_cli  # noqa: E402
from zsec_desktop.contracts import (  # noqa: E402
    ContractError,
    companion_presentation,
    status_presentation,
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

    inconsistent = copy.deepcopy(status)
    inconsistent["findings"] = 1
    with pytest.raises(ContractError, match="inconsistent counters"):
        validate_status(inconsistent)

    overclaim = copy.deepcopy(status)
    overclaim["real_time_protection"] = True
    with pytest.raises(ContractError, match="real-time protection"):
        validate_status(overclaim)


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

    contradictory_baseline = valid_baselining_companion()
    contradictory_baseline["integrity"]["runtime_hash_verified"] = False
    with pytest.raises(ContractError, match="baseline companion"):
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
