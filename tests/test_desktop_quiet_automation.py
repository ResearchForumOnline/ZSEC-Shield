from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

GUI_ROOT = Path(__file__).resolve().parents[1] / "apps" / "windows-ui"
if str(GUI_ROOT) not in sys.path:
    sys.path.insert(0, str(GUI_ROOT))

from zsec_desktop.app import (  # noqa: E402
    CYAN,
    ZsecDesktop,
    scan_requires_notification,
    threat_notice_category,
)
from zsec_desktop.contracts import ContractError, validate_watch_event  # noqa: E402


@pytest.mark.parametrize("outcome", ["no_configured_rule_matches", "review_observations"])
def test_routine_scan_results_stay_in_history(outcome: str) -> None:
    assert scan_requires_notification({"outcome": outcome}) is False


@pytest.mark.parametrize("outcome", ["configured_rule_matches_detected", "incomplete"])
def test_threat_and_failed_scan_results_still_notify(outcome: str) -> None:
    assert scan_requires_notification({"outcome": outcome}) is True


def quiet_desktop() -> ZsecDesktop:
    desktop = object.__new__(ZsecDesktop)
    desktop.monitoring_health_issue_since = None
    desktop.monitoring_notice_times = {}
    desktop.tray = MagicMock()
    return desktop


def test_folder_limitations_never_interrupt_even_after_prolonged_failures() -> None:
    desktop = quiet_desktop()
    with patch("zsec_desktop.app.time.monotonic", side_effect=[100, 399, 400, 401, 2200]):
        desktop._monitoring_notice("Check folder access")
        desktop._monitoring_notice("Check folder access")
        desktop.tray.notify.assert_not_called()
        desktop._monitoring_notice("Check folder access")
        desktop._monitoring_notice("Check folder access")
        desktop.tray.notify.assert_not_called()
        desktop._monitoring_notice("Check folder access")
        desktop.tray.notify.assert_not_called()


@pytest.mark.parametrize("category", ["findings", "integrity", "windows", "scan"])
def test_threat_security_fault_and_scan_failure_notify_immediately_once(category: str) -> None:
    desktop = quiet_desktop()
    with patch("zsec_desktop.app.time.monotonic", side_effect=[100, 101]):
        desktop._monitoring_notice("Action needed", category=category)
        desktop._monitoring_notice("Action needed", category=category)
    desktop.tray.notify.assert_called_once_with("Action needed")


def test_healthy_monitor_heartbeat_clears_transient_failure_but_retains_threats() -> None:
    desktop = quiet_desktop()
    desktop.store_managed = False
    desktop.watch_session_id = "test-session"
    desktop.watch_last_sequence = 1
    desktop.watch_findings_pending = True
    desktop.watch_inventory_complete = True
    desktop.monitoring_health_issue_since = 100
    desktop.watch_state_label = MagicMock()
    desktop.watch_events = MagicMock()
    desktop.watch_events.size.return_value = 1
    desktop._animate_activity = MagicMock()
    desktop._watch_event({
        "event": "health_heartbeat", "session_id": "test-session", "sequence": 2,
        "operational_incomplete": False,
    })
    assert desktop.monitoring_health_issue_since is None
    assert desktop.watch_findings_pending is True
    assert desktop.watch_coverage_complete is True


def test_closing_to_tray_does_not_create_routine_balloon() -> None:
    desktop = quiet_desktop()
    desktop.root = MagicMock()
    desktop.close_to_tray = MagicMock()
    desktop.close_to_tray.get.return_value = True
    desktop.tray.active = True
    desktop._window_close()
    desktop.root.withdraw.assert_called_once()
    desktop.tray.notify.assert_not_called()


def test_new_threat_evidence_is_not_suppressed_by_previous_notification() -> None:
    first = {"findings": [{"path": "first.exe", "rule_id": "hash-match", "sha256": "a"}]}
    second = {"findings": [{"path": "second.exe", "rule_id": "hash-match", "sha256": "b"}]}
    desktop = quiet_desktop()
    with patch("zsec_desktop.app.time.monotonic", side_effect=[100, 101, 102]):
        desktop._monitoring_notice("Rule match", category=threat_notice_category(first))
        desktop._monitoring_notice("Rule match", category=threat_notice_category(first))
        desktop._monitoring_notice("Rule match", category=threat_notice_category(second))
    assert desktop.tray.notify.call_count == 2


def test_partial_live_observer_stays_quiet_and_refresh_cannot_change_its_status() -> None:
    desktop = quiet_desktop()
    desktop.store_managed = True
    desktop.watch_session = MagicMock()
    desktop.watch_session_id = "test-session"
    desktop.watch_last_sequence = 0
    desktop.watch_findings_pending = False
    desktop.watch_inventory_complete = False
    desktop.protected_roots = ()
    desktop.watch_state_label = MagicMock()
    desktop.watch_events = MagicMock()
    desktop.watch_events.size.return_value = 1
    desktop._animate_activity = MagicMock()
    desktop._render_windows_protection = MagicMock()
    desktop._update_tray_status = MagicMock()
    desktop.companion_card = MagicMock()
    desktop.companion_status_label = MagicMock()
    desktop.protection_layer_labels = {"zsec": MagicMock(), "scope": MagicMock()}
    desktop.protected_roots_label = MagicMock()
    desktop.scan_protected_button = MagicMock()
    with patch("zsec_desktop.app.time.monotonic", return_value=100_000):
        desktop._watch_event({
            "event": "health_heartbeat", "session_id": "test-session", "sequence": 1,
            "operational_incomplete": True,
        })
        first = desktop.companion_card.set_value.call_args
        desktop._render_store_process_monitor({})
    assert desktop.companion_card.set_value.call_args == first
    assert first.args == ("Automatic folder checks running", CYAN)
    desktop.tray.notify.assert_not_called()
    assert desktop.watch_coverage_complete is False
    assert "Complete coverage is not verified" in (
        desktop.companion_status_label.configure.call_args.kwargs["text"]
    )


@pytest.mark.parametrize("authoritative_inventory, incomplete", [
    (False, False), (True, False), (True, True),
])
def test_only_authoritative_inventory_recovery_restores_initial_coverage(
    authoritative_inventory: bool,
    incomplete: bool,
) -> None:
    desktop = quiet_desktop()
    desktop.store_managed = False
    desktop.watch_session_id = "test-session"
    desktop.watch_last_sequence = 0
    desktop.watch_findings_pending = False
    desktop.watch_inventory_complete = False
    desktop.watch_state_label = MagicMock()
    desktop.watch_events = MagicMock()
    desktop.watch_events.size.return_value = 1
    desktop._animate_activity = MagicMock()
    desktop._watch_event({
        "event": "scan_completed", "session_id": "test-session", "sequence": 1,
        "outcome": "no_configured_rule_matches", "scan": {"findings": []},
    })
    assert desktop.watch_inventory_complete is False
    desktop._watch_event({
        "event": "health_heartbeat", "session_id": "test-session", "sequence": 2,
        "operational_incomplete": incomplete, "inventory_complete": authoritative_inventory,
    })
    expected = authoritative_inventory and not incomplete
    assert desktop.watch_inventory_complete is expected
    assert desktop.watch_coverage_complete is expected


@pytest.mark.parametrize("inventory", [None, "true", 1, {}, []])
def test_inventory_recovery_contract_rejects_nonboolean_values(inventory: object) -> None:
    with pytest.raises(ContractError, match="inventory_complete"):
        validate_watch_event({
            "schema": "zsec.shield.watch-event.v1", "event": "health_heartbeat",
            "session_id": "test-session", "sequence": 1,
            "generated_at": "2026-10-09T18:00:00Z", "backend_active": "native",
            "operational_incomplete": False, "inventory_complete": inventory,
        })


def test_inventory_recovery_contract_rejects_inconsistent_health() -> None:
    with pytest.raises(ContractError, match="incomplete operation"):
        validate_watch_event({
            "schema": "zsec.shield.watch-event.v1", "event": "health_heartbeat",
            "session_id": "test-session", "sequence": 1,
            "generated_at": "2026-10-09T18:00:00Z", "backend_active": "native",
            "operational_incomplete": True, "inventory_complete": True,
        })
