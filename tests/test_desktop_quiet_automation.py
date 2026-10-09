from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

GUI_ROOT = Path(__file__).resolve().parents[1] / "apps" / "windows-ui"
if str(GUI_ROOT) not in sys.path:
    sys.path.insert(0, str(GUI_ROOT))

from zsec_desktop.app import (  # noqa: E402
    ZsecDesktop,
    scan_requires_notification,
    threat_notice_category,
)


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


def test_transient_monitor_failure_is_quiet_and_persistent_failure_is_deduplicated() -> None:
    desktop = quiet_desktop()
    with patch("zsec_desktop.app.time.monotonic", side_effect=[100, 399, 400, 401, 2200]):
        desktop._monitoring_notice("Check folder access")
        desktop._monitoring_notice("Check folder access")
        desktop.tray.notify.assert_not_called()
        desktop._monitoring_notice("Check folder access")
        desktop._monitoring_notice("Check folder access")
        assert desktop.tray.notify.call_count == 1
        desktop._monitoring_notice("Check folder access")
        assert desktop.tray.notify.call_count == 2


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
