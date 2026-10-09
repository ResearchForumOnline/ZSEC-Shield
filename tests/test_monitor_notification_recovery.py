import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

GUI_ROOT = Path(__file__).resolve().parents[1] / "apps" / "windows-ui"
if str(GUI_ROOT) not in sys.path:
    sys.path.insert(0, str(GUI_ROOT))

from zsec_desktop.app import CYAN, GREEN, ZsecDesktop  # noqa: E402


def test_monitoring_folder_failures_never_create_desktop_notifications():
    app = object.__new__(ZsecDesktop)
    app.monitoring_notice_times = {}
    app.monitoring_health_issue_since = None
    app.tray = MagicMock()
    with patch("zsec_desktop.app.time.monotonic", side_effect=[0, 299, 300, 2099, 2100]):
        app._monitoring_notice("Persistent monitor failure")
        app._monitoring_notice("Persistent monitor failure")
        app.tray.notify.assert_not_called()
        for _ in range(3):
            app._monitoring_notice("Persistent monitor failure")
    app.tray.notify.assert_not_called()


@pytest.mark.parametrize(
    "incomplete, inventory_done, age, expected",
    [
        (False, False, 10, CYAN),
        (True, False, 10, CYAN),
        (False, False, 76, CYAN),
        (False, True, 10, GREEN),
    ],
)
def test_setup_presentation_respects_actual_health_and_freshness(
    incomplete,
    inventory_done,
    age,
    expected,
):
    app = object.__new__(ZsecDesktop)
    app._render_windows_protection = MagicMock()
    app._update_tray_status = MagicMock()
    app.protected_roots = ()
    app.watch_session = MagicMock()
    app.watch_coverage_complete = inventory_done and not incomplete
    app.watch_inventory_complete = inventory_done
    app.watch_operational_incomplete = incomplete
    app.watch_last_heartbeat_monotonic = 100
    app.watch_findings_pending = False
    app.automatic_monitoring = MagicMock()
    app.companion_card = MagicMock()
    app.companion_status_label = MagicMock()
    app.protection_layer_labels = {"zsec": MagicMock(), "scope": MagicMock()}
    app.protected_roots_label = MagicMock()
    app.scan_protected_button = MagicMock()
    with patch("zsec_desktop.app.time.monotonic", return_value=100 + age):
        app._render_store_process_monitor({})
    assert app.companion_card.set_value.call_args.args[1] == expected
    if incomplete:
        assert "Complete coverage is not verified" in (
            app.companion_status_label.configure.call_args.kwargs["text"]
        )


@pytest.mark.parametrize(
    "attempt, enabled, expected_notice",
    [
        (0, True, False),
        (1, True, False),
        (3, True, True),
        (3, False, False),
    ],
)
def test_retry_escalates_only_persistent_enabled_failure(attempt, enabled, expected_notice):
    app = object.__new__(ZsecDesktop)
    app.closing = False
    app.store_managed = True
    app.automatic_monitoring = MagicMock()
    app.automatic_monitoring.get.return_value = enabled
    app.monitoring_retry_job = None
    app.watch_session = None
    app.monitoring_retry_attempt = attempt
    app.root = MagicMock()
    app.watch_state_label = MagicMock()
    app._update_tray_status = MagicMock()
    app._monitoring_notice = MagicMock()
    app._schedule_monitoring_retry()
    assert app._monitoring_notice.called == expected_notice
    assert app.root.after.called == enabled


def test_windows_health_notices_have_independent_category():
    app = object.__new__(ZsecDesktop)
    app.monitoring_notice_times = {}
    app.monitoring_health_issue_since = None
    app.tray = MagicMock()
    with patch("zsec_desktop.app.time.monotonic", return_value=10):
        app._monitoring_notice("Monitor failure")
        app._monitoring_notice("Windows health changed", category="windows")
    # Windows security faults bypass the transient-monitor grace period.
    app.tray.notify.assert_called_once_with("Windows health changed")
    with patch("zsec_desktop.app.time.monotonic", return_value=310):
        app._monitoring_notice("Monitor failure")
    app.tray.notify.assert_called_once_with("Windows health changed")


def test_repeated_identical_findings_notify_immediately_then_remind_after_thirty_minutes():
    app = object.__new__(ZsecDesktop)
    app.monitoring_notice_times = {}
    app.tray = MagicMock()
    with patch("zsec_desktop.app.time.monotonic", side_effect=[0, 75, 1799, 1800]):
        app._monitoring_notice("Detected rule matches", category="findings")
        app.tray.notify.assert_called_once()
        for _ in range(3):
            app._monitoring_notice("Detected rule matches", category="findings")
    assert app.tray.notify.call_count == 2
