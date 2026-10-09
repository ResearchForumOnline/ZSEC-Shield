"""Automation must improve maintenance without changing the security provider."""

from __future__ import annotations

from typing import Any

import pytest
from zsec_desktop.app import ZsecDesktop
from zsec_desktop.bridge import BridgeError, ZsecBridge

from tests.test_windows_gui_contracts import valid_companion


def maintenance_evidence(*, active: bool, stale: bool) -> dict[str, Any]:
    payload = valid_companion()
    defender = payload["existing_primary_protection"]["defender"]
    for field in (
        "antivirus_enabled",
        "real_time_protection_enabled",
        "service_enabled",
        "behavior_monitor_enabled",
        "ioav_protection_enabled",
        "on_access_protection_enabled",
        "network_inspection_enabled",
    ):
        defender[field] = active
    defender["confirmed_active"] = active
    defender["baseline_features_confirmed"] = active
    defender["signatures"]["defender_reports_out_of_date"] = stale
    defender["signatures_current"] = not stale
    defender["update_recommended"] = stale
    return payload


@pytest.mark.parametrize(
    "active,stale", [(False, False), (False, True), (True, False), (True, True)]
)
def test_background_maintenance_only_requests_active_stale_defender(
    active: bool, stale: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = object.__new__(ZsecBridge)
    calls: list[str] = []
    monkeypatch.setattr(bridge, "windows_protection_action", lambda action: calls.append(action))
    bridge.maintain_windows_protection_if_needed(maintenance_evidence(active=active, stale=stale))
    assert calls == (["UpdateSignatures"] if active and stale else [])


def test_forged_active_evidence_cannot_trigger_automatic_maintenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = object.__new__(ZsecBridge)
    calls: list[str] = []
    monkeypatch.setattr(bridge, "windows_protection_action", lambda action: calls.append(action))
    evidence = maintenance_evidence(active=False, stale=True)
    evidence["existing_primary_protection"]["defender"]["confirmed_active"] = True
    with pytest.raises(BridgeError, match="contradicts"):
        bridge.maintain_windows_protection_if_needed(evidence)
    assert calls == []


def test_store_maintenance_is_async_hourly_and_does_not_retry_during_inflight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    desktop = object.__new__(ZsecDesktop)
    desktop.closing = False
    desktop.store_managed = True
    jobs: list[object] = []
    monkeypatch.setattr(desktop, "_run_async", lambda *args, **kwargs: jobs.append((args, kwargs)))
    monkeypatch.setattr("zsec_desktop.app.time.monotonic", lambda: 100.0)
    evidence = maintenance_evidence(active=True, stale=True)
    desktop._maintain_windows_protection_if_due(evidence)
    desktop._maintain_windows_protection_if_due(evidence)
    assert len(jobs) == 1
    desktop.windows_maintenance_inflight = False
    monkeypatch.setattr("zsec_desktop.app.time.monotonic", lambda: 3699.0)
    desktop._maintain_windows_protection_if_due(evidence)
    assert len(jobs) == 1
    monkeypatch.setattr("zsec_desktop.app.time.monotonic", lambda: 3700.0)
    desktop._maintain_windows_protection_if_due(evidence)
    assert len(jobs) == 2


def test_automatic_maintenance_failure_is_quiet_and_preserves_hourly_backoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    desktop = object.__new__(ZsecDesktop)
    desktop.closing = False
    desktop.store_managed = True
    status: list[dict[str, str]] = []
    label = type("Label", (), {"configure": lambda self, **kwargs: status.append(kwargs)})()
    desktop.windows_action_status = label
    jobs: list[object] = []

    def run_failed(*args: object, **kwargs: Any) -> None:
        jobs.append(args)
        kwargs["failure"](BridgeError("Windows refused the signature refresh"))

    monkeypatch.setattr(desktop, "_run_async", run_failed)
    monkeypatch.setattr("zsec_desktop.app.time.monotonic", lambda: 100.0)
    monkeypatch.setattr(
        "zsec_desktop.app.messagebox.showerror",
        lambda *args, **kwargs: pytest.fail("Routine maintenance must not create a popup"),
    )
    desktop._maintain_windows_protection_if_due(maintenance_evidence(active=True, stale=True))
    assert desktop.windows_maintenance_inflight is False
    assert "retry later" in status[0]["text"]
    desktop._maintain_windows_protection_if_due(maintenance_evidence(active=True, stale=True))
    assert len(jobs) == 1
