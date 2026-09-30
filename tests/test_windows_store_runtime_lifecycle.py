from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_store_runtime_uses_package_identity_not_environment_claims() -> None:
    source = (ROOT / "apps/windows-ui/zsec_desktop/distribution.py").read_text(encoding="utf-8")
    assert "GetCurrentPackageFullName" in source
    assert "ERROR_INSUFFICIENT_BUFFER" in source
    assert "APPX_PACKAGE_FAMILY_NAME" not in source


def test_store_runtime_does_not_write_direct_startup_registration() -> None:
    settings = (ROOT / "apps/windows-ui/zsec_desktop/settings.py").read_text(encoding="utf-8")
    app = (ROOT / "apps/windows-ui/zsec_desktop/app.py").read_text(encoding="utf-8")
    assert "if self.store_managed:" in settings
    assert "Windows manages startup for this Store installation" in settings
    assert "StartupRegistration(store_managed=self.store_managed)" in app


def test_store_runtime_owns_bounded_monitoring_and_due_feed_checks() -> None:
    app = (ROOT / "apps/windows-ui/zsec_desktop/app.py").read_text(encoding="utf-8")
    bridge = (ROOT / "apps/windows-ui/zsec_desktop/bridge.py").read_text(encoding="utf-8")
    assert "def _start_store_monitoring" in app
    monitoring = (ROOT / "apps/windows-ui/zsec_desktop/monitoring.py").read_text(encoding="utf-8")
    assert "standard_monitoring_roots()" in app
    assert all(f'("{name}",' in monitoring for name in ("Downloads", "Documents", "Desktop"))
    assert "SHGetKnownFolderPath" in monitoring
    assert "quarantine=False" in app
    assert "watch_coverage_complete" in app
    assert "def _schedule_monitoring_retry" in app
    assert "while this Store app is running" in app
    assert "def update_intelligence_if_due" in bridge
    assert 'self._argv("update-intelligence", "--json")' in bridge
    assert "--force" not in bridge.split("def update_intelligence_if_due", 1)[1].split("def ", 1)[0]
