from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_gui_spec_is_windowed_versioned_and_keeps_cli_out_of_process() -> None:
    spec = (ROOT / "packaging" / "zsec-antivirus-desktop.spec").read_text(encoding="utf-8")
    assert 'name="ZSEC Antivirus"' in spec
    assert "console=False" in spec
    assert "ZSEC_GUI_WINDOWS_VERSION_FILE" in spec
    assert "ZSEC_GUI_WINDOWS_ICON" in spec
    assert "zsec_shield" not in spec
    assert '"pystray._win32"' in spec
    assert '"PIL.Image"' in spec


def test_desktop_builder_is_syntax_valid_and_records_coexistence_policy() -> None:
    source = (ROOT / "packaging" / "windows_desktop_release.py").read_text(encoding="utf-8")
    ast.parse(source)
    assert '"primary_antivirus": False' in source
    assert '"pre_access_enforcement": False' in source
    assert '"existing_provider_must_remain_active": True' in source
    assert '"automatic_provider_removal": False' in source
    assert '"automatic_companion_lifecycle": True' in source
    assert 'Sync-ZsecAntivirusCompanion.ps1' in source
    assert 'Invoke-ZsecWindowsProtectionAction.ps1' in source
    assert '"publisher_code_signing": "not-performed-by-this-build"' in source
    assert '"ZSEC Antivirus Build"' in source
    assert 'os.environ.get("LOCALAPPDATA")' in source


def test_desktop_installer_has_no_security_provider_mutation_surface() -> None:
    installer = (ROOT / "windows" / "desktop" / "Install-ZsecAntivirusDesktop.ps1").read_text(
        encoding="utf-8"
    )
    lowered = installer.casefold()
    for forbidden in (
        "set-mppreference",
        "add-mppreference",
        "remove-mppreference",
        "uninstall-package",
        "win32_product",
        "securitycenter2",
        "rootcertificate",
        "new-netfirewallrule",
    ):
        assert forbidden not in lowered
    assert "security_products_modified = $false" in installer
    assert "existing_provider_must_remain_active = $true" in installer


def test_windows_protection_orchestration_has_only_update_and_scan_actions() -> None:
    action = (
        ROOT / "windows" / "companion" / "Invoke-ZsecWindowsProtectionAction.ps1"
    ).read_text(encoding="utf-8")
    lowered = action.casefold()
    assert '[validateset("updatesignatures", "quickscan", "fullscan")]' in lowered
    assert "update-mpsignature" in lowered
    assert "start-mpscan -scantype quickscan" in lowered
    assert "start-mpscan -scantype fullscan" in lowered
    for forbidden in (
        "set-mppreference",
        "add-mppreference",
        "remove-mppreference",
        "uninstall-package",
        "msiexec",
        "stop-service",
        "securitycenter2).delete",
    ):
        assert forbidden not in lowered
    for invariant in (
        "provider_configuration_changed = $false",
        "exclusions_changed = $false",
        "security_center_registration_changed = $false",
        "existing_provider_removed = $false",
    ):
        assert invariant in action


def test_desktop_installer_activation_is_transactional_and_restores_prior_state() -> None:
    installer = (ROOT / "windows" / "desktop" / "Install-ZsecAntivirusDesktop.ps1").read_text(
        encoding="utf-8"
    )
    assert '".install-transaction-"' in installer
    assert "$currentBackup" in installer
    assert "$desktopShortcutBackup" in installer
    assert "$startMenuShortcutBackup" in installer
    assert "new-desktop-shortcut.lnk" in installer
    assert "new-start-menu-shortcut.lnk" in installer
    assert "Write-JsonAtomic -Path $currentPath -Value $installed" in installer
    assert "activation rollback also failed" in installer
    assert "Copy-Item -LiteralPath $currentBackup -Destination $currentPath" in installer
    assert "Remove-RegularFileIfPresent $destination" in installer
    assert "automatic_companion_lifecycle = $true" in installer
    assert "Sync-ZsecAntivirusCompanion.ps1" in installer
    assert "$previousEngineForRollback" in installer
    assert "$companionSynchronized" in installer
    assert "prior automatic companion failed rollback verification" in installer


def test_user_facing_gui_brand_does_not_call_itself_preview() -> None:
    app = (ROOT / "apps" / "windows-ui" / "zsec_desktop" / "app.py").read_text(encoding="utf-8")
    assert "Desktop Preview" not in app
    assert "DESKTOP PREVIEW" not in app
    assert 'self.root.title("ZSEC Antivirus")' in app
    assert 'text="COMMUNITY 0.3.7"' in app


def test_gui_has_bounded_activity_animation_and_reduced_motion_control() -> None:
    app = (ROOT / "apps" / "windows-ui" / "zsec_desktop" / "app.py").read_text(encoding="utf-8")
    assert "self.busy_operations" in app
    assert "LOCAL ENGINE IDLE" in app
    assert "LOCAL CORE READY" not in app
    assert "VERIFYING" in app
    assert "Reduce motion" in app
    assert "after_cancel" in app
    assert "ModernStatusCard" in app
    assert "NavSelected.TButton" in app
    assert 'style.layout("Content.TNotebook.Tab", [])' in app
    assert "_layout_overview_cards" in app
    assert "lambda: not self.reduce_motion.get()" in app
    assert "width >= 1040" in app
    assert "width >= 520" in app
    assert "TrayController" in app
    assert "_tray_scan_downloads" in app
    assert "_window_close" in app
    assert "Start ZSEC Antivirus in the notification area" in app


def test_companion_sync_is_bounded_verified_and_rolls_back() -> None:
    sync = (ROOT / "windows" / "companion" / "Sync-ZsecAntivirusCompanion.ps1").read_text(
        encoding="utf-8"
    )
    assert "windows-companion-sync-plan.v1" in sync
    assert "windows-companion-sync-result.v1" in sync
    assert "Wait-CompanionActivation" in sync
    assert 'decision = "initializing"' in sync
    assert "activation_verified = $true" in sync
    assert "AddSeconds(30)" in sync
    assert "Get-RollbackInstaller" in sync
    assert "prior healthy companion was restored" in sync
    assert "existing_provider_must_remain_active = $true" in sync
    assert "automatic_provider_changes = $false" in sync
    assert '"-Confirm:`$false"' not in sync
    assert "AllowNonzeroJson" in sync
    assert "Get-MigratedProtectedRoots" in sync
    assert "legacy_temp_root_retired" in sync
    assert "Move-PartialCompanionAside" in sync
