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


def test_desktop_builder_is_syntax_valid_and_records_coexistence_policy() -> None:
    source = (ROOT / "packaging" / "windows_desktop_release.py").read_text(encoding="utf-8")
    ast.parse(source)
    assert '"primary_antivirus": False' in source
    assert '"pre_access_enforcement": False' in source
    assert '"existing_provider_must_remain_active": True' in source
    assert '"automatic_provider_removal": False' in source
    assert '"publisher_code_signing": "not-performed-by-this-build"' in source


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


def test_user_facing_gui_brand_does_not_call_itself_preview() -> None:
    app = (ROOT / "apps" / "windows-ui" / "zsec_desktop" / "app.py").read_text(encoding="utf-8")
    assert "Desktop Preview" not in app
    assert "DESKTOP PREVIEW" not in app
    assert 'self.root.title("ZSEC Antivirus")' in app
    assert 'text="COMMUNITY 0.3.5"' in app


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
