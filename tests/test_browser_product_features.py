from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "browser" / "zsec-desktop-preview" / "src" / "ZsecBrowserApp.cs"
STATE = ROOT / "browser" / "zsec-desktop-preview" / "src" / "BrowserProductState.cs"
DIALOGS = ROOT / "browser" / "zsec-desktop-preview" / "src" / "BrowserProductDialogs.cs"
LOGIN_DIALOGS = ROOT / "browser" / "zsec-desktop-preview" / "src" / "BrowserLoginDialogs.cs"
VAULT_DIALOGS = ROOT / "browser" / "zsec-desktop-preview" / "src" / "BrowserVaultDialogs.cs"
CREDENTIAL_IMPORT = ROOT / "browser" / "zsec-desktop-preview" / "src" / "BrowserCredentialImport.cs"
POLICY = ROOT / "browser" / "zsec-desktop-preview" / "src" / "BrowserProductPolicy.cs"
THEME = ROOT / "browser" / "zsec-desktop-preview" / "src" / "BrowserTheme.cs"
NEW_TAB = ROOT / "browser" / "zsec-desktop-preview" / "assets" / "new-tab" / "index.html"
YOUTUBE_PROTECTION = (
    ROOT / "browser" / "zsec-desktop-preview" / "assets" / "youtube-player-protection.js"
)
BUILD = ROOT / "windows" / "browser" / "Build-ZsecBrowserPreview.ps1"
README = ROOT / "browser" / "zsec-desktop-preview" / "README.md"
PRODUCT_TESTS = (
    ROOT
    / "browser"
    / "zsec-desktop-preview"
    / "tests"
    / "Run-Product-Tests.ps1"
)


@pytest.mark.skipif(sys.platform != "win32", reason="C# harness requires Windows PowerShell")
def test_product_state_harness_passes() -> None:
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(PRODUCT_TESTS),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Browser product state tests passed" in completed.stdout


def test_theme_system_is_persisted_bounded_and_covers_runtime_surfaces() -> None:
    state = STATE.read_text(encoding="utf-8")
    theme = THEME.read_text(encoding="utf-8")
    app = APP.read_text(encoding="utf-8")
    dialogs = DIALOGS.read_text(encoding="utf-8")
    new_tab = NEW_TAB.read_text(encoding="utf-8")
    build = BUILD.read_text(encoding="utf-8")

    assert 'Theme = "soft_dark"' in state
    assert 'AccentColor = "teal"' in state
    assert '"soft_dark", "slate", "midnight"' in theme
    assert '"teal", "blue", "violet", "amber"' in theme
    assert "BrowserThemePalette.NormalizeTheme(settings.Theme)" in state
    assert "BrowserThemePalette.NormalizeAccent(settings.AccentColor)" in state
    assert "view.DefaultBackgroundColor = Background" in app
    assert "ApplyNewTabThemeAsync" in app
    assert "BrowserDialogTheme.Configure(theme)" in app
    assert "themeChoice.AccessibleName" in dialogs
    assert "accentChoice.AccessibleName" in dialogs
    assert "--z-bg:#182028" in new_tab
    assert "$ThemeSource" in build


def test_tray_lifecycle_has_restore_and_explicit_exit() -> None:
    app = APP.read_text(encoding="utf-8")

    assert "new NotifyIcon()" in app
    assert "BuildTrayMenu()" in app
    assert "BrowserWindowResize" in app
    assert "BrowserWindowClosing" in app
    assert "RestoreFromTray" in app
    assert "HideToTray" in app
    assert "ExitBrowser" in app
    assert "CloseReason.UserClosing" in app
    assert "productData.Settings.CloseToTray" in app
    assert "trayIcon.Visible = false" in app
    assert "trayIcon.Dispose()" in app


def test_bookmarks_history_and_main_menu_are_wired() -> None:
    app = APP.read_text(encoding="utf-8")
    state = STATE.read_text(encoding="utf-8")

    for token in (
        "BuildMainMenu()",
        "Bookmark manager",
        "Import bookmarks",
        "Export bookmarks",
        "RefreshBookmarksBar",
        "AddActiveBookmark",
        "ShowHistory",
        "ClearBrowsingHistory",
        "TryRecordHistory",
    ):
        assert token in app
    assert "browser-data.json" in state
    assert "MaximumBookmarks = 1000" in state
    assert "MaximumHistoryEntries = 5000" in state
    assert "NETSCAPE-Bookmark-file-1" in state
    assert "Uri.UriSchemeHttps" in state
    assert "Uri.UriSchemeHttp" in state
    assert "File.Replace(temporary, statePath, null)" in state
    assert "FileAttributes.ReparsePoint" in state
    assert "javascript:" not in state
    assert "GetAddressSuggestions" in state
    assert "TypedCount" in state
    assert "AutoCompleteMode.SuggestAppend" in app
    assert "RefreshAddressSuggestions" in app


def test_settings_surface_is_complete_and_truthful() -> None:
    dialogs = DIALOGS.read_text(encoding="utf-8")

    for category in (
        'Page("Privacy"',
        'Page("Permissions"',
        'Page("Shields"',
        'Page("Startup"',
        'Page("Appearance"',
        'Page("Downloads"',
        'Page("Default behavior"',
    ):
        assert category in dialogs
    assert "Popup default: block every page-requested window" in dialogs
    assert "Exact HTTPS sites allowed to request popup tabs" in dialogs
    assert "Background requests and popup bursts remain blocked" in dialogs
    assert "working.PopupAllowedOrigins" in dialogs
    assert "Choose a contrast-tested native browser theme and accent" in dialogs
    assert "All supplied palettes avoid white startup surfaces" in dialogs
    assert "Windows protects the actual default-app choice" in dialogs
    assert "native strict policy and the extension High-Risk mode are separate" in dialogs
    assert "Every download still requires an explicit allow decision" in dialogs
    assert "Default address bar search engine" in dialogs
    assert "Apply Journalist high-risk preset" in dialogs
    assert "Restore standard compatibility" in dialogs
    assert "Block YouTube advertising" in dialogs


def test_password_workflow_ui_is_explicit_recoverable_and_accessible() -> None:
    dialogs = DIALOGS.read_text(encoding="utf-8")
    login_dialogs = LOGIN_DIALOGS.read_text(encoding="utf-8")
    vault_dialogs = VAULT_DIALOGS.read_text(encoding="utf-8")

    assert "Offer to save or update passwords after a login is submitted" in dialogs
    assert "Automatically fill a saved login on its exact HTTPS website" in dialogs
    assert "ZSEC does not submit the form" in dialogs
    assert "Clear never-save list" in dialogs
    assert "PasswordNeverSaveOrigins.Clear()" in dialogs
    assert "Save settings and open ZSEC Passwords" in dialogs
    assert "disabled WebView2 password storage" in dialogs
    assert "No password value is displayed in this confirmation" in login_dialogs
    assert "you can clear that list in Settings > Passwords" in login_dialogs
    assert "BrowserLoginDialogText.SingleLineUsername" in login_dialogs
    assert 'AccessibleName = "Saved usernames"' in login_dialogs
    assert 'searchLabel.Text = "Search"' in vault_dialogs
    assert "RefreshActionAvailability" in vault_dialogs
    assert "Replace the password currently in this field" in vault_dialogs
    assert "BrowserVaultUiPolicy.RevealSeconds" in vault_dialogs
    assert "reveal.ShouldConceal(DateTime.UtcNow)" in vault_dialogs
    assert "Deactivate += delegate { ConcealPassword(); }" in vault_dialogs
    assert "ClearPendingClipboard();" in vault_dialogs
    assert "if unchanged" in vault_dialogs


def test_password_csv_import_is_explicit_bounded_and_never_overwrites() -> None:
    vault_dialogs = VAULT_DIALOGS.read_text(encoding="utf-8")
    credential_import = CREDENTIAL_IMPORT.read_text(encoding="utf-8")

    assert 'BrowserDialogTheme.Button("Import CSV"' in vault_dialogs
    assert "OpenFileDialog" in vault_dialogs
    assert "BrowserCredentialImportPolicy.ParseExport" in vault_dialogs
    assert "Delete the plaintext CSV export now?" in vault_dialogs
    assert "MessageBoxDefaultButton.Button2" in vault_dialogs
    assert "Cookies, sessions, passkeys, TOTP secrets and history" in vault_dialogs
    assert "MaximumFileBytes = 2 * 1024 * 1024" in credential_import
    assert "MaximumRows = 1000" in credential_import
    assert "NormalizeSecureOrigin" in credential_import
    assert "existing.Contains(identity)" in credential_import
    assert "vault.Delete(id)" in credential_import
    assert "SourceMatchesPlan" in credential_import
    assert "SourceSha256" in credential_import


def test_all_source_native_filter_and_youtube_runtime_evidence_are_wired() -> None:
    app = APP.read_text(encoding="utf-8")
    policy = POLICY.read_text(encoding="utf-8")
    youtube = YOUTUBE_PROTECTION.read_text(encoding="utf-8")

    assert "CoreWebView2WebResourceRequestSourceKinds.All" in app
    assert "IsReviewedThirdPartyTracker" in app
    assert "IsYoutubeAdRequest" in app
    assert "native_request_filter_source_kinds=all" in app
    assert "native_subresource_runtime_probe_status=" in app
    assert "youtube_protection_hook_status=" in app
    assert "youtube_ad_intervention_count=" in app
    assert "AddScriptToExecuteOnDocumentCreatedAsync" in app
    assert "youtube-player-protection.js" in app
    assert "YoutubeAdPathPrefixes" in policy
    assert "__zsecYoutubeProtection" in youtube
    assert "ytInitialPlayerResponse" in youtube
    assert "youtubei/v1/player" in youtube
    assert ".currentTime =" not in youtube
    assert "setInterval(" not in youtube


def test_search_provider_catalogue_is_explicit_and_bounded() -> None:
    policy = POLICY.read_text(encoding="utf-8")
    for provider in (
        "Brave Search",
        "DuckDuckGo",
        "Startpage",
        "Qwant",
        "Ecosia",
        "Microsoft Bing",
        "Google",
    ):
        assert provider in policy
    assert 'return provider == null ? "brave"' in policy


def test_shortcuts_and_accessibility_contract() -> None:
    app = APP.read_text(encoding="utf-8")

    for shortcut in (
        "Keys.Control | Keys.D",
        "Keys.Control | Keys.Shift | Keys.B",
        "Keys.Control | Keys.Shift | Keys.O",
        "Keys.Control | Keys.H",
        "Keys.Control | Keys.Shift | Keys.Delete",
        "Keys.Control | Keys.Oemcomma",
        "Keys.Alt | Keys.F",
        "Keys.Control | Keys.Tab",
        "Keys.Control | Keys.Shift | Keys.Tab",
        "Keys.F6",
    ):
        assert shortcut in app
    for accessible in (
        'AccessibleName = "Browser navigation toolbar"',
        'AccessibleName = "Open browser tabs"',
        'AccessibleName = "Bookmarks bar"',
        'AccessibleName = "Browser runtime status"',
    ):
        assert accessible in app


def test_navigation_toolbar_measures_labels_and_preserves_address_space() -> None:
    app = APP.read_text(encoding="utf-8")
    state = STATE.read_text(encoding="utf-8")

    assert "TextRenderer.MeasureText" in app
    assert "LayoutNavigationToolbar()" in app
    assert "BrowserToolbarLayout.NativeGuardLabel" in app
    assert "BrowserToolbarLayout.AddressWidth" in app
    assert "int reserved = 690" not in app
    assert "text.Length > 2 ? 118 : 42" not in app
    assert 'return toolbarWidth < CompactToolbarWidth' in state
    assert '"Guard: " + mode' in state
    assert '"Native guard: " + mode' in state


def test_build_compiles_product_sources_and_docs_keep_engine_boundary() -> None:
    build = BUILD.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    normalized_readme = " ".join(readme.split())

    assert "BrowserProductState.cs" in build
    assert "BrowserProductPolicy.cs" in build
    assert "BrowserProductDialogs.cs" in build
    assert "youtube-player-protection.js" in build
    assert '"/reference:System.Web.Extensions.dll"' in build
    assert "not" in normalized_readme
    assert "separately built or maintained" in normalized_readme
    assert "Chromium fork" in normalized_readme
    assert "Windows keeps authority over the protected default-app choice" in normalized_readme
    assert "browsing metadata, not passwords or encryption keys" in normalized_readme


def test_native_shell_integrates_supported_media_fullscreen_without_codec_flags() -> None:
    app = APP.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")

    assert "ContainsFullScreenElementChanged" in app
    assert "core.ContainsFullScreenElement" in app
    assert "SetFullScreen(!isFullScreen)" in app
    assert "Keys.F11" in app
    assert "Keys.Escape && isFullScreen" in app
    assert "--disable-gpu" not in app
    assert "does not force codec or GPU flags" in readme
