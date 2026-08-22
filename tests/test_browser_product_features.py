from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "browser" / "zsec-desktop-preview" / "src" / "ZsecBrowserApp.cs"
STATE = ROOT / "browser" / "zsec-desktop-preview" / "src" / "BrowserProductState.cs"
DIALOGS = ROOT / "browser" / "zsec-desktop-preview" / "src" / "BrowserProductDialogs.cs"
BUILD = ROOT / "windows" / "browser" / "Build-ZsecBrowserPreview.ps1"
README = ROOT / "browser" / "zsec-desktop-preview" / "README.md"
PRODUCT_TESTS = (
    ROOT
    / "browser"
    / "zsec-desktop-preview"
    / "tests"
    / "Run-Product-Tests.ps1"
)


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
    assert "Per-site permission exceptions are not implemented" in dialogs
    assert "dark Community shell is the only implemented theme" in dialogs
    assert "Default-browser registration is not implemented" in dialogs
    assert "native strict policy and the extension High-Risk mode are separate" in dialogs
    assert "Every download still requires an explicit allow decision" in dialogs


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


def test_build_compiles_product_sources_and_docs_keep_engine_boundary() -> None:
    build = BUILD.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    normalized_readme = " ".join(readme.split())

    assert "BrowserProductState.cs" in build
    assert "BrowserProductDialogs.cs" in build
    assert '"/reference:System.Web.Extensions.dll"' in build
    assert "not" in normalized_readme
    assert "separately built or maintained" in normalized_readme
    assert "Chromium fork" in normalized_readme
    assert "Default-browser registration is not implemented" in normalized_readme
    assert "browsing metadata, not passwords or encryption keys" in normalized_readme
