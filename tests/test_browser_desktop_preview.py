from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "browser" / "zsec-desktop-preview" / "src" / "ZsecBrowserApp.cs"
BUILD = ROOT / "windows" / "browser" / "Build-ZsecBrowserPreview.ps1"
INSTALLER = ROOT / "windows" / "browser" / "Install-ZsecBrowserPreview.ps1"
STATUS = ROOT / "windows" / "browser" / "Get-ZsecBrowserPreviewStatus.ps1"
README = ROOT / "browser" / "zsec-desktop-preview" / "README.md"
COMPILER = ROOT / "packaging" / "compile_browser_policy.py"
MANIFEST = ROOT / "browser" / "zeroq-shields" / "manifest.json"


def test_desktop_preview_is_a_truthful_webview2_shell() -> None:
    app = APP.read_text(encoding="utf-8")
    build = BUILD.read_text(encoding="utf-8")
    installer = INSTALLER.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")

    assert "CoreWebView2Environment.CreateAsync" in app
    assert "Microsoft Evergreen WebView2 Chromium runtime" in build
    assert 'architecture = "windows-x64-webview2-shell"' in installer
    assert "standalone_chromium_fork = $false" in installer
    assert "signed_zsec_binary = $false" in installer
    assert "not" in readme.lower() and "chromium fork" in readme.lower()
    assert "unsigned local Community build" in readme


def test_desktop_preview_preserves_browser_security_controls() -> None:
    app = APP.read_text(encoding="utf-8")
    installer = INSTALLER.read_text(encoding="utf-8")
    forbidden = (
        "--no-sandbox",
        "--disable-web-security",
        "--ignore-certificate-errors",
        "--allow-running-insecure-content",
        "--disable-site-isolation-trials",
        "--remote-debugging-port",
    )
    for flag in forbidden:
        assert flag not in app

    assert 'settings.AreHostObjectsAllowed = false' in app
    assert 'settings.IsWebMessageEnabled = false' in app
    assert 'settings.IsPasswordAutosaveEnabled = false' in app
    assert 'settings.IsGeneralAutofillEnabled = false' in app
    assert 'CoreWebView2PermissionState.Deny' in app
    assert 'CoreWebView2ServerCertificateErrorAction.Cancel' in app
    assert 'settings.AreDevToolsEnabled = false' in app
    assert 'system_security_products_modified = $false' in installer
    assert 'default_browser_changed = $false' in installer


def test_webview2_dependency_is_pinned_to_official_catalog_hash() -> None:
    build = BUILD.read_text(encoding="utf-8")
    installer = INSTALLER.read_text(encoding="utf-8")

    assert '$WebView2Version = "1.0.4129.50"' in build
    assert (
        '$WebView2Sha256 = '
        '"d3934f482d484b89fb4825df720c710664e1143a1e90f7b3a60794ef33f473d2"'
    ) in build
    assert (
        '"9TM9AZpDUiAb6OJB9s6thxl63BJFgbINcp047Zy+oiz9+cjgLhFrMRZ5Be+5wVHGvMJR3z1rmPWeJipo4g0sJw=="'
        in build
    )
    assert "Get-AuthenticodeSignature" in installer
    assert "Microsoft Corporation" in installer


def test_compiled_policy_is_deterministic_and_has_source_provenance(tmp_path: Path) -> None:
    output = tmp_path / "policy"
    subprocess.run(
        [
            sys.executable,
            str(COMPILER),
            str(ROOT / "browser" / "zeroq-shields" / "rules"),
            str(MANIFEST),
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    provenance = json.loads((output / "policy-provenance.json").read_text(encoding="utf-8"))
    domains = (output / "tracker-domains.txt").read_text(encoding="utf-8").splitlines()
    parameters = (output / "tracking-parameters.txt").read_text(encoding="utf-8").splitlines()

    assert provenance["schema"] == "zsec.browser.desktop-policy.v1"
    assert provenance["source_extension"]["name"] == "ZSEC Browser Shields"
    assert provenance["source_extension"]["version"] == "0.4.0"
    assert domains == sorted(set(domains))
    assert parameters == sorted(set(parameters))
    assert len(domains) == provenance["outputs"]["tracker_domain_count"] == 81
    assert len(parameters) == provenance["outputs"]["tracking_parameter_count"] == 21


def test_status_requires_runtime_and_integrity_evidence() -> None:
    status = STATUS.read_text(encoding="utf-8")

    assert "app_files" in status
    assert "Get-FileHash" in status
    assert "signature_verified" in status
    assert "runtime_evidence" in status
    assert "host_objects_allowed" in status
    assert "running_instance_verified" in status
