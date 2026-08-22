from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "browser" / "zsec-desktop-preview" / "src" / "ZsecBrowserApp.cs"
BUILD = ROOT / "windows" / "browser" / "Build-ZsecBrowserPreview.ps1"
INSTALLER = ROOT / "windows" / "browser" / "Install-ZsecBrowserPreview.ps1"
STATUS = ROOT / "windows" / "browser" / "Get-ZsecBrowserPreviewStatus.ps1"
RUNTIME_TEST = ROOT / "windows" / "browser" / "Test-ZsecBrowserPreviewRuntime.ps1"
README = ROOT / "browser" / "zsec-desktop-preview" / "README.md"
COMPILER = ROOT / "packaging" / "compile_browser_policy.py"
PACKAGER = ROOT / "packaging" / "browser_desktop_preview_release.py"
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
    assert "unsigned" in readme.lower() and "Community" in readme
    assert 'internal const string ProductVersion = "0.3.5"' in app
    assert '$ProductVersion = "0.3.5"' in build
    assert '$ProductVersion = "0.3.5"' in installer


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
    assert "CoreWebView2TrackingPreventionLevel.Balanced" in app
    assert "CoreWebView2WebResourceRequestSourceKinds.Document" in app
    assert "AreBrowserExtensionsEnabled = true" in app
    assert 'ExpectedShieldsExtensionId = "ddjbjhnlhapggenanpmcidieimaomiif"' in app
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
    rules = ROOT / "browser" / "zeroq-shields" / "rules"
    bounded_rules = tmp_path / "bounded-rules"
    bounded_rules.mkdir()
    for name in ("privacy.json", "link-cleaning.json"):
        (bounded_rules / name).write_bytes((rules / name).read_bytes())
    # This file is deliberately not valid JSON. Successful compilation proves
    # EasyList remains an MV3 package input rather than a duplicated native
    # desktop-policy input.
    (bounded_rules / "easylist.json").write_text(
        "not loaded by the bounded desktop policy compiler\n", encoding="utf-8"
    )

    outputs = (tmp_path / "policy-a", tmp_path / "policy-b")
    for output in outputs:
        subprocess.run(
            [
                sys.executable,
                str(COMPILER),
                str(bounded_rules),
                str(MANIFEST),
                str(output),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    output = outputs[0]
    provenance = json.loads((output / "policy-provenance.json").read_text(encoding="utf-8"))
    domains = (output / "tracker-domains.txt").read_text(encoding="utf-8").splitlines()
    parameters = (output / "tracking-parameters.txt").read_text(encoding="utf-8").splitlines()

    assert provenance["schema"] == "zsec.browser.desktop-policy.v1"
    assert provenance["source_extension"]["name"] == "ZSEC Browser Shields"
    assert provenance["source_extension"]["version"] == "0.5.1"
    assert provenance["inputs"]["compiled_rule_files"] == [
        "link-cleaning.json",
        "privacy.json",
    ]
    assert provenance["packaged_only_rulesets"] == [
        {
            "id": "easylist_ads",
            "path": "rules/easylist.json",
            "reason": "enforced by Browser Shields MV3; excluded from native desktop policy",
        }
    ]
    assert all("easylist" not in key for key in provenance["inputs"])
    assert domains == sorted(set(domains))
    assert parameters == sorted(set(parameters))
    assert len(domains) == provenance["outputs"]["tracker_domain_count"] == 81
    assert len(parameters) == provenance["outputs"]["tracking_parameter_count"] == 21
    for name in ("tracker-domains.txt", "tracking-parameters.txt", "policy-provenance.json"):
        assert (outputs[0] / name).read_bytes() == (outputs[1] / name).read_bytes()


def test_status_requires_runtime_and_integrity_evidence() -> None:
    status = STATUS.read_text(encoding="utf-8")

    assert "app_files" in status
    assert "Get-FileHash" in status
    assert "signature_verified" in status
    assert "runtime_evidence" in status
    assert "host_objects_allowed" in status
    assert "running_instance_verified" in status


def test_desktop_tabs_popups_and_modern_controls_are_wired() -> None:
    app = APP.read_text(encoding="utf-8")

    assert "newTabButton," in app
    assert "closeTabButton," in app
    assert "GetDeferral()" in app
    assert "args.NewWindow = popupView.CoreWebView2" in app
    assert "args.IsUserInitiated" in app
    assert "deferral.Complete()" in app
    assert "MaximumTabs = 32" in app
    assert "DrawMode = TabDrawMode.OwnerDrawFixed" in app
    assert "RoundedSurface" in app
    assert "Profile: isolated" not in app
    assert "ExpectedMicrosoftSystemExtensions" in app
    assert '"Microsoft Clipboard Extension"' in app
    assert '"Microsoft Edge PDF Viewer"' in app
    assert 'lastTabAction = "closed"' in app
    assert 'schema=zsec.browser.startup-failure.v1' in app
    assert "protected override bool ProcessCmdKey" in app
    assert "keyData == (Keys.Control | Keys.T)" in app
    assert "keyData == (Keys.Control | Keys.W)" in app
    assert "view.KeyDown += BrowserKeyDown" in app
    assert '"--zsec-runtime-test=new-tab"' in app
    assert 'lastTabAction = "new_tab_ready"' in app
    assert 'lastNewTabCommandSource = source' in app
    assert 'RecordTabCreationFailure("runtime_not_ready")' in app
    assert 'RecordTabCreationFailure("tab_limit_rejected")' in app
    assert 'RecordTabCreationFailure("open_failed")' in app


def test_runtime_acceptance_retries_transient_evidence_file_locks() -> None:
    runtime_test = RUNTIME_TEST.read_text(encoding="utf-8")

    assert "$openDeadline = [DateTimeOffset]::UtcNow.AddSeconds(2)" in runtime_test
    assert "catch [IO.IOException]" in runtime_test
    assert "Start-Sleep -Milliseconds 50" in runtime_test
    assert '-AdditionalArguments @("--zsec-runtime-test=new-tab")' in runtime_test
    assert "$evidence['tab_count'] -eq 2" in runtime_test
    assert "$evidence['ready_tab_count'] -eq 2" in runtime_test
    assert "$evidence['tab_creation_failure_count'] -eq 0" in runtime_test
    assert "$evidence['last_tab_action'] -eq 'new_tab_ready'" in runtime_test
    assert "$evidence['last_new_tab_command_source'] -eq 'runtime_acceptance'" in runtime_test


def test_bundled_extension_has_stable_identity_and_bounded_youtube_assist() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    build = BUILD.read_text(encoding="utf-8")
    public_key = base64.b64decode(manifest["key"], validate=True)
    digest = hashlib.sha256(public_key).digest()[:16]
    alphabet = "abcdefghijklmnop"
    extension_id = "".join(
        alphabet[byte >> 4] + alphabet[byte & 0x0F] for byte in digest
    )
    assist = (ROOT / "browser" / "zeroq-shields" / "src" / "youtube-cleanup.js").read_text(
        encoding="utf-8"
    )

    assert manifest["version"] == "0.5.1"
    assert extension_id == "ddjbjhnlhapggenanpmcidieimaomiif"
    for required_desktop_asset in (
        '"easylist.lock.json"',
        '"rules/easylist.json"',
        '"third_party/EASYLIST-LICENSE.txt"',
        '"third_party/easylist-20260817.txt"',
        '"third_party/easylist-provenance.json"',
        '"src/youtube-cosmetic-rules.js"',
    ):
        assert required_desktop_asset in build
    assert "window.top !== window" in assist
    assert "requestAnimationFrame" in assist
    assert "MutationObserver" in assist
    assert "setInterval" not in assist
    for forbidden in ("currentTime", "playbackRate", ".muted", "new Function", "eval("):
        assert forbidden not in assist


def test_community_release_is_deterministic_and_publishes_provenance(
    tmp_path: Path,
) -> None:
    build = tmp_path / "build"
    payload = build / "payload"
    payload.mkdir(parents=True)
    payload_file = payload / "README.md"
    payload_file.write_text("ZSEC Browser Community\n", encoding="utf-8")
    payload_sha = hashlib.sha256(payload_file.read_bytes()).hexdigest()
    manifest = {
        "schema": "zsec.browser.desktop-preview-build.v2",
        "version": "0.3.5",
        "architecture": "windows-x64-webview2-shell",
        "engine_distribution": "Microsoft Evergreen WebView2 Chromium runtime",
        "engine_maintained_by": "Microsoft",
        "standalone_chromium_fork": False,
        "signed_zsec_binary": False,
        "webview2_sdk_version": "1.0.4129.50",
        "webview2_nuget_sha256": "a" * 64,
        "webview2_nuget_sha512_base64": "catalog-hash",
        "tracker_domain_count": 81,
        "tracking_parameter_count": 21,
        "source_extension_version": "0.5.1",
        "source_extension_id": "ddjbjhnlhapggenanpmcidieimaomiif",
        "files": [
            {"path": "README.md", "sha256": payload_sha, "bytes": 23}
        ],
    }
    (build / "build-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    revision = "1" * 40
    release_a = tmp_path / "release-a"
    release_b = tmp_path / "release-b"
    for output in (release_a, release_b):
        subprocess.run(
            [
                sys.executable,
                str(PACKAGER),
                str(build),
                str(output),
                "--source-revision",
                revision,
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    name = "zsec-browser-community-0.3.5-windows-x64-unsigned.zip"
    archive_a = release_a / name
    archive_b = release_b / name
    assert archive_a.read_bytes() == archive_b.read_bytes()
    artifact_sha = hashlib.sha256(archive_a.read_bytes()).hexdigest()
    metadata = json.loads(
        (release_a / f"{name}.json").read_text(encoding="utf-8")
    )
    assert metadata["schema"] == "zsec.browser.community-release.v1"
    assert metadata["source_revision"] == revision
    assert metadata["standalone_chromium_fork"] is False
    assert metadata["signed_zsec_binary"] is False
    assert metadata["artifact_sha256"] == artifact_sha
    assert (release_a / f"{name}.sha256").read_text(encoding="ascii") == (
        f"{artifact_sha}  {name}\n"
    )
    with zipfile.ZipFile(archive_a) as archive:
        provenance = json.loads(
            archive.read(
                "zsec-browser-community-0.3.5/release-provenance.json"
            ).decode("utf-8")
        )
    assert provenance["source_revision"] == revision
    assert provenance["standalone_chromium_fork"] is False


def test_community_package_uses_release_grade_script_names() -> None:
    build = BUILD.read_text(encoding="utf-8")
    packager = PACKAGER.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")

    for name in (
        "Install-ZsecBrowser.ps1",
        "Get-ZsecBrowserStatus.ps1",
        "Test-ZsecBrowserRuntime.ps1",
        "Uninstall-ZsecBrowser.ps1",
    ):
        assert name in build
    assert "Install-ZsecBrowser.ps1" in packager
    assert "Install-ZsecBrowserPreview.ps1" not in packager
    assert "Install-ZsecBrowserPreview.ps1" not in readme
