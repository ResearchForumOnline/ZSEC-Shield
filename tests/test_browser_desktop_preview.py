from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

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
PACKAGE_STAGING_FIXTURE = ROOT / "tests" / "fixtures" / "browser_package_staging.ps1"


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
    assert 'internal const string ProductVersion = "0.3.17"' in app
    assert '$ProductVersion = "0.3.17"' in build
    assert '$ProductVersion = "0.3.17"' in installer


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
    assert 'settings.IsWebMessageEnabled = loginAssistant.Enabled' in app
    assert 'settings.IsPasswordAutosaveEnabled = false' in app
    assert 'settings.IsGeneralAutofillEnabled = false' in app
    assert 'settings.IsPasswordAutosaveEnabled = false' in app
    assert 'settings.IsGeneralAutofillEnabled = false' in app
    assert 'CoreWebView2PermissionState.Deny' in app
    assert 'CoreWebView2ServerCertificateErrorAction.Cancel' in app
    assert 'settings.AreDevToolsEnabled = false' in app
    assert "CoreWebView2TrackingPreventionLevel.Balanced" in app
    assert "CoreWebView2WebResourceRequestSourceKinds.All" in app
    assert "IsReviewedThirdPartyTracker" in app
    assert "native_request_filter_source_kinds=all" in app
    assert "AreBrowserExtensionsEnabled = true" in app
    assert 'ExpectedShieldsExtensionId = "ddjbjhnlhapggenanpmcidieimaomiif"' in app
    assert 'system_security_products_modified = $false' in installer
    assert 'default_browser_changed = $false' in installer


def test_browser_build_dependencies_are_pinned_and_reproducible() -> None:
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
    assert '$CompilerToolsetVersion = "4.14.0"' in build
    assert (
        '$CompilerToolsetSha256 = '
        '"941a9cf3ea618d88d01a3dd6b1a45a06bcf07716a9f81ce4031caa3edd24a845"'
    ) in build
    assert (
        '"h5GExC3fx0fm0qHw8rQ6y5c0uk6cCiAsorLl9Hq/9VlotEvsv/oW60RNo8HOYApv66kNqJq4Bg/TkSAsgQAwbQ=="'
        in build
    )
    assert "microsoft.net.compilers.toolset" in build.casefold()
    assert '"tasks\\net472\\csc.exe"' in build
    assert '"/noconfig"' in build
    assert '"/deterministic+"' in build
    assert '"/pathmap:$RepoRoot=$CompilerSourcePathMap"' in build
    assert "C:\\Windows\\Microsoft.NET\\Framework64" not in build
    assert "Expand-Archive" not in build
    assert 'Join-Path $PackageCache "extracted"' not in build
    assert "Add-Type -AssemblyName System.IO.Compression.FileSystem" in build
    assert "[IO.Compression.ZipFile]::ExtractToDirectory" in build
    assert "function Expand-PinnedPackageToFreshStaging" in build
    assert "function Remove-OwnedPackageExtraction" in build
    assert '"extract-$([Guid]::NewGuid().ToString(\'N\'))"' in build
    webview_staging_call = build.index(
        "$WebViewPackageExtract = Expand-PinnedPackageToFreshStaging"
    )
    compiler_staging_call = build.index(
        "$CompilerPackageExtract = Expand-PinnedPackageToFreshStaging"
    )
    assert build.index("-ExpectedSha256 $WebView2Sha256") < webview_staging_call
    assert build.index("-ExpectedSha512Base64 $WebView2Sha512Base64") < (
        webview_staging_call
    )
    assert build.index("-ExpectedSha256 $CompilerToolsetSha256") < (
        compiler_staging_call
    )
    assert build.index("-ExpectedSha512Base64 $CompilerToolsetSha512Base64") < (
        compiler_staging_call
    )
    assert "Remove-Item -LiteralPath $resolvedPath -Recurse" not in build
    assert "[IO.Directory]::Delete($directory, $false)" in build
    assert "[IO.FileAttributes]::ReparsePoint" in build
    assert "The pinned NuGet package could not be extracted." in build
    assert '-Path $CompilerPackageExtract' in build
    assert '-PackagePath $CompilerPackagePath' in build
    assert '-Path $WebViewPackageExtract' in build
    assert 'launcher = "App/ZSEC Browser.exe"' in build
    assert 'payload_root = "payload"' in build
    assert "launcher = $LauncherPath" not in build
    assert "payload_root = $PayloadRoot" not in build
    output_guard = build.index("if (Test-Path -LiteralPath $OutputDirectory)")
    assert output_guard < build.index("New-Item -ItemType Directory -Path $AppRoot")
    assert "OutputDirectory must not already exist" in build
    assert "Get-AuthenticodeSignature" in installer
    assert "Microsoft Corporation" in installer


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell 5.1 is required")
def test_windows_powershell_uses_fresh_bounded_nupkg_staging(tmp_path: Path) -> None:
    valid_package = tmp_path / "valid.nupkg"
    partial_package = tmp_path / "partial.nupkg"
    cache_root = tmp_path / "package-cache"
    with zipfile.ZipFile(
        valid_package, "w", compression=zipfile.ZIP_DEFLATED
    ) as archive:
        archive.writestr(
            "lib/net462/Microsoft.Web.WebView2.Core.dll", "verified package core"
        )
        archive.writestr(
            "lib/net462/Microsoft.Web.WebView2.WinForms.dll", "verified package winforms"
        )
        archive.writestr(
            "runtimes/win-x64/native/WebView2Loader.dll", "verified package loader"
        )
    with zipfile.ZipFile(
        partial_package, "w", compression=zipfile.ZIP_DEFLATED
    ) as archive:
        archive.writestr("partial.txt", "created before the extraction failure")
        archive.writestr("conflict", "a file that blocks the next directory")
        archive.writestr("conflict/child.txt", "forces a partial extraction failure")

    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy",
            "RemoteSigned",
            "-File",
            str(PACKAGE_STAGING_FIXTURE),
            "-BuildScript",
            str(BUILD),
            "-ValidPackage",
            str(valid_package),
            "-PartialPackage",
            str(partial_package),
            "-CacheRoot",
            str(cache_root),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    evidence = json.loads(completed.stdout)
    assert evidence == {
        "schema": "zsec.tests.browser-package-staging.v1",
        "legacy_cache_ignored": True,
        "legacy_cache_preserved": True,
        "fresh_stage_used": True,
        "partial_stage_not_reused": True,
        "unexpected_nested_object_failed_closed": True,
        "nested_success_cleanup_verified": True,
        "nested_build_failure_cleanup_verified": True,
        "compiler_extraction_failure_cleanup_verified": True,
    }


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell 5.1 is required")
def test_build_refuses_a_preexisting_output_directory(tmp_path: Path) -> None:
    output = tmp_path / "existing-output"
    output.mkdir()
    sentinel = output / "must-remain.txt"
    sentinel.write_text("preserve existing output\n", encoding="utf-8")
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy",
            "RemoteSigned",
            "-File",
            str(BUILD),
            "-OutputDirectory",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode != 0
    assert "OutputDirectory must not already exist" in completed.stderr
    assert sentinel.read_text(encoding="utf-8") == "preserve existing output\n"
    assert list(output.iterdir()) == [sentinel]


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
    assert provenance["source_extension"]["version"] == "0.5.2"
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
    build = BUILD.read_text(encoding="utf-8")

    assert 'newTabButton.Text = "+"' in app
    assert 'CreateNewTabCommandAsync("tab_strip")' in app
    assert "PositionNewTabButton()" in app
    assert "RoundedActionButton" in app
    assert "GetDeferral()" in app
    assert "args.NewWindow = popupView.CoreWebView2" in app
    assert "args.IsUserInitiated" in app
    assert "deferral.Complete()" in app
    assert "MaximumTabs = 32" in app
    assert "DrawMode = TabDrawMode.OwnerDrawFixed" in app
    assert "RoundedSurface" in app
    assert "ControlStyles.SupportsTransparentBackColor" in app
    assert 'WriteStartupStage("runtime_evidence_ready")' in app
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
    assert (
        'ShieldsSettingsBaseUri = '
        '"chrome-extension://ddjbjhnlhapggenanpmcidieimaomiif/popup/index.html"'
    ) in app
    assert "OpenShieldsSettingsAsync" in app
    assert "IsExpectedShieldsSettingsUri" in app
    assert 'NewTabUri = "https://newtab.zsec.local/index.html"' in app
    assert "SetVirtualHostNameToFolderMapping" in app
    assert "CoreWebView2HostResourceAccessKind.DenyCors" in app
    assert '"index.html", "native-request-probe.html"' in build
    assert "await completion.Task" in app
    assert "expectedNavigationId" in app
    assert "args.NavigationId == expectedNavigationId.Value" in app
    assert "NavigationStarting -= startingHandler" in app


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
    assert "$evidence['native_subresource_runtime_probe_status'] -eq 'passed'" in runtime_test
    assert "$evidence['youtube_protection_hook_status'] -eq 'loaded'" in runtime_test
    assert "no_ad_served_is_not_a_failure = $true" in runtime_test


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

    assert manifest["version"] == "0.5.2"
    assert extension_id == "ddjbjhnlhapggenanpmcidieimaomiif"
    for required_desktop_asset in (
        '"easylist.lock.json"',
        '"rules/easylist.json"',
        '"third_party/EASYLIST-LICENSE.txt"',
        '"third_party/easylist-20260817.txt"',
        '"third_party/easylist-provenance.json"',
        '"src/popup-state.js"',
        '"src/youtube-cosmetic-rules.js"',
        '"youtube-player-protection.js"',
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
    launcher_file = payload / "App" / "ZSEC Browser.exe"
    launcher_file.parent.mkdir()
    launcher_file.write_bytes(b"synthetic browser executable")
    launcher_sha = hashlib.sha256(launcher_file.read_bytes()).hexdigest()
    manifest = {
        "schema": "zsec.browser.desktop-preview-build.v2",
        "version": "0.3.16",
        "architecture": "windows-x64-webview2-shell",
        "engine_distribution": "Microsoft Evergreen WebView2 Chromium runtime",
        "engine_maintained_by": "Microsoft",
        "standalone_chromium_fork": False,
        "signed_zsec_binary": False,
        "launcher": "App/ZSEC Browser.exe",
        "payload_root": "payload",
        "compiler_distribution": "Microsoft.Net.Compilers.Toolset",
        "compiler_version": "4.14.0",
        "compiler_nuget_sha256": (
            "941a9cf3ea618d88d01a3dd6b1a45a06"
            "bcf07716a9f81ce4031caa3edd24a845"
        ),
        "compiler_nuget_sha512_base64": (
            "h5GExC3fx0fm0qHw8rQ6y5c0uk6cCiAsorLl9Hq/"
            "9VlotEvsv/oW60RNo8HOYApv66kNqJq4Bg/TkSAsgQAwbQ=="
        ),
        "compiler_deterministic": True,
        "compiler_source_pathmap": "/_/src",
        "webview2_sdk_version": "1.0.4129.50",
        "webview2_nuget_sha256": "a" * 64,
        "webview2_nuget_sha512_base64": "catalog-hash",
        "tracker_domain_count": 81,
        "tracking_parameter_count": 21,
        "source_extension_version": "0.5.2",
        "source_extension_id": "ddjbjhnlhapggenanpmcidieimaomiif",
        "files": [
            {
                "path": "App/ZSEC Browser.exe",
                "sha256": launcher_sha,
                "bytes": launcher_file.stat().st_size,
            },
            {"path": "README.md", "sha256": payload_sha, "bytes": 23},
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

    name = "zsec-browser-community-0.3.16-windows-x64-unsigned.zip"
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
                "zsec-browser-community-0.3.16/release-provenance.json"
            ).decode("utf-8")
        )
    assert provenance["source_revision"] == revision
    assert provenance["standalone_chromium_fork"] is False
    assert provenance["compiler"]["deterministic"] is True
    assert metadata["build"]["machine_specific_paths_absent"] is True


def test_community_release_rejects_machine_specific_manifest_paths(
    tmp_path: Path,
) -> None:
    build = tmp_path / "build"
    payload = build / "payload"
    launcher = payload / "App" / "ZSEC Browser.exe"
    launcher.parent.mkdir(parents=True)
    launcher.write_bytes(b"synthetic browser")
    manifest = {
        "schema": "zsec.browser.desktop-preview-build.v2",
        "version": "0.3.16",
        "architecture": "windows-x64-webview2-shell",
        "engine_distribution": "Microsoft Evergreen WebView2 Chromium runtime",
        "engine_maintained_by": "Microsoft",
        "standalone_chromium_fork": False,
        "signed_zsec_binary": False,
        "launcher": r"C:\\private\\build\\ZSEC Browser.exe",
        "payload_root": "payload",
        "compiler_distribution": "Microsoft.Net.Compilers.Toolset",
        "compiler_version": "4.14.0",
        "compiler_nuget_sha256": (
            "941a9cf3ea618d88d01a3dd6b1a45a06"
            "bcf07716a9f81ce4031caa3edd24a845"
        ),
        "compiler_nuget_sha512_base64": (
            "h5GExC3fx0fm0qHw8rQ6y5c0uk6cCiAsorLl9Hq/"
            "9VlotEvsv/oW60RNo8HOYApv66kNqJq4Bg/TkSAsgQAwbQ=="
        ),
        "compiler_deterministic": True,
        "compiler_source_pathmap": "/_/src",
        "webview2_sdk_version": "1.0.4129.50",
        "webview2_nuget_sha256": "a" * 64,
        "webview2_nuget_sha512_base64": "catalog-hash",
        "tracker_domain_count": 81,
        "tracking_parameter_count": 21,
        "source_extension_version": "0.5.2",
        "source_extension_id": "ddjbjhnlhapggenanpmcidieimaomiif",
        "files": [
            {
                "path": "App/ZSEC Browser.exe",
                "sha256": hashlib.sha256(launcher.read_bytes()).hexdigest(),
                "bytes": launcher.stat().st_size,
            }
        ],
    }
    (build / "build-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    completed = subprocess.run(
        [
            sys.executable,
            str(PACKAGER),
            str(build),
            str(tmp_path / "release"),
            "--source-revision",
            "1" * 40,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "launcher must be payload-relative" in completed.stderr


def test_community_package_uses_release_grade_script_names() -> None:
    build = BUILD.read_text(encoding="utf-8")
    packager = PACKAGER.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    installer = INSTALLER.read_text(encoding="utf-8")

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
    assert 'Join-Path $siblingPackageRoot "App\\ZSEC Browser.exe"' in installer
    assert "$PayloadRoot = $siblingPackageRoot" in installer
    assert installer.index("$PayloadRoot = $siblingPackageRoot") < installer.index(
        "$PayloadRoot = $repoPayload"
    )
