# ZSEC Browser Community desktop client

ZSEC Browser is a branded Windows browser shell with
its own executable, modern rounded interface, managed tabs, address and search
bar, Desktop shortcut, Start-menu entry, protection controls, and separate app
profile. It is powered by Microsoft's
automatically serviced Evergreen WebView2 Chromium runtime.

## Exact architecture boundary

This is a hardened browser shell. It is **not** a separately built or maintained
Chromium fork, is not a renamed copy of Brave, and is not yet a replacement for
a full browser such as Brave, Chrome, Edge, or Firefox. Microsoft maintains and
updates the embedded Chromium engine; ZSEC owns the native window, browser
policy, UI, profile boundary, packaging, and tests.

The build pins Microsoft WebView2 SDK `1.0.4129.50` and verifies its official
NuGet SHA-512 plus a locked SHA-256 before compilation. Installation requires a
supported, validly Microsoft-signed Evergreen runtime. The ZSEC executable is
an **unsigned direct Community build**, not a publisher-signed Store installer.

## Implemented protections

- Separate profile under `%LOCALAPPDATA%\TalkToAI\ZSEC Browser\User Data`.
- HTTPS upgrades for plaintext addresses; High-Risk mode blocks plaintext HTTP.
- Automatically loaded, exact-ID ZSEC Browser Shields 0.5.1 MV3 engine with
  49,464 pinned EasyList network rules, 39 focused privacy blockers, two
  link-cleaning rules and a bounded YouTube UI assist. Acceptable Ads is not
  bundled. The native shell independently removes 21 selected tracking parameters.
- Microsoft Balanced tracking prevention is explicitly enabled and read back.
- Optional High-Risk mode blocks cross-site active resource classes.
- Camera, microphone, location, notification, clipboard and other site
  permissions are denied by default.
- Certificate errors are cancelled; there is no bypass path in the UI.
- Downloads require a confirmation and destination choice and are never opened
  automatically by ZSEC.
- Password autosave and general form autofill are disabled.
- Host objects and web messaging are disabled, so remote pages receive no native
  filesystem, process, registry, PowerShell, antivirus or application bridge.
- A visible New tab control, Ctrl+T, tab close controls, true WebView2 popup
  binding, transactional failure cleanup and a 32-tab resource bound.
- Non-web schemes are rejected; remote debugging and developer tools are off.
- The UI labels the product as `Community 0.3.5` and exposes the exact runtime
  and policy boundary in its About dialog.

The YouTube UI assist hides selected known promotional slots and activates a
visible skip control when available. It does not rewrite video playback and does
not prove complete or permanent YouTube ad blocking. The application is
also not antivirus and cannot guarantee protection from every browser-engine,
zero-click, Pegasus-class or other exploit.

## Install the Community package

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Install-ZsecBrowser.ps1 -PlanOnly
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Install-ZsecBrowser.ps1 -Open
```

Status is read-only:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Get-ZsecBrowserStatus.ps1
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Test-ZsecBrowserRuntime.ps1
```

Uninstall removes the versioned application files and owned shortcuts while
preserving the browser profile by default. `-RemoveProfile` is a separate,
explicit destructive choice.

## Security and privacy boundary

WebView2 SmartScreen/reputation protection remains available through the
Microsoft runtime. That means security-related browsing information may be
processed by Microsoft according to its terms; ZSEC must disclose that before a
public release. ZSEC does not add telemetry or send browsing history to a ZSEC
server in this Community build.

ZMath and Zero Boundary Algebra are not substituted for the runtime sandbox,
TLS, certificate validation, Windows DPAPI/CNG, code signing, or other reviewed
cryptographic controls. Research-derived scoring may be evaluated separately,
but it must pass measurable security tests before it can affect browser policy.

## Full-browser release gate

A product comparable to Brave requires a maintained Chromium source
distribution, continuous upstream security merges, reproducible Windows/macOS/
Linux builds, browser signing, an authenticated rollback-resistant updater,
sandbox and Site Isolation evidence, browser integration tests, reputation
services with an explicit privacy contract, crash/update infrastructure, an
SBOM, third-party notices, and an operating security-response process. This
Community build does not claim those gates are complete.
