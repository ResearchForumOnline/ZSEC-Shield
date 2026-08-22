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

The build pins Microsoft WebView2 SDK `1.0.4129.50` and
Microsoft.Net.Compilers.Toolset `4.14.0`, verifies each package against its
official NuGet SHA-512 plus a locked SHA-256, extracts each into a fresh bounded
stage, and compiles with deterministic Roslyn settings and a stable source path
map. The packaged build manifest excludes machine-specific source and output
paths: its launcher and file inventory are payload-relative, while compiler
provenance records the stable synthetic `/_/src` source map. Installation
requires a supported, validly Microsoft-signed Evergreen runtime. The ZSEC
executable is an **unsigned direct Community build**, not a publisher-signed
Store installer.

## Implemented protections

- Separate profile under `%LOCALAPPDATA%\TalkToAI\ZSEC Browser\User Data`.
- HTTPS upgrades for plaintext addresses; High-Risk mode blocks plaintext HTTP.
- Automatically loaded, exact-ID ZSEC Browser Shields 0.5.2 MV3 engine with
  49,464 pinned EasyList network rules, 39 focused privacy blockers, two
  link-cleaning rules and a bounded YouTube UI assist. Acceptable Ads is not
  bundled. The native shell independently removes 21 selected tracking parameters.
- Microsoft Balanced tracking prevention is explicitly enabled and read back.
- The native request hook covers all WebView2 resource-source kinds. Reviewed
  third-party tracker domains are blocked for subresources instead of merely
  being counted, and the runtime test exercises an actual script subrequest.
- Optional High-Risk mode blocks cross-site active resource classes. A
  Journalist high-risk preset also disables new local history, requests clear
  on clean exit, enables YouTube protection, and retains a labelled standard-
  compatibility escape hatch.
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
- A Brave-style native main menu, bookmark star, local bookmarks bar and
  bookmark manager. Import and export use standard Netscape bookmark HTML;
  only bounded HTTP/HTTPS entries are accepted.
- Local per-user browsing history with a history window, explicit clear,
  optional recording and optional clear-on-clean-exit. ZSEC adds no cloud
  history or bookmark sync. Repeat visits are consolidated, explicitly typed
  addresses are ranked, and recent history/bookmarks feed bounded local
  address-bar suggestions.
- A native notification-area lifecycle: minimize-to-tray is enabled by
  default, the close button exits by default, optional close-to-tray is
  explicit, and the tray menu always exposes a clean Exit command.
- A seven-category native settings surface for privacy, permissions, Shields,
  startup, appearance, downloads and default behavior. Unsupported behavior is
  labelled read-only rather than represented by non-functional switches.
- Address-bar search supports explicit local selection among Brave Search,
  DuckDuckGo, Startpage, Qwant, Ecosia, Microsoft Bing and Google. The selected
  provider receives the query and network metadata; ZSEC does not proxy it.
- Keyboard routes for bookmarks, history, settings, menu, tab selection and
  navigation, with accessible names on primary controls.
- Non-web schemes are rejected; remote debugging and developer tools are off.
- The UI labels the product as `Community 0.3.13` and exposes the exact runtime
  and policy boundary in its About dialog.

When enabled, native YouTube protection runs at document start only on exact
YouTube/YouTube-nocookie hosts. It removes bounded advertising fields from
initial/player JSON, wraps exact player-data fetch responses, blocks reviewed
ad endpoints, hides known promotional containers and activates a visible skip
control when available. It does not seek, accelerate or mute video playback.
Runtime evidence separately reports the DNR probe, native subresource probe,
main-world hook loading and observed interventions; zero interventions is not
called a failure when no ad was served. YouTube can change delivery at any time,
so this is tested coverage rather than a guarantee of permanent ad blocking.
The application is also not antivirus and cannot guarantee protection from
every browser-engine, zero-click, Pegasus-class or other exploit.

## Local browser data and settings

Bookmarks, history and Community shell settings are stored as bounded JSON at
`%LOCALAPPDATA%\TalkToAI\ZSEC Browser\browser-data.json`. The write is atomic,
reparse-point roots/files are refused, bookmark and history counts are bounded,
and stored navigation targets are restricted to HTTP/HTTPS. This file contains
browsing metadata, not passwords or encryption keys. Password entries are stored
separately under `password-vault` using the local encrypted vault and Windows
DPAPI CurrentUser key protection; the manager never displays password values in
its list. The WebView2 profile remains a separate Microsoft-runtime data store
under `User Data`.

Implemented shortcuts:

- `Ctrl+T`, `Ctrl+W`, `Ctrl+L`/`F6`, `Ctrl+R`, `Alt+Left`, `Alt+Right`;
- `Ctrl+D` bookmark current page;
- `Ctrl+Shift+B` toggle bookmarks bar;
- `Ctrl+Shift+O` bookmark manager;
- `Ctrl+H` history and `Ctrl+Shift+Delete` clear history;
- `Ctrl+Shift+P` encrypted password vault;
- `Ctrl+,` settings and `Alt+F` main menu;
- `Ctrl+Tab` / `Ctrl+Shift+Tab` select the next/previous tab.

Permissions remain deny-by-default and do not currently support per-site
exceptions. Dark is the only implemented Community shell theme. Default-browser
registration is not implemented and the installer does not change Windows
defaults. The native strict navigation policy and the extension High-Risk mode
are separate, truthfully labelled controls.

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
