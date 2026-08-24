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
- Video and page fullscreen requests are integrated with the native window;
  `F11` toggles fullscreen and `Esc` exits it. WebView2's supported default GPU
  acceleration path is preserved (ZSEC does not force codec or GPU flags).
- WebView2's built-in password autosave and general form autofill are disabled.
  Independent ZSEC local-vault save and fill options are off by default. When a
  user opts in, save still requires confirmation, fill uses an exact top-level
  HTTPS origin match, and ZSEC does not submit the login form.
- Host objects remain disabled. Web messaging is enabled only while a ZSEC
  credential option is on and accepts a bounded, exact-origin credential
  contract; pages receive no generic filesystem, process, registry,
  PowerShell, antivirus or application bridge.
- A visible New tab control, Ctrl+T, tab close controls, true WebView2 popup
  binding, transactional failure cleanup and a 32-tab resource bound.
- A Brave-style native main menu, bookmark star, local bookmarks bar and
  bookmark manager. Import and export use standard Netscape bookmark HTML;
  the bookmark manager also includes a local Migration centre that discovers
  readable Brave, Chrome, Edge and Firefox profiles, automatically previews safe web URLs,
  deduplicates them, and imports bookmarks directly without requiring an export.
  Password migration remains an explicit browser-exported CSV workflow: ZSEC
  does not decrypt another browser's credential database. Firefox plain recovery
  plain-JSON bookmark backups and recovery sessions may be previewed; recovery
  tabs are URL-only. Compressed Firefox `.jsonlz4` files and `places.sqlite` are
  not read by this build. Cookies, login state, form data,
  passkeys and authentication tokens are never copied. Chromium sessions are not
  parsed; use the source browser's **Bookmark all tabs** command, then migrate
  those bookmarks.
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
- An optional local automation surface can be enabled for a single launch with
`--enable-local-automation`. It creates a random 256-bit session token and a
  current-Windows-user-only named pipe, printing both to the launching process's
  standard error. The five allowed operations are `ping`, `get_state`,
  `activate`, `open_url`, and `open_tab`; messages are newline-delimited JSON
  capped at 4 KiB and URL input is capped at 2,048 characters. Only HTTP/HTTPS
  URLs without embedded credentials are accepted. State exposes only version,
  tab count, active tab index, window visibility, and the enabled flag. It does
  not expose page content, titles, URLs, history, bookmarks, cookies, storage,
  passwords, tokens, downloads, filesystem access, arbitrary script execution,
  DevTools, or a TCP/remote-debugging port. Closing the process destroys the
  token and endpoint. Automation is off on every ordinary launch.
- Command-line launches accept up to 32 URL or search arguments and open each
  in a bounded tab. Switches are never interpreted as navigation input;
  unsupported/non-web schemes become a search query under the selected provider.
- The UI labels the product as `Community 0.3.23` and exposes the exact runtime
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
its list. Save/fill settings and normalized never-save HTTPS origins are stored
in `browser-data.json`, but submitted usernames and passwords are not. The
never-save list can be cleared from Settings > Passwords. The WebView2 profile
remains a separate Microsoft-runtime data store under `User Data`.

Implemented shortcuts:

- `Ctrl+T`, `Ctrl+W`, `Ctrl+L`/`F6`, `Ctrl+R`, `Alt+Left`, `Alt+Right`;
- `Ctrl+D` bookmark current page;
- `Ctrl+Shift+B` toggle bookmarks bar;
- `Ctrl+Shift+O` bookmark manager;
- `Ctrl+H` history and `Ctrl+Shift+Delete` clear history;
- `Ctrl+Shift+P` encrypted password vault;
- `Ctrl+,` settings and `Alt+F` main menu;
- `Ctrl+Tab` / `Ctrl+Shift+Tab` select the next/previous tab.

### Explicit local automation contract

Launch ZSEC Browser from an automation host that can securely capture stderr:

```text
ZSEC Browser.exe --enable-local-automation
```

The host reads the emitted `ZSEC_AUTOMATION_PIPE` and `ZSEC_AUTOMATION_TOKEN`,
connects to that named pipe as the same Windows user, and sends one request per
connection, for example:

```json
{"Token":"SESSION_TOKEN","Command":"open_tab","Url":"https://example.com/"}
```

The response is one bounded JSON line. Tokens must not be logged, persisted, put
on a command line, or shared with another process. There is deliberately no DOM
inspection or click/type API: UI automation and accessibility clients should use
the browser's native accessible controls for those actions, while this IPC
surface remains a small navigation/state capability.

Permissions remain deny-by-default and do not currently support per-site
exceptions. Soft dark, Slate and Midnight blue are the implemented bounded
palettes, with Teal, Blue, Violet and Amber accents. The installer registers
ZSEC Browser as an available per-user handler for HTTP, HTTPS, HTM and HTML;
Windows keeps authority over the protected default-app choice, and the user
confirms any change in Settings. The native strict navigation policy and the
extension High-Risk mode are separate, truthfully labelled controls.

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
