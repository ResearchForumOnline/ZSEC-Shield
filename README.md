# ZSEC Antivirus + ZSEC Browser

![ZSEC Antivirus launch artwork](assets/brand/zero-security-hero.png)

**ZSEC Antivirus Community is a working cross-platform scanner with automatic
per-user post-change monitoring, authenticated encrypted quarantine, signed
data-only rules, health evidence, and reversible Windows/macOS/Linux launchers.**
This repository also contains ZSEC Browser Shields, a working local privacy layer
for Chromium-family browsers, plus ZSEC Browser Community: a visible Windows
browser shell powered by Microsoft's Evergreen WebView2 Chromium runtime. The ZSEC
binary is not a maintained Chromium fork or publisher-signed public browser release.

ZSEC Shield is a deterministic, non-AI file scanner for Python 3.11+. It hashes
regular files with SHA-256, applies exact byte and digest rules, verifies
Ed25519-signed data-only rule feeds, produces structured JSON, and can move an
explicitly selected match into recoverable encrypted quarantine. The Community
channel can also remain in the foreground and automatically scan file create and
change events, with a disclosed polling fallback, anti-starvation debounce,
verified-file metadata reconciliation, and cache-independent full sweeps.
The CLI routes exact-rule and conservative review-provider work through a bounded,
path-free child process;
the broker streams bytes from its already validated descriptor and independently
checks the SHA-256 result. This limits worker crash/state persistence and fails
closed on protocol or digest disagreement. The child currently retains the
invoking user's authority, so it is process separation—not a reduced-privilege
sandbox or evidence that the hostile-parser replacement gate is complete.

Community 0.3.12 is unsigned and is not itself a replacement primary antivirus on
any platform. A version tag or passing workflow is not artifact acceptance: use the
published source revision, SHA-256, manifest, and installed-runtime evidence for the
exact package. ZSEC still has no Windows minifilter/AMSI/ELAM stack, macOS Endpoint
Security system extension, Linux fanotify broker, production platform-keychain
profile, publisher-signed installer, or independent efficacy certification. Those
are explicit engineering and release gates, not features claimed by a dashboard.
See the [Windows programme](docs/FULL_ANTIVIRUS_PROGRAM.md),
[macOS programme](docs/MACOS_DESKTOP_PROGRAM.md),
[Linux programme](docs/LINUX_DESKTOP_PROGRAM.md), and machine-readable
[replacement-readiness contract](docs/REPLACEMENT_READINESS.md).

## What works now and the remaining replacement gates

| Layer | Current evidence | Replacement-antivirus gate |
| --- | --- | --- |
| Scan engine | Broker-verified streaming SHA-256 and exact byte/digest rules plus bounded review-only PE metadata, script-chain and ZIP central-directory checks; cache-only Windows Authenticode evidence; deterministic JSON | AppContainer/sandboxed hostile-format and document engines, locked malware and cleanware evaluation |
| Quarantine | Per-object AES-256-GCM, automatic Windows DPAPI key sealing, authenticated ZBA metadata, tamper-fail restore | Windows service key isolation, TPM/CNG root, crash and recovery certification |
| Updates | Strict Ed25519 signed data-only feed with expiry and rollback checks | Authenticode plus threshold TUF metadata, staged binary/rule/driver rollback |
| Automatic file monitoring | Per-user Windows Scheduled Task, macOS LaunchAgent and Linux systemd-user packages; native events, baseline, anti-starvation debounce, bounded raw/pending work, verified-file metadata reconciliation, cache-independent full sweeps, heartbeat and rollback | Windows FltMgr/AMSI/ELAM; macOS Endpoint Security; Linux fanotify—with platform-specific deadline and failure tests |
| Recovery self-test | Isolated synthetic encrypted-quarantine, authenticated-restore, no-overwrite, tamper-rejection and device-key loss/recovery drill | Independent crash, corruption, key-recovery, restore and rollback certification on the exact release |
| Desktop intelligence | 957-record initial CISA/MSRC/Apple/Ubuntu catalog with strict parsing, raw/semantic digests, atomic update and rollback state | Version applicability, independently validated detection-content providers, signed staged rollout |
| Platform trust | Read-only inventory | Windows WSC/MVI; Apple entitlement, Developer ID and notarization; signed DEB/RPM repositories and enforced Linux service confinement |
| Browser | Testable ZSEC Browser Shields MV3 extension; installed Windows WebView2 Community shell with isolated profile and runtime acceptance evidence | Maintained Chromium distribution, upstream security cadence, signed updater and browser regression fleet |

Your existing antivirus and native operating-system protections should remain
active while these gates are developed in isolated environments and tested on
dedicated pilot hardware. No placeholder driver/provider, fake registration,
unsigned privileged package, or security-control bypass belongs on a real machine.

## Security boundaries

- Scanning is local and runs either on demand or as explicit foreground post-change
  monitoring. No AI model, API key, telemetry endpoint, or cloud upload is used.
- Foreground protection does not mediate file access, run as a service, register as
  the operating-system antivirus, or replace existing protection. Queue/backend/
  trust failures produce an incomplete result, and state/quarantine paths are
  excluded before events are queued.
- Symlinks and Windows reparse points are not followed. Special files are skipped.
- Recursive scans stay on the starting filesystem by default.
- Files larger than 64 MiB are skipped by default; the limit is explicit and
  reported.
- Content inspection uses a versioned 1 MiB-bounded process protocol,
  a bounded response deadline and periodic worker replacement. Crash, timeout, malformed
  output, digest disagreement and unavailable-worker outcomes are incomplete;
  there is no in-process compatibility fallback. The worker is not yet
  AppContainer/restricted-token isolated and may retain current-user filesystem
  and network authority.
- PE, script and ZIP observations are conservative review evidence only. ZIPs are
  never extracted, inspection retains at most 16 MiB, and these observations can
  never authorize quarantine. Informational metadata alone does not turn a scan
  into a review outcome.
- Quarantine is disabled unless `--quarantine` is present.
- New quarantine objects use a fresh random AES-256 key, AES-GCM authentication,
  an automatically DPAPI-sealed device root on Windows, and a MAC over operational
  metadata. The macOS and Linux filesystem-key fallback remains development-only
  and is not production platform key protection. No routine password prompt is required.
- Restore never overwrites an existing destination, and the verified recovery
  object is retained after restore.
- Feed signatures, schemas, timestamps, key status, sequence numbers, and payload
  digests are checked before feed rules are used.
- Feed objects accept only SHA-256 and exact literal-byte rules. Command, script,
  package, firewall, URL-action, and configuration fields are rejected.
- If a feed, trust store, or rollback record is invalid, every feed rule is ignored
  and the command reports an incomplete result. Built-in rules remain available.

See the [threat model](docs/THREAT_MODEL.md), [ZSV2 vault
profile](specs/ZSV2.md), [research integration](docs/RESEARCH_INTEGRATION.md),
[bounded exact-rule worker protocol](docs/EXACT_RULE_WORKER.md), and
[feed format](docs/FEED_FORMAT.md).

## ZBA and ZMath integration

Zero Boundary Algebra 1.1 is used where it is strongest: typed entering,
boundary, emerging, rejected, sealed, recursion, and lineage states. The record
and original file commitment are canonicalized and authenticated as AES-GCM AAD.
Changing the ZBA phase, evidence state, path, digest, rule matches, or object
identity causes restore to fail.

ZBA is not marketed as a cipher. AES-GCM, HKDF, DPAPI/CNG, signatures, isolation,
and release engineering provide the security properties. The new `ZSV2`
namespace avoids silently combining three incompatible older formats that all
used the `ZME1` name.

## ZSEC Browser and ZSEC Browser Shields

The open-source extension lives in
[`browser/zeroq-shields`](browser/zeroq-shields). It provides 39 packaged local
network blockers, two tracking-link cleaners, a per-site pause switch, and
best-effort YouTube skip/nuisance cleanup. Community 0.5.2 adds 49,464 pinned
EasyList network rules without Acceptable Ads and retains the optional
High-Risk Browsing profile: two fixed local rules block top-level plaintext HTTP
navigation and third-party scripts, subframes, objects, and WebSockets. It is off
by default, may materially break sites, and is exposure reduction rather than
spyware detection or zero-day immunity. The extension has no analytics endpoint,
remote code, TLS interception, replacement ads, or affiliate rewriting.

```powershell
cd browser\zeroq-shields
npm test
npm run validate
npm run test:runtime
```

The runtime test uses an isolated temporary Chromium profile and local-only test
servers; it never opens the normal user profile. See the
[bounded mercenary-spyware defence analysis](docs/MERCENARY_SPYWARE_DEFENCE.md)
for the exact enforced decision points and non-claims, and the
[journalist and high-risk user profile](docs/JOURNALIST_HIGH_RISK_PROFILE.md)
for the implemented-now versus release-gated protection programme.

The native Windows Community desktop source lives in
[`browser/zsec-desktop-preview`](browser/zsec-desktop-preview). Version 0.3.12
provides a modern rounded dark interface, managed tabs and popups, local
bookmarks and bounded history, typed-address suggestions, seven selectable
search providers, tray controls, a native settings surface and a separate
WebView2 profile. Its request hook receives document and subresource requests
across all WebView2 resource-source kinds, blocks reviewed third-party tracker
subresources and records a real local subresource probe instead of treating a
configuration self-test as runtime proof. It retains default-deny site
permissions, certificate-error cancellation, explicit downloads, HTTPS
upgrading, Microsoft Balanced tracking prevention, and the automatically loaded
exact-ID Browser Shields 0.5.2 MV3 engine with 49,464 pinned EasyList-derived
network rules, 21 tracking-parameter cleaners and 19 selected packaged YouTube
cosmetic selectors. Bounded YouTube protection adds reviewed endpoint blocking
and exact-host, document-start player-data sanitisation without seeking,
accelerating or muting playback; site changes can still evade it. A Journalist
high-risk preset disables new app-history recording, requests app-history
cleanup on clean exit, and enables the native strict cross-site and YouTube
controls. It is exposure reduction, not an ephemeral profile, spyware verdict,
Pegasus detector or exploit guarantee. The build verifies the pinned Microsoft
SDK package against the official NuGet SHA-512 and a locked SHA-256;
installation requires a validly Microsoft-signed Evergreen runtime.

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\windows\browser\Build-ZsecBrowserPreview.ps1
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\windows\browser\Install-ZsecBrowserPreview.ps1 -PlanOnly
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\windows\browser\Install-ZsecBrowserPreview.ps1 -Open
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\windows\browser\Test-ZsecBrowserPreviewRuntime.ps1
```

The per-user installer registers ZSEC Browser with Windows Default Apps for
`http`, `https`, `.htm`, and `.html`. It does not modify protected `UserChoice`
values. Choose **Set as default browser** in ZSEC Browser's main menu and confirm
the desired associations in Windows Settings. Status reports registration and
the current user-confirmed associations; uninstall removes only ZSEC-owned
registration values.

The extension and desktop shell are working Community layers, not a separately
maintained Chromium distribution. The direct ZSEC Community executable is unsigned
and no rollback-resistant ZSEC binary updater has shipped. Keep the
Microsoft Evergreen runtime and existing browser/operating-system protections
updated; do not bypass SmartScreen to run an unsigned ZSEC binary.

The canonical product pages are
[talktoai.org/zero-security](https://talktoai.org/zero-security/) and
[talktoai.org/zero-browser](https://talktoai.org/zero-browser/). Exact verified
build and install guidance lives at
[ZSEC Antivirus downloads](https://talktoai.org/zero-security/download/) and
[ZSEC Browser Shields installation](https://talktoai.org/zero-browser/download/).

## Platform scope

The same public scanner, feed, evidence, and encrypted-container core runs on all
three desktop families. Production enforcement and key custody must use each
operating system's supported security architecture:

| Desktop | Current public build | Production programme—not shipped |
| --- | --- | --- |
| Windows 10/11 | On-demand scanning; per-user automatic ReadDirectoryChangesW monitoring; health evidence; DPAPI-backed quarantine; WebView2 ZSEC Browser Community shell | FltMgr minifilter, protected service, x86/x64 AMSI, ELAM, approved WSC/MVI integration; signed maintained browser distribution/updater |
| macOS | On-demand scanning; per-user LaunchAgent with FSEvents; read-only inventory; filesystem key root is development-only | Universal 2 app, Endpoint Security system extension, Keychain root, Developer ID, Hardened Runtime and notarization |
| Linux | On-demand scanning; hardened systemd-user companion with inotify; read-only inventory; filesystem key root is development-only | Narrow distro/kernel matrix, fanotify broker, confined daemon/workers, signed DEB/RPM packages and repositories |

Inventory adapters identify only basic OS/runtime context. They do not claim that
patches, Microsoft Defender, XProtect, Gatekeeper, SIP, packages, SELinux,
AppArmor, or another antivirus are healthy.

## Install the Community build

Create an isolated environment with Python 3.11 or newer:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\zsec-shield.exe --version
```

On macOS or Linux:

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .
.venv/bin/zero-security --version
```

`zsec-antivirus` is the product command. `zero-security` and `zsec-shield` remain
compatible aliases for existing scripts.

The runtime dependencies are `cryptography`, used for Ed25519 verification,
AES-256-GCM quarantine, and HKDF key separation, plus the pinned `watchdog`
filesystem-event observer used by foreground post-change protection.

## Native archives

Versioned GitHub Releases can include self-contained native CLI archives for Windows,
macOS, and Linux. These use an inspectable PyInstaller one-directory layout, not an
installer or privileged service. Keep the executable beside its `_internal` directory.

Each archive contains `NATIVE-MANIFEST.json`, per-file SHA-256 values, component and
license metadata, the empty local trust store, and operating documentation. Release
assets include SHA-256 checksum files. See the
[native distribution guide](docs/NATIVE_DISTRIBUTION.md) before downloading or
redistributing an archive.

The workflow does not generate signing keys or perform Authenticode, Apple Developer
ID/notarization, or Linux package signing. A checksum verifies bytes, not publisher
identity, and unsigned Community builds may trigger platform warnings. Follow local
security policy; do not bypass operating-system protections merely to run ZSEC.

Build an archive locally on its target operating system:

```bash
python -m pip install -e ".[native]"
python packaging/native_release.py build
```

PyInstaller is not a cross-compiler. The build smoke-tests `--version`, the stable
`status --json` [bridge contract](docs/STATUS_CONTRACT.md), and the intentionally
non-successful replacement guard before creating anything under `dist/native`.

## Quick start

Scan one file or directory:

```bash
zsec-shield check ./downloads
```

Scan several roots and save a machine-readable report:

```bash
zsec-shield check ./downloads ./incoming --report ./reports/check.json --json
```

Automatically scan new or modified files while the command remains in the
foreground (quarantine stays off):

```bash
zero-security watch ./downloads ./incoming
```

For a bounded session with newline-delimited events and a final atomic report:

```bash
zero-security watch ./incoming \
  --duration-seconds 300 \
  --json-lines \
  --report ./reports/watch.json
```

The native backend is attempted first and initial startup may fall back to polling
with a visible record. Use `--backend native` to require native events or
`--backend polling` deliberately. This is post-change user-mode monitoring, not
pre-access real-time enforcement. Keep the existing antivirus active. See the
[foreground watch contract](docs/FOREGROUND_WATCH_MODE.md).

### ZSEC Antivirus automatic desktop companion

The Windows Community channel includes review-first scripts for a reversible,
current-user logon task protecting a bounded set of current-user folders. Start with the
read-only plan; repository tests never execute task registration:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned `
  -File .\windows\companion\Install-ZsecAntivirusCompanion.ps1 -PlanOnly
```

The generated task runs at limited user privilege, permits one instance, uses
bounded event/log/restart settings, and writes a 30-second health heartbeat. Its
status combines task/action/hash/process proof with supported aggregate Windows
Security Center health and separate Defender feature, tamper, intelligence,
scan and service evidence while keeping raw provider `productState`
uninterpreted. The Windows GUI can request only a Defender intelligence update,
quick scan or confirmed full scan. A three-state handoff interlock distinguishes
blocked, operator-cutover-eligible and verified states, but it does not remove a
provider or make ZSEC the enforcing antivirus. Microsoft Defender supplies
supported real-time enforcement when confirmed active. ZSEC never changes
Defender preferences or exclusions, registers itself with Windows Security, or
uninstalls Malwarebytes. See the [ZSEC Antivirus Windows companion
guide](windows/companion/README.md).

Equivalent current-user LaunchAgent and systemd-user packages are included for
macOS and Linux. They pin the selected CLI by SHA-256, require the native event
backend, keep bounded evidence logs, preserve platform security controls, and
offer plan/status/uninstall commands. Their source and native-test boundary is in
the [macOS/Linux companion guide](packaging/companion/README.md).

### Daily desktop security intelligence

The data-only updater ingests strict, allowlisted advisory metadata from CISA,
Microsoft MSRC, Apple and Ubuntu. It validates source identity, HTTPS redirects,
sizes, timestamps, schema, exact raw hashes, semantic rollback state and ZBA-typed
provenance before an atomic catalog update. It never downloads malware, executes
remote content, creates scanner signatures or applies remediation:

```bash
python scripts/update_desktop_intelligence.py --dry-run --json
python scripts/update_desktop_intelligence.py --json
```

See the [desktop intelligence contract](docs/DESKTOP_INTELLIGENCE.md).

Inspect status and read-only inventory:

```bash
zsec-shield status --json
zsec-shield inventory --json
```

Prove that the current build must keep the existing antivirus active:

```bash
zero-security replacement-readiness --json
zero-security replacement-readiness --platform windows --json
zero-security replacement-readiness --platform macos --json
zero-security replacement-readiness --platform linux --json
zero-security recovery-drill --json
```

The guard returns `eligible_for_primary_replacement: false`, disables automatic
and manual overrides, and exits `2` on the current release. It does not uninstall,
disable, reconfigure, or add exclusions to any protection product.

Desktop integrations must follow the [fail-closed status contract](docs/STATUS_CONTRACT.md).

The `scan` command is an alias for `check`.

### EICAR test detection

The built-in rule set detects both the exact bytes and SHA-256 of the canonical
EICAR antivirus test file. EICAR is a harmless test pattern, not malware. Existing
antivirus software may block or remove it before ZSEC Shield can open it, so only
use the official EICAR test instructions in an isolated test directory. The test
suite validates the signature in memory and does not write the canonical EICAR
content to disk.

## Quarantine and recovery

A normal check does not alter scanned content:

```bash
zsec-shield check ./incoming
```

Quarantine requires the explicit flag:

```bash
zsec-shield check ./incoming --quarantine --report ./reports/quarantine.json
```

For each matched file, ZSEC Shield creates an encrypted private recovery object
while hashing the same opened source handle. A fresh random content key is wrapped
to the local device root. Immutable metadata and the typed ZBA boundary record are
authenticated as AAD; mutable metadata is authenticated with a separate derived
MAC. The original is removed only if it still matches the scan result. If removal
fails, metadata says `copy_only` and the command returns an incomplete exit code.
This is not reported as a successful quarantine.

List and restore entries:

```bash
zsec-shield quarantine list --json
zsec-shield quarantine restore 00000000-0000-0000-0000-000000000000
zsec-shield quarantine restore ENTRY-ID --destination ./recovered/sample.bin
```

Restore requires an existing, non-reparse parent directory and refuses to overwrite.
There is intentionally no purge command in this MVP.

## Signed feed update

The packaged keyring is intentionally empty: this MVP does not invent a production
trust anchor. Pin an operator-controlled Ed25519 public key in a keyring and pass it
explicitly, set `ZSEC_SHIELD_KEYRING`, or place it at
`STATE_DIR/trusted_keys.json`.

```bash
zsec-shield --keyring ./trusted_keys.json update --file ./feed.json --json
zsec-shield --keyring ./trusted_keys.json update --url https://security.example/feed.json --json
zsec-shield --keyring ./trusted_keys.json check ./incoming
```

Remote URLs must use credential-free HTTPS and remain HTTPS through at most three
redirects. Feeds are capped at 2 MiB. An update is verified before installation;
older sequences and sequence reuse with different signed content are rejected.

The feed supplies detection data only. It cannot request execution, deletion,
quarantine, package installation, network access, or system changes.

## State directories

Override the state root with global `--state-dir` or `ZSEC_SHIELD_HOME`.
Defaults are:

| Platform | Default |
| --- | --- |
| Windows | `%LOCALAPPDATA%\ZSEC\Shield` |
| macOS | `~/Library/Application Support/ZSEC Shield` |
| Linux | `$XDG_STATE_HOME/zsec-shield` or `~/.local/state/zsec-shield` |

The state root is excluded automatically when it lies beneath a requested scan root.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan or bounded watch completed with no configured rule match, or diagnostic/update command succeeded. |
| `1` | One or more configured rules matched and the scan/watch otherwise completed. |
| `2` | Incomplete/blocked operation: unreadable or changing file, invalid feed, lost watch coverage, unsafe restore, or replacement not authorized. |
| `130` | Foreground watch or another operation was interrupted by the operator. |

A `0` is deliberately phrased as “no configured rule matches,” never “clean.”

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
ruff check src tests
mypy src/zsec_shield
python -m build
python packaging/native_release.py build
```

GitHub Actions tests Python 3.11 and 3.13 on Windows, macOS, and Linux, with a
separate lint/build job. A version tag builds source and native archives, verifies
their metadata and checksums, and creates a draft GitHub Release for human review.

## License

Apache License 2.0. See [LICENSE](LICENSE).

The product model is [open core](OPEN_CORE.md): the public core remains useful and
auditable; any proprietary cloud intelligence, licensed OEM engine, or enterprise
control service is identified separately. Hidden or obfuscated code is not called
open source and is never treated as a security boundary.
