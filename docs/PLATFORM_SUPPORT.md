# Platform support and delivery status

Last reviewed: 25 August 2026.

ZSEC Antivirus Community 0.3.27 means a Windows graphical protection control plane
plus a cross-platform command-line scanner and installable, per-user automatic
post-change companion. On Windows, Microsoft Defender may supply the supported
real-time/on-access enforcement only when the live status contract verifies it.
ZSEC itself is not a privileged system service, pre-access provider, signed
installer, or registered primary-antivirus replacement.

## Release/source distinction

| Surface | Version/status | What it contains |
| --- | --- | --- |
| Current Windows desktop source | `0.3.27` | Defender-backed Windows control plane, bounded local scanning, self-restarting post-change monitoring, encrypted quarantine, signed data-only feeds, and browser controls described below |
| Unpublished artifact checkpoint | [`v0.3.11`](https://github.com/ResearchForumOnline/ZSEC-Shield/tree/v0.3.11) | Exact extracted-package acceptance found that the no-argument Antivirus installer and nested companion synchronizer could receive an empty sibling root under built-in Windows PowerShell 5.1; the draft release was not promoted or accepted for installation |
| Unpublished source checkpoint | [`v0.3.10`](https://github.com/ResearchForumOnline/ZSEC-Shield/tree/v0.3.10) | Browser artifact acceptance found non-deterministic compiler output and machine-specific build paths in the packaged manifest, so this checkpoint was not promoted to an accepted Browser package |
| Published release rejected for site cutover | [`v0.3.9`](https://github.com/ResearchForumOnline/ZSEC-Shield/tree/v0.3.9) | Rejected for the TalkToAI site cutover because the installed Windows status path could reject Defender evidence when `FullScanAge` carried the no-scan sentinel; its immutable bytes remain available for historical verification and should not be used for provider-handoff decisions |
| Historical source checkpoint | [`v0.3.8`](https://github.com/ResearchForumOnline/ZSEC-Shield/tree/v0.3.8) | Source tag only; it was not published as an accepted GitHub Release because its bundled release-status documentation failed the pre-publication audit |
| Browser Shields package | `0.5.2` | Separately versioned Manifest V3 data rules and local controls for compatible Chromium-family browsers |

Version names do not identify accepted bytes by themselves. Require the exact tag
revision, platform manifest, SHA-256, authenticated release asset, and relevant
installed-runtime evidence. A tag, workflow run, draft release, or locally built
archive is not a published accepted release on its own.

## Native-archive build matrix

The 0.3.12 release workflow builds these self-contained PyInstaller one-directory
CLI archives. Publication requires every release gate to pass. This table
describes bounded build targets, not proof that a particular byte sequence was
accepted, production desktop support, or a platform antivirus certification.

| Artifact family | Architecture | Delivery | Automatic companion | Key protection in Community 0.3.12 | Publisher identity | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Windows | x86-64 | ZIP CLI | Per-user startup launcher scripts | CurrentUser DPAPI | No Authenticode signature | Workflow build target; exact asset manifest and checksum required; post-change companion, not primary AV |
| macOS | Workflow manifest identifies native architecture | `tar.gz` CLI | Per-user LaunchAgent scripts | `filesystem-0600-preview`; not production Keychain custody | No Developer ID signature/notarization | Workflow build target; exact asset manifest and checksum required; physical-hardware GUI/provider qualification absent |
| Linux | x86-64 | `tar.gz` CLI | systemd-user scripts | `filesystem-0600-preview`; not production Secret Service/TPM custody | No signed DEB/RPM package or repository | Workflow build target; exact asset manifest and checksum required; distro package/provider qualification absent |

The GitHub release workflow builds a Windows x86-64 target on `windows-2022`, a
machine-native macOS target on `macos-14`, and Linux x86-64 on `ubuntu-22.04`.
The macOS target name is deliberately `macos-native`: it does not claim a
Universal 2 archive. A release asset's own native manifest and hash—not a broad
website phrase—identify its actual operating system and architecture.

Source installations may run on other Python 3.11+ combinations, and CI runs the
Python test suite on GitHub-hosted Windows, macOS, and Linux with Python 3.11 and
3.13. That is useful core compatibility evidence; it is not a support promise
for every OS version, CPU, filesystem, desktop, or security configuration.

The 0.3.12 `watch` command is a foreground process using native filesystem
notifications with a disclosed polling fallback. It performs post-change scans and has
`pre_access_enforcement: false` and `real_time_protection: false`; the existing
platform/endpoint provider must remain active.

## Safe Community use

1. Use an artifact tied to an exact version and source revision.
2. Verify its SHA-256 and GitHub provenance, while remembering that a checksum
   beside an unsigned archive is not publisher identity.
3. Start in a disposable VM/profile or with copied, non-sensitive test files.
4. Keep the existing antivirus and native operating-system controls enabled.
5. Interpret “no configured rule matches” literally; it is not “the system is
   clean.”
6. Test quarantine and authenticated restore only on disposable copies before
   relying on the workflow.
7. Do not bypass SmartScreen, Gatekeeper, package policy, or another antivirus
   warning merely to run an unsigned Community build on an everyday computer.
8. Use `zero-security replacement-readiness --json`; current exit `2` is an
   intentional block on provider removal and cutover.

## Browser desktop application

ZSEC Browser Community 0.3.12 is an unsigned Windows x64 application with its own
native ZSEC window and isolated profile. Microsoft maintains the Evergreen
WebView2 Chromium engine; ZSEC maintains the shell, UI and data-only policy
adapter. It includes managed tabs, tray controls, bookmarks, local typed-history
suggestions, seven selectable search providers, all-resource native filtering, a
bounded exact-host YouTube protection hook, and a Journalist preset. The installed
acceptance run verifies application hashes, the Microsoft runtime signature,
dedicated profile, HTTPS navigation, tracking cleanup, configured policy, an
actual blocked local script-subresource probe, YouTube hook loading, and absence
of prohibited weakening flags in observed runtime processes.

It is not a direct Chromium fork, a proven Brave replacement, publisher-signed
installer, antivirus, spyware detector, or exploit-immunity product. YouTube and
other sites can change around blocking logic. The ZSEC executable is unsigned,
WebView2's full sandbox/Site Isolation configuration has not been independently
attested, no ZSEC binary updater has shipped, and macOS/Linux graphical browser
shells do not exist. A high-risk user must keep WebView2 and Windows patched and
use specialist incident response when compromise is suspected.

## Platform boundaries

### Windows

- Keep Malwarebytes or Microsoft Defender active.
- The preview is not registered with Windows Security and has no production
  real-time minifilter, AMSI provider, ELAM driver, or protected service.
- Replacement remains unavailable until the exact publisher-signed release
  passes the [Windows G0-G8 programme](FULL_ANTIVIRUS_PROGRAM.md), Windows
  Security reads Zero active/current, coexistence passes, and rollback restores
  the prior or operating-system provider.

### macOS

- Keep XProtect, Gatekeeper, SIP, FileVault, and Apple security updates enabled.
- The preview has no notarized native app, production Endpoint Security system
  extension, or background provider and should not request Full Disk Access.
- The filesystem-only development key root is not acceptable for a production
  macOS vault. The [macOS programme](MACOS_DESKTOP_PROGRAM.md) requires a new
  versioned Keychain-backed profile and Apple-supported consent/signing paths.

### Linux

- Keep distribution security updates, SELinux/AppArmor where configured, and
  any existing endpoint or antivirus agent enabled.
- The preview has no supported fanotify broker, confined background daemon,
  signed DEB/RPM repository, or production real-time enforcement.
- Linux has no universal Windows-Security-Center-equivalent provider registry.
  The [Linux programme](LINUX_DESKTOP_PROGRAM.md) therefore treats discovery,
  coexistence, activation, health, and rollback as explicit evidence problems.

## Production desktop programmes

| Programme | Initial production boundary | Replacement gate |
| --- | --- | --- |
| Windows | Exact Windows 10/11 builds and architectures in the signed candidate manifest | FltMgr/AMSI/ELAM/protected service, approved WSC/MVI path, efficacy, compatibility and rollback evidence |
| macOS | Proposed supported macOS 14/15/26 matrix; Universal 2 after real hardware qualification | Endpoint Security entitlement/system extension, consent, Keychain vault, Developer ID, Hardened Runtime, notarization and independent evidence |
| Linux | Proposed narrow Ubuntu/Debian/Fedora x86-64 matrix with exact kernels/filesystems/MAC policy | fanotify mediation, confined components, signed packages/repositories, distro-specific efficacy/coexistence and transactional rollback |

Each programme is a target specification. Its existence in the repository is not
evidence that the component has been built, installed, certified, or released.

## Removal and migration

The native preview is an archive, not an installer. Removing its extracted code
does not authorize deletion of the state directory or encrypted quarantine.
Preserve recovery objects and keys until every object has been restored, exported
with a tested recovery route, or explicitly and irreversibly destroyed.

Zero Security has no current automatic-removal function for Malwarebytes or any
other product. A future installer may offer a named, user-confirmed provider
change only after the [replacement-readiness contract](REPLACEMENT_READINESS.md)
is satisfied for the exact release and the rollback path has been exercised.
