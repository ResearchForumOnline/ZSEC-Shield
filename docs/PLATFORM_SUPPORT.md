# Platform support and delivery status

Last reviewed: 22 August 2026.

ZSEC Antivirus Community currently means a cross-platform command-line scanner
plus an installable, per-user automatic post-change companion. It does not mean a
privileged system service, pre-access real-time provider, signed installer, or
primary-antivirus replacement.

## Release/source distinction

| Surface | Version/status | What it contains |
| --- | --- | --- |
| [Latest public GitHub release](https://github.com/ResearchForumOnline/ZSEC-Shield/releases/tag/v0.1.2) | `0.1.2` prerelease | Earlier on-demand scanner, feed and status implementation plus unsigned native CLI archives |
| Current development branch | `0.3.4` candidate | 0.3.3 feature set plus stricter Windows GUI evidence, bounded event-priority scanning during the first inventory and fail-closed companion presentation; ZSEC Browser remains independently versioned |
| `main` branch | May lag the draft branch | The canonical public source only after reviewed changes merge |

Do not publish or distribute the current feature set under `0.1.2`; that version
and tag already identify different bytes. A passing draft pull request does not
make `0.3.4` released.

## Current public native-archive matrix

The `0.1.2` release exposes these self-contained PyInstaller one-directory CLI
archives. This table describes artifacts, not production desktop support.

| Artifact family | Architecture | Delivery | Automatic companion | Key protection in 0.3.4 development code | Publisher identity | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Windows | x86-64 | ZIP CLI | Per-user Scheduled Task scripts | CurrentUser DPAPI | No Authenticode signature | Automatic post-change companion candidate |
| macOS | Apple silicon (`arm64`) | `tar.gz` CLI | Per-user LaunchAgent scripts | `filesystem-0600-preview`; not production Keychain custody | No Developer ID signature/notarization | Native validation still required |
| Linux | x86-64 | `tar.gz` CLI | systemd-user scripts | `filesystem-0600-preview`; not production Secret Service/TPM custody | No signed DEB/RPM package or repository | Native validation still required |

The GitHub release workflow builds a Windows x86-64 target on `windows-2022`, a
machine-native macOS target on `macos-14`, and Linux x86-64 on `ubuntu-22.04`.
The macOS target name is deliberately `macos-native`: it does not claim a
Universal 2 archive. A release asset's own native manifest and hash—not a broad
website phrase—identify its actual operating system and architecture.

Source installations may run on other Python 3.11+ combinations, and CI runs the
Python test suite on GitHub-hosted Windows, macOS, and Linux with Python 3.11 and
3.13. That is useful core compatibility evidence; it is not a support promise
for every OS version, CPU, filesystem, desktop, or security configuration.

The development candidate's `watch` command is a foreground process using native
filesystem notifications with a disclosed polling fallback. It is not present in
the published `0.1.2` bytes. It performs post-change scans and has
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

ZSEC Browser Community 0.3.5 is a Windows x64 application with its own
native ZSEC window and isolated profile. Microsoft maintains the Evergreen
WebView2 Chromium engine; ZSEC maintains the shell, UI and data-only policy
adapter. The local acceptance run verifies application hashes, the Microsoft
runtime signature, dedicated profile, HTTPS navigation, tracking-parameter
cleanup, a reviewed tracker-domain block and absence of prohibited weakening
flags in the observed runtime processes.

It is not a direct Chromium fork, Brave replacement, public signed installer or
antivirus. The ZSEC executable is unsigned, WebView2's full sandbox/Site
Isolation configuration has not been independently attested, no ZSEC binary
updater has shipped, and macOS/Linux desktop shells do not exist. Public and
cross-platform distribution remain blocked on signing, rollback-resistant
updates, privacy review and a sustained browser security-patch operation.

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
