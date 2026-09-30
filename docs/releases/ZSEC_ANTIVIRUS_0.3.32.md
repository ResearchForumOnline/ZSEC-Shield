# ZSEC Antivirus 0.3.32 release evidence

Recorded 30 September 2026. Antivirus source `0.3.32`, direct Windows package
`0.3.32`, Microsoft Store package `0.3.32.0`.

## Public Windows desktop archive

The [stable release](https://github.com/ResearchForumOnline/ZSEC-Shield/releases/tag/v0.3.32-windows)
is tagged at the actual clean build source
`ab8afef28e3ff99b51b84b6d6013283cb93b66a1`. Later Browser-only main changes do not
change this immutable Antivirus source tag.

- ZIP: `zsec-antivirus-desktop-0.3.32-windows-x86_64.zip`
- Bytes: `33,859,917`
- SHA-256: `7c21369d8b95a037432463218b9852f07182329b083ca0d0b5ff2f27125945f0`
- [Verification receipt](ZSEC_ANTIVIRUS_0.3.32.json)
- [Store/source comparison](ZSEC_ANTIVIRUS_0.3.32_STORE_COMPARISON.json)

The actual published ZIP and receipts were downloaded again. Archive size,
SHA-256, checksum sidecar and receipt values matched the reviewed build. All 1,107
manifest file sizes and SHA-256 hashes, plus the archive CRC, passed. The archive
contains the GUI, scanner engine, per-user installer and companion tools.

## Tests and packaged smoke

- Complete unchanged source suite: **301 passed, 14 subtests passed** on
  Windows/Python 3.12.10.
- Focused packaging suite: **43 passed**.
- GUI and CLI PE identities and versions `0.3.32.0`: passed.
- Per-monitor DPI and long-path GUI manifest: passed.
- Packaged CLI synthetic scan and quarantine smoke: passed.
- Packaged GUI `--help`: passed.

The first full source test run hit a Windows PowerShell temporary-path length
limit. The same suite passed with a shorter dedicated temporary directory. The
first new archive recorded a transient local test log as modified-tree provenance;
it was rejected. The published replacement records a clean source tree.

These are source, packaging and bounded synthetic smoke results. A clean-VM
Store-signed install/upgrade/uninstall test was not performed during this release
synchronization. Detection efficacy and primary-antivirus replacement are not
established by these checks.

## Microsoft Store comparison

Partner Center was read on 30 September 2026 and showed the latest
[ZSEC Antivirus Store update](https://apps.microsoft.com/detail/9N1HTFN88B1K)
available as package `0.3.32.0`. This dated portal observation does not establish
which version is installed on an individual device.

The retained pre-signing Store upload is 36,416,537 bytes, SHA-256
`2cb7592011489d41648755bdb1e92effe0f7a8f2a2fe73127d63e7ff3d0d17d6`.
Its project-owned compiled modules were compared without executing code, including
bytecode, constants, variable/name metadata, flags, exception tables and line
tables. Compiler build filenames were excluded.

Of 39 GUI/CLI compiled units, **38 match** the current public-source direct build.
All six companion PowerShell scripts are byte-identical. The differing module is
`zsec_shield.intelligence`: current public source includes validated handling of
Ubuntu livepatch/LSN notices from 30 August commit
`0c210f199a609718f58cb24eb9e0007a947bd5b7`; the retained 28 August Store build
predates it. Third-party libraries and packaging are not asserted identical.

The new direct archive is current public source, not a byte-identical copy of the
Store upload. Both direct executables report Authenticode `NotSigned`. Microsoft
signs and distributes its Store edition separately.

## Application notification metadata

`updates/application-release.json` records the already verified public archive,
its exact hash, byte count, URL and actual build revision. It retains
`notification_only: true`, `auto_install_allowed: false` and `authenticode:
unsigned`.

The existing protected GitHub workflow signs and publishes this metadata using
its established key route. The GitHub release alone does not prove that signed
feed publication completed. Feed status requires separate workflow, public
signature and digest verification.

## Product and privacy boundaries

Keep Microsoft Defender or another supported primary antivirus active. ZSEC is
a user-mode security companion, not a registered primary provider, protected
service or kernel pre-access filter. A bounded scan never certifies that a device
is clean. No private credentials, runtime profiles, vaults, raw local build logs
or secret signing material were published in this synchronization.
