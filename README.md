# Zero Security / ZSEC Shield

![Zero Security launch artwork](assets/brand/zero-security-hero.png)

**Zero Security is a cross-platform scanning and foreground post-change protection
preview, plus an engineering programme for proper supported Windows, macOS, and
Linux antivirus editions.**
This repository contains its already working, auditable ZSEC Shield engine and
the next production foundations: signed data-only protection feeds, automatic
authenticated encrypted quarantine, ZBA-bound provenance, and the ZeroQ Shields
browser protection preview.

ZSEC Shield is a deterministic, non-AI file scanner for Python 3.11+. It hashes
regular files with SHA-256, applies exact byte and digest rules, verifies
Ed25519-signed data-only rule feeds, produces structured JSON, and can move an
explicitly selected match into recoverable encrypted quarantine. The development
candidate can also remain in the foreground and automatically scan file create and
change events, with a disclosed polling fallback, duplicate-event debounce, and
periodic reconciliation.

The current tagged build is still an on-demand preview, not a replacement
antivirus on any platform. It has no Windows minifilter/AMSI/ELAM stack, macOS
Endpoint Security system extension, Linux fanotify broker, production
platform-keychain profile, publisher-signed installer, or independent efficacy
certification. Those are explicit engineering and release gates, not features
claimed by a mock dashboard. See the [Windows programme](docs/FULL_ANTIVIRUS_PROGRAM.md),
[macOS programme](docs/MACOS_DESKTOP_PROGRAM.md),
[Linux programme](docs/LINUX_DESKTOP_PROGRAM.md), and machine-readable
[replacement-readiness contract](docs/REPLACEMENT_READINESS.md).

## What is real now, and what comes next

| Layer | Current evidence | Replacement-antivirus gate |
| --- | --- | --- |
| Scan engine | Streaming SHA-256, exact byte/digest rules, EICAR wiring test, deterministic JSON | Sandboxed PE/script/document/archive engines, locked malware and cleanware evaluation |
| Quarantine | Per-object AES-256-GCM, automatic Windows DPAPI key sealing, authenticated ZBA metadata, tamper-fail restore | Windows service key isolation, TPM/CNG root, crash and recovery certification |
| Updates | Strict Ed25519 signed data-only feed with expiry and rollback checks | Authenticode plus threshold TUF metadata, staged binary/rule/driver rollback |
| Automatic file monitoring | Foreground post-change event scans with baseline, debounce, bounded queue and polling fallback; no pre-access enforcement | Windows FltMgr/AMSI/ELAM; macOS Endpoint Security; Linux fanotify—with platform-specific deadline and failure tests |
| Platform trust | Read-only inventory | Windows WSC/MVI; Apple entitlement, Developer ID and notarization; signed DEB/RPM repositories and enforced Linux service confinement |
| Browser | Testable MV3 ZeroQ Shields extension | Maintained Chromium build, upstream security cadence, signed updater and browser regression fleet |

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
- Quarantine is disabled unless `--quarantine` is present.
- New quarantine objects use a fresh random AES-256 key, AES-GCM authentication,
  an automatically DPAPI-sealed device root on Windows, and a MAC over operational
  metadata. The macOS and Linux filesystem-key fallback remains a preview and is
  not production platform key protection. No routine password prompt is required.
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
and [feed format](docs/FEED_FORMAT.md).

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

## Zero Browser and ZeroQ Shields

The open-source extension preview lives in
[`browser/zeroq-shields`](browser/zeroq-shields). It provides 38 packaged local
network blockers, two tracking-link cleaners, a per-site pause switch, and
best-effort YouTube skip/nuisance cleanup. It has no analytics endpoint, remote
code, TLS interception, replacement ads, or affiliate rewriting.

```powershell
cd browser\zeroq-shields
npm test
npm run validate
```

The extension is an early protection layer, not yet a Chromium browser binary.
The canonical product pages are
[talktoai.org/zero-security](https://talktoai.org/zero-security/) and
[talktoai.org/zero-browser](https://talktoai.org/zero-browser/). Exact preview
downloads and install guidance live at
[Zero Security downloads](https://talktoai.org/zero-security/download/) and
[ZeroQ Shields installation](https://talktoai.org/zero-browser/download/).

## Platform scope

The same public scanner, feed, evidence, and encrypted-container core runs on all
three desktop families. Production enforcement and key custody must use each
operating system's supported security architecture:

| Desktop | Current public build | Production programme—not shipped |
| --- | --- | --- |
| Windows 10/11 | On-demand scanning, foreground ReadDirectoryChangesW monitoring, read-only inventory and DPAPI-backed preview quarantine | FltMgr minifilter, protected service, x86/x64 AMSI, ELAM, approved WSC/MVI integration |
| macOS | On-demand scanning, foreground FSEvents monitoring and read-only inventory; filesystem key root is preview-only | Universal 2 app, Endpoint Security system extension, Keychain root, Developer ID, Hardened Runtime and notarization |
| Linux | On-demand scanning, foreground inotify monitoring and read-only inventory; filesystem key root is preview-only | Narrow distro/kernel matrix, fanotify broker, confined daemon/workers, signed DEB/RPM packages and repositories |

Inventory adapters identify only basic OS/runtime context. They do not claim that
patches, Microsoft Defender, XProtect, Gatekeeper, SIP, packages, SELinux,
AppArmor, or another antivirus are healthy.

## Install for evaluation

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

`zero-security` is the product command. `zsec-shield` remains a compatible alias
for existing scripts.

The runtime dependencies are `cryptography`, used for Ed25519 verification,
AES-256-GCM quarantine, and HKDF key separation, plus the pinned `watchdog`
filesystem-event observer used by foreground post-change protection.

## Native archives

Versioned GitHub Releases can include self-contained native CLI archives for Windows,
macOS, and Linux. These use an inspectable PyInstaller one-directory layout, not an
installer or privileged service. Keep the executable beside its `_internal` directory.

Each archive contains `NATIVE-MANIFEST.json`, per-file SHA-256 values, component and
license metadata, the empty preview trust store, and operating documentation. Release
assets include SHA-256 checksum files. See the
[native distribution guide](docs/NATIVE_DISTRIBUTION.md) before downloading or
redistributing an archive.

The workflow does not generate signing keys or perform Authenticode, Apple Developer
ID/notarization, or Linux package signing. A checksum verifies bytes, not publisher
identity, and unsigned preview builds may trigger platform warnings. Follow local
security policy; do not bypass operating-system protections merely to run the preview.

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

Inspect status and read-only inventory:

```bash
zsec-shield status --json
zsec-shield inventory --json
```

Prove that the preview must keep the current antivirus active:

```bash
zero-security replacement-readiness --json
zero-security replacement-readiness --platform windows --json
zero-security replacement-readiness --platform macos --json
zero-security replacement-readiness --platform linux --json
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
