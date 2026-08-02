# ZSEC Shield

ZSEC Shield is a deterministic, non-AI, on-demand file scanner for Python 3.11+.
It hashes regular files with SHA-256, applies exact byte and digest rules, verifies
Ed25519-signed data-only rule feeds, produces structured JSON, and can move an
explicitly selected match into recoverable quarantine.

This is an MVP, not a complete antivirus product. It has no kernel driver,
real-time filesystem interception, behavior monitoring, memory scanner, cloud
reputation service, exploit blocker, or guarantee that a host is clean.

## Security boundaries

- Scanning is local and on demand. No AI model, API key, telemetry endpoint, or
  cloud upload is used.
- Symlinks and Windows reparse points are not followed. Special files are skipped.
- Recursive scans stay on the starting filesystem by default.
- Files larger than 64 MiB are skipped by default; the limit is explicit and
  reported.
- Quarantine is disabled unless `--quarantine` is present.
- Restore never overwrites an existing destination, and the verified recovery
  object is retained after restore.
- Feed signatures, schemas, timestamps, key status, sequence numbers, and payload
  digests are checked before feed rules are used.
- Feed objects accept only SHA-256 and exact literal-byte rules. Command, script,
  package, firewall, URL-action, and configuration fields are rejected.
- If a feed, trust store, or rollback record is invalid, every feed rule is ignored
  and the command reports an incomplete result. Built-in rules remain available.

See [Threat model](docs/THREAT_MODEL.md) and [Feed format](docs/FEED_FORMAT.md).

## Platform scope

The scanning core uses Python and standard filesystem calls on:

- Windows 10 and 11;
- currently supported macOS releases;
- mainstream Linux distributions.

Inventory adapters are read-only. They identify basic OS and runtime context but do
not claim that patches, Microsoft Defender, XProtect, package databases, or security
controls are healthy.

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
.venv/bin/zsec-shield --version
```

The runtime dependency is `cryptography`, used only for Ed25519 verification.

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

PyInstaller is not a cross-compiler. The build smoke-tests `--version` and the stable
`status --json` [bridge contract](docs/STATUS_CONTRACT.md) before creating anything
under `dist/native`.

## Quick start

Scan one file or directory:

```bash
zsec-shield check ./downloads
```

Scan several roots and save a machine-readable report:

```bash
zsec-shield check ./downloads ./incoming --report ./reports/check.json --json
```

Inspect status and read-only inventory:

```bash
zsec-shield status --json
zsec-shield inventory --json
```

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

For each matched file, ZSEC Shield first creates and hashes a private recovery copy.
It removes the original only if the source still matches the scan result. If source
removal fails, metadata says `copy_only` and the command returns an incomplete exit
code. This is not reported as a successful quarantine.

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
| `0` | Scan completed with no configured rule match, or diagnostic/update command succeeded. |
| `1` | One or more configured rules matched and the scan otherwise completed. |
| `2` | Incomplete/failed operation: unreadable or changing file, invalid feed, unsafe restore, or other operational error. |
| `130` | Interrupted by the operator. |

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
