# Native distribution

Native archives provide a self-contained command-line build for one operating system
and processor architecture. They use PyInstaller's one-directory layout. Keep the
executable and its `_internal` directory together.

The archive does not install a service, driver, scheduled task, shell extension, or
startup entry. It remains an on-demand scanner and has no telemetry or real-time
filesystem interception. The bundled feed keyring is empty in this preview, so feed
rules require an operator-supplied Ed25519 public-key ring.

## Archive contents

- `zsec-shield` or `zsec-shield.exe` and its `_internal` runtime directory;
- `NATIVE-MANIFEST.json`, including target, source revision/tree state, component,
  policy, and per-file hashes;
- `native-manifest.schema.json` for machine validation;
- project license, security policy, operating documentation, and third-party notices;
- license texts for the bundled interpreter and components. The build prefers the
  target Python installation's license and uses the checksum-pinned CPython 3.11
  license stored in `packaging/licenses` when a runner does not expose that file.

Windows builds are ZIP files. macOS and Linux builds are `tar.gz` files so executable
permissions and any internal symbolic links are preserved.

## Integrity and publisher identity

Every workflow artifact has a SHA-256 sidecar, and a draft GitHub Release receives a
combined `SHA256SUMS.txt`. Compare the downloaded archive's digest with the value from
the authenticated release page before extracting it.

SHA-256 detects accidental or post-publication changes; a checksum stored beside an
archive is not an independent publisher signature. This build deliberately performs
no Authenticode signing, Apple Developer ID signing/notarization, Linux package
signing, or signing-key generation. Operating systems may therefore show an
unidentified-publisher warning. Follow local policy and do not bypass platform
security controls merely to run the preview.

## Build locally

Use Python 3.11 or newer in an isolated environment on the target operating system:

```bash
python -m pip install -e ".[native]"
python packaging/native_release.py build
```

PyInstaller is not a cross-compiler: build Windows artifacts on Windows, macOS
artifacts on macOS, and Linux artifacts on Linux. The output is written under
`dist/native` and is never installed automatically.

Smoke-test the extracted executable with a disposable state directory:

```bash
zsec-shield --version
zsec-shield --state-dir ./temporary-state status --json
```

The build script performs both checks before creating the archive.
