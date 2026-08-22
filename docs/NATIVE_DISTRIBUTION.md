# Native distribution

Native archives provide a self-contained command-line build for one operating system
and processor architecture. They use PyInstaller's one-directory layout. Keep the
executable and its `_internal` directory together.

The archive does not install a service, driver, scheduled task, shell extension, or
startup entry. It supports on-demand scanning and an explicit foreground
post-change `watch` process, with no telemetry, pre-access enforcement, or
operating-system antivirus registration. The bundled feed keyring is empty in this
preview, so feed rules require an operator-supplied Ed25519 public-key ring.

Windows archives also carry the review-first ZSEC Antivirus companion scripts.
Merely extracting an archive installs nothing. Task Scheduler is changed only if
the current user later runs the installer without `-PlanOnly`; the installed task
is limited-user, per-user, reversible, and never a Windows service/provider.

Exact released OS/architecture coverage, key-protection status, and safe-preview
instructions are maintained in the [platform support matrix](PLATFORM_SUPPORT.md).
An archive described as “native” contains a self-contained platform CLI; it is not
a native graphical desktop application or operating-system security provider.

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

The separate Windows desktop archive uses a versioned per-user install root and
validates every manifest-listed file before activation. Activation is
transactional: the previous `current.json` and both shortcuts are copied into a
product-owned transaction directory, both replacement shortcuts are prepared,
and any activation failure restores the prior record and shortcuts before the
new version directory is removed. This rollback protects ZSEC-owned desktop
state; it does not alter or roll back any antivirus provider.

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
zsec-shield watch --help
zsec-shield --state-dir ./temporary-state status --json
zsec-shield replacement-readiness --json
zsec-shield recovery-drill --json
```

The build script performs the version, watch-command, status and isolated synthetic
recovery-drill checks, then requires the replacement-readiness command to return exit `2` with
`decision: keep_existing_protection`. That deliberate non-success is a packaging
invariant for the preview, not a failed build. The readiness check does not create
the disposable state directory or change installed protection. The recovery drill
must return all five exact v1 control results while continuing to state that it is
not independent certification.

Python/wheel installation exposes the `zsec-antivirus`, `zero-security`, and
`zsec-shield` command aliases in the 0.3.5 Community release. Native archives
retain the `zsec-shield` executable name for compatibility.

Native manifest v2 lists both `on-demand` and
`foreground-post-change-protection` modes while fixing
`pre_access_enforcement`, `background_service`, `real_time_protection`,
default `automatic_quarantine`, and `telemetry` to `false`; the separate
`opt_in_companion_quarantine: true` field records the explicit Windows installer
switch without implying a default. It records `watchdog` as a
licensed runtime component. This capability metadata prevents a self-contained
CLI archive from being mistaken for an installed primary-antivirus provider.
`per_user_background_companion: true` means reviewed companion tooling is present,
not that the archive has installed or activated it.
