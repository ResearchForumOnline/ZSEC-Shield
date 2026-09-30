# ZSEC Antivirus 0.3.33 for Windows

This release fixes a verified compatibility failure in automatic advisory updates. The production signed intelligence envelope is 2,379,423 bytes, exceeding the shared transport's 2 MiB limit. A dedicated intelligence transport now uses its verifier's existing fixed 8 MiB cap. Rules/general downloads remain bounded at 2 MiB; application notices retain their 64 KiB verification limit.

HTTPS, redirect and timeout bounds, pinned signatures, expiry, rollback and last-known-good catalog protection remain in place. No advisory records were discarded and no signing keys or privacy contracts changed.

## Download and verify

- Archive: `zsec-antivirus-desktop-0.3.33-windows-x86_64.zip`
- Size: **33,860,318 bytes**
- SHA-256: `2613a665949187747ecfa38d202361a80a44b736e87fa1d9e2ae30e2d6ada1de`
- Exact clean source: `d467e04e99bbe7227afd88c5c2415fe780c4ef1d`
- Checksum sidecar and sanitized build-verification JSON are included as release assets.

The ZIP includes the desktop GUI, scanner engine, documented per-user installation scripts, companion tools and license notices. Follow its `DESKTOP.md` instructions.

## Verification

- Full source suite: **327 tests and 14 subtests passed**; Ruff and mypy passed.
- Source CI passed on the exact build commit.
- Archive CRC and all **1,107** manifest file sizes and hashes verified.
- GUI/CLI PE versions `0.3.33.0`, GUI DPI/long-path manifest, packaged synthetic scan/quarantine and GUI help checks passed.
- The actual packaged engine downloaded the canonical signed feed, accepted sequence 60, and installed all **1,648** advisories in disposable state. No Windows protection-provider action was performed.
- Transport tests cover oversized response/header refusal, unsupported limits, HTTPS redirect restrictions, invalid signatures, expiry and rollback. Rejected signed updates preserve the previously verified catalog.

## Distribution state

This direct archive is **unsigned**; both executables report `NotSigned`. A separate `0.3.33.0` Microsoft Store upload payload was built from exactly the same runtime bytes. Its preparation does not establish Store certification, public availability or a Store-signed installation test.

ZSEC remains a user-mode security companion. Keep Microsoft Defender or another supported primary antivirus active. This release does not register ZSEC as the primary antivirus or establish malware-detection efficacy. Application notification metadata cannot authorize automatic installation of the unsigned direct archive; its separate signed publication is verified independently.
