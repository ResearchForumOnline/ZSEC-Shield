# Zero Security and Zero Browser architecture

Status: implementation preview. This document defines boundaries and release
gates; it does not claim real-time antivirus certification.

## Product family

| Product | Current role | Does not currently claim |
| --- | --- | --- |
| Zero Security | Product umbrella and full replacement-antivirus programme | Replacement protection in the current preview build |
| ZSEC Shield | Deterministic, on-demand scanner and encrypted quarantine core | Kernel interception, memory scanning, EDR, or zero-day prevention |
| Zero Browser | Chromium privacy/security extension preview | A separately maintained Chromium binary or complete ad blocking on every site |

## Automatic protection model

Ordinary quarantine protection is automatic:

1. A random device root key is created once.
2. On Windows it is sealed with CurrentUser DPAPI before being written to disk.
3. Every quarantined object receives a fresh random AES-256 content key.
4. The content key is wrapped with a key derived from the device root and a
   per-entry salt.
5. File bytes are encrypted with AES-256-GCM.
6. Canonical ZBA lifecycle fields, the original SHA-256, size, entry identity,
   and original path are bound as authenticated additional data (AAD).
7. Restore reconstructs and authenticates the same AAD before any plaintext is
   published to its destination.

No password prompt is required for routine use. This convenience does not remove
the need for recovery. A later recovery kit will wrap the device root under a
separate recovery key, with an optional YubiKey/passkey PRF route. Recovery must
be explicit, testable, revocable, and must never export the raw device root.

ZBA supplies typed lifecycle and provenance semantics. Cryptographic security is
provided by established primitives and correct key management, not modulo labels.

## Current safe user-mode layers

```text
Unelevated UI
    |
    v
Restricted local broker/service
    |
    +-- authenticated local IPC
    v
Unprivileged, bounded scanner workers
    +-- hashing and exact rules
    +-- Authenticode and metadata
    +-- bounded archive/document parsing
    +-- licensed engine adapter (optional)
    +-- encrypted quarantine
```

The public preview stays on demand and coexists with the currently registered
antivirus. The destination is a genuine replacement product, not a permanent
companion: a Microsoft-supported FltMgr minifilter, protected user-mode service,
x86/x64 AMSI providers, ELAM, approved Windows Security/MVI onboarding, signed
drivers, compatibility testing, staged updates, rollback drills, and independent
efficacy evidence. The executable programme and cutover gates are defined in
`FULL_ANTIVIRUS_PROGRAM.md`.

## Browser layers

The extension preview uses Manifest V3 declarative rules for local ad/tracker
blocking and a small content script for user-interface cleanup. It does not proxy
traffic, install a root certificate, upload browsing history, or inject affiliate
links. YouTube assistance is best effort because site behavior changes frequently.

A future Zero Browser distribution must preserve Chromium's sandbox and Site
Isolation, carry complete third-party notices, and merge upstream security fixes
on an operational weekly/emergency cadence. It must not depend on restricted
Google Chrome services or artwork.

## Shared supply-chain controls

- Reproducible, pinned builds and dependency inventories.
- SHA-256 manifests plus platform publisher signatures.
- Signed update metadata with version, expiry, rollback, and freeze protection.
- Stable, beta, and canary rings with automatic health halts.
- No feed-driven command, package, firewall, or configuration execution.
- Public vulnerability-disclosure process and deterministic rollback records.

## Release language

Passing unit tests, EICAR, or a feature check proves only that a defined path
works. It does not establish malware-detection efficacy. Public protection claims
require measurements whose corpus, methodology, date, version, and limitations
are disclosed.
