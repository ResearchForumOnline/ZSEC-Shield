# Zero Security and Zero Browser architecture

Status: implementation preview. This document defines boundaries and release
gates; it does not claim real-time antivirus certification.

## Product family

| Product | Current role | Does not currently claim |
| --- | --- | --- |
| Zero Security | Cross-platform security umbrella with on-demand and foreground post-change preview modes | Background, pre-access, or replacement protection on any platform |
| ZSEC Shield | Deterministic scanner, file-event watcher, and encrypted quarantine core | Kernel interception, memory scanning, EDR, or zero-day prevention |
| Zero Browser | Chromium privacy/security extension preview | A separately maintained Chromium binary or complete ad blocking on every site |

## Automatic protection model

Ordinary quarantine protection is automatic:

1. A random device root key is created once.
2. On Windows it is sealed with CurrentUser DPAPI before being written to disk.
   The current macOS/Linux filesystem-key profile is explicitly preview-only;
   production requires a Keychain-backed macOS profile and an approved,
   recoverable Linux key-custody profile.
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

## Current Community user-mode layers

```text
Unelevated UI
    |
    v
User-scoped CLI broker
    +-- path/reparse policy and descriptor validation
    +-- broker-calculated SHA-256
    +-- signed feed and final result policy
    |
    v
Bounded out-of-process rule and review-provider worker
    +-- path-free content stream
    +-- exact literal rules and independent digest
    +-- bounded PE/script/ZIP review-only observations
    +-- strict bounded response; failures are incomplete
```

The public development preview runs on demand or as an explicit foreground
post-change watcher and coexists with current protection. The watcher starts its
observer before a baseline, debounces a bounded event queue, excludes state, runs
periodic reconciliation, and reports known coverage loss as incomplete. It does
not mediate access or install system persistence. The exact-rule child is replaced
periodically and separates worker crashes/state from the broker, but currently
runs with the invoking user's authority. It is not a reduced-privilege sandbox,
does not pass the hostile-parser readiness gate. Its current PE metadata,
conservative script-chain and ZIP central-directory providers are bounded,
review-only, and never authorize quarantine; ZIP content is not extracted. It has
no document/macro parser. Shared
scanner, evidence, feed, quarantine-envelope, updater-policy, and UI concepts sit
above three separately released enforcement planes:

| Platform | Enforcement plane | Native trust and delivery plane |
| --- | --- | --- |
| Windows | Thin FltMgr minifilter, protected broker/workers, x86/x64 AMSI and ELAM | Authenticode/Microsoft driver signing, approved Windows Security/MVI integration |
| macOS | Deadline-safe Endpoint Security system extension plus sandboxed XPC workers | Apple entitlement, user/MDM consent, Keychain, Developer ID, Hardened Runtime and notarization |
| Linux | Minimal fanotify broker, unprivileged daemon/workers and explicit mount coverage | systemd plus SELinux/AppArmor confinement and signed distro-scoped DEB/RPM repositories |

None of these privileged enforcement planes ships in the current CLI preview. Their
executable and cutover gates are defined in
`FULL_ANTIVIRUS_PROGRAM.md`, `MACOS_DESKTOP_PROGRAM.md`, and
`LINUX_DESKTOP_PROGRAM.md`. The shared
`replacement-readiness` contract remains non-successful until the exact platform
candidate passes its programme and common release gates.

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
