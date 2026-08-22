# Zero Security for macOS: production desktop antivirus programme

Status: architecture and release-gate programme, 21 August 2026.

This document defines the work required to turn the current ZSEC Shield
on-demand scanner into a production macOS desktop security product. It does not
claim that real-time monitoring, Endpoint Security blocking, system-wide Full
Disk Access scanning, independently measured antivirus efficacy, or production
macOS quarantine-key protection is shipped today.

The current repository remains an open-source, deterministic, local,
**on-demand** scanner. Until every applicable gate in section 21 passes, public
copy must say “foreground post-change security preview,” not “complete antivirus,” “real-time
protection,” “replaces XProtect,” or “stops all malware.”

## 1. Product outcome and governing principles

The target is a native macOS application that can:

- run explicit files, folders, quick, and full scans;
- monitor relevant system activity through Apple’s Endpoint Security framework;
- deny only high-confidence, locally decidable malicious executions before their
  individual authorization deadline;
- asynchronously inspect new or changed content without blocking the desktop;
- quarantine findings into authenticated encrypted storage and restore them
  safely;
- receive signed, data-only rule and application updates with rollback and freeze
  controls;
- coexist with Gatekeeper, notarization, XProtect, FileVault, System Integrity
  Protection, and other security products;
- make every permission, degradation, detection, and destructive action visible
  to the user.

The design principles are:

1. Apple security controls remain enabled and authoritative.
2. User and administrator consent is a control, not an onboarding obstacle to
   bypass.
3. The Endpoint Security authorization path is bounded, local, deterministic,
   and allocation/I/O-minimal.
4. Complex file formats are parsed outside privileged processes.
5. Unknown, overloaded, or late authorization decisions explicitly allow and
   raise a degraded-health signal; a missed deadline is never an intended policy.
6. Feeds contain signed data, never executable commands or configuration scripts.
7. Quarantine publishes a verified encrypted recovery object before source
   removal.
8. Product claims are versioned evidence statements, not branding language.

## 2. Supported platform and architecture boundary

### 2.1 Initial release matrix

The proposed first generally available release has a deployment target of macOS
14.0 and supports only Macs running the latest Apple security update for one of
these major versions:

| macOS | Apple silicon | Intel | Product boundary |
| --- | --- | --- | --- |
| macOS Tahoe 26 | Supported after native-hardware qualification | Supported only on Tahoe-compatible Intel Macs | Full current feature target |
| macOS Sequoia 15 | Supported after native-hardware qualification | Supported on Apple-supported Sequoia Intel Macs | Full target except features Apple exposes only on later releases |
| macOS Sonoma 14 | Supported after native-hardware qualification | Supported on Apple-supported Sonoma Intel Macs | Baseline Endpoint Security target; Gatekeeper-bypass/XProtect event correlation introduced later is unavailable |

Apple’s current version page identifies Tahoe 26, Sequoia 15, and Sonoma 14 as
the three newest major versions. Support is a Zero Security product policy, not a
claim that Apple promises a fixed three-version security-support window. The
release pipeline must re-read Apple’s current-version and security-release pages
before every release and update the matrix when Apple’s support changes.

macOS 13 and earlier are out of scope for the first desktop release even though
Endpoint Security itself predates macOS 14. A smaller matrix is necessary for
repeatable extension, consent, parser, APFS, update, and recovery testing.

Apple’s Tahoe compatibility list contains four Intel models alongside Apple
silicon systems: MacBook Pro 13-inch 2020 with four Thunderbolt 3 ports, MacBook
Pro 16-inch 2019, iMac Retina 5K 27-inch 2020, and Mac Pro 2019. Those are the
Tahoe Intel boundary; a generic “Intel Mac” promise would be inaccurate.

Official references:

- [Apple’s current macOS version list](https://support.apple.com/en-us/109033)
- [macOS Tahoe 26 compatible computers](https://support.apple.com/en-gb/122867)
- [Apple security releases](https://support.apple.com/100100)

### 2.2 Universal 2 requirement

Every executable component must ship as a Universal 2 binary with native `arm64`
and `x86_64` slices:

- GUI application;
- Endpoint Security system extension;
- XPC services and any Service Management helper;
- scanner and parser binaries;
- bundled dynamic/static libraries and command-line diagnostic tools.

Apple recommends making all compiled components universal, not only the main app.
The release gate verifies every Mach-O with `lipo -archs` and rejects a missing or
unexpected architecture. Apple silicon must run the `arm64` slice natively; the
product must not silently depend on Rosetta. Intel tests run on physical supported
Intel hardware, not only an `x86_64` process translated on Apple silicon.

Reference: [Building a universal macOS binary](https://developer.apple.com/documentation/apple-silicon/building-a-universal-macos-binary).

### 2.3 Lifecycle policy

- A major macOS release enters beta qualification when Apple publishes its first
  developer beta, but it is not listed as supported until a signed production
  build passes all mandatory platform tests on the public release.
- A retiring macOS generation receives at least 180 days’ product notice unless
  an unfixable security defect requires earlier withdrawal.
- Intel support is maintained while a listed macOS generation and physical model
  remain in the product matrix. Removal requires a dated notice, export/recovery
  path, and a final rule-feed expiry policy; it cannot be inferred merely from
  Apple silicon being preferred.
- Virtual machines are supported for CI and negative tests, not as substitutes
  for performance, sleep/wake, FileVault, approval, or efficacy testing on real
  hardware.
- Hackintosh systems, unsupported boot loaders, disabled SIP, reduced-security
  development configurations, and prerelease macOS are not production-supported.

## 3. Truthful delivery phases

The programme is deliberately staged so the UI and marketing cannot outrun the
implementation.

| Phase | Shipped capability | Permitted claim |
| --- | --- | --- |
| M0: current repository | Command-line/local deterministic scan, signed feed verification, preview quarantine | On-demand scanner preview |
| M1: desktop on-demand | Native GUI, user-selected/full scans, notifications, safe local updates, production macOS key protection | Desktop on-demand security app |
| M2: observe-only ES | Approved Endpoint Security extension, NOTIFY telemetry processed locally, no authorization denial | Real-time activity monitoring preview; not real-time prevention |
| M3: narrow prevention | `AUTH_EXEC` denial for exact, high-confidence, locally cached indicators only | Real-time blocking for the documented rule classes |
| M4: expanded antivirus | Reviewed bounded classifiers/parsers, measured behavior rules, independent clean/malicious evaluation | Antivirus only with published dated efficacy and false-positive evidence |

Advancing a phase requires a signed release decision containing the build hash,
platform matrix, test artifacts, known limitations, rollback build, and approved
claim text. A successful demo or EICAR response does not advance a phase.

## 4. Process architecture and trust boundaries

```text
ZeroSecurity.app (sandboxed, user session)
  - onboarding, scan requests, findings, quarantine UI, settings
  - no unrestricted privileged filesystem API
  - outbound network only for signed update/reputation features that are enabled
             |
             | authenticated, schema-limited XPC
             v
ZeroSecurityEndpoint.systemextension (privileged, system-wide)
  - Endpoint Security client and deadline-safe decisions
  - minimal read-handle broker for protected files
  - no UI, web client, archive parser, model runtime, or update installer
             |
             | bounded read-only descriptors and immutable job records
             v
Scan coordinator + disposable parser XPC workers (unprivileged)
  - hashing, literal rules, code-signature metadata
  - archive/document parsing with resource budgets
  - no arbitrary network, write, process-control, or policy authority
             |
             v
Authenticated encrypted quarantine + signed data-only feeds
```

The high-privilege extension is a policy enforcement and file-handle broker, not
an all-purpose daemon. It may hash or inspect bounded fixed-format data needed for
a deadline-safe decision. It must never parse archives, PDFs, office documents,
images, media, disk images, or other complex attacker-controlled formats.

If supported XPC/file-descriptor transfer cannot maintain this split on every
supported macOS version, the release must pause for an Apple-reviewed topology.
The fallback is not to move complex parsers into the extension. A separate helper
is allowed only under section 7 and after its own threat model.

Persistent local state belongs in a private app-group container shared only by
the exact signed components that need it. On macOS 15 and later, Apple documents
additional System Integrity Protection for app-group containers; this is defense
in depth, not a reason to weaken authentication or file permissions.

Reference: [Protecting local app data using containers on macOS](https://developer.apple.com/documentation/xcode/protecting-local-app-data-using-containers).

## 5. Endpoint Security system extension

### 5.1 Apple entitlement and packaging gate

Endpoint Security is Apple’s supported C API for security products to receive
notification and authorization events such as execution and filesystem activity.
The extension must:

- be packaged inside the app under `Contents/Library/SystemExtensions`;
- be activated, updated, and deactivated through the SystemExtensions framework;
- use the same Apple Developer Team ID as the containing application;
- have its own bundle identifier, version, signed entitlements, and distribution
  provisioning profile;
- receive Apple’s restricted
  `com.apple.developer.endpoint-security.client` entitlement before any product
  schedule assumes it can ship;
- run with the Hardened Runtime and no prohibited runtime exception entitlements;
- expose an honest `NSSystemExtensionUsageDescription` explaining monitoring and
  blocking;
- be installed from an app in `/Applications`, as Apple’s sample flow requires.

Lacking the Endpoint Security entitlement causes `es_new_client` to fail. Apple
may deny or delay entitlement approval, so approval is release gate G2, not an
administrative afterthought.

Official references:

- [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity)
- [Endpoint Security client entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client)
- [Monitoring System Events with Endpoint Security](https://developer.apple.com/documentation/endpointsecurity/monitoring-system-events-with-endpoint-security)
- [Installing System Extensions and Drivers](https://developer.apple.com/documentation/systemextensions/installing-system-extensions-and-drivers)

### 5.2 Subscription progression

M2 begins with the smallest useful NOTIFY set, version-gated at runtime. A
candidate set includes process execution/exit and file close/rename/unlink events
needed to enqueue scans. Each event type requires a written reason, minimum OS,
data-retention decision, load test, and response to gaps. Subscribing “to
everything” is prohibited.

M3 initially subscribes to `AUTH_EXEC` only. Broader authorization such as
`AUTH_OPEN` is prohibited until a separate deadline, compatibility, and false-
positive review passes. Authorization responses follow this order:

1. Validate the message version and copy only fields required beyond the handler
   lifetime.
2. Check a bounded in-memory decision cache keyed by stable execution identity,
   rule epoch, code-signing identity/CDHash where available, and relevant file
   identity—not a mutable path alone.
3. Deny only an exact, active, non-expired, locally verified high-confidence rule.
4. Explicitly allow known-good policy decisions that remain valid for the event.
5. Explicitly allow unknown, unavailable, overloaded, or soon-to-expire decisions
   and enqueue asynchronous inspection.
6. Respond well before the individual message deadline and record latency/result.

There is no DNS, HTTP, cloud reputation, database compaction, archive parsing,
large hashing, UI call, synchronous XPC round trip, or lock with unbounded wait in
the AUTH handler. Network reputation can inform later remediation but never holds
the kernel operation open.

Apple documents that every AUTH message has its own deadline; a missed deadline
may terminate the client and restart a system extension. Apple also documents
that a missed deadline applies an implicit uncached allow. Zero Security must make
that overload behavior explicit before the deadline, count it, show degraded
health, and never misreport the operation as inspected or blocked.

References:

- [Endpoint Security message deadline](https://developer.apple.com/documentation/endpointsecurity/es_message_t/deadline)
- [Build an Endpoint Security app](https://developer.apple.com/videos/play/wwdc2020/10159/)

### 5.3 Caching, gaps, and feedback loops

- Use Apple’s ES cache only as a performance optimization. Policy remains in the
  signed local decision set.
- Never cache a response that depends on process arguments, environment, script
  target, user, mutable policy, or an incomplete identity.
- Clear relevant caches on feed activation, exclusion/policy change, restoration,
  or component replacement. Treat the ES cache as best effort because Apple may
  expire it.
- Inspect per-event sequence numbers. Any gap increments a durable metric, marks
  real-time coverage degraded, and schedules a bounded retrospective scan.
- Perform as little work as possible in the handler. If a copied message is used
  asynchronously, it must be freed exactly once on every completion/cancellation
  path.
- Inspect the event’s ES-client indicator and avoid blocking, recursively scanning,
  or creating feedback loops with this or another Endpoint Security client.
- Muting is narrow and measured. Prefer stable process identity to thousands of
  path rules, and never combine a muted process with a cached denial policy that
  can expire into silent allowance.

## 6. System Extension approval and Full Disk Access

There are two separate consent steps on an unmanaged Mac:

1. system extension activation/approval; and
2. Full Disk Access under System Settings > Privacy & Security.

Full Disk Access allows approved software to access broad protected data,
including other applications’ data and Time Machine backups. It is therefore a
material privacy permission. The application must explain the exact purpose and
must work in a limited on-demand/user-selected mode when it is absent.

The product must not:

- write to or edit the TCC database;
- automate clicks, simulate approval, install a local PPPC profile, or claim that
  approval was granted before an API health check succeeds;
- request Accessibility, Screen Recording, Input Monitoring, Automation, camera,
  microphone, or location permission for antivirus functionality;
- repeatedly nag after a user declines;
- describe Full Disk Access as harmless or mandatory merely to open the UI.

After activation, health is established by a successful `es_new_client`, exact
subscription, event self-test, and observed authorization response—not by the
presence of a settings toggle alone. The only supported Full Disk Access check is
the real Endpoint Security client result/behavior on the target OS.

Managed enterprise deployment may use Apple’s System Extension policy and
Privacy Preferences Policy Control payloads through user-approved device
management. Consumer documentation and managed documentation remain separate;
the consumer installer must not import enterprise profiles.

Official references:

- [Mac Privacy & Security settings and Full Disk Access](https://support.apple.com/guide/mac-help/change-privacy-security-settings-on-mac-mchl211c911f/mac)
- [Apple’s Endpoint Security sample installation flow](https://developer.apple.com/documentation/endpointsecurity/monitoring-system-events-with-endpoint-security)
- [Apple WWDC guidance for managed system-extension/FDA payloads](https://developer.apple.com/videos/play/wwdc2020/10159/)

## 7. App Sandbox, helpers, and XPC authority

### 7.1 Sandboxed desktop app

The GUI uses App Sandbox even for Developer ID distribution. Apple describes App
Sandbox as a kernel-enforced containment layer that limits filesystem, network,
and resource access if an app is compromised. The GUI receives only the
entitlements it needs:

- app group and keychain access group;
- user-selected file read access for manual scans;
- outbound network client access only if signed updates or an explicitly enabled
  online feature is present;
- notifications as required by the supported SDK.

It receives no general server/listener, camera, microphone, Contacts, Calendar,
Photos, Bluetooth, USB, Apple Events, Accessibility, or JIT entitlement. The UI
does not gain arbitrary system reads because another component has Full Disk
Access.

References:

- [Configuring the macOS App Sandbox](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
- [Accessing files from the macOS App Sandbox](https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox)

### 7.2 Privileged helper rule

The initial design adds no general root helper: the Endpoint Security system
extension is already the narrow high-privilege component. If a separate
LaunchDaemon becomes unavoidable, it must be registered with `SMAppService`
(available from macOS 13), packaged inside the signed app, and justified by a
threat model. Deprecated `SMJobBless`, installer scripts, setuid binaries, and
manual writes to `/Library/LaunchDaemons` are not the new-design route.

A permitted helper may open/revalidate a file, provide a read-only descriptor,
perform an atomic quarantine rename/copy, or mediate a protected state directory.
It may not parse complex content, make detection policy, browse the network,
install updates, change privacy settings, disable competitors, execute feed data,
or expose a generic “run command/read path/write path” RPC.

Reference: [SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice).

### 7.3 XPC contract

Every cross-process method has a versioned allowlisted schema, explicit byte and
collection bounds, deadlines, cancellation, and structured error codes. Peers are
validated against an exact Team ID, bundle/signing identifier, designated
requirement, and required entitlement. PID, UID, a socket pathname, or possession
of a Mach service name alone is not identity.

Where available, use `NSXPCConnection.setCodeSigningRequirement` or Security
framework validation against the audit token. Reject unknown methods and fields.
Never authorize a privileged operation from a path string supplied by the GUI;
use user-selected security-scoped access or a broker-opened, revalidated file
descriptor and an immutable job identifier.

References:

- [XPC](https://developer.apple.com/documentation/xpc)
- [Enforcing an XPC peer code-signing requirement](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement%28_%3A%29)
- [SecCodeCheckValidity](https://developer.apple.com/documentation/security/seccodecheckvalidity%28_%3A_%3A_%3A%29)

## 8. Gatekeeper, notarization, and XProtect coexistence

Apple documents three built-in malware-defense layers: launch prevention through
the App Store or Gatekeeper and notarization, blocking through Gatekeeper,
notarization and XProtect, and remediation through XProtect. XProtect includes
signature-based detection/removal and behavioral capability with background
updates. Zero Security is an additional layer and must not suppress or replace
those controls.

Required behavior:

- never disable Gatekeeper, XProtect, automatic security data updates, SIP,
  FileVault, or the signed system volume;
- never clear or fabricate Apple’s `com.apple.quarantine` provenance attribute to
  avoid Gatekeeper;
- distinguish Apple File Quarantine/provenance from the Zero Security encrypted
  quarantine vault in UI and logs;
- if XProtect moves/removes a file first, record an externally remediated finding
  rather than treating its absence as a Zero Security success;
- on macOS 15 and later, consume Gatekeeper-bypass and XProtect events only when
  available, identify the source as Apple, and do not count them as proprietary
  detections;
- do not upload XProtect event details or affected content without the user’s or
  administrator’s separately documented telemetry/sample-sharing choice;
- advise users to keep macOS and background security data current.

Official references:

- [Protecting against malware in macOS](https://support.apple.com/guide/security/sec469d47bd8/web)
- [Gatekeeper and runtime protection](https://support.apple.com/guide/security/sec5599b66df/web)

## 9. Detection and prevention policy

### 9.1 Decision classes

Every result is one of:

- `allow-known`: verified trusted policy for the exact identity and epoch;
- `deny-exact`: active exact malicious indicator with sufficient provenance;
- `allow-pending-scan`: unknown content explicitly allowed and queued;
- `allow-degraded`: policy engine unavailable/overloaded or deadline budget low;
- `detect-observe`: asynchronous detection with no prior prevention;
- `error-unscanned`: content could not be inspected under declared limits.

“Clean” is never returned merely because no current rule matched. UI language is
“No threats found by this version and rule set” and includes skipped/error counts.

### 9.2 Initial prevention scope

M3 auto-denial is limited to exact hashes or equally deterministic immutable code
identities that have:

- traceable source and review;
- active start/expiry and rollback epoch;
- severity `critical` or `high` under a documented policy;
- a tested false-positive revocation path;
- no wildcard path or publisher-wide effect unless explicitly reviewed.

Literal byte matches, heuristic scores, archive members, scripts, unsigned
reputation responses, and AI/model outputs remain detection-only until their own
prevention gates pass. A cloud timeout never becomes a denial.

### 9.3 Remediation

A denied execution and quarantine are separate events. The extension may deny
first, then enqueue a user-visible remediation. Source deletion/quarantine never
occurs inside the AUTH deadline. Automatic quarantine is enabled only for a narrow
reviewed class and after the encrypted recovery object is complete.

Killing an already running process, deleting persistence, reverting system
settings, and cleaning other files are out of scope until an action-specific
transaction/rollback specification and efficacy test exists. Findings recommend
safe next steps without claiming full remediation.

## 10. macOS quarantine encryption and recovery

### 10.1 Current incompatibility gate

The repository’s current Windows profile seals a device root with DPAPI. Its
non-Windows `filesystem-0600-preview` root is not production key protection and
must not be used by the macOS desktop release.

Before M1, the macOS product requires a separately versioned, golden-vector-tested
vault profile that keeps AES-256-GCM, HKDF-SHA-256, fresh per-object keys/salts/
nonces, authenticated metadata, ZBA typed provenance, and fail-closed restore but
protects the device/user root with macOS Keychain Services. It must not silently
reuse the existing ZSV2 profile identifier with different root semantics.

Apple describes Keychain Services as encrypted storage for small secrets and
cryptographic keys. The macOS root item must be non-synchronizing, scoped to the
minimum app/keychain access group or code-signing access control, and unavailable
to unrelated processes. The exact accessibility and multi-user behavior must be
verified on every supported macOS generation.

References:

- [Keychain Services](https://developer.apple.com/documentation/security/keychain-services)
- [Storing keys in the Keychain](https://developer.apple.com/documentation/security/storing-keys-in-the-keychain)

### 10.2 Vault behavior

- Generate a fresh 256-bit content key, salt, key-wrap nonce, and content nonce
  from the OS CSPRNG for every object.
- Bind immutable identity, original digest/size, source metadata, rule evidence,
  and typed ZBA record into AEAD AAD.
- MAC mutable state/history and the complete envelope.
- Store vault directories root/private-app-group owned with restrictive mode and
  ACL; reject links, aliases that escape the vault, special files, and unexpected
  ownership.
- Publish encrypted content and authenticated metadata with file and directory
  synchronization before removing or relocating the source.
- Revalidate source file ID, volume ID, size, modification/change time, and open
  handle before removal; path equality is insufficient.
- Preserve a clearly defined subset of resource fork, extended attributes,
  quarantine provenance, ACL, mode, owner, and timestamps. Unsupported metadata
  must block removal or be disclosed; it cannot disappear silently.
- Restore to a same-directory temporary file, authenticate before publication,
  verify plaintext digest/size/metadata, and publish with a no-overwrite operation.
- Retain the encrypted recovery copy until the user explicitly purges it.

APFS clones, sparse files, hard links, packages, snapshots, external volumes,
network shares, read-only volumes, case sensitivity, and volume disappearance
each require tests. Encryption destroys clone/sparse-storage efficiency; the UI
must report logical and physical space estimates before a large quarantine.

### 10.3 Recovery

Automatic use does not remove recovery risk. Before production:

- offer an explicit recovery-kit workflow that wraps but never displays the raw
  device root;
- self-test the recovery kit on a disposable vector before marking it complete;
- define device loss, Keychain reset, app-team transfer, OS migration, multi-user,
  and key-compromise procedures;
- support key rotation without reusing nonces and with crash-resumable journaling;
- require verified zero remaining objects or a destructive typed confirmation
  before deleting a root key;
- document that uninstalling code without preserving the needed key and vault can
  make quarantined files unrecoverable.

Optional YubiKey/passkey recovery is a later explicit profile. It must not be
claimed until the authenticator/browser/API support matrix, enrollment,
replacement, revocation, offline recovery, and actual restore drills pass.

## 11. Parser isolation and hostile-content handling

All content is hostile, including files from trusted paths, signed applications,
archives, reports, feeds, and restored quarantine objects.

### 11.1 Worker model

Complex parsing occurs in disposable XPC worker processes with:

- no root or Endpoint Security entitlement;
- App Sandbox and no network/server/Apple Events/JIT entitlement;
- a single read-only descriptor or bounded byte stream, not arbitrary path access;
- a read-only signed rules/parser bundle;
- private temporary storage with quota and cleanup;
- per-job wall-clock, CPU, memory, output-byte, file-count, recursion-depth, and
  decompression-ratio limits;
- cancellation and forced termination without affecting the extension;
- no dynamic plug-in discovery or loading from scanned content;
- structured result objects that cannot request actions.

The coordinator validates the worker’s result schema and independently recomputes
security-critical digest/identity fields. A parser crash is `error-unscanned`, not
clean.

### 11.2 File handling

- Sniff type from bounded bytes and metadata; extensions/MIME are hints only.
- Open with no-follow semantics where available, then use `fstat`; do not reopen
  the supplied path after validation.
- Reject device nodes, sockets, FIFOs, unexpected mount transitions, and cycles.
- Detect archive bombs, overlapping entries, traversal names, absolute members,
  symlinks/hardlinks, duplicate canonical names, encrypted members, malformed
  lengths, and nested-depth exhaustion.
- Treat disk images and filesystem containers as a separate future parser with no
  automatic mount in the initial release.
- Never execute, render with a privileged UI framework, Quick Look, import, or
  invoke the target’s interpreter to determine whether it is malicious.
- Fuzz every parser with sanitizers on both architectures; maintain crash,
  timeout, and corpus-regression fixtures.

## 12. Feed, reputation, telemetry, and privacy

### 12.1 Signed data-only rules

The existing no-remote-command boundary remains mandatory. A feed may contain
bounded declarative indicators and metadata. It cannot contain shell commands,
AppleScript, JavaScript, bytecode, dynamic libraries, parser plug-ins, URLs to
execute, filesystem actions, privacy-setting changes, system-extension requests,
or arbitrary configuration writes.

Each update is validated for strict schema, canonical encoding, trusted/revoked
key, signature, sequence, epoch, created/expires time, size/count limits,
algorithm allowlist, rollback, and freeze. Activation uses an A/B store and an
atomic current pointer. Failed activation keeps the last known-good unexpired
rules and surfaces degradation.

### 12.2 Online reputation

Online reputation is optional and never required for on-demand exact scanning or
known-rule AUTH decisions. If introduced:

- the default consumer request sends a privacy-preserving digest/metadata subset,
  not file content or full paths;
- sample upload requires a separate just-in-time consent or explicit managed
  policy and shows size, type, recipient, retention, and revocation limits;
- TLS validation and App Transport Security remain enabled; no custom root CA;
- server responses are signed or authenticated, short-lived, versioned, and
  treated as one signal rather than executable authority;
- outage, captive portal, TLS failure, or rate limiting explicitly returns local
  pending/degraded behavior, never an implicit malicious verdict.

### 12.3 Telemetry

Consumer telemetry is off until an explicit choice. Essential update requests are
documented separately from optional analytics. Never collect raw file content,
full path, usernames, browser history, message/mail database data, Keychain data,
XProtect details, or process arguments by default.

The UI includes a live “data leaving this Mac” view and export/delete controls.
Enterprise collection requires a controller policy, field-level schema, purpose,
retention, access control, regional routing, and audit. “No data collected” is
prohibited if any update, reputation, licensing, crash, or analytics request
occurs.

## 13. Developer ID, hardened runtime, notarization, and packaging

The first distribution channel is a direct-download Developer ID application,
not an unsigned ZIP and not an assumed Mac App Store submission.

Every executable is signed from the inside out with the correct Developer ID
Application identity, secure timestamp, unique identifier, least-privilege
entitlements, and Hardened Runtime. Installer packages, if used, receive the
correct Developer ID Installer signature. Do not use ad hoc signing or
`codesign --deep` to paper over nested-code mistakes.

The release must not contain:

- `com.apple.security.get-task-allow`;
- disabled library validation;
- DYLD environment, unsigned executable memory, JIT, or executable-memory
  protection exceptions;
- development provisioning profiles or debug servers;
- unsigned/adhoc nested Mach-O code;
- mutable executable code downloaded after notarization.

Apple states that notarization of directly distributed current software requires
Developer ID signing and Hardened Runtime. The pipeline submits the exact DMG/PKG
with `notarytool`, requires an accepted result with no warnings left unexplained,
staples the ticket, and tests Gatekeeper assessment and offline first launch on a
fresh Mac. Notarization is Apple’s automated known-malware/signing check, not
independent antivirus certification.

Official references:

- [Notarizing macOS software before distribution](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- [Hardened Runtime](https://developer.apple.com/documentation/security/hardened-runtime)
- [Creating distribution-signed code for macOS](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac)

## 14. Signed application and rule updates

### 14.1 Update trust

Transport TLS is necessary but not the update trust root. Each application update
has a canonical signed manifest containing:

- product/channel, version and monotonically increasing build;
- minimum/maximum supported macOS and architectures;
- package URL, exact size, SHA-256, Developer Team/signing identifier, and
  notarization requirement;
- embedded system-extension version and compatibility epoch;
- required state/vault/feed schema migrations;
- release time, expiry, minimum allowed build, rollback/freeze metadata;
- phased-rollout percentage and emergency halt/revocation references.

Manifest signatures use an offline/threshold-controlled release root with
separate online delegation and expiry. The package must also pass Apple code-
signature designated-requirement validation, Team ID, hardened-runtime,
entitlement allowlist, architecture inventory, notarization/staple, and content
hash checks. A valid Developer ID signature alone is insufficient authorization
to move channels, downgrade, or install an unexpected entitlement.

Signing credentials reside in isolated CI/HSM-backed release infrastructure with
dual approval. They never ship in the app, source tree, feed, or update server.

### 14.2 Update behavior

- Download to a private staging directory with restrictive permissions and no
  execution.
- Validate metadata before download where possible and validate the complete
  package again before staging.
- Never update during an AUTH handler, active quarantine commit, restore publish,
  or root-key migration.
- Activate rule updates independently through A/B slots; rules never replace app
  code.
- Keep a signed rescue build and previous compatible state snapshot until health
  commits the new version.
- A critical update can increase urgency and shorten deferral but cannot simulate
  consent or silently erase quarantine.
- A release server outage leaves the last known-good unexpired version active and
  shows staleness; it never downloads from an unsigned mirror.

## 15. Desktop user experience

### 15.1 Health model

The menu-bar and main-window status use explicit component states:

- `On-demand ready`;
- `System extension approval required`;
- `Full Disk Access not granted`;
- `Monitoring (observe only)`;
- `Real-time blocking active`;
- `Degraded: event gap/deadline pressure/rules expired/update failed`;
- `Stopped by user or administrator`;
- `Unsupported macOS/build`.

Green is reserved for a measured healthy state. Installing the app, receiving an
HTTP 200, seeing a settings toggle, or starting a process is not health proof.
The details view shows extension version, rule epoch/expiry, last successful
self-test/update/scan, skipped/error counts, current protection mode, consent
state, and recovery-kit status.

### 15.2 Onboarding

1. State what is implemented and what is not.
2. Explain local scanning, privacy, and built-in Apple coexistence.
3. Install/move the app to `/Applications` using a signed, user-visible flow.
4. Explain why the system extension is requested, then submit the activation
   request and wait for the real delegate result.
5. Explain Full Disk Access with a screenshot/instructions matched to the current
   OS; open the relevant System Settings pane only after a user click.
6. Verify the Endpoint Security client and run a harmless event self-test.
7. Start in observe-only mode; offer real-time blocking only when the release
   phase and health state permit it.
8. Offer, but do not force, signed updates, optional telemetry, and recovery-kit
   setup with distinct choices.

No fake Apple dialog, urgency countdown, blocked close button, preselected data
sharing, or purchase screen may obscure a security consent decision.

### 15.3 Scan and finding experience

- Quick, selected, and full scans show roots, item count, bytes, elapsed time,
  exclusions, skipped/errors, throttle state, and cancellability.
- Cancel stops new work, lets atomic quarantine/restore commits finish safely, and
  records a cancelled—not clean—result.
- Findings show rule source/version, confidence class, hash, code-signing status,
  path, detection time, whether execution was blocked, whether Apple also acted,
  and available actions.
- Destructive actions require confirmation and state their recovery consequence.
- Restore never overwrites. A collision offers a new destination rather than a
  hidden rename.
- False-positive reporting previews exactly which metadata/sample, if any, will
  leave the device.

### 15.4 Accessibility and localization

All flows pass VoiceOver, Full Keyboard Access, reduced motion/transparency,
increased contrast, Dynamic Type-equivalent scaling, color-independence, focus
order, and localized-number/date/path tests. Status is never encoded only by
green/red. Security text is written for translation without concatenated strings.

## 16. Performance and reliability budgets

These are release gates, not current benchmark claims. Measurements publish the
build, rule set, macOS build, hardware, power state, corpus, repetitions, and
confidence intervals.

### 16.1 Endpoint Security budgets

- Zero missed AUTH deadlines in the release stress suite and 72-hour soak.
- Zero unaccounted sequence gaps. Any injected gap must trigger degraded health
  and the documented recovery scan.
- AUTH decision latency, excluding Apple delivery time: p50 at most 1 ms, p95 at
  most 5 ms, p99 at most 10 ms for cache/local exact-policy paths, and always less
  than 20% of the individual remaining deadline budget.
- Event-handler synchronous work: p99 at most 500 microseconds before copied work
  is queued or an authorization response is issued.
- Extension resident memory at steady state: at most 100 MiB; total idle
  background product memory at most 250 MiB.
- Idle CPU over an eight-hour logged-in period: median below 0.5% of one core and
  p99 below 2%, excluding an active scan/update.
- No unbounded queue. At the high-water mark, low-priority asynchronous jobs are
  coalesced/dropped with accounting while AUTH events still receive an explicit
  response.

### 16.2 Workload budgets

Against an instrumented product-disabled baseline on the same machine:

- interactive app-launch suite p95 wall-clock regression at most 5%;
- source-build and package-install suite median regression at most 5% on Apple
  silicon and 8% on supported Intel;
- file-copy suite median throughput regression at most 5%;
- sleep/wake/login/logout/fast-user-switch tests produce no crash loop, stuck
  extension, or incorrect healthy state;
- battery test adds no more than 3 percentage points of battery consumption over
  an eight-hour idle/light-work profile;
- no sustained memory growth above 1% per hour after warm-up in a 72-hour soak.

Full-scan throughput and duration have no universal marketing number. The UI
estimates from measured local progress and publishes device-specific benchmark
ranges only after reproducible testing. On battery, Low Power Mode, thermal
pressure, or high interactive load, background scanning throttles or pauses unless
an administrator policy with disclosed impact says otherwise.

The hardware lab includes at least an 8 GB M1 baseline, a current Apple silicon
Mac, two distinct Tahoe-compatible Intel models, and each supported macOS major.

## 17. Efficacy, false positives, and model governance

### 17.1 Evidence design

Training/rule-development data, tuning data, and final held-out evaluation data
are immutable and disjoint by hash. Malware handling occurs in isolated legally
authorised infrastructure, never on an employee desktop. The test protocol
defines family/time split, duplicates/near-duplicates, packed samples, prevalence
weighting, clean sources, code-signing status, scoring, confidence intervals, and
every exclusion before the result is run.

At minimum, publish:

- on-demand file detection and missed/error rate;
- pre-execution blocking rate for the exact M3/M4 prevention scope;
- time to detection/remediation;
- false-positive rate per clean executable and per installed application;
- high-impact false positives affecting macOS boot/login, Apple software,
  browsers, developer tools, and common business applications;
- performance and stability alongside efficacy;
- the exact build, rule epoch, dates, corpus provenance, limitations, and whether
  an independent lab reproduced the result.

### 17.2 Promotion gates

Before M3 narrow prevention:

- every denial rule has a positive fixture and at least one wrong-near-neighbor
  negative fixture;
- zero false denials across current clean installations of all supported macOS
  versions/architectures and the release clean-app corpus;
- the one-sided 95% upper confidence bound for automatic-denial false positives is
  below 1 in 100,000 clean executable observations (requiring at least 300,000
  independent clean observations with zero events under the preregistered model);
- 30 days of consented beta observe-only operation has no unexplained high-impact
  false positive and no deadline miss.

Before an M4 “antivirus” claim:

- a preregistered recent held-out malicious corpus meets at least 95% weighted
  on-demand detection and at least 90% pre-execution prevention for the declared
  supported classes;
- zero high-impact false positives and the same below-1-in-100,000 upper-bound
  target on the clean corpus;
- an independent recognised lab or independent reproducibility partner verifies
  the primary rates and methodology;
- all errors/skips remain in denominators under the published scoring rule;
- a second clean/malicious regression after the final signed build and rules
  reproduces the threshold.

These are internal go/no-go thresholds, not claims of 100% protection. A passing
EICAR test verifies only a harmless test path. A model, heuristic, or AI label is
not allowed to auto-deny until it independently satisfies the same prevention
false-positive gate and has an explainable rollback version.

### 17.3 False-positive response

- One control disables the affected Zero Security rule/action while leaving
  XProtect/Gatekeeper untouched.
- A critical false-positive report is triaged within one hour, canary revocation
  produced within four hours when confirmed, and broad deployment halted
  immediately.
- Revocations are signed data with sequence/expiry; a server cannot issue an
  executable “repair.”
- Quarantine restore requires successful authentication and never overwrites.
- Post-incident review publishes affected rule/build, cause, scope, correction,
  regression fixture, and whether measurements/claims must be withdrawn.

## 18. Coexistence with other antivirus and EDR products

Apple documents that when multiple Endpoint Security clients subscribe to the
same AUTH event, macOS combines their responses using the most restrictive
result. Therefore an allow from Zero Security cannot override another product’s
deny, while duplicate scanning and two denials can still create performance and
support problems.

Required coexistence behavior:

- never uninstall, stop, mute, inject into, tamper with, or change another
  security product;
- never ask users to disable XProtect, Gatekeeper, SIP, FileVault, or automatic
  Apple security updates;
- identify other ES clients in events and avoid feedback loops;
- offer `Coexistence (observe only)` when another real-time product is present or
  conflict cannot be ruled out; on-demand scanning and quarantine remain explicit;
- make real-time mode a user/admin decision with a clear explanation of duplicate
  scanning and most-restrictive authorization;
- do not silently add mutual exclusions. Every exclusion is visible, scoped,
  expiring where possible, and warns that it reduces this product’s coverage;
- maintain a dated physical-hardware compatibility matrix with representative
  current third-party AV/EDR products and Apple OS updates;
- if crash loops, event gaps, or workload regression occur with a peer client,
  automatically disable only Zero Security’s AUTH subscriptions, retain observe/
  on-demand capability where safe, and show degraded coexistence.

The product may recommend a single primary real-time blocker for performance, but
it must not claim that coexistence is universally safe or that another product is
inferior without comparable evidence.

Reference: [Build an Endpoint Security app](https://developer.apple.com/videos/play/wwdc2020/10159/).

## 19. Transactional install, cutover, rollback, and uninstall

### 19.1 First install

1. Preflight supported OS/build, native architecture, disk space, time, network
   only if update is requested, existing vault/state, and possible security peers.
2. Verify package hash, update manifest signature, Developer ID designated
   requirement/Team ID, entitlement allowlist, Hardened Runtime, notarization
   ticket, and all nested architectures before copying executable code.
3. Atomically place the app in `/Applications`; do not run from the DMG or a
   writable temporary directory.
4. Create/migrate private state with a write-ahead journal and backup of only the
   files being changed.
5. Complete onboarding consent, request system-extension activation, and then
   request Full Disk Access through the supported user/MDM path.
6. Start observe-only, run self-tests, and commit `healthy` only after the
   extension, feed, key, quarantine test vector, XPC peer checks, and event stream
   all pass.
7. If any step fails, leave a working on-demand app or roll back exact changed
   state. Never display real-time protection as active.

### 19.2 Application/system-extension update

Apple’s SystemExtensions framework detects an existing extension with the same
identifier and asks the app’s request delegate whether to replace it based on
bundle versions. The updater uses that supported activation/replacement path.

Transactional update sequence:

1. Stage and fully verify the new app, extension, migrations, and signed manifest.
2. Confirm the new build can read current vault/feed/state and that a rollback
   build can read the pre-migration snapshot.
3. Stop new scans; allow in-progress quarantine/restore commits to finish; flush
   journals and fsync state.
4. Take narrow authenticated backups of the exact mutable state files.
5. Replace the application bundle atomically where supported and submit the
   extension activation/replacement request.
6. Require a versioned health handshake from the new extension, an ES self-test,
   correct entitlements/Team ID, rule-load verification, and no event gap/deadline
   miss during cutover.
7. Commit the new build/epoch only after the health window passes; then retire the
   old app while retaining the rollback snapshot for the declared period.
8. On failure, use a separately signed rescue build with a higher monotonic build
   number and explicit rollback authorization rather than weakening anti-rollback
   checks or reinstalling an unsigned old bundle.

Reference: [Installing, updating, and deactivating system extensions](https://developer.apple.com/documentation/systemextensions/installing-system-extensions-and-drivers).

### 19.3 Uninstall

Uninstall is an explicit signed workflow, not `rm -rf` and not an attempt to edit
Apple’s TCC database.

1. Inventory active scans, findings, quarantine objects, recovery readiness,
   policies, helper/extension state, and managed ownership.
2. Require the user/administrator to choose for quarantine: restore selected,
   export a verified recovery bundle, retain encrypted vault plus key/recovery
   instructions, or irreversibly purge with typed confirmation.
3. Enter draining mode; immediately respond ALLOW to any outstanding AUTH request,
   unsubscribe, stop new work, and finish/abort atomic commits safely.
4. Submit a SystemExtensions deactivation request and verify its result. Apple
   also documents that deleting the containing app removes its system extension,
   but explicit deactivation gives an auditable state transition.
5. Unregister any approved `SMAppService` helpers and verify they stop.
6. Remove app code and optional non-sensitive cache/log data. Do not delete the
   root Keychain item while any retained vault object needs it.
7. Instruct the user/MDM how to remove Full Disk Access/system-extension policy if
   desired; never manipulate TCC directly.
8. Write/export a final receipt containing component versions, actions,
   retained/deleted data, and recovery consequence without sensitive paths.

If deactivation awaits user approval or restart, uninstall reports `pending` and
keeps the minimal signed uninstaller/state needed to complete. It must not claim
completion merely because the app icon disappeared.

## 20. Operational security and incident response

- Reproducible/pinned builds, SBOM, dependency hashes, compiler/Xcode/macOS runner
  versions, and source-to-release provenance are mandatory.
- CI uses separate untrusted test and protected signing stages. Pull requests and
  test malware cannot access release credentials.
- Every entitlement and privacy permission is diffed against an allowlist at
  release.
- Release keys, feed keys, TLS keys, crash keys, and telemetry keys have separate
  roles, rotation, revocation, and incident runbooks.
- Logs are structured, bounded, privacy-minimized, and resistant to attacker-
  supplied terminal/control characters. Sensitive paths are redacted in exported
  diagnostics unless the user chooses otherwise.
- A signed emergency rule can revoke a detection or move the product to
  observe-only; it cannot execute repair code or weaken Apple controls.
- The team drills compromised Developer ID, notarization revocation, feed-key
  compromise, malicious update server, parser zero-day, extension crash loop,
  Keychain loss, quarantine corruption, and false-positive outbreak.
- Public vulnerability disclosure includes a security contact, supported-version
  policy, coordinated disclosure target, signed advisories, CVE handling where
  applicable, and update verification instructions.

## 21. Exact release gates

No gate is satisfied by prose alone. Each requires an artifact linked from the
release decision. `PASS` means the exact signed candidate on the exact support
matrix passed; `WAIVED` is not allowed for a mandatory gate.

| Gate | Mandatory evidence | Blocks |
| --- | --- | --- |
| G0 Scope/claims | Approved claim matrix showing current on-demand/foreground-observe/block capability and every non-goal | Any public release |
| G1 Platform | Physical-hardware results for macOS 14/15/26, Apple silicon and required Intel; all executables verified Universal 2 | M1+ |
| G2 Apple entitlement | Production Endpoint Security entitlement and distribution profiles approved for exact Team/bundle IDs | M2+ |
| G3 Consent | Fresh unmanaged and MDM install tests for extension approval/FDA decline, grant, revoke, reinstall, multi-user, restart | M2+ |
| G4 Signing/notary | Nested signature/DR/Team/entitlement audit, Hardened Runtime, accepted notarization log, stapled offline Gatekeeper test | M1+ |
| G5 ES correctness | Zero deadline misses/gaps in stress and 72-hour soak; event-version tests; explicit overload/degraded behavior | M2+ |
| G6 AUTH safety | Latency budgets, local-only decision proof, exact deny policy, cache invalidation, interpreter/argument cases | M3+ |
| G7 Privilege/XPC | Threat model, peer-signing enforcement, schema/bounds fuzzing, confused-deputy/path-race tests, no generic privileged RPC | M1+ |
| G8 Parser isolation | Sandboxed disposable workers, sanitizer/fuzz corpus, archive-bomb/path traversal/timeout/crash tests on both architectures | Any complex parser |
| G9 macOS vault | Keychain-backed versioned profile, cross-implementation positive/negative vectors, crash/race/APFS/metadata/restore tests | Quarantine in M1+ |
| G10 Recovery | Fresh-Mac recovery drill, rotation/compromise/migration/multi-user/uninstall-key retention tests | Quarantine GA |
| G11 Feeds | Strict data-only schema, signature/key-revocation/expiry/rollback/freeze/A-B activation and offline-stale behavior | Any feed use |
| G12 App updates | Independent manifest signature, package code/notary/entitlement/arch validation, staged cutover and signed rescue rollback drill | Auto-update |
| G13 Performance | Every section 16 budget met on the hardware/OS/coexistence matrix with published method | M2+ |
| G14 Clean/efficacy | Phase-appropriate section 17 preregistered held-out and independent evidence; errors included | M3/M4 claims |
| G15 Coexistence | XProtect/Gatekeeper tests plus dated representative other-ES-client matrix and most-restrictive conflict cases | M2+ |
| G16 UX/accessibility | Onboarding/decline/degraded/quarantine/restore/uninstall usability plus VoiceOver/keyboard/localization QA | M1+ |
| G17 Privacy | Data-flow inventory, consent, retention/delete/export tests, no undeclared network requests, policy/legal review | Any network/telemetry |
| G18 Install/update/uninstall | Transactional failure injection at every step; extension/helper/key/vault final-state verification | GA |
| G19 External review | Independent architecture/crypto/privilege/parser review; all critical/high findings fixed or release stopped | M3/M4 GA |
| G20 Operations | Signing/update/feed incidents and false-positive rollback rehearsed; security contact/advisories live | GA |

The release decision also records:

- exact Git commit and source-tree status;
- SHA-256 of app/DMG/PKG, SBOM, rules, schemas, vectors, and test reports;
- Developer Team ID, designated requirements, entitlements, provisioning-profile
  UUID/expiry, notarization submission/ticket, minimum OS, and architectures;
- rule epoch/expiry and update root versions;
- unresolved limitations and disabled features;
- rollback/rescue build and verified recovery point;
- claim text approved for the site, installer, UI, GitHub release, and support.

## 22. Explicit non-goals

Unless a later version adds a reviewed and gated design, this programme does not
include or claim:

- a kernel extension, disabled SIP, reduced startup security, or direct kernel
  hooking;
- replacement or disabling of Gatekeeper, XProtect, notarization, FileVault, the
  signed system volume, or Apple security updates;
- network TLS interception, a root certificate, firewall, VPN, email gateway,
  browser-history collection, or universal phishing/ad blocking;
- memory forensics, exploit prevention, firmware/boot-sector scanning, full EDR,
  DLP, remote shell, fleet command execution, or automatic persistence removal;
- guaranteed zero-day, polymorphic, packed, archive, or script detection;
- 100% protection, “unhackable,” “stops hackers,” or superior-to-competitor claims;
- secure deletion from APFS/SSD media merely because a pathname was unlinked;
- a Keychain-protected macOS vault before its new profile and recovery gates pass;
- post-quantum or quantum encryption, QKD, QPU-derived keys, or provider-backed
  security;
- support for macOS 13 or earlier, unsupported Intel hardware, Hackintosh, or
  disabled-platform-security configurations;
- a promise that two real-time antivirus products will coexist without measured
  performance/behavior impact.

## 23. Claim vocabulary by state

| Evidence state | Allowed wording | Prohibited shortcut |
| --- | --- | --- |
| M0 | “Local deterministic on-demand scanner preview” | “macOS antivirus” |
| M1 | “macOS desktop on-demand scanning and encrypted quarantine” | “real-time protection” |
| M2 | “Real-time activity monitoring preview; unknown activity may proceed” | “blocks threats in real time” |
| M3 | “Pre-execution blocking for listed exact high-confidence indicators” | “complete antivirus” |
| M4 with G14/G19 | “Antivirus evaluated on [dated build/corpus/method], with [rates/limits]” | timeless/unqualified rates |
| Any degraded state | “Protection degraded: [specific reason and effect]” | green/healthy or silent fallback |

## 24. Primary Apple sources reviewed

Reviewed 21 August 2026. Apple documentation can change; release engineering must
refresh it at every supported-macOS/Xcode transition.

- [Current macOS versions](https://support.apple.com/en-us/109033)
- [Apple security releases](https://support.apple.com/100100)
- [Tahoe-compatible Macs](https://support.apple.com/en-gb/122867)
- [Building a universal macOS binary](https://developer.apple.com/documentation/apple-silicon/building-a-universal-macos-binary)
- [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity)
- [Endpoint Security restricted entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client)
- [Monitoring System Events with Endpoint Security](https://developer.apple.com/documentation/endpointsecurity/monitoring-system-events-with-endpoint-security)
- [Build an Endpoint Security app, WWDC20](https://developer.apple.com/videos/play/wwdc2020/10159/)
- [System Extensions](https://developer.apple.com/documentation/systemextensions)
- [Installing System Extensions and Drivers](https://developer.apple.com/documentation/systemextensions/installing-system-extensions-and-drivers)
- [Full Disk Access and Privacy & Security settings](https://support.apple.com/guide/mac-help/change-privacy-security-settings-on-mac-mchl211c911f/mac)
- [SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice)
- [App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [XPC](https://developer.apple.com/documentation/xpc)
- [Protecting against malware in macOS](https://support.apple.com/guide/security/sec469d47bd8/web)
- [Gatekeeper and runtime protection](https://support.apple.com/guide/security/sec5599b66df/web)
- [Keychain Services](https://developer.apple.com/documentation/security/keychain-services)
- [Hardened Runtime](https://developer.apple.com/documentation/security/hardened-runtime)
- [Notarizing macOS software](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- [Creating distribution-signed Mac code](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac)

This programme becomes a product claim only one signed, verified release at a
time. The default interpretation of missing evidence is “not yet shipped.”
