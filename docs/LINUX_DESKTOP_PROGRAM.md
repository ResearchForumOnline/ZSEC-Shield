# Zero Security Linux desktop antivirus programme

Status: production design and release-gate specification, 21 August 2026.

The repository currently provides an on-demand scanner and foreground post-change
inotify monitoring through Watchdog. It does not currently
provide real-time Linux protection, a privileged daemon, fanotify mediation,
eBPF monitoring, desktop integration, signed Linux repositories, or independently
validated Linux malware-detection efficacy. This document defines the evidence
required before any of those claims may be made.

No step in this programme authorizes installation on the current machine,
modification of system services, loading of eBPF programs, changing SELinux or
AppArmor, installing packages, disabling another antivirus, or testing live
malware outside an approved isolated lab.

## Product outcome

The target is a supported Linux desktop antivirus with:

- deterministic on-demand and scheduled scanning;
- bounded real-time filesystem notification and selected access mediation using
  supported fanotify interfaces;
- a least-privilege daemon and a minimal fanotify broker;
- isolated executable, script, archive, and document parsers;
- automatic encrypted quarantine with recoverable device-bound keys;
- native signed Debian and RPM packages plus rollback-resistant signed data
  updates;
- an unelevated GNOME/KDE-compatible desktop UI;
- enforced systemd and SELinux/AppArmor confinement;
- independently measured detection and false-positive performance; and
- transactional activation, coexistence, cutover, upgrade, rollback, and
  uninstall procedures.

It is not a promise to stop every attack. Linux fanotify has documented coverage
gaps; root can subvert a user-space antivirus; and a compromised kernel, firmware,
boot chain, or hypervisor is outside the trust boundary.

## Supported platform matrix

Support is a tuple of distribution release, architecture, vendor kernel,
filesystem, desktop session, mandatory-access-control mode, systemd version, and
package version—not simply “Linux.” The initial production matrix is deliberately
narrow.

| Tier | Distribution and desktop | Architecture | Kernel/package boundary |
| --- | --- | --- | --- |
| 1 | Ubuntu Desktop 24.04 LTS and 26.04 LTS, GNOME | x86-64 | Canonical-supported GA/HWE kernels and official APT updates only |
| 1 | Debian 13 stable, GNOME and KDE Plasma | x86-64 | Debian stable kernel and official stable/security updates only |
| 1 | Fedora Workstation/KDE Plasma Desktop 43 and 44 | x86-64 | Fedora-supported kernels and official DNF updates only |
| Evaluation | The same releases on AArch64 | AArch64 | Build/test results only; no support claim until its complete gate matrix passes |

Ubuntu 24.04 and 26.04 are current LTS releases in Canonical's published lifecycle;
Debian identifies version 13 as stable; and Fedora 43 and 44 are the supported
Fedora releases at the date of this document. A release manifest must pin exact
tested point releases, kernel ranges, systemd, glibc, fanotify features,
filesystems, desktop sessions, and MAC-policy package versions. The manifest—not
this table—controls whether a particular installation is supported.

Initial filesystem enforcement coverage is local ext4, XFS, and Btrfs on the
stock distribution kernels. Each filesystem has its own test results. FUSE,
overlay, NFS, SMB/CIFS, removable media, encrypted user-space mounts, bind mounts,
containers, and network home directories are reported separately as supported,
notification-only, on-demand-only, or unsupported. They must not inherit a broad
“Linux supported” claim.

Not initially supported:

- Arch, Gentoo, Linux Mint, openSUSE, NixOS, SteamOS, immutable Fedora variants,
  WSL, ChromeOS containers, or end-of-life distributions;
- custom, self-built, real-time, vendor appliance, or security-disabled kernels;
- Linux servers, Kubernetes nodes, containers as protected endpoints, or
  multi-tenant terminal servers; and
- 32-bit systems, RISC-V, POWER, s390x, or AArch64 until their separate matrices
  pass.

An unsupported system may continue to use the on-demand scanner on a best-effort
basis, but it must not enable real-time permission mode or display “fully
protected.”

## Architecture and trust boundaries

```text
  per-user desktop session
  +---------------------+         read-only status / authorized requests
  | zero-security-ui    |<-----------------------------------------------+
  | unelevated GTK UI   |                                                |
  +---------------------+                                                |
                                                                         |
  system scope                                                           |
  +---------------------+   fd-only authenticated IPC   +----------------v--+
  | zero-fanotify-broker+------------------------------>| zero-avd          |
  | tiny, privileged    |<------------------------------| policy/orchestrator|
  | owns fanotify groups|       bounded verdicts        | verdict cache     |
  +----------+----------+                               +--+----------+-----+
             |                                             |          |
   FAN_ALLOW / FAN_DENY                         handle IPC |          +-- reputation
             |                                             v
       Linux VFS/fanotify                         +---------------------+
                                                 | restricted workers  |
                                                 | PE/script/archive/  |
                                                 | document/OEM        |
                                                 +----------+----------+
                                                            |
                                               structured evidence only

  +---------------------+    authorized transaction    +------------------+
  | zero-remediationd   |<------------------------------| zero-avd / UI    |
  | narrow root helper  |                               +------------------+
  +---------------------+

  +---------------------+   signed data only   TUF root/targets/snapshot/time
  | zero-update-service |<----------------------------------------------- CDN
  +---------------------+

  Optional eBPF observer: telemetry enrichment only; never the primary scanner
  or required protection path in the initial production release.
```

### Privilege separation

`zero-fanotify-broker` is the only component permitted to initialize permission
fanotify groups and add system-wide marks. `FAN_CLASS_CONTENT` requires
`CAP_SYS_ADMIN`, a broad capability. The broker therefore contains no parser,
rules engine, updater, cloud client, UI toolkit, archive library, or general
command execution. It accepts a fixed versioned policy, owns the fanotify file
descriptors, and passes read-only event file descriptors plus bounded metadata to
`zero-avd` over an `AF_UNIX` `SOCK_SEQPACKET` channel using `SCM_RIGHTS`.

The broker validates `SO_PEERCRED`, message schema, sequence, length, timeout,
file identity, and verdict authenticator. It answers each permission event once.
It rejects path-based arbitrary scan requests and arbitrary `ioctl`, mount,
process, network, or package operations. If the validated kernel/distro permits
capability drop after all durable marks are created, it drops `CAP_SYS_ADMIN`;
otherwise the capability remains confined to this small broker and is called out
as residual risk. Hot-plug or new-mount support cannot silently re-expand that
privilege.

`zero-avd` runs as a dedicated unprivileged `zeroav` account with no Linux
capabilities. It owns policy, verdict caching, job scheduling, worker lifecycle,
health, quarantine metadata, and privacy-safe audit records. It never receives an
ambient ability to read arbitrary paths; it scans the already-open file
descriptor supplied for a specific event or an explicitly authorized on-demand
descriptor.

Parser workers run under an even narrower identity or sandbox scope. Each worker
receives only input descriptors and an output socket. It has no network, no
package-management access, no device access, no writable executable path, no
access to signing keys, no fanotify descriptor, and no direct quarantine or
original-path write access.

`zero-remediationd` is a separate, small root helper. It accepts only a typed,
authenticated remediation transaction referring to a daemon-issued object ID and
content identity. It performs race-resistant descriptor-relative operations and
cannot execute caller-supplied commands. Desktop requests that change protection,
restore another user's object, or modify system paths require a narrowly named
polkit action and interactive authorization under distro policy.

The updater has write access only to staged update and component-data locations.
It cannot change service units, MAC state, firewall rules, users, boot settings,
or arbitrary files. Native binary/package updates remain the responsibility of
APT or DNF.

## fanotify design

### Separate notification and permission groups

Use two groups because the kernel API gives them different semantics and feature
compatibility:

1. A `FAN_CLASS_NOTIF` group receives non-blocking change information for cache
   invalidation, post-write scans, health accounting, and scheduled follow-up.
   Where the tested kernel/filesystem supports it, this group uses file-handle
   reporting such as `FAN_REPORT_FID`, directory FID/name records, filesystem
   marks, and mount-change tracking.
2. A `FAN_CLASS_CONTENT` group receives the selected permission events and uses
   event file descriptors. File-handle reporting is not mixed into this group
   where the API rejects that combination. The initial enforcement event is
   `FAN_OPEN_EXEC_PERM`; `FAN_OPEN_PERM` is enabled only for frozen high-risk
   scopes and workloads that meet latency and compatibility gates.

The primary change signals are `FAN_CLOSE_WRITE`, executable open, and relevant
move/create events supported by the notification-group feature profile. A
post-write notification schedules scanning; it does not retroactively claim that
earlier access was blocked. Directory marks are not assumed recursive. Prefer
tested filesystem marks, with mount marks where necessary, and continuously
inventory the host mount namespace.

### Permission decision lifecycle

For each permission event:

1. Broker validates event structure and captures monotonic arrival/deadline time.
2. Broker passes the kernel-provided read-only file descriptor and bounded event
   context to `zero-avd`.
3. Daemon derives a content identity and checks an unexpired verdict cache bound
   to filesystem identity, file content, engine, rules, and policy versions.
4. A miss is scanned in restricted workers within the real-time budget.
5. Daemon returns one authenticated `ALLOW`, `DENY`, or policy-defined
   `ALLOW_UNKNOWN` result with reason and expiry.
6. Broker writes exactly one documented `FAN_ALLOW` or `FAN_DENY` response,
   closes its event descriptor, and records latency/health counters.

High-risk executable permission events may deny on a conclusive malicious
verdict. An incomplete, encrypted, unsupported, or timed-out scan is never
reported as clean. The fallback for each scope is explicit in signed policy.
System-critical paths default to availability-preserving `ALLOW_UNKNOWN` with an
urgent health event; a user-writable untrusted executable scope may use
`DENY_RETRY` after that policy passes application-compatibility testing. There is
no universal fail-closed setting that can deadlock boot, login, package upgrade,
or recovery.

### Documented fanotify limitations

fanotify is valuable but incomplete. The product, UI, threat model, and release
claims must preserve all of these facts:

- permission classes require `CAP_SYS_ADMIN` and corresponding kernel
  configuration support;
- multiple programmes can monitor the same objects; ordering differs by class,
  and ordering within the same class is undefined;
- event queues can overflow and events are then lost; `FAN_Q_OVERFLOW` is a
  health failure that invalidates affected caches and schedules a bounded sweep;
- when all descriptors for a group close, outstanding permission events are
  allowed by the kernel, so daemon/broker crash is not fail-closed;
- fanotify sees user-space filesystem API events, not remote changes performed on
  a network filesystem;
- accesses or modifications caused through `mmap`, `msync`, and `munmap` are not
  reported by fanotify;
- mount marks can miss access through another bind mount; filesystem marks reduce
  that gap where supported and tested;
- directory monitoring is not recursive, and adding new child marks has a race;
- FUSE filesystems can provide insufficient/zero filesystem identifiers for some
  file-handle monitoring arrangements;
- namespace, overlay, container, removable-media, encrypted-mount, and unusual
  filesystem behaviour varies by kernel and distribution; and
- a privileged attacker can close, bypass, or tamper with a user-space mediation
  service unless the surrounding OS policy prevents it.

The broker uses an internal deadline plus systemd watchdog so that a hung engine
does not indefinitely stall applications. Closing the group is an emergency
availability action and is accurately reported as protection degraded/fail-open.
No UI wording may turn that into “still fully protected.”

## eBPF boundary

The initial production antivirus does not depend on eBPF for blocking or file
content inspection. An optional signed eBPF observer may enrich behaviour events
such as process execution relationships or selected LSM audit points when every
condition below is true:

- the exact distro kernel advertises the required BPF, BTF, helper, map, ring
  buffer, and attachment features;
- a CO-RE object passes the kernel verifier and the project's kernel matrix;
- loading is performed by a minimal loader with only the capabilities required
  on that kernel (`CAP_BPF`/`CAP_PERFMON` where sufficient); if it requires broad
  persistent `CAP_SYS_ADMIN`, the feature remains disabled;
- maps have fixed upper bounds and contain no file contents or secrets;
- event loss is measured and causes degraded telemetry, never an invented clean
  verdict;
- detaching the programme leaves fanotify and on-demand scanning functional; and
- interaction with SELinux, AppArmor, lockdown, Secure Boot, other BPF users, and
  kernel updates passes the release matrix.

BPF LSM can implement MAC/audit hooks, but portability, hook ordering, distro
configuration, privilege, policy coexistence, and update risk make it unsuitable
as the first-release enforcement root. The kernel verifier limits unsafe BPF
programs; it does not prove antivirus detection correctness. BPF signing, where
supported, proves origin/integrity and remains additional to capability checks and
verification. No custom out-of-tree kernel module is planned.

## Scanner engine and restricted parsers

The Linux engine combines independently testable evidence:

- exact content hashes and signed intelligence;
- versioned data-only signatures and YARA-compatible rules;
- ELF metadata, interpreter/shebang, executable permission, capabilities,
  set-user-ID, package provenance, and trusted repository signer evidence;
- script normalization and suspicious construct analysis without execution;
- archive/container enumeration and recursive member scanning;
- PDF, OLE, OOXML, RTF, and supported embedded-object extraction;
- optional privacy-limited reputation lookup; and
- later behavioural correlation, with ML used only after a locked evaluation
  demonstrates incremental value at an acceptable false-positive cost.

No parser shells out to a desktop application or executes macros, scripts,
installers, document renderers, emulators, or archive hooks. Native libraries are
pinned, inventoried, fuzzed, and invoked only in restricted workers. A parser
crash kills the worker, not the daemon.

Default real-time container budgets are versioned policy values:

- maximum nesting depth: 8;
- maximum members: 10,000;
- maximum cumulative expanded data: 2 GiB;
- maximum expansion ratio: 100:1;
- maximum real-time worker wall clock: 5 seconds; and
- maximum on-demand worker wall clock: 60 seconds before explicit continuation
  or policy action.

These are safety ceilings, not assertions that everything below them is fully
scanned. A budget breach, damaged container, password protection, unsupported
compression method, or parser error produces `INCOMPLETE` with a reason—not
`CLEAN`. Extracted executables are independently intercepted when later opened
for execution on a covered local filesystem.

Verdict cache records bind at least content digest, filesystem/file identity,
size, relevant timestamps/version, engine, rules, policy, scan context, evidence
digest, issue/expiry time, and service authenticator. Notification events,
overflow, write activity, package updates, policy changes, engine/rule changes,
or identity mismatch invalidate the relevant cache entry.

## Quarantine and key storage

Quarantine data resides under `/var/lib/zero-security/quarantine` in a dedicated
non-user-readable filesystem tree. Plaintext is never published there. Each
object uses:

- a fresh random AES-256 content key;
- AES-256-GCM through a maintained audited crypto library;
- canonical authenticated metadata including object ID, original digest/size,
  detection evidence, original path, UID/GID, mode, extended-attribute summary,
  MAC-label summary, engine/rules/policy versions, and timestamps; and
- a crash-safe sequence: create private temporary object, encrypt, flush,
  authenticate, atomically publish, then remove/replace the source under a narrow
  remediation transaction.

The per-object key is wrapped by a random device root. Where the supported
systemd and TPM2 stack passes recovery testing, the root is provisioned as an
encrypted systemd credential bound according to the published TPM/host policy
and delivered to the daemon through the service credential directory. Without a
usable TPM, the explicit fallback is a root-owned `0600` key file on an encrypted
host volume; the UI labels this weaker theft-at-rest posture. The key is never
derived from `/etc/machine-id`, hostname, username, a visual pattern, ZBA state,
or other predictable machine data.

An optional recovery package wraps the device root under an independently
generated recovery key, with a separately specified YubiKey route. Recovery is
tested before activation, revocable, and never uploads the unwrapped device root.
Ordinary users never handle encryption keys.

Restore is a separate authorized transaction. It authenticates the entire object
before plaintext publication, refuses symlink/reparse/path traversal, preserves
only safe metadata, revalidates the destination and content identity, and never
silently overwrites an existing file. Restoring a malicious item requires an
explicit risk warning and re-scan; system-path restore requires the narrow root
helper and polkit authorization. Uninstall preserves quarantine and recovery
material by default until the user exports, restores, or explicitly destroys it.

ZBA may record lifecycle/provenance states. It is not encryption, malware
detection, a Linux authorization mechanism, or evidence that a verdict is true.

## systemd service hardening

Every unit has a reviewed per-distro hardening profile. The exact supported
directives depend on the distro's systemd version; unknown or ignored directives
are release failures, not silently accepted protection.

The unprivileged daemon and workers should use, wherever compatible:

```ini
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
UMask=0077
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native
```

Use `StateDirectory=`, `CacheDirectory=`, `LogsDirectory=`, `RuntimeDirectory=`,
and read-only credential delivery rather than broad writable paths. Workers allow
only `AF_UNIX`; only the separately confined reputation/update clients may use
`AF_INET`/`AF_INET6`. Apply a tested syscall allow-list/deny-list, file-descriptor
limits, process/task limits, memory ceilings, CPU accounting, watchdog, and
restart-rate limits.

The fanotify broker necessarily differs: it needs host mount visibility and the
capability needed to initialize/maintain its configured marks. Do not apply
`PrivateMounts=yes` or a mount namespace that makes protection appear active while
watching only a private view. Its exception set is explicit, minimal, reviewed,
and separately tested. `systemd-analyze security` is recorded as a regression
signal, not treated as proof that a unit is secure.

## SELinux and AppArmor

Mandatory access control is mandatory on distributions that ship it in the Tier
1 profile. The product never asks users to set SELinux permissive/disabled or put
AppArmor profiles in complain mode to make the antivirus work.

Fedora packages ship a versioned SELinux policy package defining separate
domains and file types for the broker, daemon, workers, updater, remediation
helper, state, quarantine, cache, run sockets, and logs. The policy permits the
minimum descriptor transfer and labelled data access. It does not grant a worker
general home-directory reads, `unconfined_t`, package-manager execution, kernel
module loading, or arbitrary network access. File contexts survive package
upgrade and are verified after restore. `audit2allow` output is evidence for
analysis, never blindly incorporated.

Ubuntu and Debian packages ship AppArmor profiles for every system component.
Production profiles load in enforce mode, use the narrowest maintained
abstractions, constrain Unix sockets and capabilities, deny raw network/device
access for parsers, and make distro/version differences explicit. A missing,
failed, or complain-mode required profile means the confinement gate failed.

Both policy families are exercised against normal operation, upgrades, crash
recovery, parser attacks, quarantine/restore, user homes, encrypted homes,
multiple sessions, and false-positive workflows. Denials are triaged; the fix is
not a broad wildcard.

## Native packaging and signed updates

### Debian/Ubuntu

Ship architecture-specific `.deb` packages from a dedicated HTTPS APT repository.
APT authenticates the repository's signed `InRelease`/`Release` metadata and the
package hashes it contains. Configure a Deb822 source with a repository-specific
`Signed-By` key; never use deprecated global trust or bypass options such as
allowing insecure/downgraded repositories. Metadata has a bounded validity period,
and key rotation/revocation is tested.

Package roles are split so users and policy can see privilege:

- `zero-security-engine`;
- `zero-security-daemon`;
- `zero-security-fanotify`;
- `zero-security-ui`;
- `zero-security-apparmor`;
- `zero-security-repo-keyring`; and
- `zero-security-cli`.

### Fedora

Ship architecture-specific `.rpm` packages with OpenPGP package signatures and a
dedicated DNF repository. Both package signature checking and signed repository
metadata checking are enabled in the provided repository definition. Signing is
performed by a release identity isolated from the build account. Fedora packaging
includes a required `zero-security-selinux` policy package.

### Update authority

APT/DNF remains authoritative for executable, service, UI, MAC policy, and broker
updates. The antivirus does not overwrite package-owned executables behind the
package manager. Data-only engine/rule/reputation packages use TUF-style root,
targets, snapshot, and timestamp metadata in addition to transport security:

- offline root: 2-of-3 threshold keys;
- separately delegated stable/beta targets for engine, rules, models, and
  emergency false-positive policy;
- snapshot consistency and target length/digest binding;
- short-lived timestamp metadata for freeze detection; and
- monotonic rollback policy with explicit, signed emergency rollback.

Updates contain no shell, maintainer script, firewall instruction, systemd unit,
package-manager command, arbitrary path, or remote command. They stage in an
untrusted download directory, validate all authorization and compatibility,
fsync, atomically activate a versioned directory, run a self-test, and revert to
the last known-good data set on failure.

`.deb`/`.rpm` maintainer scripts are minimal, noninteractive, idempotent, and
tested under failure injection. Installing a package does not silently activate
permission mode, disable another antivirus, add exclusions, or delete data.
Flatpak, Snap, AppImage, curl-pipe-shell installers, and generic tarballs are not
supported delivery formats for the privileged daemon. They cannot accurately
represent the required host service, package, MAC, and rollback integration.

Every release archives source revision, dependency lock, build container,
compiler, SBOM, license inventory, provenance, artifact digests, package/repository
signatures, and reproducibility variance. Signing keys and credentials are never
present in the build job or public repository.

## Desktop UI and authorization

The initial UI is an unelevated GTK application tested in the declared GNOME and
KDE sessions under Wayland. It communicates with `zero-avd` through a versioned
system D-Bus API or authenticated Unix socket and never reads daemon state files
or quarantine objects directly.

The UI shows independently derived facts:

- current mode: on-demand, notification, or permission;
- covered and excluded mounts/filesystems;
- fanotify group and queue health, including overflow/degraded state;
- daemon/worker/update/MAC-policy health;
- engine, rules, policy, package, and last-successful-update versions;
- last completed scan and whether it was complete, partial, or interrupted;
- quarantine and recovery readiness;
- coexistence status and known coverage limits; and
- optional telemetry/reputation/sample-upload choices.

A green state requires all mandatory signals to be fresh and internally
consistent. Closing the fanotify descriptor, missing a mount, queue overflow,
expired rules, failed confinement, or unavailable remediation produces an
immediate degraded state. Desktop notification agents run per user and expose no
privileged method. The application has a standard `.desktop` file, AppStream
metadata, icons, accessible names, keyboard navigation, screen-reader semantics,
high-contrast support, and reduced-motion behaviour.

Read-only status needs no elevation. Protection changes, exclusions, restore,
sample submission, and system-path remediation use distinct policy actions.
Authentication is requested only at the final consequential step and never cached
beyond the policy's justified lifetime.

## Performance and availability contract

Real-time mediation is an application-latency path. The release benchmark profile
pins CPU, RAM, storage, filesystem, kernel, desktop, power mode, corpus, warm/cold
cache state, concurrency, and competing workload. The initial provisional gates,
which may become stricter but not looser after candidate testing begins, are:

| Measure | Release ceiling |
| --- | --- |
| Cached permission decision | p99 <= 5 ms; p99.9 <= 25 ms |
| Cold untrusted executable up to 25 MiB | p95 <= 500 ms; p99 <= 2 s |
| Reference desktop application launch regression | p95 <= 10% versus disabled baseline |
| Reference boot-to-interactive regression | median <= 5% versus disabled baseline |
| Idle daemon/broker/worker CPU | <= 0.5% of one reference core over 30 minutes |
| Idle resident memory, excluding UI | <= 250 MiB on the reference build |
| Queue overflow or missed permission deadline in the release stress profile | 0 |
| Unbounded queue, worker, archive expansion, or retry loop | 0 |

Report distributions, not averages alone. Performance is remeasured on each Tier
1 distro/filesystem, clean install and upgrade, SSD and supported minimum-memory
profiles, cold/warm caches, concurrent builds/package updates, login storms, large
archives, and worker/reputation failure. A faster `ALLOW_UNKNOWN` does not count as
a successful scan. Users can schedule CPU/I/O-limited scans and pause on battery,
but high-risk permission enforcement cannot silently turn off.

## Efficacy and false-positive programme

Evaluation uses immutable, access-controlled corpus manifests and separates rule
development from held-out testing. The release profile is frozen before labels or
candidate results are exposed. It covers:

- current and historical Linux malware families across ELF, scripts, installers,
  malicious documents, archives, miners, stealers, ransomware, droppers, and
  cross-platform payloads;
- packed, malformed, nested, password-protected, incomplete, offline, and
  reputation-enabled cases;
- execution-time prevention, post-write detection, on-demand detection,
  quarantine, restore, and remediation outcomes;
- signed packages from every Tier 1 base/update/security repository;
- common desktop, development, container-tooling, game, accessibility, document,
  browser, language-runtime, self-extracting, and administrative cleanware; and
- system-critical false positives, user-file false positives, per-family recall,
  time-to-verdict, incomplete scan rate, and performance.

Required release outcomes:

- zero false positives against the exact signed base OS/package corpus used in
  the supported-release image matrix;
- zero false positives that prevent boot, login, desktop, package update, browser,
  backup, accessibility, or antivirus recovery in the compatibility suite;
- broader cleanware false-positive rate no greater than 0.01% per scanned object
  with the sample count and confidence interval published internally;
- all malware detection and family/recency thresholds in the frozen release
  profile met by the exact engine/rules/policy candidate; and
- at least one relevant independent Linux endpoint evaluation before marketing
  the product as independently tested, with public wording limited to the exact
  version, platform, mode, date, methodology, and result.

EICAR and AMTSO feature checks are safe plumbing/feature tests only. They do not
measure malware-family coverage, zero-day protection, Linux rootkit detection, or
false-positive quality. No “100% protection,” “unhackable,” “quantum-secure,” or
“AI stops unknown threats” claim is permitted.

## Coexistence with other antivirus products

Linux has no universal Windows-Security-Center-equivalent registry that proves
which antivirus is primary. Discovery is therefore evidence-limited: installed
packages, enabled/running units, known sockets, fanotify groups visible to the
process, administrator declarations, and vendor-specific supported interfaces.
An absent detection does not prove no other product exists.

Multiple fanotify listeners are allowed, but permission-event ordering within the
same class is undefined and duplicate scanning can multiply latency or deadlock
poorly designed products. Consequently:

- install defaults to on-demand mode;
- when another real-time product is detected or declared, Zero may run on-demand
  or notification-only after compatibility testing;
- simultaneous real-time permission mode is unsupported unless the exact vendor,
  versions, distro/kernel, ordering, update, failure, and removal matrix passes;
- Zero never creates exclusions in another product or asks the other product to
  exclude Zero automatically; and
- Zero never stops, disables, masks, removes, or modifies another product without
  an explicit, named, user-authorized cutover transaction.

The UI distinguishes “another product detected,” “coexistence tested,” “unknown,”
and “no other product found.” It does not call the last state proof.

## Transactional activation, cutover, and uninstall

### Safe staged activation

```text
INSTALL SIGNED PACKAGES, PERMISSION MODE OFF
  -> verify package/repository signatures and MAC policy
  -> daemon/worker/quarantine/update self-tests
  -> notification-only soak and mount coverage inventory
  -> coexistence discovery and explicit user decision
  -> recovery/rollback readiness test
  -> activate permission mode on a bounded pilot scope
  -> verify fanotify, latency, EICAR path, quarantine, update, reboot
  -> expand only through signed policy and staged rings
```

The activation record includes the exact prior service/package state of a detected
other antivirus. The product does not change that state during installation. If
the user later chooses replacement, it presents the exact vendor-specific action,
consequences, recovery method, and required authorization. Generic process killing
or service masking is prohibited.

Every transition has a deadline and rollback. Failure to initialize all mandatory
marks, load confinement policy, start the broker, meet a permission deadline,
validate rules, write quarantine, or report health disables new permission
activation and returns to the last verified mode. The transaction is complete
only after restart/reboot verification; “command returned zero” is not sufficient.

### Uninstall

Uninstall is availability-first and recoverable:

1. refuse new activation/policy transactions;
2. resolve or explicitly allow outstanding permission events;
3. remove fanotify marks and close the groups;
4. verify applications and package management are no longer mediated;
5. stop/disable only Zero units and detach only Zero eBPF links;
6. remove packages through APT/DNF, restoring no unrelated file;
7. preserve quarantine, audit, and recovery keys by default; and
8. offer a separate authenticated export/restore or explicit cryptographic/data
   destruction workflow.

If a prior antivirus was changed by an authorized cutover, restoration is a
separate user-confirmed transaction using the recorded exact prior state and the
vendor's supported method. Uninstall never assumes that reinstalling or enabling
a unit proves protection; it verifies that product's documented health where an
interface exists and otherwise reports verification unavailable.

Package purge does not delete quarantine while objects remain. Key destruction is
allowed only after confirmed empty/exported quarantine and a high-friction
warning that remaining ciphertext becomes unrecoverable.

## Exact release gates

Each gate is pass/fail for an immutable candidate evidence index: source revision,
dependency locks, build environment, packages, SBOM, engine, rules, policy,
signatures, distro image, kernel, filesystem, corpus manifests, and test results.
No dashboard may override missing evidence.

### L0 — claims, design, and threat model

- Current on-demand status and every unsupported capability are explicit.
- Data flows, privilege, IPC, fanotify gaps, eBPF boundary, update trust,
  quarantine, remediation, cutover, and rollback are versioned and reviewed.
- Zero unresolved critical design finding; all high findings have an accepted,
  expiring owner/remediation date and cannot affect the release boundary.

### L1 — on-demand engine

- Unit/property/integration tests pass on every Tier 1 package image.
- Determinism, cancellation, file replacement/TOCTOU, large files, sparse files,
  permissions, xattrs, Unicode, symlinks, hard links, special files, and low
  disk/memory pass.
- Locked efficacy/cleanware profile passes; EICAR is labelled plumbing only.

### L2 — parser isolation

- Every hostile parser runs out of daemon process under the frozen seccomp,
  systemd, and MAC profile with no network or arbitrary-path access.
- Frozen fuzz campaign has zero untriaged crash, hang, sanitizer, escape, or
  memory-safety finding.
- Container ceilings, cancellation, worker replacement, malformed outputs, and
  protocol version mismatch fail safely and never return clean.

### L3 — privilege and IPC

- Broker contains only fanotify/IPC/deadline/health logic; daemon and workers
  have empty capability sets.
- Peer-credential, descriptor-type, schema, replay, flood, confused-deputy,
  stale-verdict, and unauthorized-client tests pass.
- No IPC request can name an arbitrary root operation or execute a command.
- Capability and writable-path inventories exactly match the approved manifest.

### L4 — fanotify notification mode

- Exact mount/filesystem coverage is enumerated and visible in the UI.
- Create/move/write-close, cache invalidation, bind mount, mount attach/detach,
  overflow, namespace, network, FUSE, overlay, and unsupported-filesystem tests
  match documented outcomes.
- Overflow invalidates affected cache, raises degraded health, and completes the
  configured recovery sweep.
- No notification-only path is described as access prevention.

### L5 — fanotify permission mode

- `FAN_OPEN_EXEC_PERM` and every enabled `FAN_OPEN_PERM` scope pass allow, deny,
  timeout, crash, close-group, service restart, boot, login, upgrade, and rollback
  tests on every Tier 1 kernel/filesystem.
- The broker answers each event once; zero unreconciled permission event,
  indefinite application stall, queue overflow, or missed deadline occurs in the
  release stress profile.
- Kernel-documented close/fail-open behaviour is visible and tested.
- Permission mode cannot activate with missing mandatory marks or stale health.

### L6 — quarantine and remediation

- AES-GCM known-answer, nonce uniqueness, AAD tamper, truncation, swap, wrong-key,
  crash/power-loss, atomicity, full-disk, and concurrent-operation tests pass.
- TPM/systemd-credential and root-file fallback modes have distinct recovery and
  theft-at-rest evidence.
- Restore/path race, symlink, hard link, xattr/MAC label, ownership, overwrite,
  malicious restore, multi-user, uninstall-preservation, and key-destruction tests
  pass.
- No plaintext remains after a completed quarantine transaction beyond explicitly
  documented filesystem/storage limitations.

### L7 — systemd and MAC confinement

- Unit directive support is verified on every distro; no ignored hardening
  directive or unexpected writable/executable path.
- SELinux enforcing and AppArmor enforcing profiles pass normal and adversarial
  suites with zero unexplained denial and zero broad wildcard/unconfined escape.
- `systemd-analyze security`, capabilities, syscalls, sockets, namespaces, files,
  devices, and labels are diffed against the approved baseline.
- Product operates without weakening host SELinux, AppArmor, Secure Boot,
  lockdown, or kernel module policy.

### L8 — packaging and update supply chain

- `.deb` repository metadata verifies through scoped `Signed-By`; `.rpm` package
  and repository metadata signatures verify with checking enabled.
- Upgrade, downgrade rejection, key rotation/revocation, expired metadata,
  interrupted transaction, dependency failure, and maintainer-script rollback
  pass on clean and upgraded systems.
- TUF threshold/delegation, freeze, rollback, mix-and-match, wrong-platform,
  truncation, mirror compromise, and emergency data rollback tests pass.
- Package-owned binaries are never overwritten by the data updater; no remote
  command or arbitrary path exists.

### L9 — desktop and accessibility

- GNOME/KDE, Wayland, multi-session, standard user, administrator, screen reader,
  keyboard-only, high contrast, localization, notification, and polkit flows pass.
- Every green/degraded status is reproduced from independently queried component
  health; simulated/demo data cannot appear in production.
- UI compromise cannot change protection, read quarantine plaintext, or reach a
  privileged general method.

### L10 — performance and availability

- Every numeric ceiling in the performance contract passes on every Tier 1
  reference profile, with raw distributions archived.
- Package update, compiler/build, browser, backup, login, low-resource, and
  adversarial event-flood workloads produce no data loss, deadlock, starvation,
  unbounded resource use, or hidden protection downgrade.
- Stop conditions and last-known-good rollback are exercised, not merely written.

### L11 — efficacy and false positives

- Exact candidate passes the frozen internal malware/cleanware thresholds.
- Zero base-system critical false positives and no more than 0.01% broader
  cleanware false positives under the declared method.
- Remediation and execution prevention are measured separately from detection.
- Independent evidence exists before any independent-testing claim; wording is
  constrained to that evidence.

### L12 — coexistence, activation, and uninstall

- Known competing-product discovery is tested but never claimed complete.
- Every advertised coexistence tuple passes simultaneous load, ordering,
  performance, update, crash, rollback, and removal tests.
- Install defaults on-demand; no other antivirus is altered without explicit
  cutover authorization.
- Failed activation restores the last verified Zero mode and leaves package
  management/application access usable.
- Uninstall removes all Zero mediation/links/units, preserves quarantine by
  default, and changes no unrelated service, package, policy, key, or user data.

### L13 — pilot and replacement release

- Signed canary, internal, and limited external rings meet predeclared crash,
  latency, overflow, missed-event, false-positive, detection, update, rollback,
  battery, and support-volume stop conditions.
- Emergency update halt, rules rollback, package rollback, broker-disable,
  quarantine recovery, signing-key revocation, and incident communications drills
  have current evidence.
- Support, false-positive response, vulnerability disclosure, compatibility, and
  distribution-lifecycle ownership are staffed.
- Only after L0–L13 pass may the exact build be called real-time Linux desktop
  antivirus or offered as a replacement for another product.

## Non-goals and prohibited claims

The initial product does not claim:

- kernel, bootloader, UEFI, firmware, hypervisor, or hardware rootkit removal;
- complete coverage of memory-only, `mmap`-only, remote network-filesystem, raw
  disk, container, namespace, or root-initiated activity;
- a host firewall, IDS/IPS, VPN, TLS interception proxy, password manager,
  vulnerability scanner, patch manager, full EDR/XDR, SIEM, or SOC service;
- guaranteed disinfection of modified binaries or automatic repair of arbitrary
  system state;
- scanning plaintext unavailable inside encrypted/password-protected content;
- support for every Linux distribution, kernel, filesystem, desktop, package
  manager, or CPU;
- eBPF as a universal security boundary or a custom kernel-module shield;
- protection against an attacker who already controls root or the kernel;
- zero false positives, zero-day certainty, 100% detection, “unhackable,” or
  “future/quantum-proof” protection; or
- open-source status for proprietary corpora, OEM engines, models, threat
  intelligence, signing systems, or services whose source is not published.

Obfuscation is not a security boundary. ZBA/ZMath state is not detection or
cryptography. AI may assist analysts but does not have autonomous root authority,
modify host policy, or bypass deterministic release and remediation controls.

## Primary references

- [Linux `fanotify_init(2)` manual](https://man7.org/linux/man-pages/man2/fanotify_init.2.html)
- [Linux `fanotify(7)` overview, limits, queue and close semantics](https://man7.org/linux/man-pages/man7/fanotify.7.html)
- [Linux `fanotify_mark(2)` manual](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html)
- [Linux kernel BPF LSM documentation](https://docs.kernel.org/bpf/prog_lsm.html)
- [Linux kernel eBPF syscall documentation](https://docs.kernel.org/userspace-api/ebpf/syscall.html)
- [Linux kernel self-protection documentation](https://docs.kernel.org/security/self-protection.html)
- [systemd execution environment and sandboxing source documentation](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [`systemd-analyze` source documentation](https://github.com/systemd/systemd/blob/main/man/systemd-analyze.xml)
- [systemd system and service credentials](https://systemd.io/CREDENTIALS/)
- [polkit authorization API](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [SELinux Project reference-policy documentation](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/reference_policy.md)
- [AppArmor profile syntax and modes](https://apparmor.net/man/3.0/apparmor.d/)
- [APT repository authentication](https://manpages.debian.org/testing/apt/apt-secure.8.en.html)
- [APT repository-scoped `Signed-By`](https://manpages.debian.org/testing/apt/sources.list.5.en.html)
- [RPM package signing](https://rpm.org/docs/latest/man/rpmsign.1)
- [The Update Framework metadata model](https://theupdateframework.io/docs/metadata/)
- [Ubuntu release lifecycle](https://ubuntu.com/about/release-cycle)
- [Debian stable release information](https://www.debian.org/releases/stable/)
- [Fedora release lifecycle](https://docs.fedoraproject.org/en-US/releases/lifecycle/)
- [AMTSO Security Features Check](https://www.amtso.org/security-features-check/)
