# Zero Security full Windows antivirus programme

Status: target architecture and release programme. This document describes the
work required to turn the current on-demand preview into a supported replacement
Windows antivirus. It is not evidence that those capabilities exist today.

## Absolute safety rule

**Placeholder, sample, stub, proof-of-concept, or always-clean drivers and
providers must never be installed, loaded, registered, signed for distribution,
or presented to Windows as protection.** This includes minifilters, ELAM drivers,
AMSI providers, services, WSC adapters, and installer prototypes.

Until every applicable gate in this document is satisfied, Malwarebytes or
Microsoft Defender remains the active real-time provider. Development must not
disable it, modify its exclusions, alter Windows Security Center registration,
or test live malware on the developer's everyday computer. Kernel, AMSI, ELAM,
WSC, coexistence, and cutover work belongs in disposable, snapshotted Windows
virtual machines and later on dedicated pilot hardware.

## Product outcome

The finished product is a Windows security provider with:

- real-time file interception before execution and at relevant write/close
  transitions;
- x86 and x64 AMSI inspection for scripts and other AMSI-enabled applications;
- deterministic and heuristic local scanning, optional reputation lookup, and
  independently measured detection efficacy;
- automatic remediation and authenticated encrypted quarantine;
- a protected antimalware service, ELAM integration, tamper protection, and
  supported Windows Security integration;
- cryptographically authorized, rollback-resistant engine, rules, application,
  and driver updates;
- transactional installation, provider cutover, uninstall, and recovery; and
- support, false-positive response, vulnerability disclosure, compatibility,
  and annual independent recertification operations.

An EICAR detection, a passing unit test, a polished dashboard, a registered
service, or a loadable driver does not establish that outcome.

## Production architecture

```text
                         +-----------------------+
                         | Unelevated Windows UI |
                         +-----------+-----------+
                                     |
                              authenticated IPC
                                     |
  +------------------+     +---------v-----------+      +------------------+
  | AMSI x86 provider+---->| zero-av-service     |<-----+ WSC integration  |
  +------------------+     | policy/orchestration|      | approved path    |
  +------------------+     | verdict cache       |      +------------------+
  | AMSI x64 provider+---->| remediation/health  |
  +------------------+     +---+---------+-------+
                                  |         |
                 bounded handle IPC         +---- reputation client
                                  |
             +--------------------v---------------------+
             | Restricted, replaceable scanner workers |
             | PE | script | archive | document | OEM  |
             +--------------------+---------------------+
                                  |
                          structured evidence
                                  |
  file operations      +----------v-----------+       signed TUF metadata
  -------------------->| zero-realtime.sys    |       + signed packages
                       | thin minifilter       |<------ zero-update-service
                       +-----------------------+

  boot driver classification ---> zero-elam.sys ---> protected-service trust
```

The security boundary is operating-system isolation, least privilege,
authenticated IPC, standard cryptography, code signing, and narrowly scoped
authorization. Obfuscation, private algorithms, ZBA labels, and UI state are not
security boundaries.

### `zero-realtime.sys`: runtime minifilter

The minifilter is intentionally small. Its responsibilities are to:

- observe Microsoft-supported file-system callback points;
- identify the file by volume, file ID, stream, and current content identity;
- request or reuse an unexpired service-issued verdict;
- hold, allow, or deny the operation under a bounded policy; and
- emit minimum diagnostic state needed to investigate a failure.

It must cover the product's declared threat paths, including create/open,
write/cleanup, rename/replace, alternate data streams, executable image-section
creation, supported local file systems, and explicitly documented network-share
behaviour. It must safely handle recursion, paging I/O, cancellation, service
restart, shutdown, low memory, low disk, and timeout conditions.

The driver must not parse PE files, documents, archives, or scripts; evaluate
YARA; call the network; run ML; contain a general command channel; or accept
arbitrary privileged I/O requests. The service communication protocol is
versioned and rejects unknown message types, oversized messages, stale requests,
and unauthorized clients.

Production uses a unique altitude assigned by Microsoft in the `FSFilter
Anti-Virus` load-order group. A sample altitude, a Defender-associated altitude,
or an invented production altitude is forbidden. The architecture follows the
kernel-to-user-mode division demonstrated by Microsoft's Scanner minifilter
sample, but sample code is not production code.

### `zero-av-service.exe`: trusted orchestrator

The Windows service owns:

- policy and exclusion evaluation;
- authenticated minifilter, AMSI, UI, worker, updater, and WSC IPC;
- content/verdict caching with explicit expiry and invalidation;
- scan scheduling, cancellation, and resource budgets;
- remediation transactions and quarantine inventory;
- protection health and definition freshness;
- audit events without file contents or secrets; and
- controlled recovery when a worker or dependent component fails.

It does not parse hostile formats in-process. It accepts file handles or bounded
streams, not caller-controlled paths, and passes them to restricted workers. A
crashed worker is discarded and replaced. The service applies the final policy
to structured worker evidence.

The mature service is registered as a Windows protected antimalware service only
after the ELAM trust chain and Microsoft programme requirements have been met.
Every non-Windows DLL loaded into the protected service must be allowed by that
trust model and correctly signed. The UI remains an ordinary unelevated process;
it cannot directly change protection state, rules, quarantine, or updates.

### Restricted scanning workers

Use separate, replaceable workers for high-risk parser families:

- PE/native executable and Authenticode metadata;
- scripts and normalized AMSI content;
- archives and compressed containers;
- documents and embedded objects; and
- optional separately licensed/OEM engines.

Workers run with restricted tokens or AppContainer where compatible, no ambient
network access, no writable executable directories, a minimal handle allow-list,
and Job Object process, CPU, memory, child-process, and wall-clock limits. Archive
depth, member count, expanded bytes, compression ratio, and parser recursion are
bounded. Results are schema-validated evidence, never executable instructions.

### AMSI providers for x86 and x64

Ship separate signed in-process COM providers for 32-bit and 64-bit hosts. Each
implements the documented `IAntimalwareProvider` contract and remains thin:

1. validate the AMSI stream and metadata;
2. send bounded content to the service over authenticated local IPC;
3. enforce a strict response deadline; and
4. return the service verdict using documented AMSI result semantics.

Providers do not embed the full engine, contact cloud services, load components
by unsafe search paths, or return `clean` merely because the service is missing,
crashed, incompatible, or timed out. Provider registration is an installer
operation allowed only after VM integration gates pass. An always-clean or
placeholder AMSI implementation must never be registered, even for a demo on a
real machine.

### `zero-elam.sys` and protected service

ELAM is a separate minimal boot-start driver, not the runtime scanner. It
classifies boot-start drivers from a compact, signed policy and establishes the
certificate information used to validate protected antimalware service binaries.
It must meet Microsoft's ELAM submission, memory, timing, recovery-copy, and
signature requirements. The runtime antimalware service must be ready before
ELAM unloads.

ELAM implementation starts only after the user-mode engine and runtime minifilter
are stable. Production ELAM submission and protected-service registration are
blocked on Microsoft Virus Initiative eligibility and the approved Microsoft
process. A hand-built or test-signed ELAM driver is never loaded on the everyday
PC.

### Windows Security Center and MVI

The public Windows Security Center interfaces are used now only to read aggregate
health, enumerate providers, and verify state. The repository must not implement
registry/WMI manipulation or undocumented COM calls to make Zero Security appear
registered.

Provider registration is added only through the documented/approved Microsoft
onboarding path available to an eligible security vendor. The programme plans
for the current Microsoft Virus Initiative requirements, including a commercial
real-time antimalware product, Windows compatibility maintenance, trusted code
signing, a qualifying independent lab result, agreements, support operations,
and annual recertification. Requirements are re-read from Microsoft before each
submission because they can change.

### Signed updater

`zero-update-service.exe` is separate from scanners and exposes no remote shell,
script, firewall, registry, package-manager, or arbitrary-command mechanism.
Updates are declarative packages for named component classes only.

The authorization model uses The Update Framework roles:

- offline root role: 2-of-3 threshold keys;
- delegated targets roles for application, engine, rules, AMSI, minifilter, and
  ELAM packages;
- snapshot metadata binding the complete repository view; and
- short-lived timestamp metadata preventing freeze attacks.

Acceptance requires all of the following: trusted TUF path, matching component
and platform, unexpired metadata, length and digest match, monotonic rollback
policy, valid Authenticode publisher signature, and—where applicable—a valid
Microsoft-signed driver package. Root keys and production signing credentials
are never distributed with source or builds.

Install is staged, verified, atomically activated, health-checked, and reversible.
Rules, engine, application, and kernel packages use separate rollout rings and
stop conditions. A feed record can describe detection data; it cannot cause code
execution or system configuration changes.

## Detection and verdict model

The first defensible engine combines independently testable layers:

1. exact hashes and signed local intelligence;
2. versioned signatures and YARA-compatible data rules;
3. Authenticode validation and signer policy;
4. bounded PE, script, archive, and document static analysis;
5. optional privacy-limited reputation lookup;
6. later behavioural correlation from narrowly defined events; and
7. ML only after locked, representative evaluation demonstrates incremental
   value at an acceptable false-positive cost.

No single heuristic or model score silently produces a high-impact verdict.
Policy combines evidence, file origin, content type, execution context, publisher
trust, prevalence, and confidence. Human-reviewed emergency false-positive
overrides are signed, scoped, expiring, and auditable.

A cached verdict token binds at least:

```text
schema_version        file_content_hash       volume_and_file_identity
verdict               reason_codes            confidence_class
engine_version        ruleset_version         policy_version
scan_context          issued_at               expires_at
evidence_digest       service_authenticator
```

Changing the file, relevant metadata, engine, rules, policy, or expiry invalidates
the cache as defined by the versioned policy. Kernel code enforces the token; it
does not recalculate research formulas or reinterpret model output.

Timeout behaviour is risk-specific. An untrusted executable, script, or image
mapping can remain held or blocked. Lower-risk content may be marked unknown and
queued according to policy. The driver must never apply a universal fail-closed
rule that can deadlock boot, logon, update, or storage recovery.

## Quarantine, ZBA, and ZMath

Quarantine uses the versioned ZME2 container and established cryptography:

- fresh random AES-256 content key per object;
- AES-GCM encryption and authenticated canonical metadata;
- device root protected by Windows DPAPI and, where supported, TPM binding;
- crash-safe write, flush, verification, and atomic publication;
- restore to a non-conflicting destination unless the user explicitly approves
  replacement; and
- recorded detection, policy, engine, rules, and restore provenance.

Routine quarantine is automatic. Recovery uses a separately wrapped recovery
key, optionally strengthened by a supported YubiKey route. Machine GUIDs,
password-derived local identifiers, visual patterns, and ZBA values are never
cryptographic keys.

ZBA is useful as a lifecycle/provenance state model:

- `0`: observed or untrusted;
- `3`: analysis incomplete or pending; and
- `6`: determined under identified engine, rules, and policy versions.

ZBA records and explains state transitions. ZMath can specify container and
state invariants. Neither detects malware, proves that a verdict is correct,
replaces authenticated encryption, or justifies quantum-security claims.

## Malwarebytes coexistence and cutover

### Phase 0 — safe development now

The everyday PC remains protected by Malwarebytes or Defender. Build and test:

- specifications, feed verifier, engine, restricted workers, IPC library,
  ZME2 vault, updater verifier, and UI;
- read-only WSC inventory and health reporting;
- unsigned or development-signed packages as build artifacts only; and
- driver/provider source and CI compilation without local installation.

On-demand scans may inspect copied benign fixtures in an isolated state
directory. They do not claim real-time protection.

### Phase 1 — disposable VM integration

Use snapshotted Windows VMs with no personal data. First test a clean Microsoft
Defender configuration, then separate Malwarebytes coexistence images. Load only
test-signed builds in these VMs. Exercise service loss, timeouts, crashes,
shutdown, upgrade, rollback, malformed files, EICAR, AMTSO feature checks, and
private malware samples under an isolated lab procedure.

Do not attempt WSC provider registration in this phase. EICAR and AMTSO prove
path wiring only, not product efficacy.

### Phase 2 — signed internal alpha

After user-mode and VM gates pass, obtain the required organizational signing
identity, Microsoft-assigned minifilter altitude, Partner Center access, and
signed driver packages. Install only on dedicated internal hardware. Run
compatibility, performance, verifier, HVCI, upgrade, recovery, and long-duration
tests. Zero Security is still not the everyday PC's primary provider.

### Phase 3 — certification and supported integration

Complete the relevant Windows Hardware Lab Kit coverage, Microsoft driver
submission, independent antimalware lab evaluation, MVI application/agreements,
ELAM submission, protected-service work, and approved WSC integration. Establish
support, false-positive, compatibility, incident, and signed-update operations.

### Phase 4 — narrow replacement pilot

Use dedicated pilot machines with recoverable images. The cutover transaction is:

```text
PRECHECK
  -> STAGE SIGNED ZERO COMPONENTS
  -> LOCAL SELF-TEST
  -> APPROVED WSC REGISTRATION
  -> READ BACK ZERO ACTIVE AND CURRENT
  -> USER-CONFIRMED MALWAREBYTES REMOVAL OR MODE CHANGE
  -> READ BACK EXPECTED SINGLE-PROVIDER HEALTH
  -> COMPLETE
```

Before cutover, precheck OS/build support, Secure Boot and HVCI state, pending
reboot, disk space, current providers, signatures, update freshness, recovery
path, and rollback package. Do not force-remove or disable Malwarebytes.

If any stage fails, deactivate and remove the staged Zero components using the
tested rollback path, restore the previous provider where necessary, and verify
through documented WSC read APIs that Malwarebytes or Defender is active and
current. A log message or successful uninstall command alone is insufficient.

### Phase 5 — everyday-PC cutover

The user's everyday PC is last, after the independent efficacy, supported WSC,
driver, update, rollback, and pilot-health gates pass. Cutover requires an exact
backup/recovery point and an explicit choice about removing Malwarebytes. The
machine is not considered protected by Zero until WSC read-back, Zero service
health, definitions, real-time test, quarantine test, and reboot persistence all
verify successfully.

## Target repository component layout

This is the intended programme layout; directories do not imply implemented or
certified capabilities.

```text
zero-security-suite/
|-- apps/
|   `-- windows-ui/
|-- specs/
|   |-- scan-ipc.md
|   |-- verdict-token.md
|   |-- remediation-state.md
|   `-- zme2-container.md
|-- service/
|   |-- orchestrator/
|   |-- quarantine/
|   |-- remediation/
|   |-- reputation-client/
|   |-- health/
|   `-- updater/
|-- providers/
|   `-- amsi/
|       |-- x86/
|       `-- x64/
|-- drivers/
|   |-- minifilter/
|   `-- elam/
|-- workers/
|   |-- common-sandbox/
|   |-- pe/
|   |-- scripts/
|   |-- archives/
|   |-- documents/
|   `-- oem-adapter/
|-- engine/
|   |-- hashes/
|   |-- signatures/
|   |-- rules/
|   |-- signer-trust/
|   |-- heuristics/
|   `-- verdict-fusion/
|-- platform/
|   |-- ipc/
|   |-- crypto/
|   |-- tpm/
|   |-- wsc-readonly/
|   `-- logging/
|-- vault/
|   |-- zme2/
|   `-- zba-ledger/
|-- update/
|   |-- tuf-client/
|   `-- metadata-tools/
|-- installer/
|   |-- msi/
|   |-- driver-package/
|   `-- cutover-rollback/
|-- tests/
|   |-- unit/
|   |-- property/
|   |-- fuzz/
|   |-- cleanware/
|   |-- synthetic/
|   |-- amtso/
|   |-- vm-integration/
|   |-- coexistence/
|   |-- driver/
|   `-- recovery/
|-- windows/
|   `-- README.md
`-- docs/
    |-- FULL_ANTIVIRUS_PROGRAM.md
    |-- PRIVACY_CONTRACT.md
    |-- THREAT_MODEL.md
    `-- release-runbook.md
```

Private systems contain live malware corpora, sensitive threat intelligence,
OEM engine material, unreleased signatures/models, production reputation data,
release credentials, HSM policy, and signing operations. Private modules are
described as proprietary or separately licensed, never as open source.
Obfuscation may slow casual copying but is not access control or a security
boundary.

## Release and certification gates

A gate passes only with immutable evidence linked to the exact source revision,
dependency lock, toolchain, rules, engine, policy, binaries, and corpus manifest.
Waivers are written, scoped, expiring, risk-owned, and cannot waive the absolute
no-placeholder-installation rule, signing, WSC approval, efficacy, or rollback
requirements.

### G0 — design and threat-model gate

- IPC, verdict, update, quarantine, privilege, data-flow, and rollback formats
  are versioned and reviewed.
- Threat model covers malicious files, parser escape, local admin, compromised
  update infrastructure, rollback/freeze, symlink/reparse races, TOCTOU,
  denial-of-service, and false-positive recovery.
- Unsupported claims and current limitations are present in release material.
- Result: signed design review with no unresolved critical finding.

### G1 — user-mode engine gate

- Unit and property tests pass on every supported Windows architecture/build.
- All hostile-format parsers complete their frozen fuzz campaign with zero
  unreproduced or untriaged crash, hang, sanitizer, or memory-safety finding.
- Resource limits are enforced for archive bombs, recursion, oversized input,
  cancellation, and worker death.
- Locked cleanware and private malware evaluations use immutable manifests;
  the numeric detection and false-positive thresholds are approved and frozen
  before labels/results are unblinded, then met by the exact release candidate.
- Quarantine encryption, tamper, crash, restore, path-conflict, and key-recovery
  tests pass.

### G2 — AMSI gate

- Native x86 and x64 host matrices pass with the exact signed providers.
- PowerShell, Windows Script Host, Office-supported paths, chunked streams,
  Unicode, empty/large content, cancellation, timeout, service restart, and
  version mismatch behave as specified.
- Fault injection confirms service/provider failure never becomes a clean result.
- Registration, upgrade, rollback, and removal restore the prior system state.
- No provider is registered outside disposable VMs before this gate passes.

### G3 — runtime minifilter gate

- Microsoft has assigned the production altitude; INF/service settings use it.
- Static analysis, CodeQL where applicable, compiler security warnings, API
  validation, Driver Verifier, and File System Filter Verifier show zero
  unresolved release-blocking findings.
- Required HLK tests and the HVCI/Memory Integrity compatibility test pass with
  Secure Boot and Memory Integrity enabled.
- Boot, logon, shutdown, restart, sleep/resume, update, rollback, service loss,
  low memory/disk, cancellation, high I/O, multi-user, supported file systems,
  network policy, reparse points, and simultaneous security software tests pass.
- There are zero untriaged kernel crashes, hangs, deadlocks, verifier violations,
  or data-corruption events for the candidate soak.
- The exact driver package is signed through the approved Microsoft path.

### G4 — remediation and tamper gate

- On-access detect/block, quarantine, process handling, persistence cleanup,
  restore, exclusions, reboot completion, and partial-failure rollback pass.
- Unauthorized UI, standard user, low-integrity, worker, and local IPC clients
  cannot weaken protection or modify protected state.
- A broken rule/engine update automatically returns to the last known-good
  combination without corrupting quarantine or disabling the active provider.
- Support can reproduce every user-visible action from privacy-safe audit data.

### G5 — supply-chain and update gate

- Release binaries carry the required Authenticode or Microsoft driver signature.
- TUF root threshold, delegation, expiry, snapshot consistency, and target
  authorization validate for the exact artifacts.
- Freeze, rollback, mix-and-match, mirror compromise, expired metadata, wrong
  channel, wrong platform, truncated package, and key-rotation tests fail safely.
- SBOM, provenance, SHA-256 manifest, dependency/license inventory, and
  reproducible-build variance report are published or archived as policy requires.
- Offline-root ceremony, online-key rotation, emergency revocation, ring halt,
  package rollback, and disaster-recovery drills have current evidence.

### G6 — efficacy and independent validation gate

- EICAR and AMTSO feature checks pass but are recorded only as wiring checks.
- A locked internal evaluation meets its predeclared malware-family, recency,
  prevalence, offline/online, remediation, performance, and cleanware gates.
- At least one independent result from a laboratory and certification level
  currently accepted by MVI meets Microsoft's current published minimum.
- No release claim exceeds the exact tested platform, mode, version, date,
  methodology, and limitations.

### G7 — Microsoft integration gate

- Organizational identity, Partner Center, trusted signing, support, and Windows
  compatibility operations are active.
- MVI eligibility and required agreements are confirmed by Microsoft.
- ELAM submission/signing and protected-service tests pass where used.
- WSC integration uses only the approved provider path.
- Documented read-back shows Zero active and current, stale/error states report
  correctly, and rollback restores the expected prior provider.

### G8 — coexistence, cutover, and pilot gate

- Supported Defender and Malwarebytes coexistence/uninstall matrices pass on
  clean, upgrade, repair, rollback, and failed-install paths.
- Installer never leaves a tested machine without a verified active provider.
- Canary and internal rings meet the frozen crash, hang, boot failure, detection,
  false-positive, performance, update, and support-volume stop conditions.
- Rollout automatically halts on a breached condition; rollback is exercised,
  not merely documented.
- The release authority signs the evidence index for the exact candidate.

### G9 — replacement release gate

Only after G0–G8 pass may a build be described as a replacement antivirus or be
offered for cutover on the user's everyday PC. Continuing release requires:

- monitored staged deployment rather than universal first-day distribution;
- current definition, engine, application, and driver signing operations;
- ongoing vulnerability and false-positive response;
- Windows compatibility testing before relevant Windows updates;
- annual independent certification and current MVI obligations; and
- tested emergency revocation, recovery, and provider-restoration procedures.

## Privacy and operational contract

Protection works locally without uploading file contents. Reputation and sample
submission are separate, transparent choices. Default telemetry is limited to
the minimum needed to establish component health, crash/update safety, and
aggregate efficacy; it excludes document contents, browsing history, credentials,
raw quarantine objects, and unrelated file names. A user can inspect retention,
disable optional collection, and delete account-linked data without disabling
local scanning.

Security operations maintain published contacts and service levels for false
positives, vulnerable components, revoked signatures, failed updates, and
recovery. Definitions and software expose exact version, build time, freshness,
channel, signature status, and last successful self-test. A green dashboard is a
rendering of these facts, not an independent source of truth.

## Primary implementation references

- [Microsoft Virus Initiative membership criteria](https://learn.microsoft.com/en-us/unified-secops/virus-initiative-criteria)
- [Protecting antimalware services](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)
- [Early Launch Anti-Malware overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/early-launch-antimalware)
- [ELAM driver requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-driver-requirements)
- [ELAM driver submission](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-driver-submission)
- [AMSI developer audience](https://learn.microsoft.com/en-us/windows/win32/amsi/dev-audience)
- [`IAntimalwareProvider`](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nn-amsi-iantimalwareprovider)
- [Microsoft AMSI provider sample](https://learn.microsoft.com/en-us/samples/microsoft/windows-classic-samples/iantimalwareprovider-sample/)
- [Minifilter load-order groups and altitude ranges](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers)
- [Allocated minifilter altitudes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes)
- [Microsoft Scanner minifilter sample](https://github.com/microsoft/Windows-driver-samples/blob/main/filesys/miniFilter/scanner/README.md)
- [Windows Security provider architecture](https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/windows-defender-security-center/windows-defender-security-center)
- [Windows Security Center API](https://learn.microsoft.com/en-us/windows/win32/api/wscapi/)
- [Driver signing requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs)
- [Driver security checklist](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/driver-security-checklist)
- [File System Filter Verification](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/file-system-filter-verification)
- [Safe driver deployment practices](https://learn.microsoft.com/en-us/windows-hardware/drivers/develop/safe-deployment-best-practices-for-drivers)
- [The Update Framework metadata model](https://theupdateframework.io/docs/metadata/)
- [AMTSO Security Features Check](https://www.amtso.org/security-features-check/)
