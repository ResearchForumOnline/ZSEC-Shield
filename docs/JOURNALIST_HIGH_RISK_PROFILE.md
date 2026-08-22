# Journalist and high-risk user protection profile

Status: evidence-backed control contract and implementation roadmap, 22 August
2026. This profile reduces exposure and improves incident readiness. It is not a
claim that ZSEC detects or prevents Pegasus, Predator, Graphite, or every
mercenary-spyware exploit.

The intended users are journalists, civil-society organisations, elected
officials, diplomats, researchers, lawyers, sources, and other people whose work
may attract targeted attacks. The UK National Cyber Security Centre classifies
journalists and others with access to sensitive information as high-risk
individuals and advises using centrally managed devices where possible. ZSEC is
one layer within that operating model, not a substitute for an organisation's
security team or a specialist forensic service.

The machine-readable companion to this document is
[`../specs/journalist-high-risk-profile.v1.json`](../specs/journalist-high-risk-profile.v1.json).
Repository tests bind its implemented states to concrete source markers so an
implemented control cannot silently become a marketing-only statement.

## Outcome and non-claims

The profile has four defensible outcomes:

1. reduce browser attack surface before an untrusted page is processed;
2. retain and attest the operating system's supported real-time protection;
3. surface patch, encryption, exploit-mitigation, and protection-health gaps;
4. preserve bounded, privacy-conscious evidence for qualified incident response.

It cannot establish any of the following:

- that a device is immune to Pegasus or another named implant;
- that a no-match means a device is clean;
- that a suspicious domain, crash, process, or file identifies an attacker;
- that a browser can stop a zero-click delivered through iMessage, WhatsApp,
  baseband processing, another application, firmware, or a mobile OS service;
- that ZSEC's current post-change watcher is pre-access real-time antivirus; or
- that Zero Boundary Algebra supplies encryption, exploit mitigation, malware
  detection, entropy, key derivation, or threat attribution.

Apple states that mercenary-spyware attacks are exceptionally well funded,
evolve over time, and cannot be detected with absolute certainty. Amnesty's
Security Lab likewise warns that public indicators and general forensic tools
may not detect the latest advanced spyware without expert knowledge and private
indicators. ZSEC must preserve those boundaries in every UI, installer, report,
and site claim.

## Threat routes

The phrase "Pegasus protection" hides materially different attack paths. ZSEC
must keep them separate.

| Route | Documented example | ZSEC-relevant control | Remaining boundary |
| --- | --- | --- | --- |
| Plaintext traffic injection | Google TAG documented an Intellexa campaign that redirected an ordinary HTTP visit to an exploit server | HTTPS upgrading; strict mode blocks top-level HTTP | An HTTPS destination can still contain malicious or compromised content |
| Watering hole or targeted browser link | Google TAG documented compromised government sites delivering iOS WebKit and Android Chrome exploit chains | fast Evergreen runtime updates, Chromium sandbox/Site Isolation, strict third-party active-content blocking, permission denial | An unknown same-site exploit or a complete renderer/sandbox chain may still succeed |
| Browser download | Targeted links and drive-by delivery may place a payload on disk | explicit user approval, safe destination allocation, no automatic open, OS real-time provider, post-download ZSEC scan | ZSEC's current watcher is post-change and cannot replace pre-access enforcement |
| Account takeover and spear phishing | NCSC and Google identify high-risk accounts and targeted phishing as primary routes | passkeys or FIDO2 security keys, account recovery review, provider advanced-protection programmes | A browser cannot enrol or recover an external account on the user's behalf |
| Non-browser zero-click | Citizen Lab's BLASTPASS chain used malicious PassKit images delivered through iMessage | current OS updates; Apple Lockdown Mode on supported Apple devices; expert response | ZSEC Browser has no decision point in this path |
| Post-compromise surveillance | An implant may access data after an OS or application exploit | native provider health, encryption-at-rest posture, evidence preservation and qualified forensics | Endpoint encryption does not protect data while a compromised logged-in user can access it |

## Current enforcement

The following controls are in the current Windows browser source and can be
described only at their exact decision points:

- installation requires a validly Microsoft-signed Evergreen WebView2 runtime;
- the browser uses a separate WebView2 user-data folder, does not configure
  known security-reducing runtime flags, and its status check fails health if
  one is observed;
- host objects and web messages are disabled, password saving and general
  autofill are disabled, developer tools are disabled, and script dialogs are
  disabled;
- site permission requests are denied and not persisted;
- certificate errors are cancelled rather than bypassed;
- unexpected extension identities fail startup; the expected ZSEC Shields
  extension must be present once and enabled;
- HTTP navigation is upgraded in standard mode and blocked in native strict
  mode;
- native strict mode blocks cross-site scripts, documents, stylesheets,
  XMLHttpRequest, Fetch, and WebSocket traffic;
- the MV3 high-risk profile separately blocks top-level HTTP plus third-party
  scripts, subframes, objects, and WebSockets;
- every download requires an explicit confirmation, is never automatically
  opened, and uses a bounded non-overwriting destination; and
- local product history can be disabled or cleared on exit.

These controls are meaningful exposure reduction. They do not attest that
JavaScript JIT is disabled, that every renderer remained sandboxed, that Site
Isolation was effective for a particular navigation, or that a blocked request
was spyware. The current status tool explicitly records
`sandbox_attestation_complete: false`.

The current ZSEC Antivirus companion adds deterministic local scanning,
post-change filesystem monitoring, bounded content review, encrypted quarantine,
baseline scanning, and reconciliation. It does not interpose before file access
or execution and is not a registered Windows primary antivirus provider.

## Implement-now versus release-gated matrix

"Implement now" means the work can be built using supported, documented
user-mode or operating-system interfaces. It does not mean the control may be
advertised before its tests and runtime evidence pass. "Release gated" means
the control depends on a stable vendor API, signing/onboarding, dedicated test
systems, independent evaluation, or another external condition.

| Control | Current state | Implement now | Release gate and required evidence |
| --- | --- | --- | --- |
| Evergreen browser engine | Microsoft-signed Evergreen WebView2 is required and runtime update availability is surfaced | record engine version, update-ready state, restart age, and security-channel freshness in one posture report | fail release when the supported runtime is absent, stale, unsigned, or launched with a prohibited flag |
| Browser sandbox and Site Isolation | inherited from Microsoft Chromium; prohibited disabling flags are checked | enumerate WebView2 process types and record flags and engine identity | do not claim attestation until an automated supported runtime probe proves the declared process boundary; never add `--no-sandbox` or `--disable-site-isolation-trials` |
| JIT-reduced enhanced security | not enabled or attested by the pinned SDK | upgrade only to a stable, pinned WebView2 SDK exposing `EnhancedSecurityModeState`; add strict-mode UI, compatibility escape, runtime evidence, and regression tests | the current documented API is prerelease; no reflection, undocumented COM calls, or generic command-line flag may be treated as production enforcement |
| Strict third-party active-content policy | native strict and MV3 high-risk controls are implemented, with different resource sets | unify them under a named High-Risk profile; show the exact blocked classes; add a per-origin exception list that is empty by default and auditable | loopback tests must prove requests never reached the server and that ordinary mode is restored transactionally; breakage must be explicit |
| HTTPS-only navigation | upgrading and high-risk blocking are implemented | add an HTTPS-only status indicator and record whether any fallback was attempted | no certificate-error bypass, user-installed interception root, or silent HTTP fallback |
| Permission and extension reduction | permissions are denied; host bridges, password saving, autofill, developer tools, and unexpected extensions are blocked | expose a read-only posture page listing each effective setting without browsing telemetry | fail closed if an unknown extension, host bridge, or persisted permission is observed |
| Ephemeral browser session | app-level history can be cleared on exit; the WebView2 profile, cookies, cache, IndexedDB, service workers, and site permissions remain | add an explicit Ephemeral Session that creates a fresh bounded UDF before navigation, refuses reparse paths, prevents recovery of the previous session, and securely schedules crash leftovers for deletion | test clean exit, crash, update, concurrent start, sign-in breakage, and deletion failure; never say "nothing retained" while OS, DNS, network, provider, or crash logs may remain |
| Download protection | explicit approval, safe path allocation, and no automatic open are implemented | after completion, pass the final immutable file identity to the active Windows real-time provider and ZSEC bounded scan; show each provider's independent result; never auto-open | pre-access enforcement must come from the active OS-integrated provider until ZSEC's primary-antivirus gates pass |
| Windows real-time antivirus | Malwarebytes and/or Microsoft Defender supplies supported real-time enforcement; ZSEC is post-change | make ZSEC a verified control plane over the supported active provider: show WSC aggregate health, Defender engine/platform/signature age, real-time/tamper state, last scan, and a safe update/scan action | never call ZSEC the primary provider merely because its UI displays Defender results; removal of another provider requires Defender active/current plus transactional rollback, or all native ZSEC primary gates |
| Exploit-protection posture | not yet a unified ZSEC check | read and report Windows Exploit Protection, Smart App Control or App Control state where supported, and high-risk gaps; provide documented user/admin remediation | do not silently change organisation policy, ASR, Controlled Folder Access, or exploit settings because compatibility impact is material |
| Full-disk encryption posture | ZSV2 protects ZSEC quarantine; it does not encrypt the whole device | report BitLocker device-encryption state, protection status, key protectors, suspended state, and recovery-key readiness without exposing key material | enabling or changing BitLocker requires verified recovery escrow, power/reboot readiness, and explicit owner or administrator policy |
| OS and application updates | browser engine update availability is detected; full Windows update posture is not | report pending security updates, reboot requirement, OS support state, and last successful update; link to the managed update path | ZSEC must not become a general remote command or arbitrary package channel |
| Account hardening | external to ZSEC | provide an evidence-free checklist for passkeys/FIDO2 keys, backup keys, recovery contacts, Google Advanced Protection, Apple Account security, and centrally managed devices | ZSEC cannot claim enrollment without an authoritative provider confirmation and must never collect passkeys, PINs, recovery codes, or account credentials |
| Incident-response preservation | bounded watch evidence exists; no complete handoff bundle exists | export a consented local bundle containing product/runtime versions, signed hashes, policy/ruleset IDs, update posture, provider health, ZSEC events, failures, and a manifest; redact browsing history and filenames by default | encrypt for a named responder when configured; preserve originals; no factory reset, quarantine sweep, IOC-driven deletion, or attacker attribution before expert direction |
| Historical spyware indicators | no unexpiring spyware-domain list is shipped | support signed, data-only, exact-match, source-dated, expiring indicators in a separate review lifecycle; label a match as a historical-indicator match only | a no-match is never "clean"; expired, reassigned, sinkholed, wildcard, or provenance-free indicators are rejected |
| Native ZSEC primary antivirus | not implemented | continue engine, quarantine, worker isolation, updater, efficacy, and coexistence development only in disposable test systems | signed minifilter, protected service, AMSI, Microsoft-approved WSC/MVI integration, signed rollback-resistant updates, cleanware/malware evaluation, false-positive operations, and independent testing are mandatory |
| Apple/mobile spyware response | outside the desktop browser and scanner | detect no mobile infection; provide links to Apple threat-notification verification, Lockdown Mode, and expert support | only Apple/device-vendor security updates and qualified mobile forensics can cover those platforms; ZSEC must not ingest a phone backup and declare it clean |

## Windows replacement path that protects the user today

The fastest safe way for ZSEC to replace the Malwarebytes *experience* is to use
Microsoft Defender as the supported real-time enforcement layer while ZSEC owns
the local dashboard, posture checks, bounded second-opinion scan, encrypted
quarantine, incident receipts, and high-risk workflow. This is not the same as
ZSEC becoming a registered primary antivirus.

A cutover from Malwarebytes is defensible only after a transactional check shows:

1. Defender Antivirus is active, not passive, and real-time protection is on;
2. Defender platform, engine, and signatures are current;
3. tamper protection and Windows Security aggregate health are good;
4. the ZSEC download and post-change scan paths pass harmless acceptance tests;
5. a full or appropriate baseline scan has completed without unresolved errors;
6. the previous provider can be restored if Defender activation or reboot fails;
7. no organisation policy, licence, or managed-security requirement forbids the
   change; and
8. the user sees which engine supplies the real-time verdict.

Until those checks pass on the exact machine, keeping Malwarebytes is the safer
state. A scheduled watcher, EICAR result, fresh heartbeat, or green GUI badge is
not equivalent to a pre-access provider.

## Incident-response handoff

If targeted compromise is suspected, ZSEC should favour preservation and expert
coordination over aggressive cleanup:

1. stop interacting with the suspicious page, message, attachment, or account;
2. use a known-clean device to contact the organisation's security team or a
   qualified civil-society response service;
3. do not factory-reset, uninstall suspected components, mass-delete files, or
   run an unreviewed cleanup script before the responder advises it;
4. preserve the original device and its timestamps; avoid opening suspected
   artifacts merely to inspect them;
5. export the bounded ZSEC handoff bundle from a trusted path if the responder
   requests it; and
6. treat every automated result as evidence for review, never final attribution
   or clearance.

Apple directs recipients of authentic threat notifications to verify the alert
at `account.apple.com`, enable Lockdown Mode, and seek expert assistance. It
specifically recommends Access Now's 24/7 Digital Security Helpline. Amnesty's
Mobile Verification Toolkit and AndroidQF are expert forensic tools, not a
consumer antivirus verdict; public indicators alone cannot establish that a
device is uncompromised.

## ZBA and ZMath: unique value with a strict boundary

The reviewed Zero Boundary Algebra 1.1 paper defines a typed state and
provenance calculus. It explicitly says that directional zero values are tagged
workflow states, that the numerals are mnemonic, and that conventional
cryptography supplies security. The current ZSEC implementation uses a narrow
sequence-zero ZBA quarantine record; it does not implement a complete append-only
ZBA lifecycle chain.

ZBA can provide distinctive value by making assurance claims inspectable:

- `claimed`: a setting or provider reports a state;
- `checked`: ZSEC independently observed the supported interface;
- `sealed`: exact versions, hashes, policy, time, and evidence digest are bound
  into a conventional authenticated record;
- `rejected`: required evidence is missing, stale, contradictory, or invalid;
- `entering`, `boundary`, and `emerging`: a change is proposed, verified at a
  release/cutover boundary, then activated; and
- lineage: later posture receipts bind to the prior accepted receipt so silent
  rollback or relabelling becomes detectable when independently anchored.

This could support local "ZSEC Security Receipts" for browser startup, ruleset
activation, provider cutover, update completion, quarantine, restore, and
incident export. The security properties must still come from canonical
serialization, SHA-256 or a stronger approved hash, authenticated encryption,
digital signatures, OS key protection, and correctly managed trust anchors.

The receipt feature remains release gated until ZSEC implements an explicit
transition log, policy verifier, rollback control, signing profile, deterministic
vectors, privacy limits, and an independent review. ZBA must never be used as a
malware score, cryptographic key, source of entropy, substitute for YARA or an
AV engine, or basis for identifying Pegasus or an attacking government.

## Acceptance tests

A high-risk profile is releasable only when disposable test systems demonstrate:

- the exact engine, app, extension, ruleset, and profile versions are recorded;
- a prohibited runtime flag or unexpected extension makes posture fail;
- plaintext navigation and every declared third-party active-content class are
  blocked before a loopback server receives the request;
- certificate errors and permission requests cannot be silently accepted;
- ephemeral mode starts with a fresh UDF and handles clean exit, crash, update,
  deletion failure, and concurrent start without touching another profile;
- downloads are never automatically opened and receive independent provider and
  ZSEC results bound to the final file identity;
- Defender-backed status distinguishes active, passive, stale, disabled, and
  unknown states and cannot turn a registration record alone into "protected";
- BitLocker, update, exploit-protection, and reboot checks distinguish unknown
  from good and never expose recovery material;
- an incident bundle is bounded, manifest-hashed, privacy-redacted by default,
  and leaves original evidence unchanged;
- historical indicators expire and a miss is never rendered as clean; and
- all public strings reject Pegasus immunity, actor attribution, ZBA-as-cipher,
  and ZSEC-primary-AV claims unless their separate gates have actually passed.

## Primary and specialist sources

- [Apple: About Lockdown Mode](https://support.apple.com/en-euro/105120)
- [Apple: threat notifications and protection against mercenary spyware](https://support.apple.com/en-in/102174)
- [Google Advanced Protection Program](https://support.google.com/accounts/answer/7519408)
- [Google TAG: commercial-surveillance exploit delivery through injected HTTP traffic](https://blog.google/threat-analysis-group/0-days-exploited-by-commercial-surveillance-vendor-in-egypt/)
- [Google TAG: government watering holes reusing commercial-surveillance exploits](https://blog.google/threat-analysis-group/state-backed-attackers-and-commercial-surveillance-vendors-repeatedly-use-the-same-exploits/)
- [Google TAG: commercial-surveillance-vendor ecosystem](https://blog.google/threat-analysis-group/commercial-surveillance-vendors-google-tag-report/)
- [Microsoft: develop secure WebView2 applications](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/security)
- [Microsoft: Edge enhanced security mode](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-security-browse-safer)
- [Microsoft: WebView2 EnhancedSecurityModeState prerelease API](https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/winrt/microsoft_web_webview2_core/corewebview2enhancedsecuritymodestate)
- [Chromium: Site Isolation](https://www.chromium.org/Home/chromium-security/site-isolation/)
- [UK NCSC: guidance for high-risk individuals](https://www.ncsc.gov.uk/collection/defending-democracy/guidance-for-high-risk-individuals)
- [CISA: Mobile Communications Best Practice Guidance](https://www.cisa.gov/sites/default/files/2024-12/guidance-mobile-communications-best-practices.pdf)
- [CISA and partners: mitigating cyber threats with limited resources for civil society](https://www.cisa.gov/sites/default/files/2024-05/joint-guide-mitigating-cyber-threats-with-limited-resources-guidance-for-civil-society-508c_3.pdf)
- [Citizen Lab: BLASTPASS zero-click chain](https://citizenlab.ca/blastpass-nso-group-iphone-zero-click-zero-day-exploit-captured-in-the-wild/)
- [Citizen Lab: Pegasus targeting and Lockdown Mode observations](https://citizenlab.ca/research/pegasus-russian-belarusian-speaking-opposition-media-europe/)
- [Amnesty Security Lab: tools, limits, and expert support](https://securitylab.amnesty.org/tools-and-guides/)
- [Mobile Verification Toolkit: indicators and their limitations](https://docs.mvt.re/en/stable/iocs/)
- [Access Now Digital Security Helpline](https://www.accessnow.org/help/)
