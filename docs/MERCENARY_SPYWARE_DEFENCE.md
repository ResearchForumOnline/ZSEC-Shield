# Bounded defence against browser-delivered mercenary spyware

Status: implemented exposure-reduction profile plus a reviewable response
architecture. This is not a claim of zero-day immunity, exploit detection, or
primary-antivirus coverage.

## Security outcome

Commercial surveillance vendors use targeted links, watering holes, traffic
injection, browser renderer exploits, sandbox escapes, and payload delivery.
No extension can promise to recognize or stop an unknown exploit in the browser
that runs it. ZSEC therefore separates controls by the decision point they can
actually enforce:

| Layer | Enforceable decision | Current control | Cannot establish |
| --- | --- | --- | --- |
| Chromium MV3 | Permit or block a matching request before it is sent | Opt-in High-Risk Browsing DNR rules | Whether allowed content is safe; whether Chromium has an exploitable bug |
| Chromium built-ins | Browser patching, Safe Browsing, sandbox and Site Isolation | Retained; ZSEC does not disable or replace them | ZSEC does not configure or attest these browser-managed controls |
| Desktop companion | Scan a selected file after a filesystem change | Bounded post-change scan, native user-level event backends and periodic reconciliation | Blocking the first read/execute or observing memory-only exploitation |
| Existing primary antivirus | OS-integrated real-time protection | Must remain installed and healthy | ZSEC companion is not a registered primary provider |

## Implemented High-Risk Browsing policy

High-Risk Browsing is a local, explicit opt-in stored with the extension's other
settings. It adds exactly two dynamic `declarativeNetRequest` block rules:

1. block top-level `http://` navigation; and
2. block third-party `script`, `sub_frame`, `object`, and `websocket` requests.

The first rule reduces exposure to plaintext traffic injection. Google Threat
Analysis Group documented a commercial-spyware campaign in which interception
of an HTTP visit silently redirected a target to an exploit server. The second
rule reduces third-party active delivery paths commonly used by watering holes
and embedded exploit stages. It is intentionally narrower than blocking every
third-party request: images, stylesheets, fonts, media, fetch/XHR, and other
resources continue to work.

Both rules use priority `1000`, above the normal site-pause allow priority of
`100`. A tracker-filtering exception therefore cannot silently weaken High-Risk
Browsing. The user must turn the mode off explicitly. This ordering follows
Chrome's documented within-extension DNR priority model.

The rule builder is policy-only: two fixed rule IDs, fixed resource types, no
regular expressions, no downloaded data, no executable feed, no telemetry, and
no per-request log. Service-worker restarts rebuild rules from normalized local
storage, rather than relying on in-memory state.

## Failure and usability behavior

- The mode defaults off because blocking third-party active content can break
  authentication, payment, CAPTCHA, support chat, embedded documents, and other
  legitimate integrations.
- If DNR installation fails, the existing runtime-health state becomes failed
  and the popup displays an error badge; the extension does not report success.
- The main protection switch is a master gate. When it is off, neither static
  filtering nor High-Risk Browsing rules are active, even if the stored high-risk
  preference remains selected for the next enable.
- Pausing ordinary protection on a site is disabled and explained while the
  high-risk rules are active; its lower-priority allow rules cannot override them.
- The `HIGH` badge proves that both the master switch and local high-risk
  preference were successfully applied; `OFF` means no ZSEC network rules are
  active. It is not a threat or infection verdict.
- Turning High-Risk Browsing or the master switch off is the deliberate
  compatibility escape hatch.
- The extension does not collect the URLs or contents of blocked requests, so it
  cannot provide a forensic request log or claim that a block was spyware.

## Desktop companion boundary

The current-user Windows package defaults to the Downloads directory. Equivalent
macOS LaunchAgent and Linux systemd-user packages bind the same scanner to
selected user directories through their native user-level event backends. They
debounce duplicate events, scan resulting files with configured local rules,
record bounded health/evidence, and periodically reconcile the watched roots.
Browser temporary files that vanish before scanning are recorded as superseded;
files that remain are revisited by reconciliation. Quarantine remains off unless
explicitly enabled. Windows uses an automatically DPAPI-sealed quarantine root;
the macOS and Linux filesystem-key fallback remains preview-only rather than
production platform-key protection.

This is useful against a payload that reaches disk and matches configured rules,
but it is post-change monitoring. It cannot suspend Chrome, interpose on file
open or execute, inspect renderer memory, detect a sandbox escape merely because
one occurred, or prevent an unknown payload from running before the scan. The
default 64 MiB per-file bound and configured detection corpus also limit what it
can examine. Malwarebytes or another approved primary provider must remain
active.

## Why no bundled historical spyware-domain list was added

Google TAG and other primary researchers publish valuable campaign indicators.
Those are observations at a point in time, not permanent ownership or safety
facts. Old domains can expire, be reassigned, sinkholed, or become research
infrastructure. Shipping them years later as an unexpiring blocklist creates a
false-positive and provenance problem, while a match would still not prove
infection and a non-match would never prove safety.

This release therefore does not copy historical indicator lists into a static
ruleset. Adding such a ruleset requires a separate data-only lifecycle with:

- exact domains only; no broad suffixes, wildcards, or regex patterns;
- a primary-source URL, campaign context, first/last-observed times, reviewer,
  review date, and mandatory expiry for every indicator;
- reassignment/sinkhole review before release and automatic removal at expiry;
- signed, reproducible packaging with no remote executable-code path;
- collision, public-suffix, allowlist, and false-positive tests; and
- UI/report wording of "matched a configured historical indicator," never
  "infected," "clean," or "safe."

An authenticated remote reputation service would materially change the privacy
contract and is not authorized by this architecture.

## High-risk operating guidance

For people at elevated targeting risk, this extension is only one layer:

1. keep the Chromium-family browser and desktop operating system fully patched
   and restart promptly after security updates;
2. retain Safe Browsing or the browser vendor's equivalent plus the platform
   sandbox and Site Isolation;
3. retain the approved primary antivirus or native platform protections and
   verify their supported aggregate
   health independently of raw Security Center registrations;
4. enable High-Risk Browsing before opening an untrusted targeted link, accepting
   that the destination may break;
5. do not bypass browser interstitials, certificate errors, or file warnings;
6. if targeting is suspected, stop interacting with the page, preserve device
   state, and seek a qualified incident-response/forensic channel rather than
   treating a ZSEC no-match as clearance;
7. remember that ZSEC Browser Shields is a desktop Chromium extension. It cannot
   inspect iMessage, HomeKit, baseband traffic, mobile operating-system memory,
   or another application. Apple users who receive an authentic threat
   notification should verify it directly at `account.apple.com`, consider
   Lockdown Mode, and obtain expert assistance as Apple recommends.

## Release gates

- Unit tests prove the opt-in default, exact two-rule budget, resource types,
  stable IDs, and priority over site pauses.
- Static validation proves the popup discloses breakage, the service worker uses
  normalized local policy, rules only block, and source contains no remote code.
- The disposable runtime test proves on each named browser/OS combination that
  both classes of request are blocked before reaching a loopback test server and
  that explicitly disabling the profile removes the two dynamic rules.
- Deterministic browser packaging contains the high-risk rule module.
- Any permission increase, remote endpoint, IOC ruleset, content inspection, or
  Windows enforcement claim requires a separate privacy, threat-model, and
  release review.

## Primary technical sources

- [Chrome declarativeNetRequest API and rule evaluation](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest)
- [Chrome extension service-worker lifecycle and persistent state](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle)
- [Google TAG: commercial-surveillance exploit delivery through injected HTTP traffic](https://blog.google/threat-analysis-group/0-days-exploited-by-commercial-surveillance-vendor-in-egypt/)
- [Google TAG: repeated commercial-surveillance browser exploits and watering holes](https://blog.google/threat-analysis-group/state-backed-attackers-and-commercial-surveillance-vendors-repeatedly-use-the-same-exploits/)
- [Google TAG: commercial-surveillance-vendor ecosystem](https://blog.google/threat-analysis-group/commercial-surveillance-vendors-google-tag-report/)
- [Citizen Lab: BLASTPASS NSO Group zero-click chain](https://citizenlab.ca/blastpass-nso-group-iphone-zero-click-zero-day-exploit-captured-in-the-wild/)
- [Apple: threat notifications and high-risk-user guidance](https://support.apple.com/102174)
- [Microsoft: Edge enhanced security mode and JIT reduction](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-security-browse-safer)
