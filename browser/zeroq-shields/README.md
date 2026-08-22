# ZSEC Browser Shields

ZSEC Browser Shields is the open-source Manifest V3 protection engine for ZSEC
Browser. Version 0.5.0 adds 49,464 pinned EasyList network rules compiled by
eyeo's Adblock Plus release pipeline, while omitting the Acceptable Ads
allowlist. It also blocks a focused local set of analytics, fingerprinting and
session-replay domains; removes common campaign identifiers
from top-level links; offers a per-site breakage switch; and performs best-effort
YouTube skip-button and promoted-slot cleanup.

The YouTube helper is deliberately bounded: it hides a packaged list of known
promoted interface containers and clicks only a visible, enabled skip/close
control exposed by the page. It does not alter video playback, inspect response
bodies, download filtering logic, or promise to suppress server-selected,
unskippable, already-buffered, or markup-changed advertising.

It does not upload browsing history, inject affiliate links, install a root
certificate, proxy traffic, or download executable rules. Its three static
rulesets contain 49,464 pinned EasyList network rules, 39 focused local privacy
rules and two link-cleaning rules. The checked-in lock, source snapshot,
generated DNR bytes, license and provenance make the filter input reproducible.
EasyList is not the complete Adblock Plus extension: cosmetic filtering,
scriptlets and the ABP account/Premium stack are not bundled. ZSEC does not
promise to block every ad, especially same-origin or server-inserted video ads,
malicious site or browser exploit.

The rule-priority hierarchy is explicit: EasyList at 10-21, tracking-link
cleanup at 40, focused ZSEC privacy blocks at 50, user-selected site pause at
100 and High-Risk Browsing security rules at 1000. EasyList exceptions cannot
override ZSEC privacy or High-Risk Browsing rules; site pause remains the
deliberate breakage-recovery control outside High-Risk mode.

## EasyList provenance and licensing

The pinned upstream is eyeo's `adblockplus-4.43.2` release at commit
`c9bfed65505242f089aa32844feee6c6b8963a04`. The exact archive, source list,
source DNR and generated output hashes are recorded in `easylist.lock.json` and
`third_party/easylist-provenance.json`. Regeneration is offline and fail-closed:

```powershell
py -3 .\packaging\import_easylist_dnr.py PATH_TO_PINNED_ABP_MV3_ZIP
```

EasyList is provided under GPL-3.0-or-later or CC-BY-SA-3.0-or-later; see
`third_party/EASYLIST-LICENSE.txt` and the retained source snapshot. ZSEC is not
affiliated with or endorsed by eyeo, Adblock Plus or the EasyList project.

## Opt-in High-Risk Browsing

High-Risk Browsing is off by default. When the user turns it on while the master
protection switch is on, two bounded
dynamic Manifest V3 rules block plaintext HTTP top-level navigation and
third-party `script`, `sub_frame`, `object`, and `websocket` requests. The rules
have higher priority than the normal per-site pause. Site pause is disabled and
explained while the profile is active, so it cannot silently bypass the high-risk
rules. Turning High-Risk Browsing or the master protection switch off is the
explicit break-glass control. The `HIGH` badge means both switches are active;
`OFF` means no ZSEC network rule profile is active.

This can materially break sign-in, payment, CAPTCHA, embedded-document, chat,
and other sites that rely on third-party active content. It is exposure
reduction, not a maliciousness verdict or zero-day shield. First-party exploit
delivery, browser/extension compromise, non-blocked resource types, cached or
non-network attack paths, and code already executing in a page remain outside
the guarantee. See [the defensive architecture](../../docs/MERCENARY_SPYWARE_DEFENCE.md).

## Test locally

```powershell
npm test
npm run validate
```

On a Windows system with Brave, Chrome, or Edge installed, the disposable
runtime smoke test uses a fresh temporary browser profile and loopback-only HTTP
servers. It proves the dynamic rules are installed, a cross-site script and
plaintext top-level navigation are blocked before either request reaches the
server, and the explicit off switch restores navigation:

```powershell
npm run test:runtime
```

The script deletes its isolated profile when it finishes and never opens the
normal browser profile. Branded Chrome builds may ignore command-line unpacked
extension loading; that is a test-harness limitation, not evidence that manual
Developer mode installation failed. Record only the exact browser/OS
combinations that complete the smoke test.

Load the directory as an unpacked extension from `chrome://extensions` only on
a test browser profile. The feature branch does not install it automatically.

## Full browser boundary

This extension is a reusable protection layer and an early-user test vehicle. A
separately distributed ZSEC Browser requires a maintained Chromium source/build
pipeline, upstream security-patch cadence, code signing, sandbox/Site Isolation
tests, updater rollback, third-party notices, and browser-specific security
review. The extension alone is not a browser fork.
