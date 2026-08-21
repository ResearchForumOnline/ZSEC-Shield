# ZSEC Browser Shields

ZSEC Browser Shields is the open-source Manifest V3 protection engine for ZSEC
Browser. It blocks a conservative local set of advertising, analytics,
fingerprinting and session-replay domains; removes common campaign identifiers
from top-level links; offers a per-site breakage switch; and performs best-effort
YouTube skip-button and promoted-slot cleanup.

It does not upload browsing history, inject affiliate links, install a root
certificate, proxy traffic, or download executable rules. Its two static
rulesets contain 39 local blocking rules and two link-cleaning rules. They are
deliberately reviewable and testable. ZSEC does not promise to block every ad,
malicious site or browser exploit.

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
