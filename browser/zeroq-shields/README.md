# ZeroQ Shields Preview

ZeroQ Shields is the open-source Manifest V3 protection engine preview for Zero
Browser. It blocks a conservative local set of advertising and tracking domains,
offers a per-site breakage switch, and performs best-effort YouTube skip-button
and promoted-slot cleanup.

It does not upload browsing history, inject affiliate links, install a root
certificate, proxy traffic, or download executable rules. The current rule set
is deliberately small and testable. It does not promise to block every ad or
malicious site.

## Test locally

```powershell
npm test
npm run validate
```

Load the directory as an unpacked extension from `chrome://extensions` only on
a test browser profile. The feature branch does not install it automatically.

## Full browser boundary

This extension is a reusable protection layer and an early-user test vehicle. A
separately distributed Zero Browser requires a maintained Chromium source/build
pipeline, upstream security-patch cadence, code signing, sandbox/Site Isolation
tests, updater rollback, third-party notices, and browser-specific security
review. The extension alone is not a browser fork.
