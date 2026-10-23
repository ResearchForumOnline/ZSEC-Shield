# ZSEC Browser 0.3.29 release preparation

Prepared 23 October 2026. Browser source **0.3.29**, Browser Shields **0.5.3**, Microsoft Store candidate **0.3.29.0**.

## Session-only closed-tab recovery

Choose **Reopen closed tab** from the main menu or press **Ctrl+Shift+T** to reopen the most recently closed web tab. Recovery remembers at most ten URLs in memory. It excludes internal pages, unsupported schemes and URLs containing embedded credentials. Automatic sign-in popup closure does not add a recovery entry.

Clearing history, disabling history or enabling High-Risk mode erases the list. Recovery is unavailable while history is disabled or High-Risk mode is active. Closing the app discards the list; forms, page contents, navigation stacks and tabs from previous sessions are not restored. Reopened URLs use the normal tab creation, permissions and request protection path, retain the existing 32-tab bound and roll back safely if tab creation fails.

## Candidate verification

- The native product-state harness passed **274 assertions**, including bounded recovery order, unsafe URL exclusion, empty-cache behavior and privacy clearing.
- The focused browser, product, extension packaging, listing, Store packaging, lifecycle and screenshot validator suite passed **69 tests**. The successful run used a dedicated short temporary root because the host's default pytest temporary directory denied access and longer Win32 extraction paths exceeded the extraction tool's path limit.
- A fresh native build verified the pinned WebView2 SDK and deterministic Roslyn compiler packages, then compiled the current browser source.
- Store staging rehashed the native payload and retained the exact existing `talktoai.ZSECBrowser` identity, publisher, HTTP/HTTPS associations and `runFullTrust` capability.
- MakeAppx created `ZSEC-Browser-0.3.29.0-x64-release.msix` with normal validation. Candidate size: **4,356,774 bytes**. SHA-256: `eaff950d93c44c2dcc5701270ed5be0fa6c642bac7b3501b3bea7235f4c473f4`.

This records a reviewed unsigned submission candidate. Live interactive runtime acceptance, Windows App Certification Kit results, Partner Center submission/certification, Store-signed installation, upgrade and public availability are separate checks and are not established here. The previous dated [0.3.28 publication evidence](ZSEC_BROWSER_0.3.28.md) remains available.

## Scope and privacy

This update changes the browser and its submission materials. It does not change Antivirus code, feed data, server configuration, the embedded Microsoft-maintained Chromium engine, or a user's installed profile. Private Store identity configuration, API credentials, browser profiles, vaults and raw runtime logs are excluded from the source publication. Existing project and third-party license notices remain included.
