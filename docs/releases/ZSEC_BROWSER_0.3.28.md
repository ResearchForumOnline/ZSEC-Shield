# ZSEC Browser 0.3.28 release evidence

Recorded 30 September 2026. Browser source `0.3.28`, Browser Shields `0.5.3`,
Microsoft Store package `0.3.28.0`.

## Microsoft Store distribution

Partner Center was read on 30 September 2026 and showed that Submission 4
passed certification and that the latest product update was available in the
Microsoft Store. Its package entry was
`ZSEC-Browser-0.3.28.0-x64-release.msix`, version `0.3.28.0`.

- Product: [ZSEC Browser](https://apps.microsoft.com/detail/9PHBSSG3N99V)
- Product ID: `9PHBSSG3N99V`
- Reviewed upload bytes: `4,354,689`
- Reviewed upload SHA-256:
  `9266c9273171cfb456d70196c19bd5029ddc274d0c2f6cd0ec3bcabfb5bff0fb`

This is a dated portal check, not a claim that every device has received or
installed the update. The reviewed pre-signing upload is unsigned; Microsoft
signs and distributes the Store edition. No package installation or user
profile replacement was performed during this synchronization.

## Source and build synchronization

The existing working checkout was preserved. A separate checkout started from
public main `ab8afef`, retaining the current signed data feeds, Antivirus source
and licences. Only the reviewed browser, extension, shared Store browser
packaging validation, related tests and release documentation were imported.

A fresh Windows build used the pinned WebView2 SDK `1.0.4129.50` and Roslyn
compiler `4.14.0`, checking their SHA-256 and official NuGet SHA-512 hashes.
All **32 App payload files** reproduced the reviewed Store upload byte for byte,
including the native launcher, extension modules and YouTube hook.

Native launcher SHA-256:
`20cd8f3f8d01f954a396bb0a7163f44064a1fb83b8119e704396f343c9a68390`.

The [machine-readable receipt](ZSEC_BROWSER_0.3.28.json) records the payload
hashes and verification boundaries. Direct Community releases remain unsigned
and are a separate distribution from the Microsoft Store edition.

## Implemented changes

- Scoped HTTPS functional login requests for Google, ChatGPT/OpenAI, Facebook,
  Microsoft, GitHub and Apple. These exceptions do not disable the general
  tracker rules and cannot override High-Risk Browsing.
- Reviewed user-clicked sign-in popups with exact origin, tab and burst bounds.
  Unknown/background popups retain the existing blocked or explicit-permission
  behavior.
- YouTube receives no default login-compatibility exception. Its bounded helper
  handles visible skip controls, duplicate controls and back/forward cache
  restoration more reliably.
- HTTP/HTTPS and HTM/HTML default-handler declarations. Windows retains the
  protected default-browser choice; the app does not silently replace it.
- Public browser listing and privacy URLs use `talktoai.org/zsec/` routes.

## Verification

- Native product regression harness: **267 assertions passed**.
- Browser Shields extension: **55 tests passed**, zero failures.
- MV3 validation: **49,464 EasyList rules**, **39 privacy blockers**, **2 link
  cleaners**, **9 source modules**.
- Focused browser/Store Python suite: **55 tests passed**, including a regression
  that rejects Unicode bullet markers in Store feature fields.
- Adjacent extension packaging, journalist profile, screenshot and Store
  runtime lifecycle checks: **19 tests passed**. The complete combined slice
  passed **74 tests**.
- Fresh native build and 32-file Store payload comparison: passed.

The standalone Browser Shields archive builder now includes the new login
compatibility module. Its deterministic archive test checks the module's exact
source bytes and extension version `0.5.3`; this is separate from the already
reviewed Store App payload.

The original review also recorded eight Chromium DNR fixtures. Those fixtures
were not rerun during this source synchronization. Live credential logins were
not tested. Provider restrictions on embedded-browser authentication remain
independent of ZSEC filtering. Complete YouTube ad suppression is not guaranteed.

## Licence and privacy

The ZSEC application remains Apache-2.0. EasyList and other bundled material
retain their separately identified notices and licences. No owner credentials,
browser profiles, vaults, raw approval logs, account screenshots or private Store
configuration are included in this publication.
