# Microsoft Store Partner Center draft — not submitted

These copy-and-paste materials are validated against the current ZSEC source versions.
They do not contain or replace the two Partner Center package identities. Do not upload
or submit until every pre-submission gate below passes against the exact Store package.

Microsoft field limits used by the validator:

- Description: 10,000 characters maximum.
- Short description: 1,000 maximum; kept below the recommended 270 characters.
- Features: up to 20, each no more than 200 characters.
- Keywords: up to 7 terms, each no more than 40 characters, with no more than
  21 unique words across all terms.
- Additional system requirements: up to 11 items, each no more than 200 characters.
- Copyright/trademark: 200 characters maximum; Developed by: 255 maximum.
- Additional Testing Information / Notes for certification: 2,000 characters maximum.
- Desktop screenshots: PNG, at least 1366x768, no more than 50 MB; one required,
  four or more recommended, and ten maximum.
- IARC questionnaire: required for the first submission.
- Restricted-capability declaration: required because both manifests use runFullTrust.

## ZSEC Antivirus

Source version: `0.3.31`
Listing language: `en-US`
Suggested category: `Security`

Select the closest currently available non-game security category in Partner Center; do not classify this companion as a Microsoft Defender replacement.

### Short description

Local Windows security companion for Defender evidence and fixed scans, bounded post-change file monitoring, deterministic checks, and authenticated encrypted quarantine.

### Full description

ZSEC Antivirus Community is a local-first Windows security companion. It shows supported Windows Security and Microsoft Defender evidence, can request fixed Defender intelligence-update, quick-scan, and confirmed full-scan actions, and adds bounded per-user post-change file monitoring, deterministic file hashing and exact-rule checks, reports, authenticated encrypted quarantine, and recovery checks.

Important protection boundary: Microsoft Defender or another supported primary provider must remain active. ZSEC is not a primary antivirus, registered Windows Security provider, protected service, or kernel pre-access filter, and it has not received independent malware-efficacy certification. Monitoring reacts after file changes, and a limited scan result is not proof that the computer is clean.

Files, scanner reports, monitoring state, and quarantine data remain local by default. No ZSEC account, advertising, telemetry endpoint, sample upload, or cloud analysis is required. Quarantine is an explicit per-scan choice, and restore refuses to overwrite an existing destination.

The app is free and open core. Its source, threat model, privacy contract, deterministic release metadata, and security boundaries are available for review.

### Product features

- Supported Windows Security and Microsoft Defender status evidence
- Fixed Defender intelligence update, quick scan, and confirmed full scan actions
- Bounded per-user post-change file monitoring with fail-closed health evidence
- Deterministic file hashing and exact signed-rule checks
- Explicit opt-in authenticated encrypted quarantine
- No-overwrite restore and isolated synthetic recovery self-test
- Local reports with incomplete and review states kept visibly distinct
- No ZSEC account, advertising, telemetry endpoint, or file-sample upload
- Reduced-motion interface and native notification-area controls

### URLs and license

- Website: https://talktoai.org/zero-security/
- Support: https://github.com/ResearchForumOnline/ZSEC-Shield/issues
- Privacy policy: https://talktoai.org/zero-security/#privacy
- Vulnerability reporting: https://talktoai.org/.well-known/security.txt
- License terms: Apache License 2.0. The complete license is included with the application and available at https://github.com/ResearchForumOnline/ZSEC-Shield/blob/main/LICENSE.
- Copyright/trademark: Copyright 2026 ZSEC contributors. ZSEC is not affiliated with or endorsed by Microsoft.
- Developed by: ZSEC contributors

### Discovery and system requirements

Keywords (enter as separate terms):

- security companion
- Microsoft Defender
- file scanner
- file monitoring
- encrypted quarantine

Additional system requirements (enter as separate items):

- Windows 10 or Windows 11, x64.
- Microsoft Defender is required for Defender evidence, intelligence updates, and Defender scan actions.

### Restricted capability: runFullTrust

ZSEC Antivirus is an existing Win32 desktop security companion. runFullTrust is required to launch its packaged GUI and sibling scanner and companion executables at medium integrity; hash and scan user-selected files; read supported Windows Security and Microsoft Defender status; invoke only the fixed Defender Update-MpSignature, QuickScan, and FullScan actions after explicit user interaction; run bounded per-user post-change monitoring; and manage local authenticated encrypted quarantine. The app does not request elevation, register as a Windows Security provider, change Defender preferences, add exclusions or firewall rules, or disable, select, or remove security software.

### Additional Testing Information

Prepared 26 August 2026. No account or test credentials are required. Windows Desktop x64 only. This is a packaged Win32 security companion; runFullTrust use is described separately. Keep Microsoft Defender enabled. ZSEC is not the primary antivirus, a Windows Security provider, protected service, or kernel pre-access filter. Use only benign disposable test files. Quarantine starts off. A completed result covers only configured evidence and does not certify a clean device.

Test the exact Store-signed candidate on a clean Windows 10/11 x64 VM:
1. Launch from Start; refresh Overview and verify evidence-backed Defender and companion state.
2. In Windows protection, refresh intelligence and run Quick scan. Full scan requires separate confirmation. Verify that no Defender preference, exclusion, provider, or firewall setting changes.
3. Scan a disposable benign folder with quarantine off. Cancel a second scan and verify it remains incomplete.
4. Monitor a disposable folder, edit a benign text file, confirm a fresh heartbeat and post-change event, then stop monitoring.
5. Run Protection assurance's isolated synthetic recovery self-test; verify encrypted copy, restore, no-overwrite, tamper rejection, and device-key recovery.
6. Restart to verify settings and companion state, then uninstall. Defender must remain enabled and no security product may be removed or reconfigured.

### Supporting internal certification detail

No account or test credentials are required. This is a packaged Win32 desktop security companion and declares runFullTrust for the bounded functions stated in the restricted-capability justification. Microsoft Defender or another supported primary provider must remain enabled. ZSEC is not registered as the primary antivirus and provides no kernel pre-access enforcement. Use only benign test files. A completed ZSEC scan reports configured-rule evidence and never certifies that the device is clean. Quarantine is off by default. The package must be tested on Windows Desktop only. Before submission, the clean-VM gate must confirm packaged companion startup, scan, recovery self-test, settings persistence, update, and uninstall behavior.

Test account required: **No**

### Certification tester steps

1. Install the Store-signed candidate on a clean supported Windows 10 or Windows 11 x64 VM with Microsoft Defender enabled, then launch ZSEC Antivirus from Start.
2. On Overview, select Refresh. Confirm that the app reports evidence-backed Defender and companion state and does not call ZSEC the primary antivirus.
3. Open Windows protection. Run Refresh intelligence and Quick scan. Full scan must require a separate confirmation. Confirm that no Defender preference, exclusion, provider, or firewall setting is changed.
4. Open Scan, choose a disposable folder containing benign text files, leave quarantine off, and start a scan. Confirm that scope and elapsed time are shown without a fabricated percentage and that the result states its evidence boundary.
5. Start another benign scan and select Cancel. Confirm that the result remains incomplete rather than becoming a clean result.
6. Open Monitor, choose a disposable folder, start per-user monitoring, create or modify a benign text file, and refresh. Confirm a fresh heartbeat and bounded post-change evidence, then stop monitoring.
7. Open Protection assurance and run the isolated synthetic recovery self-test. It must test encrypted copy, restore, no-overwrite, tamper rejection, and device-key recovery without using a real user document.
8. Close and relaunch the app to verify settings and companion state, then uninstall it. Confirm that Microsoft Defender remains enabled and no security product is removed or reconfigured.

### Age and content notes

Complete the current IARC questionnaire from the behavior of the submitted binary. The app itself contains no sexual content, graphic violence, gambling, controlled substances, profanity, advertising, purchases, social communication, or unrestricted web browser. Security advisories may contain non-graphic descriptions of vulnerabilities or malware. User-selected file names and local scan evidence may be displayed only to that Windows user.

Factual questionnaire inputs:

- `general_web_browser`: `false`
- `app_authored_mature_content`: `false`
- `user_generated_content_service`: `false`
- `social_or_user_communication`: `false`
- `advertising`: `false`
- `purchases_or_subscriptions`: `false`
- `location_access`: `false`
- `parental_controls`: `false`

### Free pricing and availability checklist

Base price: **Free**
Trial, purchases, and subscription: **None**

- Set the base price to Free and verify there are no market-specific price overrides.
- Do not configure a trial, subscription, add-on, or in-app purchase.
- Review target markets for legal and support coverage; do not assume worldwide availability without that review.
- Target Windows Desktop only; do not select Xbox, HoloLens, or Surface Hub unless separately tested.
- Use a manual publishing hold for the first submission so certification success cannot publish before final review.
- Verify the support, privacy, license, and vulnerability-reporting URLs immediately before submission.

### Screenshot requirements and plan

Desktop `PNG`, minimum `1366x768`, maximum `50 MB`; plan: `5` screenshots.

- Capture the exact Store package candidate on a clean supported Windows VM at 100 percent display scale.
- Use only synthetic paths and benign files; remove usernames, device names, provider identifiers, quarantine contents, and other personal or security-sensitive data.
- Do not composite marketing text, extra logos, borders, or claims over screenshots.
- Keep important UI in the top two-thirds because Store overlays can cover the lower third.
- Show a healthy state only when current on-screen evidence actually verifies it; otherwise preserve the amber or red state.

1. **overview** — Evidence-led overview of Windows protection, ZSEC monitoring, scan status, and recovery readiness.
   Capture: Overview after a fresh evidence refresh on the clean test VM.
2. **scan-active** — A bounded local scan shows its real scope and elapsed time without inventing a completion percentage.
   Capture: Scan page using a synthetic disposable folder while the scan is active.
3. **scan-result** — Validated scan results distinguish configured-rule matches, review observations, and incomplete coverage.
   Capture: Completed benign scan with the clean-system limitation visible.
4. **windows-protection** — Supported Defender evidence and fixed update or scan actions without changing protection preferences.
   Capture: Windows protection page with all machine-specific identifiers sanitized.
5. **recovery** — An isolated synthetic recovery self-test checks encryption, restore, no-overwrite, and tamper rejection.
   Capture: Protection assurance page after a passing synthetic self-test.

### Pre-submission gates

- Use the exact Partner Center identity and Store-signed package candidate.
- Pass Windows App Certification Kit with no unexplained failures.
- Pass clean-VM packaged-path companion startup, monitoring, scan, recovery, update, and uninstall acceptance.
- Verify that uninstall preserves the active Windows security provider and does not claim removal of protected user quarantine data unless that behavior is separately disclosed and tested.
- Review every Store claim against the exact release evidence and current privacy page.

## ZSEC Browser

Source version: `0.3.25`
Listing language: `en-US`
Suggested category: `Productivity`

Select the closest currently available browser or productivity category in Partner Center; do not present the app as a maintained Chromium distribution.

### Short description

Privacy-focused Windows browser shell using Microsoft Evergreen WebView2, an isolated local profile, reviewed request rules, and a user-operated encrypted vault.

### Full description

ZSEC Browser Community is a Windows browser shell powered by Microsoft's Evergreen WebView2 Chromium runtime, which Microsoft services separately. ZSEC owns the desktop shell, isolated local profile, native request policy, and bundled Browser Shields package. It is not a separately maintained Chromium fork.

The app provides managed tabs, address and search controls, bookmarks, bounded local history, popup protections, default-deny site permissions, HTTPS-focused navigation controls, Microsoft Balanced tracking prevention, and an exact-identity Browser Shields package with reviewed network and tracking-link rules. Controls can reduce selected advertising and tracking requests but do not guarantee that a site is safe or stop every browser, operating-system, extension, or spyware exploit.

A user-operated local encrypted password vault supports explicit add, edit, import, generated passwords, timed reveal, and exact-origin HTTPS fill. Save prompts and fill are separate opt-in settings and begin off. ZSEC never silently submits a login or copies another browser's cookies, sessions, tokens, passkeys, or profile.

ZSEC adds no account, advertising, analytics, browsing-history upload, vault sync, crash-upload, or remote-control endpoint. Browsing still sends normal requests to Microsoft WebView2 services and the third-party websites the user chooses, subject to those providers' privacy terms.

### Product features

- Microsoft Evergreen WebView2 runtime with an isolated local ZSEC profile
- Managed tabs, bookmarks, bounded history, search, fullscreen, downloads, and tray controls
- Reviewed Browser Shields request rules and native tracking-link cleanup
- Microsoft Balanced tracking prevention and default-deny site permissions
- Page-requested windows blocked by default with revocable exact-HTTPS permissions
- Local encrypted password vault with timed reveal and explicit HTTPS-origin fill
- Password save prompts and autofill are separate opt-in settings and begin off
- Review-first bookmark, history-export, and password-export migration workflows
- No ZSEC account, advertising, analytics, browsing-history upload, or vault sync

### URLs and license

- Website: https://talktoai.org/zero-browser/
- Support: https://github.com/ResearchForumOnline/ZSEC-Shield/issues
- Privacy policy: https://talktoai.org/zero-browser/privacy/
- Vulnerability reporting: https://talktoai.org/.well-known/security.txt
- License terms: Apache License 2.0 for the ZSEC application, with separately identified third-party notices and licenses included in the package. The project license is available at https://github.com/ResearchForumOnline/ZSEC-Shield/blob/main/LICENSE.
- Copyright/trademark: Copyright 2026 ZSEC contributors. Microsoft, Windows, and WebView2 are trademarks of Microsoft Corporation; no endorsement is implied.
- Developed by: ZSEC contributors

### Discovery and system requirements

Keywords (enter as separate terms):

- privacy browser
- WebView2
- tracking protection
- password vault
- bookmarks

Additional system requirements (enter as separate items):

- Windows 10 or Windows 11, x64.
- Microsoft Edge WebView2 Evergreen Runtime.

### Restricted capability: runFullTrust

ZSEC Browser is an existing Win32 Windows Forms application using Microsoft WebView2. runFullTrust is required to launch the packaged classic desktop executable at medium integrity; create and use its isolated per-user profile under LocalAppData; load the packaged Browser Shields files; interact with the installed Microsoft WebView2 runtime; provide standard desktop file dialogs and notification-area controls; and read or write user-selected bookmark, history-export, password-export, and download files. The user-opened Migration center may read supported local browser bookmark files for local preview. The app does not run a service, inject into another browser, read another browser's cookies, sessions, tokens, passkeys, or encrypted credential store, request broadFileSystemAccess or device capabilities, or silently change the Windows default browser.

### Additional Testing Information

Prepared 26 August 2026. No ZSEC account or test credentials are required. Windows Desktop x64 only. This is a packaged Win32 browser shell using Microsoft's Evergreen WebView2 runtime; ZSEC is not a separately maintained Chromium fork. runFullTrust use is described separately. Test only public unauthenticated HTTPS pages and synthetic data. Password save prompts and exact-origin fill start off. Do not use real credentials or another browser profile.

Test the exact Store-signed candidate on a clean Windows 10/11 x64 VM with WebView2 available:
1. Launch from Start; verify the local new-tab page and a public HTTPS page open without ZSEC sign-in.
2. Open, switch, and close tabs; test back, forward, reload, address search, bookmarks, and fullscreen.
3. Open ZSEC Shields. Verify exact-identity and runtime status are evidence-led; a failed probe must not appear protected.
4. In Settings, verify site permissions deny by default, settings persist, and password save and fill remain off.
5. Add, export, remove, and re-import a synthetic HTTPS bookmark using tester-selected files only.
6. Verify the password vault begins locked or empty. If needed, use only synthetic credentials, test timed reveal and lock, then remove them.
7. On a controlled benign page, verify a requested popup is blocked by default and any exact-HTTPS permission is explicit and revocable.
8. Restart, then uninstall. Verify no other browser profile, credential, default-app choice, or security product changed.

### Supporting internal certification detail

No ZSEC account or test credentials are required. This is a packaged Win32 WebView2 desktop browser shell and declares runFullTrust for the bounded functions stated in the restricted-capability justification. Microsoft maintains the Evergreen WebView2 runtime; ZSEC is not a separately maintained Chromium fork. Test with public non-authenticated HTTPS pages only. Password save prompts and exact-origin fill begin off and must not be enabled with real credentials during certification. The app does not import cookies, sessions, tokens, passkeys, or another browser profile. The Store manifest does not claim HTTP or HTTPS protocol ownership and does not silently change Windows defaults. Before submission, clean-VM gates must confirm launch, request filtering, local persistence, update, and uninstall from the exact Store package.

Test account required: **No**

### Certification tester steps

1. Install the Store-signed candidate on a clean supported Windows 10 or Windows 11 x64 VM with the Microsoft Evergreen WebView2 runtime available, then launch ZSEC Browser from Start.
2. Confirm the local new-tab page loads, the protection status becomes evidence-led, and a normal public HTTPS address can be opened without any ZSEC sign-in.
3. Open two additional tabs, switch among them, close one, and verify back, forward, reload, address search, and fullscreen controls.
4. Open ZSEC Shields from the toolbar. Confirm the exact extension is loaded and the runtime status reports honestly; do not treat a failed probe as protected.
5. Open Settings. Verify site permissions are deny by default, history and appearance controls persist after restart, and password save prompts and autofill begin off.
6. Use a synthetic HTTPS bookmark, open the bookmark manager, export it to a tester-selected file, remove it, and import it again. Do not use a real browser profile or account.
7. Open Passwords and verify the vault begins locked or empty. If vault UI testing is required, use only synthetic example credentials, verify timed reveal and lock, then remove them before capture.
8. On a controlled benign page that requests a popup, confirm the request is blocked by default. Any site permission must require an explicit exact-HTTPS choice and be revocable in Settings.
9. Close and relaunch the app to verify local settings, then uninstall it. Confirm no other browser profile, credentials, default-app choice, or security product was changed.

### Age and content notes

Complete the current IARC questionnaire as a general-purpose web browser, not only from ZSEC-authored screens. The app itself contains no authored sexual content, graphic violence, gambling, controlled substances, profanity, advertising, purchases, or social network. However, it provides unrestricted access to third-party websites that may contain user-generated communication, commerce, gambling, mature, or other rated content. It has no parental-control system. Answer the unrestricted Internet or browser-access questions affirmatively and let IARC determine the rating.

Factual questionnaire inputs:

- `general_web_browser`: `true`
- `app_authored_mature_content`: `false`
- `user_generated_content_service`: `false`
- `third_party_user_generated_content_accessible`: `true`
- `social_or_user_communication`: `false`
- `advertising`: `false`
- `purchases_or_subscriptions`: `false`
- `location_access`: `false`
- `parental_controls`: `false`

### Free pricing and availability checklist

Base price: **Free**
Trial, purchases, and subscription: **None**

- Set the base price to Free and verify there are no market-specific price overrides.
- Do not configure a trial, subscription, add-on, or in-app purchase.
- Review target markets for browser, encryption, privacy, and support obligations; do not assume worldwide availability without that review.
- Target Windows Desktop only; do not select Xbox, HoloLens, or Surface Hub unless separately tested.
- Use a manual publishing hold for the first submission so certification success cannot publish before final review.
- Verify the support, privacy, license, and vulnerability-reporting URLs immediately before submission.

### Screenshot requirements and plan

Desktop `PNG`, minimum `1366x768`, maximum `50 MB`; plan: `5` screenshots.

- Capture the exact Store package candidate on a clean supported Windows VM at 100 percent display scale.
- Use only the packaged local new-tab page, project website, or controlled synthetic pages; show no accounts, cookies, history, downloads, bookmarks, passwords, or personal identifiers.
- Do not composite marketing text, extra logos, borders, or claims over screenshots.
- Keep important UI in the top two-thirds because Store overlays can cover the lower third.
- Show Shields as verified only when the current session's exact-identity and runtime probe evidence actually passes.

1. **new-tab** — ZSEC Browser's isolated local new-tab page inside the native tab and address interface.
   Capture: Main window on the packaged local new-tab page with no account or personal data.
2. **tabs-navigation** — Managed tabs, address search, navigation, bookmarks, Shields status, and native browser controls.
   Capture: Main window on the public ZSEC product page with two synthetic tabs.
3. **shields** — Reviewed Browser Shields controls with evidence-led extension and request-rule status.
   Capture: Shields panel only after exact-identity and runtime verification passes.
4. **privacy-settings** — Local privacy, permissions, history, appearance, and password opt-in settings.
   Capture: Settings dialog with password save and fill visibly off and no site-specific personal data.
5. **local-data-tools** — Local bookmark and migration tools preview selected data without transferring browser sessions.
   Capture: Bookmark manager or Migration center populated only with synthetic example bookmarks.

### Pre-submission gates

- Use the exact Partner Center identity and Store-signed package candidate.
- Pass Windows App Certification Kit with no unexplained failures.
- Pass clean-VM launch, WebView2 runtime, Shields, local-data persistence, update, and uninstall acceptance.
- Verify Store-packaged behavior does not claim default-browser registration that is absent from the minimized Store manifest.
- Review rule counts, privacy claims, third-party notices, and every feature against the exact submitted release.

## Authoritative Microsoft guidance

- Store listing fields: https://learn.microsoft.com/windows/apps/publish/publish-your-app/msix/add-and-edit-store-listing-info
- Screenshots and images: https://learn.microsoft.com/windows/apps/publish/publish-your-app/msix/screenshots-and-images
- Age ratings: https://learn.microsoft.com/windows/apps/publish/publish-your-app/msix/age-ratings
- Submission options and certification notes: https://learn.microsoft.com/windows/apps/publish/publish-your-app/msix/manage-submission-options
- App capabilities: https://learn.microsoft.com/windows/apps/package-and-deploy/app-capability-declarations
- Package requirements: https://learn.microsoft.com/windows/apps/publish/publish-your-app/msix/app-package-requirements
