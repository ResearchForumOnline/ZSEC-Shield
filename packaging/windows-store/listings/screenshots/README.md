# Microsoft Store screenshot capture gate

No Store screenshots are checked in yet. Capture them only from the exact packaged
release candidates on a clean supported Windows VM. This directory is a provenance
and validation gate, not a place for mockups or composited marketing artwork.

## Required clean-VM setup

1. Start from a clean Windows 10 or Windows 11 x64 VM with no personal accounts,
   files, browser profiles, history, bookmarks, downloads, passwords, email, or
   cloud sync. Take a VM snapshot before installing either candidate.
2. Set Windows display scaling to 100 percent and use a display of at least
   1366x768. Keep the complete app window visible; do not include the taskbar,
   desktop, notifications, another app, VM chrome, or capture-tool UI.
3. Install the exact Store-signed candidate that will be submitted. Record the
   package and packaged executable SHA-256 values through the validator. Do not
   substitute a development build or an already installed copy.
4. Use only synthetic, non-identifying state. Review every visible pixel at full
   resolution before copying the PNG out of the VM. Automated validation cannot
   prove that visible content is private or that an on-screen security claim is true.
5. Save direct app-window captures as static, non-interlaced 8-bit RGB PNG files.
   Do not add text, logos, borders, redactions, overlays, or reconstructed UI. A
   crop is acceptable only to isolate the unchanged app window without hiding
   evidence or changing the meaning of its state.

## ZSEC Antivirus 0.3.31

Restore the clean snapshot, install the exact Antivirus candidate, keep Microsoft
Defender or another supported primary provider active, and use a disposable path
such as `C:\ZSEC-Store-Demo\Benign-Samples` containing only benign synthetic files.
Never expose real user paths, device names, provider identifiers, quarantine data,
or reports. Never paint incomplete coverage green: preserve every amber/red warning
and capture a healthy status only when the current on-screen evidence verifies it.
Do not use a real document for the recovery view.

Save under `antivirus/` with these exact names:

1. `01-overview.png`
2. `02-scan-active.png`
3. `03-scan-result.png`
4. `04-windows-protection.png`
5. `05-recovery.png`

## ZSEC Browser 0.3.26

Restore the clean snapshot again, install the exact Browser candidate, and allow it
to create a new package-local profile. Do not import any existing browser profile or
sign into any account. Keep password save and fill disabled. Use only the packaged
local new-tab page, the public ZSEC product page, or a controlled synthetic page;
synthetic bookmarks must use example-only names and URLs. Show Shields as verified
only when the current session's exact-identity and runtime evidence passes.

Save under `browser/` with these exact names:

1. `01-new-tab.png`
2. `02-tabs-navigation.png`
3. `03-shields.png`
4. `04-privacy-settings.png`
5. `05-local-data-tools.png`

## Manifest and validation

After the full-resolution human review, run `validate_screenshots.py create` with
the applicable product, listing JSON, exact MSIX, exact packaged executable, UTC
capture time, and all four attestation flags. For example:

```powershell
python packaging/windows-store/validate_screenshots.py create `
  --product antivirus `
  --screenshots packaging/windows-store/listings/screenshots/antivirus `
  --listing packaging/windows-store/listings/zsec-antivirus.en-US.json `
  --package packaging/windows-store/out/ZSEC-Antivirus-0.3.31.0-x64.msix `
  --executable "packaging/windows-store/out/antivirus-0.3.31.0-layout/App/ZSEC Antivirus.exe" `
  --captured-at 2026-08-25T12:00:00Z `
  --synthetic-state-only `
  --reviewed-no-personal-data `
  --no-taskbar-or-other-apps `
  --no-composited-overlays
```

This writes `capture-manifest.json` beside the five PNGs. Re-run the `validate`
subcommand against the same exact package and executable immediately before upload.
Any changed byte, wrong filename, unsupported PNG structure, stale screenshot plan,
or failed attestation blocks the set. The manifest intentionally stores no absolute
paths, Windows username, hostname, VM identifier, or other machine provenance.
