# ZSEC Microsoft Store packaging

This directory is an isolated, fail-closed MSIX staging lane for **ZSEC
Antivirus** and **ZSEC Browser**. It does not reserve names, invent package
identities, sign packages, change installed applications, or submit to Partner
Center.

The manifests declare only the restricted `runFullTrust` capability required by
the existing Win32 desktop executables. They intentionally do not request
`broadFileSystemAccess`, device capabilities, background tasks, protocol
ownership, or an app-execution alias. In particular, this scaffold does not
register ZSEC Antivirus as a Windows Security provider and does not make ZSEC
Browser the default browser.

## Current version mapping

MSIX requires a four-part numeric version. The validator derives rather than
duplicates the source version:

- ZSEC Antivirus: `[project].version` in `pyproject.toml` -> `x.y.z.0`.
- ZSEC Browser: `$ProductVersion` in
  `windows/browser/Build-ZsecBrowserPreview.ps1` -> `x.y.z.0`.

Each later Store submission must use a numerically higher package version.
Never reuse the same package identity, architecture, and version for different
bytes.

## Required Partner Center input

Reserve **two separate products** in Partner Center. For each product open
**Product management > Product identity** (wording can vary), then copy the
exact values for:

1. `Package/Identity/Name`
2. `Package/Identity/Publisher`
3. `Package/Properties/PublisherDisplayName`

Copy `store-identity.example.json` to the gitignored
`store-identity.json` and replace every `PARTNER_CENTER_...` value. The build
rejects placeholders, malformed identity names, and publishers that do not
start with `CN=`. Do not substitute the Partner Center seller ID, Store ID,
package family name, or a guessed certificate subject.

Microsoft's identity guidance is authoritative:
<https://learn.microsoft.com/windows/apps/publish/view-app-identity-details>.

## Validate and stage

Generate the checked-in base-scale package assets after changing either brand
source image:

```powershell
python packaging/windows-store/generate_assets.py
```

Validate templates, exact image dimensions, capability minimization, and source
version mapping:

```powershell
python packaging/windows-store/build_store_package.py validate
```

Build the existing verified direct-distribution payloads first. Then stage one
product. `--payload` is the extracted antivirus release root containing
`DESKTOP-MANIFEST.json`, or the browser build directory containing
`build-manifest.json` and `payload/`:

```powershell
python packaging/windows-store/build_store_package.py stage `
  --product antivirus `
  --payload C:\absolute\path\to\zsec-antivirus-desktop-x.y.z-windows-x86_64 `
  --identity packaging/windows-store/store-identity.json `
  --output packaging/windows-store/out/antivirus-layout

python packaging/windows-store/build_store_package.py stage `
  --product browser `
  --payload C:\absolute\path\to\browser-build `
  --identity packaging/windows-store/store-identity.json `
  --output packaging/windows-store/out/browser-layout
```

Staging re-hashes every source file against the product build manifest, rejects
a stale payload version, copies only Store runtime content, renders
`AppxManifest.xml`, and writes deterministic `store-package-files.json`.

## Build the unsigned Store upload package

Install a current Windows SDK so the x64 `MakeAppx.exe` is available, then run:

```powershell
python packaging/windows-store/build_store_package.py pack `
  --product antivirus `
  --layout packaging/windows-store/out/antivirus-layout `
  --output packaging/windows-store/out/ZSEC-Antivirus-x.y.z.0-x64.msix `
  --makeappx "C:\Program Files (x86)\Windows Kits\10\bin\<sdk>\x64\MakeAppx.exe"
```

Repeat with `--product browser`. The command emits an unsigned `.msix`, JSON
metadata, and SHA-256 sidecar. Microsoft re-signs an accepted Store package;
local installation testing needs a test certificate whose subject exactly
matches the manifest publisher. Never upload a locally modified package after
testing its signed copy.

Microsoft documents manual desktop conversion and MakeAppx here:
<https://learn.microsoft.com/windows/msix/desktop/desktop-to-uwp-manual-conversion>.

## Certification gates still requiring human/account action

Passing this repository lane is not Store certification. Before upload:

- run the Windows App Certification Kit and fix every failure;
- install each signed test package on a clean supported Windows VM and verify
  launch, navigation/scanning, settings persistence, update, and uninstall;
- confirm packaged-path behavior for the antivirus companion lifecycle and all
  PowerShell tools; the MSIX must not run the existing direct installer;
- request/justify the restricted `runFullTrust` capability in Partner Center;
- use claims matching the evidence: ZSEC Antivirus is currently a companion,
  not a primary antivirus or pre-access enforcement provider, and ZSEC Browser
  is a WebView2 shell, not a maintained Chromium fork;
- provide current privacy-policy URLs, support contact, age rating, screenshots,
  descriptions, third-party notices, and certification notes;
- set price to **Free** and review markets, but stop for final review before
  pressing **Submit for certification**.

Store package requirements and upload formats are documented at
<https://learn.microsoft.com/windows/apps/publish/publish-your-app/msix/app-package-requirements>
and
<https://learn.microsoft.com/windows/apps/publish/publish-your-app/msix/upload-app-packages>.

## Offline Partner Center listing and certification draft

The copy-and-paste listing source is kept in `listings/` and rendered to
`PARTNER_CENTER_DRAFT.md`. It includes bounded short and full descriptions,
feature bullets, reviewed privacy/support URLs, separate `runFullTrust`
justifications, certification notes and tester steps, IARC facts, Free pricing
checks, and five-screenshot plans for each product.

Validate that descriptions and captions remain within Microsoft field limits,
versions still match the build sources, the Browser remains disclosed as a
general web browser for IARC, pricing remains Free, and unsupported protection
claims have not entered the copy:

```powershell
python packaging/windows-store/listing_materials.py
```

After an intentional JSON edit, regenerate the Markdown and immediately rerun
the validator:

```powershell
python packaging/windows-store/listing_materials.py --write
python packaging/windows-store/listing_materials.py
```

These files are drafts, not evidence of a reservation, completed submission, or
certification. They deliberately stop before any Partner Center write. The
identity, WACK, Store-signed clean-VM acceptance, current URL review, final
market selection, screenshot capture, and human submission review remain hard
gates.
