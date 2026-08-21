# ZSEC Chromium downstream bootstrap gate

This directory is a reviewable, fail-closed bootstrap gate for a future ZSEC Chromium downstream. It does **not** contain Chromium source, a browser build, an installer, an updater, Google Chrome branding, or a claim that ZSEC maintains Chromium today.

The package defaults to audit-only mode. It will not fetch Chromium unless every pinned host/toolchain check passes and the operator supplies both `-FetchChromium` and the exact confirmation token. On the current Windows 10 PC the host-OS check fails before any directory creation or network fetch.

## Security boundary

The scripts in this directory:

- do not install Visual Studio, Windows SDKs, or `depot_tools`;
- do not disable, stop, reconfigure, or exclude paths from antivirus products;
- do not alter Windows Security Center or another security provider;
- do not delete or overwrite an existing checkout;
- do not fetch from a failed or incomplete audit;
- do not enable Google Chrome branding or proprietary Google services;
- do not build, sign, install, update, or deploy a browser;
- preserve a partial fetch for review rather than deleting it after an error.

The pinned requirements live in [`toolchain.requirements.json`](toolchain.requirements.json). Treat any change to that file as a security-sensitive toolchain change requiring source review.

## Pinned host and toolchain

The gate requires:

- Windows 11 x64 build 22000 or newer, or supported Windows Server x64 build 17763 or newer;
- Visual Studio/Build Tools 2026 version 18.0 or newer;
- `Microsoft.VisualStudio.Component.VC.Tools.x86.x64`;
- `Microsoft.VisualStudio.Component.VC.ATLMFC`;
- Windows 11 SDK installer release 10.0.28000.2270, exposing SDK directory `10.0.28000.0` with x86 and x64 libraries;
- x64 Debugging Tools for Windows version 10.0.26100.3323 or newer;
- a real `depot_tools` git clone at `C:\src\depot_tools`;
- `C:\src\depot_tools` as the first effective PATH entry;
- `depot_tools\python3.bat` and `depot_tools\gclient.bat` as the first resolved commands;
- `DEPOT_TOOLS_WIN_TOOLCHAIN=0`;
- an existing, space-free `C:\src` root on NTFS;
- at least 16 GiB RAM and 250 GiB free on the checkout drive.

These gates are intentionally stricter than Chromium's absolute 100 GB/8 GB floor. They represent the smallest operational reserve accepted for a maintained ZSEC checkout, not a guarantee of acceptable build speed.

## Audit only

From a normal `cmd.exe` shell:

```cmd
cd /d C:\path\to\zero-security-suite\browser\chromium-downstream
bootstrap.cmd
```

From PowerShell:

```powershell
& .\scripts\Test-ZsecChromiumHost.ps1
```

Machine-readable output:

```powershell
& .\scripts\Test-ZsecChromiumHost.ps1 -Json
```

Exit codes:

- `0`: every gate passed;
- `2`: audit failure or fatal audit error;
- other non-zero values: a bounded bootstrap refusal or fetch failure.

An audit failure is expected on the current Windows 10 machine. Do not attempt to bypass it with Visual Studio 2022 or an unsupported Windows 11 installation.

## Supported-host preparation

Perform these steps only on a separate supported Windows 11/Windows Server build host.

1. Install Visual Studio Build Tools 2026 from Microsoft's signed bootstrapper:

   ```cmd
   vs_buildtools.exe ^
     --wait ^
     --passive ^
     --norestart ^
     --add Microsoft.VisualStudio.Workload.VCTools ^
     --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 ^
     --add Microsoft.VisualStudio.Component.VC.ATLMFC ^
     --includeRecommended
   ```

2. Separately install Windows SDK release `10.0.28000.2270`. The Visual Studio workload's recommended 26100 SDK is not the pinned Chromium SDK. Select Desktop C++ x86/x64, Signing Tools, and Debugging Tools for Windows.

3. Clone `depot_tools` and create the build root from `cmd.exe`:

   ```cmd
   mkdir C:\src
   cd /d C:\src
   git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
   set "PATH=C:\src\depot_tools;%PATH%"
   set "DEPOT_TOOLS_WIN_TOOLCHAIN=0"
   set "vs2026_install=THE_EXACT_PATH_RETURNED_BY_VSWHERE"
   gclient
   where python3
   where gclient
   ```

4. Confirm that `where python3` resolves `C:\src\depot_tools\python3.bat` first and `where gclient` resolves `C:\src\depot_tools\gclient.bat` first.

The first `gclient` bootstrap must run from `cmd.exe`, not PowerShell, Cygwin, Git Bash, or WSL. A WSL checkout must use a different `depot_tools` clone.

## Deliberate source fetch

After the audit passes on a supported host, preview the proposed mutation:

```powershell
& .\scripts\Invoke-ZsecChromiumBootstrap.ps1 `
  -FetchChromium `
  -Confirmation FETCH_CURRENT_CHROMIUM `
  -WhatIf
```

Run the reviewed fetch:

```powershell
& .\scripts\Invoke-ZsecChromiumBootstrap.ps1 `
  -FetchChromium `
  -Confirmation FETCH_CURRENT_CHROMIUM `
  -Confirm:$false
```

The wrapper executes the pinned equivalent of:

```cmd
set "GIT_CACHE_PATH=C:\src\zsec-git-cache"
cd /d C:\src\zsec-chromium
C:\src\depot_tools\fetch.bat --git-cache chromium
```

It deliberately does not use `--no-history`; a maintained security downstream needs full history for rebasing, bisecting, and release comparison.

## Build boundary after fetch

The first complete browser target is `chrome`, not `all`:

```cmd
cd /d C:\src\zsec-chromium\src
gn gen out\ZsecDev
autoninja -C out\ZsecDev chrome
```

An initial `base` target may prove the compiler and linker, but it is not a browser. `mini_installer` is a later packaging target and must not be offered publicly before application IDs, profile paths, signing, update/rollback, tests, notices, and uninstall behavior are independently reviewed.

Any future GN configuration must retain:

```gn
is_chrome_branded = false
```

A successful `chrome.exe` build is not evidence of a maintained, signed, or secure public browser release.

## Self-contained tests

The tests require only PowerShell and do not inspect or mutate Task Scheduler, antivirus, registry providers, Windows Security Center, or Chromium source:

```powershell
& .\tests\Run-Tests.ps1
```

They exercise the pure policy evaluator with supported and rejected host snapshots and statically reject dangerous security-provider mutation commands in the bootstrap scripts.

## Primary sources

- [Current Chromium Windows build instructions](https://chromium.googlesource.com/chromium/src.git/+/HEAD/docs/windows_build_instructions.md)
- [Chromium Visual Studio/SDK toolchain detection](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/build/vs_toolchain.py)
- [Visual Studio 2026 system requirements](https://learn.microsoft.com/en-us/visualstudio/releases/2026/vs-system-requirements)
- [Visual Studio Build Tools 2026 component IDs](https://github.com/MicrosoftDocs/visualstudio-docs/blob/main/docs/install/includes/vs-2026/workload-component-id-vs-build-tools.md)
- [Windows SDK downloads](https://learn.microsoft.com/en-us/windows/apps/windows-sdk/downloads)
- [Debugging Tools for Windows](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools)
