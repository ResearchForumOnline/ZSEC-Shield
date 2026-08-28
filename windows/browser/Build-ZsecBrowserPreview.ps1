#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputDirectory = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProductVersion = "0.3.26"
$WebView2Version = "1.0.4129.50"
$WebView2Uri = "https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/$WebView2Version/microsoft.web.webview2.$WebView2Version.nupkg"
$WebView2Sha256 = "d3934f482d484b89fb4825df720c710664e1143a1e90f7b3a60794ef33f473d2"
$WebView2Sha512Base64 = "9TM9AZpDUiAb6OJB9s6thxl63BJFgbINcp047Zy+oiz9+cjgLhFrMRZ5Be+5wVHGvMJR3z1rmPWeJipo4g0sJw=="
$CompilerToolsetVersion = "4.14.0"
$CompilerToolsetUri = "https://api.nuget.org/v3-flatcontainer/microsoft.net.compilers.toolset/$CompilerToolsetVersion/microsoft.net.compilers.toolset.$CompilerToolsetVersion.nupkg"
$CompilerToolsetSha256 = "941a9cf3ea618d88d01a3dd6b1a45a06bcf07716a9f81ce4031caa3edd24a845"
$CompilerToolsetSha512Base64 = "h5GExC3fx0fm0qHw8rQ6y5c0uk6cCiAsorLl9Hq/9VlotEvsv/oW60RNo8HOYApv66kNqJq4Bg/TkSAsgQAwbQ=="
$CompilerSourcePathMap = "/_/src"

function Assert-PinnedNuGetPackage {
    param(
        [Parameter(Mandatory = $true)][string]$PackagePath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedSha512Base64,
        [Parameter(Mandatory = $true)][string]$PackageLabel
    )
    if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) {
        throw "The pinned $PackageLabel package is absent."
    }
    $actualSha256 = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $PackagePath
    ).Hash.ToLowerInvariant()
    if ($actualSha256 -ne $ExpectedSha256) {
        throw "The pinned $PackageLabel package failed its SHA-256 check."
    }
    $sha512 = [Security.Cryptography.SHA512]::Create()
    $stream = $null
    try {
        $stream = [IO.File]::Open(
            $PackagePath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $actualSha512Base64 = [Convert]::ToBase64String(
            $sha512.ComputeHash($stream)
        )
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        $sha512.Dispose()
    }
    if ($actualSha512Base64 -ne $ExpectedSha512Base64) {
        throw "The pinned $PackageLabel package failed the NuGet catalog SHA-512 check."
    }
}

function Remove-OwnedPackageExtraction {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$CacheRoot,
        [Parameter(Mandatory = $true)][string]$PackagePath
    )
    $resolvedCache = [IO.Path]::GetFullPath($CacheRoot).TrimEnd('\', '/')
    $resolvedPath = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $parent = [IO.Path]::GetDirectoryName($resolvedPath)
    $leaf = [IO.Path]::GetFileName($resolvedPath)
    if (
        -not [string]::Equals(
            $parent,
            $resolvedCache,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        $leaf -notmatch '^extract-[0-9a-f]{32}$'
    ) {
        throw "Package-extraction cleanup refused a path outside its exact owned boundary."
    }
    $cacheItem = Get-Item -LiteralPath $resolvedCache -Force -ErrorAction Stop
    if (-not $cacheItem.PSIsContainer -or
        ($cacheItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Package-extraction cleanup refused an unsafe cache root."
    }
    if (-not (Test-Path -LiteralPath $resolvedPath)) {
        return
    }
    $rootItem = Get-Item -LiteralPath $resolvedPath -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Package-extraction cleanup refused an unexpected staging object."
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $directories = @{}
    $directories[$resolvedPath] = $true
    $archive = [IO.Compression.ZipFile]::OpenRead($PackagePath)
    try {
        foreach ($entry in $archive.Entries) {
            if ([string]::IsNullOrWhiteSpace($entry.FullName)) {
                continue
            }
            $relative = $entry.FullName.Replace(
                '/',
                [IO.Path]::DirectorySeparatorChar
            )
            $candidate = [IO.Path]::GetFullPath((Join-Path $resolvedPath $relative))
            $prefix = $resolvedPath + [IO.Path]::DirectorySeparatorChar
            if (-not $candidate.StartsWith(
                    $prefix,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw "Package-extraction cleanup refused an archive path escape."
            }
            if (-not [string]::IsNullOrEmpty($entry.Name)) {
                if (Test-Path -LiteralPath $candidate) {
                    $fileItem = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
                    if ($fileItem.PSIsContainer -or
                        ($fileItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                        throw "Package-extraction cleanup refused a changed archive file."
                    }
                    [IO.File]::Delete($candidate)
                }
                $directory = [IO.Path]::GetDirectoryName($candidate)
            }
            else {
                $directory = $candidate.TrimEnd('\', '/')
            }
            while (-not [string]::IsNullOrWhiteSpace($directory)) {
                if ($directory.StartsWith(
                        $prefix,
                        [StringComparison]::OrdinalIgnoreCase
                    ) -or
                    [string]::Equals(
                        $directory,
                        $resolvedPath,
                        [StringComparison]::OrdinalIgnoreCase
                    )) {
                    $directories[$directory] = $true
                }
                else {
                    break
                }
                if ([string]::Equals(
                        $directory,
                        $resolvedPath,
                        [StringComparison]::OrdinalIgnoreCase
                    )) {
                    break
                }
                $directory = [IO.Path]::GetDirectoryName($directory)
            }
        }
    }
    finally {
        $archive.Dispose()
    }
    $orderedDirectories = @(
        $directories.Keys | Sort-Object { $_.Length } -Descending
    )
    foreach ($directory in $orderedDirectories) {
        if (-not (Test-Path -LiteralPath $directory)) {
            continue
        }
        $directoryItem = Get-Item -LiteralPath $directory -Force -ErrorAction Stop
        if (-not $directoryItem.PSIsContainer -or
            ($directoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Package-extraction cleanup refused a changed archive directory."
        }
        [IO.Directory]::Delete($directory, $false)
    }
    if (Test-Path -LiteralPath $resolvedPath) {
        throw "Package-extraction staging cleanup could not be verified."
    }
}

function Expand-PinnedPackageToFreshStaging {
    param(
        [Parameter(Mandatory = $true)][string]$PackagePath,
        [Parameter(Mandatory = $true)][string]$CacheRoot
    )
    if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) {
        throw "The verified package is absent before extraction."
    }
    $leaf = "extract-$([Guid]::NewGuid().ToString('N'))"
    $staging = Join-Path ([IO.Path]::GetFullPath($CacheRoot)) $leaf
    if (Test-Path -LiteralPath $staging) {
        throw "The fresh package-extraction staging path already exists."
    }
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        [IO.Compression.ZipFile]::ExtractToDirectory($PackagePath, $staging)
        return $staging
    }
    catch {
        $extractionFailure = $_.Exception.Message
        try {
            Remove-OwnedPackageExtraction `
                -Path $staging `
                -CacheRoot $CacheRoot `
                -PackagePath $PackagePath
        }
        catch {
            throw (
                "The pinned NuGet package extraction failed and " +
                "staging cleanup could not be verified."
            )
        }
        throw "The pinned NuGet package could not be extracted. Details: $extractionFailure"
    }
}

$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $RepoRoot "dist\browser-desktop-preview\$ProductVersion"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) {
    throw "OutputDirectory must not already exist; use a fresh path for each build."
}
$PayloadRoot = Join-Path $OutputDirectory "payload"
$AppRoot = Join-Path $PayloadRoot "App"
$PolicyRoot = Join-Path $AppRoot "policy"
$LauncherSource = Join-Path $RepoRoot "browser\zsec-desktop-preview\src\ZsecBrowserApp.cs"
$ProductStateSource = Join-Path $RepoRoot "browser\zsec-desktop-preview\src\BrowserProductState.cs"
$ProductPolicySource = Join-Path $RepoRoot "browser\zsec-desktop-preview\src\BrowserProductPolicy.cs"
$ProductDialogsSource = Join-Path $RepoRoot "browser\zsec-desktop-preview\src\BrowserProductDialogs.cs"
$VaultContractsSource = Join-Path $RepoRoot "browser\zsec-desktop-preview\src\BrowserVaultUiContracts.cs"
$PasswordVaultSource = Join-Path $RepoRoot "browser\zsec-desktop-preview\src\BrowserPasswordVault.cs"
$CredentialWorkflowSource = Join-Path $RepoRoot "browser\zsec-desktop-preview\src\BrowserCredentialWorkflowPolicy.cs"
$CredentialImportSource = Join-Path $RepoRoot "browser\zsec-desktop-preview\src\BrowserCredentialImport.cs"
$MigrationSource = Join-Path $RepoRoot "browser\zsec-desktop-preview\src\BrowserMigration.cs"
$VaultDialogsSource = Join-Path $RepoRoot "browser\zsec-desktop-preview\src\BrowserVaultDialogs.cs"
$LoginAssistantSource = Join-Path $RepoRoot "browser\zsec-desktop-preview\src\BrowserLoginAssistant.cs"
$SignInMigrationSource = Join-Path $RepoRoot "browser\zsec-desktop-preview\src\BrowserSignInMigration.cs"
$LoginDialogsSource = Join-Path $RepoRoot "browser\zsec-desktop-preview\src\BrowserLoginDialogs.cs"
$ThemeSource = Join-Path $RepoRoot "browser\zsec-desktop-preview\src\BrowserTheme.cs"
$LocalAutomationSource = Join-Path $RepoRoot "browser\zsec-desktop-preview\src\BrowserLocalAutomation.cs"
$YoutubeProtectionSource = Join-Path $RepoRoot "browser\zsec-desktop-preview\assets\youtube-player-protection.js"
$ExtensionSource = Join-Path $RepoRoot "browser\zeroq-shields"
$IconSource = Join-Path $RepoRoot "assets\brand\zeroq-icon.png"
$Win32Manifest = Join-Path $RepoRoot "packaging\zsec-browser-desktop.manifest"
$IconPath = Join-Path $OutputDirectory "zsec-browser.ico"
$LauncherPath = Join-Path $AppRoot "ZSEC Browser.exe"
$PackageCache = Join-Path $env:LOCALAPPDATA "TalkToAI\ZSEC Browser Build\packages\Microsoft.Web.WebView2\$WebView2Version"
$PackagePath = Join-Path $PackageCache "microsoft.web.webview2.$WebView2Version.nupkg"
$CompilerPackageCache = Join-Path $env:LOCALAPPDATA "TalkToAI\ZSEC Browser Build\packages\Microsoft.Net.Compilers.Toolset\$CompilerToolsetVersion"
$CompilerPackagePath = Join-Path $CompilerPackageCache "microsoft.net.compilers.toolset.$CompilerToolsetVersion.nupkg"

foreach ($path in @(
    $LauncherSource, $ProductStateSource, $ProductPolicySource, $ProductDialogsSource,
    $VaultContractsSource, $PasswordVaultSource, $CredentialWorkflowSource, $CredentialImportSource, $MigrationSource, $VaultDialogsSource,
    $LoginAssistantSource, $SignInMigrationSource, $LoginDialogsSource, $ThemeSource, $LocalAutomationSource,
    $YoutubeProtectionSource, $IconSource, $Win32Manifest
)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required build input is absent: $path"
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $ExtensionSource "manifest.json") -PathType Leaf)) {
    throw "The reviewed ZSEC Browser Shields extension source is absent."
}

New-Item -ItemType Directory -Path $PackageCache -Force | Out-Null
New-Item -ItemType Directory -Path $CompilerPackageCache -Force | Out-Null
if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing -Uri $WebView2Uri -OutFile $PackagePath
}
if (-not (Test-Path -LiteralPath $CompilerPackagePath -PathType Leaf)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest `
        -UseBasicParsing `
        -Uri $CompilerToolsetUri `
        -OutFile $CompilerPackagePath
}
Assert-PinnedNuGetPackage `
    -PackagePath $PackagePath `
    -ExpectedSha256 $WebView2Sha256 `
    -ExpectedSha512Base64 $WebView2Sha512Base64 `
    -PackageLabel "Microsoft WebView2 SDK"
Assert-PinnedNuGetPackage `
    -PackagePath $CompilerPackagePath `
    -ExpectedSha256 $CompilerToolsetSha256 `
    -ExpectedSha512Base64 $CompilerToolsetSha512Base64 `
    -PackageLabel "Microsoft.Net.Compilers.Toolset"

$WebViewPackageExtract = Expand-PinnedPackageToFreshStaging `
    -PackagePath $PackagePath `
    -CacheRoot $PackageCache
try {
$CompilerPackageExtract = Expand-PinnedPackageToFreshStaging `
    -PackagePath $CompilerPackagePath `
    -CacheRoot $CompilerPackageCache
try {
$CoreDll = Join-Path $WebViewPackageExtract "lib\net462\Microsoft.Web.WebView2.Core.dll"
$WinFormsDll = Join-Path $WebViewPackageExtract "lib\net462\Microsoft.Web.WebView2.WinForms.dll"
$LoaderDll = Join-Path $WebViewPackageExtract "runtimes\win-x64\native\WebView2Loader.dll"
$CscPath = Join-Path $CompilerPackageExtract "tasks\net472\csc.exe"
foreach ($path in @($CoreDll, $WinFormsDll, $LoaderDll)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "The pinned Microsoft WebView2 package is incomplete: $path"
    }
}
if (-not (Test-Path -LiteralPath $CscPath -PathType Leaf)) {
    throw "The pinned Microsoft.Net.Compilers.Toolset package is incomplete."
}

New-Item -ItemType Directory -Path $AppRoot -Force | Out-Null
New-Item -ItemType Directory -Path $PolicyRoot -Force | Out-Null
& py -3 (Join-Path $RepoRoot "packaging\make_windows_icon.py") $IconSource $IconPath
if ($LASTEXITCODE -ne 0) {
    throw "The ZSEC Browser icon build failed."
}
& py -3 (Join-Path $RepoRoot "packaging\compile_browser_policy.py") `
    (Join-Path $RepoRoot "browser\zeroq-shields\rules") `
    (Join-Path $RepoRoot "browser\zeroq-shields\manifest.json") `
    $PolicyRoot
if ($LASTEXITCODE -ne 0) {
    throw "The ZSEC Browser policy compilation failed."
}

$compilerArguments = @(
    "/noconfig",
    "/nologo",
    "/target:winexe",
    "/optimize+",
    "/deterministic+",
    "/platform:x64",
    "/pathmap:$RepoRoot=$CompilerSourcePathMap",
    "/win32manifest:$Win32Manifest",
    "/reference:System.dll",
    "/reference:System.Core.dll",
    "/reference:System.Drawing.dll",
    "/reference:System.Security.dll",
    "/reference:System.Web.dll",
    "/reference:System.Web.Extensions.dll",
    "/reference:System.Windows.Forms.dll",
    "/reference:$CoreDll",
    "/reference:$WinFormsDll",
    "/win32icon:$IconPath",
    "/out:$LauncherPath",
    $LauncherSource,
    $ProductStateSource,
    $ProductPolicySource,
    $ProductDialogsSource,
    $VaultContractsSource,
    $PasswordVaultSource,
    $CredentialWorkflowSource,
    $CredentialImportSource,
    $MigrationSource,
    $VaultDialogsSource,
    $LoginAssistantSource,
    $SignInMigrationSource,
    $LoginDialogsSource,
    $ThemeSource,
    $LocalAutomationSource
)
& $CscPath @compilerArguments
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $LauncherPath -PathType Leaf)) {
    throw "The native ZSEC Browser shell build failed."
}

Copy-Item -LiteralPath $CoreDll -Destination (Join-Path $AppRoot "Microsoft.Web.WebView2.Core.dll") -Force
Copy-Item -LiteralPath $WinFormsDll -Destination (Join-Path $AppRoot "Microsoft.Web.WebView2.WinForms.dll") -Force
Copy-Item -LiteralPath $LoaderDll -Destination (Join-Path $AppRoot "WebView2Loader.dll") -Force
Copy-Item -LiteralPath $YoutubeProtectionSource -Destination (Join-Path $AppRoot "youtube-player-protection.js") -Force
$NewTabSourceRoot = Join-Path $RepoRoot "browser\zsec-desktop-preview\assets\new-tab"
$NewTabSource = Join-Path $NewTabSourceRoot "index.html"
if (-not (Test-Path -LiteralPath $NewTabSource -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $NewTabSourceRoot "native-request-probe.html") -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $NewTabSourceRoot "popup-regression.html") -PathType Leaf)) {
    throw "The packaged ZSEC Browser new-tab/probe pages are absent."
}
$NewTabRoot = Join-Path $AppRoot "new-tab"
New-Item -ItemType Directory -Path $NewTabRoot -Force | Out-Null
foreach ($newTabFile in @("index.html", "native-request-probe.html", "popup-regression.html")) {
    Copy-Item -LiteralPath (Join-Path $NewTabSourceRoot $newTabFile) -Destination (Join-Path $NewTabRoot $newTabFile) -Force
}
$ExtensionRoot = Join-Path $AppRoot "extension"
$ExtensionFiles = @(
    "manifest.json",
    "assets/zeroq-icon.png",
    "popup/index.html",
    "popup/popup.css",
    "popup/popup.js",
    "easylist.lock.json",
    "rules/easylist.json",
    "rules/link-cleaning.json",
    "rules/privacy.json",
    "src/high-risk-browsing.js",
    "src/policy.js",
    "src/popup-state.js",
    "src/runtime-health.js",
    "src/settings-transaction.js",
    "src/service-worker.js",
    "src/youtube-cosmetic-rules.js",
    "src/youtube-cleanup.js",
    "third_party/EASYLIST-LICENSE.txt",
    "third_party/easylist-20260817.txt",
    "third_party/easylist-provenance.json"
)
foreach ($relative in $ExtensionFiles) {
    $source = Join-Path $ExtensionSource $relative.Replace('/', '\')
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "The reviewed extension payload is incomplete: $relative"
    }
    $destination = Join-Path $ExtensionRoot $relative.Replace('/', '\')
    New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
    Copy-Item -LiteralPath $source -Destination $destination -Force
}
Copy-Item -LiteralPath (Join-Path $RepoRoot "LICENSE") -Destination (Join-Path $PayloadRoot "LICENSE.txt") -Force
Copy-Item -LiteralPath (Join-Path $RepoRoot "browser\zsec-desktop-preview\README.md") -Destination (Join-Path $PayloadRoot "README.md") -Force
foreach ($script in @(
    @{ Source = "Install-ZsecBrowserPreview.ps1"; Destination = "Install-ZsecBrowser.ps1" },
    @{ Source = "Get-ZsecBrowserPreviewStatus.ps1"; Destination = "Get-ZsecBrowserStatus.ps1" },
    @{ Source = "Test-ZsecBrowserPreviewRuntime.ps1"; Destination = "Test-ZsecBrowserRuntime.ps1" },
    @{ Source = "Uninstall-ZsecBrowserPreview.ps1"; Destination = "Uninstall-ZsecBrowser.ps1" }
)) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $script.Source) -Destination (Join-Path $PayloadRoot $script.Destination) -Force
}

$fileManifest = @()
foreach ($file in Get-ChildItem -LiteralPath $PayloadRoot -Recurse -File | Sort-Object FullName) {
    $fileManifest += [ordered]@{
        path = $file.FullName.Substring($PayloadRoot.Length + 1).Replace('\', '/')
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
        bytes = [long]$file.Length
    }
}
$policy = Get-Content -LiteralPath (Join-Path $PolicyRoot "policy-provenance.json") -Raw -Encoding UTF8 | ConvertFrom-Json
$result = [ordered]@{
    schema = "zsec.browser.desktop-preview-build.v2"
    product = "ZSEC Browser"
    version = $ProductVersion
    architecture = "windows-x64-webview2-shell"
    engine_distribution = "Microsoft Evergreen WebView2 Chromium runtime"
    engine_maintained_by = "Microsoft"
    standalone_chromium_fork = $false
    signed_zsec_binary = $false
    default_browser_changed = $false
    launcher = "App/ZSEC Browser.exe"
    launcher_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $LauncherPath).Hash.ToLowerInvariant()
    webview2_sdk_version = $WebView2Version
    webview2_nuget_sha256 = $WebView2Sha256
    webview2_nuget_sha512_base64 = $WebView2Sha512Base64
    compiler_distribution = "Microsoft.Net.Compilers.Toolset"
    compiler_version = $CompilerToolsetVersion
    compiler_nuget_sha256 = $CompilerToolsetSha256
    compiler_nuget_sha512_base64 = $CompilerToolsetSha512Base64
    compiler_deterministic = $true
    compiler_source_pathmap = $CompilerSourcePathMap
    tracker_domain_count = [int]$policy.outputs.tracker_domain_count
    tracking_parameter_count = [int]$policy.outputs.tracking_parameter_count
    source_extension_version = [string]$policy.source_extension.version
    source_extension_id = "ddjbjhnlhapggenanpmcidieimaomiif"
    payload_root = "payload"
    files = $fileManifest
}
$encoding = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText(
    (Join-Path $OutputDirectory "build-manifest.json"),
    (($result | ConvertTo-Json -Depth 8) + [Environment]::NewLine),
    $encoding
)
}
finally {
    Remove-OwnedPackageExtraction `
        -Path $CompilerPackageExtract `
        -CacheRoot $CompilerPackageCache `
        -PackagePath $CompilerPackagePath
}
}
finally {
    Remove-OwnedPackageExtraction `
        -Path $WebViewPackageExtract `
        -CacheRoot $PackageCache `
        -PackagePath $PackagePath
}
$result | ConvertTo-Json -Depth 8
