#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputDirectory = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProductVersion = "0.3.1"
$WebView2Version = "1.0.4129.50"
$WebView2Uri = "https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/$WebView2Version/microsoft.web.webview2.$WebView2Version.nupkg"
$WebView2Sha256 = "d3934f482d484b89fb4825df720c710664e1143a1e90f7b3a60794ef33f473d2"
$WebView2Sha512Base64 = "9TM9AZpDUiAb6OJB9s6thxl63BJFgbINcp047Zy+oiz9+cjgLhFrMRZ5Be+5wVHGvMJR3z1rmPWeJipo4g0sJw=="

$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $RepoRoot "dist\browser-desktop-preview\$ProductVersion"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$PayloadRoot = Join-Path $OutputDirectory "payload"
$AppRoot = Join-Path $PayloadRoot "App"
$PolicyRoot = Join-Path $AppRoot "policy"
$LauncherSource = Join-Path $RepoRoot "browser\zsec-desktop-preview\src\ZsecBrowserApp.cs"
$ExtensionSource = Join-Path $RepoRoot "browser\zeroq-shields"
$IconSource = Join-Path $RepoRoot "assets\brand\zeroq-icon.png"
$IconPath = Join-Path $OutputDirectory "zsec-browser.ico"
$LauncherPath = Join-Path $AppRoot "ZSEC Browser.exe"
$CscPath = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$PackageCache = Join-Path $env:LOCALAPPDATA "TalkToAI\ZSEC Browser Build\packages\Microsoft.Web.WebView2\$WebView2Version"
$PackagePath = Join-Path $PackageCache "microsoft.web.webview2.$WebView2Version.nupkg"
$PackageExtract = Join-Path $PackageCache "extracted"

foreach ($path in @($LauncherSource, $IconSource, $CscPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required build input is absent: $path"
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $ExtensionSource "manifest.json") -PathType Leaf)) {
    throw "The reviewed ZSEC Browser Shields extension source is absent."
}

New-Item -ItemType Directory -Path $PackageCache -Force | Out-Null
if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing -Uri $WebView2Uri -OutFile $PackagePath
}

$actualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $PackagePath).Hash.ToLowerInvariant()
if ($actualSha256 -ne $WebView2Sha256) {
    throw "The pinned Microsoft WebView2 SDK package failed its SHA-256 check."
}
$sha512 = [Security.Cryptography.SHA512]::Create()
try {
    $actualSha512Base64 = [Convert]::ToBase64String($sha512.ComputeHash([IO.File]::ReadAllBytes($PackagePath)))
}
finally {
    $sha512.Dispose()
}
if ($actualSha512Base64 -ne $WebView2Sha512Base64) {
    throw "The pinned Microsoft WebView2 SDK package failed the NuGet catalog SHA-512 check."
}

if (-not (Test-Path -LiteralPath $PackageExtract -PathType Container)) {
    Expand-Archive -LiteralPath $PackagePath -DestinationPath $PackageExtract
}
$CoreDll = Join-Path $PackageExtract "lib\net462\Microsoft.Web.WebView2.Core.dll"
$WinFormsDll = Join-Path $PackageExtract "lib\net462\Microsoft.Web.WebView2.WinForms.dll"
$LoaderDll = Join-Path $PackageExtract "runtimes\win-x64\native\WebView2Loader.dll"
foreach ($path in @($CoreDll, $WinFormsDll, $LoaderDll)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "The pinned Microsoft WebView2 package is incomplete: $path"
    }
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
    "/nologo",
    "/target:winexe",
    "/optimize+",
    "/platform:x64",
    "/reference:System.dll",
    "/reference:System.Core.dll",
    "/reference:System.Drawing.dll",
    "/reference:System.Security.dll",
    "/reference:System.Web.dll",
    "/reference:System.Windows.Forms.dll",
    "/reference:$CoreDll",
    "/reference:$WinFormsDll",
    "/win32icon:$IconPath",
    "/out:$LauncherPath",
    $LauncherSource
)
& $CscPath @compilerArguments
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $LauncherPath -PathType Leaf)) {
    throw "The native ZSEC Browser shell build failed."
}

Copy-Item -LiteralPath $CoreDll -Destination (Join-Path $AppRoot "Microsoft.Web.WebView2.Core.dll") -Force
Copy-Item -LiteralPath $WinFormsDll -Destination (Join-Path $AppRoot "Microsoft.Web.WebView2.WinForms.dll") -Force
Copy-Item -LiteralPath $LoaderDll -Destination (Join-Path $AppRoot "WebView2Loader.dll") -Force
$ExtensionRoot = Join-Path $AppRoot "extension"
$ExtensionFiles = @(
    "manifest.json",
    "assets/zeroq-icon.png",
    "popup/index.html",
    "popup/popup.css",
    "popup/popup.js",
    "rules/link-cleaning.json",
    "rules/privacy.json",
    "src/high-risk-browsing.js",
    "src/policy.js",
    "src/service-worker.js",
    "src/youtube-cleanup.js"
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
foreach ($name in @(
    "Install-ZsecBrowserPreview.ps1",
    "Get-ZsecBrowserPreviewStatus.ps1",
    "Test-ZsecBrowserPreviewRuntime.ps1",
    "Uninstall-ZsecBrowserPreview.ps1"
)) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $PayloadRoot $name) -Force
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
    launcher = $LauncherPath
    launcher_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $LauncherPath).Hash.ToLowerInvariant()
    webview2_sdk_version = $WebView2Version
    webview2_nuget_sha256 = $WebView2Sha256
    webview2_nuget_sha512_base64 = $WebView2Sha512Base64
    tracker_domain_count = [int]$policy.outputs.tracker_domain_count
    tracking_parameter_count = [int]$policy.outputs.tracking_parameter_count
    source_extension_version = [string]$policy.source_extension.version
    source_extension_id = "ddjbjhnlhapggenanpmcidieimaomiif"
    payload_root = $PayloadRoot
    files = $fileManifest
}
$encoding = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText(
    (Join-Path $OutputDirectory "build-manifest.json"),
    (($result | ConvertTo-Json -Depth 8) + [Environment]::NewLine),
    $encoding
)
$result | ConvertTo-Json -Depth 8
