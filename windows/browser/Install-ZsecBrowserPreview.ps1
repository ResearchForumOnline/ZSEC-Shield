#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
param(
    [string]$PayloadRoot = "",
    [switch]$Open,
    [switch]$PlanOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProductName = "ZSEC Browser"
$ProductVersion = "0.3.9"

function Get-NormalizedPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains('"')) {
        throw "A required path is empty or contains a quote character."
    }
    return [System.IO.Path]::GetFullPath($Path)
}

function Test-IsPathBelow {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$Parent
    )
    $candidatePath = (Get-NormalizedPath $Candidate).TrimEnd('\')
    $parentPath = (Get-NormalizedPath $Parent).TrimEnd('\')
    return $candidatePath.StartsWith(
        $parentPath + '\',
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Assert-RegularNonReparseFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Expected a regular, non-reparse file: $Path"
    }
}

function Write-Utf8JsonAtomic {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )
    $temporary = "$Path.tmp-$([Guid]::NewGuid().ToString('N'))"
    $encoding = New-Object System.Text.UTF8Encoding($false)
    try {
        [System.IO.File]::WriteAllText(
            $temporary,
            (($Value | ConvertTo-Json -Depth 12) + [Environment]::NewLine),
            $encoding
        )
        Move-Item -LiteralPath $temporary -Destination $Path -Force -ErrorAction Stop
    }
    finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Get-TrustedWebView2Runtime {
    $roots = @(
        (Join-Path ${env:ProgramFiles(x86)} "Microsoft\EdgeWebView\Application"),
        (Join-Path $env:ProgramFiles "Microsoft\EdgeWebView\Application")
    ) | Select-Object -Unique
    $candidates = @()
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) {
            continue
        }
        foreach ($file in Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue) {
            $runtime = Join-Path $file.FullName "msedgewebview2.exe"
            if (-not (Test-Path -LiteralPath $runtime -PathType Leaf)) {
                continue
            }
            $signature = Get-AuthenticodeSignature -LiteralPath $runtime
            if (
                $signature.Status -eq [System.Management.Automation.SignatureStatus]::Valid -and
                $null -ne $signature.SignerCertificate -and
                $signature.SignerCertificate.Subject -match 'Microsoft Corporation'
            ) {
                $versionText = (Get-Item -LiteralPath $runtime).VersionInfo.FileVersion
                try {
                    $version = [Version]$versionText
                    if ($version.Major -ge 120) {
                        $candidates += [pscustomobject]@{
                            Path = $runtime
                            Version = $version
                            Signature = $signature
                        }
                    }
                }
                catch {
                    continue
                }
            }
        }
    }
    $selected = $candidates | Sort-Object Version -Descending | Select-Object -First 1
    if ($null -eq $selected) {
        throw "A supported, validly Microsoft-signed Evergreen WebView2 Chromium runtime was not found."
    }
    return $selected
}

function Close-ObsoleteZsecBrowserWindows {
    param(
        [Parameter(Mandatory = $true)][string]$ApplicationContainer,
        [Parameter(Mandatory = $true)][string]$CurrentLauncher
    )
    $container = (Get-NormalizedPath $ApplicationContainer).TrimEnd('\') + '\'
    $current = Get-NormalizedPath $CurrentLauncher
    $candidates = @()
    foreach ($process in @(Get-Process -Name "ZSEC Browser" -ErrorAction SilentlyContinue)) {
        try {
            $path = Get-NormalizedPath $process.Path
            if (
                $path.StartsWith($container, [StringComparison]::OrdinalIgnoreCase) -and
                -not [String]::Equals($path, $current, [StringComparison]::OrdinalIgnoreCase)
            ) {
                $candidates += $process
            }
        }
        catch {
            continue
        }
    }
    foreach ($process in $candidates) {
        [void]$process.CloseMainWindow()
    }
    if ($candidates.Count -gt 0) {
        $candidates | Wait-Process -Timeout 8 -ErrorAction SilentlyContinue
    }
    $remaining = @($candidates | Where-Object { -not $_.HasExited })
    return [ordered]@{
        requested = [int]$candidates.Count
        closed = [int]($candidates.Count - $remaining.Count)
        still_running = [int]$remaining.Count
        forced_termination = $false
        profile_preserved = $true
    }
}

if ($PSVersionTable.PSEdition -eq "Core" -and -not $IsWindows) {
    throw "ZSEC Browser installation is supported only on Windows."
}

if ([string]::IsNullOrWhiteSpace($PayloadRoot)) {
    $siblingPackageRoot = $PSScriptRoot
    $siblingPayload = Join-Path $PSScriptRoot "payload"
    $repoPayload = Join-Path $PSScriptRoot "..\..\dist\browser-desktop-preview\$ProductVersion\payload"
    if (Test-Path -LiteralPath (Join-Path $siblingPackageRoot "App\ZSEC Browser.exe") -PathType Leaf) {
        # The public Community archive flattens payload/App to App beside this
        # installer. Prefer that self-contained layout before developer paths.
        $PayloadRoot = $siblingPackageRoot
    }
    elseif (Test-Path -LiteralPath $siblingPayload -PathType Container) {
        $PayloadRoot = $siblingPayload
    }
    else {
        $PayloadRoot = $repoPayload
    }
}

$payload = Get-NormalizedPath $PayloadRoot
$payloadApp = Join-Path $payload "App"
$payloadLauncher = Join-Path $payloadApp "ZSEC Browser.exe"
$payloadCore = Join-Path $payloadApp "Microsoft.Web.WebView2.Core.dll"
$payloadWinForms = Join-Path $payloadApp "Microsoft.Web.WebView2.WinForms.dll"
$payloadLoader = Join-Path $payloadApp "WebView2Loader.dll"
$payloadPolicy = Join-Path $payloadApp "policy\policy-provenance.json"
foreach ($path in @($payloadLauncher, $payloadCore, $payloadWinForms, $payloadLoader, $payloadPolicy)) {
    Assert-RegularNonReparseFile $path
}

$versionInfo = (Get-Item -LiteralPath $payloadLauncher).VersionInfo
if ($versionInfo.ProductName -ne "ZSEC Browser" -or $versionInfo.FileVersion -notlike "$ProductVersion.*") {
    throw "The ZSEC Browser executable identity or version is invalid."
}
$policy = Get-Content -LiteralPath $payloadPolicy -Raw -Encoding UTF8 | ConvertFrom-Json
if (
    $policy.schema -ne "zsec.browser.desktop-policy.v1" -or
    $policy.source_extension.name -ne "ZSEC Browser Shields" -or
    [string]$policy.source_extension.version -ne "0.5.2" -or
    [int]$policy.outputs.tracker_domain_count -lt 1
) {
    throw "The compiled ZSEC Browser policy identity is invalid."
}
$runtime = Get-TrustedWebView2Runtime

$productRoot = Get-NormalizedPath (Join-Path $env:LOCALAPPDATA "TalkToAI\ZSEC Browser")
$appContainer = Join-Path $productRoot "App"
$versionRoot = Join-Path $appContainer $ProductVersion
$installedLauncher = Join-Path $versionRoot "ZSEC Browser.exe"
$profileRoot = Join-Path $productRoot "User Data"
$statePath = Join-Path $productRoot "install-state.json"
$desktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "ZSEC Browser.lnk"
$startMenuDirectory = Join-Path ([Environment]::GetFolderPath("StartMenu")) "Programs\TalkToAI"
$startMenuShortcut = Join-Path $startMenuDirectory "ZSEC Browser.lnk"
$launcherHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $payloadLauncher).Hash.ToLowerInvariant()

$payloadFiles = @()
foreach ($file in Get-ChildItem -LiteralPath $payloadApp -Recurse -File | Sort-Object FullName) {
    $payloadFiles += [ordered]@{
        path = $file.FullName.Substring($payloadApp.Length + 1).Replace('\', '/')
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
        bytes = [long]$file.Length
    }
}

$plan = [ordered]@{
    schema = "zsec.browser.desktop-preview-plan.v2"
    product = $ProductName
    version = $ProductVersion
    architecture = "windows-x64-webview2-shell"
    standalone_chromium_fork = $false
    signed_zsec_binary = $false
    engine_path = $runtime.Path
    engine_version = $runtime.Version.ToString()
    engine_signature = $runtime.Signature.Status.ToString()
    engine_maintained_by = "Microsoft"
    payload_root = $payload
    install_root = $versionRoot
    profile_root = $profileRoot
    desktop_shortcut = $desktopShortcut
    start_menu_shortcut = $startMenuShortcut
    launcher_sha256 = $launcherHash
    tracker_domain_count = [int]$policy.outputs.tracker_domain_count
    tracking_parameter_count = [int]$policy.outputs.tracking_parameter_count
    default_browser_changed = $false
    system_security_products_modified = $false
    plan_only = [bool]$PlanOnly
}

if ($PlanOnly) {
    $plan | ConvertTo-Json -Depth 8
    return
}
if (-not $PSCmdlet.ShouldProcess($versionRoot, "Install ZSEC Browser Community desktop client")) {
    $plan | ConvertTo-Json -Depth 8
    return
}

New-Item -ItemType Directory -Path $appContainer -Force | Out-Null
New-Item -ItemType Directory -Path $profileRoot -Force | Out-Null
New-Item -ItemType Directory -Path $startMenuDirectory -Force | Out-Null

if (Test-Path -LiteralPath $versionRoot) {
    if (-not (Test-IsPathBelow -Candidate $versionRoot -Parent $productRoot)) {
        throw "The existing version directory is outside the owned product root."
    }
    Assert-RegularNonReparseFile $installedLauncher
    $installedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $installedLauncher).Hash.ToLowerInvariant()
    if ($installedHash -ne $launcherHash) {
        throw "The existing versioned ZSEC Browser executable differs; refusing overwrite."
    }
}
else {
    $stagingRoot = Join-Path $appContainer (".staging-" + [Guid]::NewGuid().ToString("N"))
    if (-not (Test-IsPathBelow -Candidate $stagingRoot -Parent $productRoot)) {
        throw "The staging directory is outside the owned product root."
    }
    try {
        Copy-Item -LiteralPath $payloadApp -Destination $stagingRoot -Recurse -ErrorAction Stop
        foreach ($entry in $payloadFiles) {
            $stagedPath = Join-Path $stagingRoot ([string]$entry.path).Replace('/', '\')
            Assert-RegularNonReparseFile $stagedPath
            $stagedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $stagedPath).Hash.ToLowerInvariant()
            if ($stagedHash -ne [string]$entry.sha256) {
                throw "A staged ZSEC Browser file failed its SHA-256 check: $($entry.path)"
            }
        }
        Move-Item -LiteralPath $stagingRoot -Destination $versionRoot -ErrorAction Stop
    }
    finally {
        if (Test-Path -LiteralPath $stagingRoot) {
            Remove-Item -LiteralPath $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

$shell = New-Object -ComObject WScript.Shell
foreach ($shortcutPath in @($desktopShortcut, $startMenuShortcut)) {
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $installedLauncher
    $shortcut.WorkingDirectory = $versionRoot
    $shortcut.Description = "ZSEC Browser - hardened browser shell powered by Microsoft WebView2 Chromium"
    $shortcut.IconLocation = "$installedLauncher,0"
    $shortcut.Save()
    if (-not (Test-Path -LiteralPath $shortcutPath -PathType Leaf)) {
        throw "Shortcut creation failed: $shortcutPath"
    }
}

$state = [ordered]@{
    schema = "zsec.browser.desktop-preview-installation.v2"
    product = $ProductName
    version = $ProductVersion
    installed_at = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    architecture = "windows-x64-webview2-shell"
    standalone_chromium_fork = $false
    signed_zsec_binary = $false
    engine = [ordered]@{
        product = "Microsoft Edge WebView2 Runtime"
        path = $runtime.Path
        version = $runtime.Version.ToString()
        signature_status = $runtime.Signature.Status.ToString()
        signer_subject = $runtime.Signature.SignerCertificate.Subject
        maintained_by = "Microsoft"
        distribution = "Evergreen"
    }
    launcher = [ordered]@{
        path = $installedLauncher
        sha256 = $launcherHash
    }
    app_files = $payloadFiles
    policy = [ordered]@{
        source_name = [string]$policy.source_extension.name
        source_version = [string]$policy.source_extension.version
        provenance_path = (Join-Path $versionRoot "policy\policy-provenance.json")
        tracker_domain_count = [int]$policy.outputs.tracker_domain_count
        tracking_parameter_count = [int]$policy.outputs.tracking_parameter_count
    }
    profile_root = $profileRoot
    runtime_evidence_path = (Join-Path $productRoot "runtime-state.txt")
    shortcuts = @($desktopShortcut, $startMenuShortcut)
    security_boundary = [ordered]@{
        default_browser_changed = $false
        system_security_products_modified = $false
        separate_profile = $true
        host_objects_allowed = $false
        web_messages_enabled = $false
        site_permissions_default = "deny"
        signed_upstream_engine_required = $true
    }
}
Write-Utf8JsonAtomic -Path $statePath -Value $state
$obsoleteWindows = Close-ObsoleteZsecBrowserWindows `
    -ApplicationContainer $appContainer `
    -CurrentLauncher $installedLauncher

if ($Open) {
    Start-Process -FilePath $desktopShortcut | Out-Null
}

[ordered]@{
    schema = "zsec.browser.desktop-preview-install-result.v2"
    product = $ProductName
    version = $ProductVersion
    installed = $true
    opened = [bool]$Open
    architecture = "windows-x64-webview2-shell"
    standalone_chromium_fork = $false
    signed_zsec_binary = $false
    launcher_path = $installedLauncher
    launcher_sha256 = $launcherHash
    profile_root = $profileRoot
    desktop_shortcut = $desktopShortcut
    start_menu_shortcut = $startMenuShortcut
    engine_path = $runtime.Path
    engine_version = $runtime.Version.ToString()
    tracker_domain_count = [int]$policy.outputs.tracker_domain_count
    obsolete_windows = $obsoleteWindows
    default_browser_changed = $false
    system_security_products_modified = $false
} | ConvertTo-Json -Depth 8
