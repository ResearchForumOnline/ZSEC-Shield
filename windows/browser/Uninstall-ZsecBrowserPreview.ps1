#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [string]$ProductRoot = (Join-Path $env:LOCALAPPDATA "TalkToAI\ZSEC Browser"),
    [switch]$RemoveProfile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-NormalizedPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Assert-BelowProductRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$Root
    )
    $candidatePath = Get-NormalizedPath $Candidate
    $rootPath = Get-NormalizedPath $Root
    if (-not $candidatePath.StartsWith($rootPath + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing a destructive action outside the exact ZSEC Browser product root: $candidatePath"
    }
}

$root = Get-NormalizedPath $ProductRoot
$statePath = Join-Path $root "install-state.json"
if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    throw "Cannot validate ZSEC Browser ownership because the installation marker is absent."
}
$state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
if (
    $state.schema -ne "zsec.browser.desktop-preview-installation.v2" -or
    $state.product -ne "ZSEC Browser" -or
    $state.architecture -ne "windows-x64-webview2-shell"
) {
    throw "The installation marker does not belong to ZSEC Browser."
}

# Remove only ZSEC-owned per-user registration. Never write or remove Windows'
# protected UserChoice keys; Windows will retain or request a replacement default.
$registeredApplicationRemoved = $false
$clientRegistrationRemoved = $false
$progIdRemoved = $false
$registeredApps = "HKCU:\Software\RegisteredApplications"
if (Test-Path $registeredApps) {
    $registeredValue = (Get-ItemProperty -Path $registeredApps -Name "ZSEC Browser" -ErrorAction SilentlyContinue)."ZSEC Browser"
    if ($registeredValue -eq "Software\Clients\StartMenuInternet\ZSECBrowser\Capabilities" -and
        $PSCmdlet.ShouldProcess("ZSEC Browser default-app registration", "Remove owned registration")) {
        Remove-ItemProperty -Path $registeredApps -Name "ZSEC Browser" -Force
        $registeredApplicationRemoved = $true
    }
}
$clientKey = "HKCU:\Software\Clients\StartMenuInternet\ZSECBrowser"
if (Test-Path $clientKey) {
    $registeredCommand = $null
    try { $registeredCommand = (Get-Item -Path (Join-Path $clientKey "shell\open\command") -ErrorAction Stop).GetValue("") } catch { }
    if ($registeredCommand -eq ('"' + [string]$state.launcher.path + '"') -and
        $PSCmdlet.ShouldProcess($clientKey, "Remove owned ZSEC Browser client registration")) {
        Remove-Item -Path $clientKey -Recurse -Force
        $clientRegistrationRemoved = $true
    }
}
$progIdKey = "HKCU:\Software\Classes\ZSECBrowserHTML"
if (Test-Path $progIdKey) {
    $registeredCommand = $null
    try { $registeredCommand = (Get-Item -Path (Join-Path $progIdKey "shell\open\command") -ErrorAction Stop).GetValue("") } catch { }
    $expectedCommand = '"' + [string]$state.launcher.path + '" "%1"'
    if ($registeredCommand -eq $expectedCommand -and
        $PSCmdlet.ShouldProcess($progIdKey, "Remove owned ZSEC Browser ProgID")) {
        Remove-Item -Path $progIdKey -Recurse -Force
        $progIdRemoved = $true
    }
}

foreach ($shortcutPath in @($state.shortcuts)) {
    if (Test-Path -LiteralPath ([string]$shortcutPath) -PathType Leaf) {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut([string]$shortcutPath)
        if (
            (Get-NormalizedPath ([string]$shortcut.TargetPath)) -ne
            (Get-NormalizedPath ([string]$state.launcher.path))
        ) {
            throw "Refusing to remove a shortcut that no longer targets the owned launcher: $shortcutPath"
        }
        if ($PSCmdlet.ShouldProcess([string]$shortcutPath, "Remove owned ZSEC Browser shortcut")) {
            Remove-Item -LiteralPath ([string]$shortcutPath) -Force
        }
    }
}

$versionRoot = Split-Path -Parent ([string]$state.launcher.path)
Assert-BelowProductRoot -Candidate $versionRoot -Root $root
if (Test-Path -LiteralPath $versionRoot -PathType Container) {
    if ($PSCmdlet.ShouldProcess($versionRoot, "Remove versioned ZSEC Browser application files")) {
        Remove-Item -LiteralPath $versionRoot -Recurse -Force
    }
}

if ($RemoveProfile) {
    $profileRoot = [string]$state.profile_root
    Assert-BelowProductRoot -Candidate $profileRoot -Root $root
    if (Test-Path -LiteralPath $profileRoot -PathType Container) {
        if ($PSCmdlet.ShouldProcess($profileRoot, "Permanently remove the ZSEC Browser profile")) {
            Remove-Item -LiteralPath $profileRoot -Recurse -Force
        }
    }
}

if ($PSCmdlet.ShouldProcess($statePath, "Remove ZSEC Browser installation marker")) {
    Remove-Item -LiteralPath $statePath -Force
}

[ordered]@{
    schema = "zsec.browser.desktop-preview-uninstall-result.v1"
    product = "ZSEC Browser"
    application_removed = $true
    shortcuts_removed = $true
    default_browser_registration_removed = ($registeredApplicationRemoved -and $clientRegistrationRemoved -and $progIdRemoved)
    registered_application_removed = $registeredApplicationRemoved
    client_registration_removed = $clientRegistrationRemoved
    prog_id_removed = $progIdRemoved
    user_choice_modified = $false
    profile_removed = [bool]$RemoveProfile
    profile_recoverable = (-not [bool]$RemoveProfile)
} | ConvertTo-Json -Depth 4
