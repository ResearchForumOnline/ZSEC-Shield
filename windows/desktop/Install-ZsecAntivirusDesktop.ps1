#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$PackageRoot = $PSScriptRoot,
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "TalkToAI\ZSEC Antivirus"),
    [switch]$Open,
    [switch]$PlanOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-NormalizedPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains('"')) {
        throw "A required path is empty or contains an invalid quote character."
    }
    return [IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Test-IsBelow {
    param([string]$Candidate, [string]$Parent)
    $child = Get-NormalizedPath $Candidate
    $root = Get-NormalizedPath $Parent
    return $child.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Assert-RegularDirectory {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Expected a regular non-reparse directory: $Path"
    }
}

function Assert-RegularFile {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Expected a regular non-reparse file: $Path"
    }
}

function Remove-RegularFileIfPresent {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        Assert-RegularFile $Path
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    }
}

function Write-JsonAtomic {
    param([string]$Path, $Value)
    $temporary = "$Path.tmp-$([Guid]::NewGuid().ToString('N'))"
    $encoding = New-Object Text.UTF8Encoding($false)
    try {
        [IO.File]::WriteAllText(
            $temporary,
            (($Value | ConvertTo-Json -Depth 8) + [Environment]::NewLine),
            $encoding
        )
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Test-ManifestFiles {
    param([string]$Root, $Manifest)
    Assert-RegularDirectory $Root
    $seen = @{}
    foreach ($record in @($Manifest.files)) {
        if ($record.type -ne "file" -or [string]::IsNullOrWhiteSpace([string]$record.path)) {
            throw "The desktop manifest contains an unsupported record."
        }
        $relative = ([string]$record.path).Replace('/', '\')
        if ([IO.Path]::IsPathRooted($relative) -or $relative.Split('\') -contains '..') {
            throw "The desktop manifest contains an unsafe path: $relative"
        }
        $candidate = Get-NormalizedPath (Join-Path $Root $relative)
        if (-not (Test-IsBelow -Candidate $candidate -Parent $Root)) {
            throw "The desktop manifest path escapes the package root: $relative"
        }
        $key = $candidate.ToLowerInvariant()
        if ($seen.ContainsKey($key)) {
            throw "The desktop manifest contains a duplicate path: $relative"
        }
        $seen[$key] = $true
        Assert-RegularFile $candidate
        $file = Get-Item -LiteralPath $candidate
        if ([int64]$file.Length -ne [int64]$record.size) {
            throw "Size verification failed for $relative"
        }
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $candidate).Hash.ToLowerInvariant()
        if ($hash -ne ([string]$record.sha256).ToLowerInvariant()) {
            throw "SHA-256 verification failed for $relative"
        }
    }
}

$package = Get-NormalizedPath $PackageRoot
$productRoot = Get-NormalizedPath $InstallRoot
Assert-RegularDirectory $package
$manifestPath = Join-Path $package "DESKTOP-MANIFEST.json"
Assert-RegularFile $manifestPath
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (
    $manifest.schema -ne "zsec.antivirus.windows-desktop-distribution.v1" -or
    $manifest.product -ne "ZSEC Antivirus" -or
    [string]::IsNullOrWhiteSpace([string]$manifest.version)
) {
    throw "The desktop package manifest is not a supported ZSEC Antivirus distribution."
}
if (
    $manifest.runtime_policy.primary_antivirus -ne $false -or
    $manifest.runtime_policy.pre_access_enforcement -ne $false -or
    $manifest.runtime_policy.existing_provider_must_remain_active -ne $true -or
    $manifest.runtime_policy.automatic_provider_removal -ne $false
) {
    throw "The desktop package violates the coexistence policy."
}
Test-ManifestFiles -Root $package -Manifest $manifest

$versionRoot = Get-NormalizedPath (Join-Path (Join-Path $productRoot "App") ([string]$manifest.version))
$desktopExe = Join-Path $versionRoot "App\ZSEC Antivirus.exe"
$engineExe = Join-Path $versionRoot "Engine\zsec-shield.exe"
$currentPath = Join-Path $productRoot "current.json"
$desktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "ZSEC Antivirus.lnk"
$startMenuDirectory = Join-Path ([Environment]::GetFolderPath("Programs")) "ZSEC"
$startMenuShortcut = Join-Path $startMenuDirectory "ZSEC Antivirus.lnk"
$plan = [ordered]@{
    schema = "zsec.antivirus.windows-desktop-install-plan.v1"
    version = [string]$manifest.version
    source = $package
    destination = $versionRoot
    desktop_executable = $desktopExe
    engine_executable = $engineExe
    desktop_shortcut = $desktopShortcut
    start_menu_shortcut = $startMenuShortcut
    existing_provider_must_remain_active = $true
    security_products_modified = $false
    plan_only = [bool]$PlanOnly
}
if ($PlanOnly) {
    $plan | ConvertTo-Json -Depth 8
    return
}
if (Test-Path -LiteralPath $versionRoot) {
    throw "This version is already installed; the installer never overwrites it: $versionRoot"
}

$createdVersion = $false
$rollbackRoot = $null
$currentBackup = $null
$desktopShortcutBackup = $null
$startMenuShortcutBackup = $null
try {
    if (Test-Path -LiteralPath $productRoot) {
        Assert-RegularDirectory $productRoot
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $versionRoot) | Out-Null
    Copy-Item -LiteralPath $package -Destination $versionRoot -Recurse -ErrorAction Stop
    $createdVersion = $true
    Assert-RegularDirectory $versionRoot
    Test-ManifestFiles -Root $versionRoot -Manifest $manifest
    Assert-RegularFile $desktopExe
    Assert-RegularFile $engineExe

    New-Item -ItemType Directory -Force -Path $productRoot | Out-Null
    $rollbackRoot = Get-NormalizedPath (Join-Path $productRoot (".install-transaction-" + [Guid]::NewGuid().ToString("N")))
    if (-not (Test-IsBelow -Candidate $rollbackRoot -Parent $productRoot)) {
        throw "The installer transaction directory escaped the owned product root."
    }
    New-Item -ItemType Directory -Path $rollbackRoot -ErrorAction Stop | Out-Null
    Assert-RegularDirectory $rollbackRoot
    $currentBackup = Join-Path $rollbackRoot "current.json"
    $desktopShortcutBackup = Join-Path $rollbackRoot "desktop-shortcut.lnk"
    $startMenuShortcutBackup = Join-Path $rollbackRoot "start-menu-shortcut.lnk"
    if (Test-Path -LiteralPath $currentPath) {
        Assert-RegularFile $currentPath
        Copy-Item -LiteralPath $currentPath -Destination $currentBackup -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $desktopShortcut) {
        Assert-RegularFile $desktopShortcut
        Copy-Item -LiteralPath $desktopShortcut -Destination $desktopShortcutBackup -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $startMenuShortcut) {
        Assert-RegularFile $startMenuShortcut
        Copy-Item -LiteralPath $startMenuShortcut -Destination $startMenuShortcutBackup -ErrorAction Stop
    }

    $installed = [ordered]@{
        schema = "zsec.antivirus.windows-desktop-installation.v1"
        product = "ZSEC Antivirus"
        version = [string]$manifest.version
        installed_at = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        version_root = $versionRoot
        desktop_executable = $desktopExe
        desktop_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $desktopExe).Hash.ToLowerInvariant()
        engine_executable = $engineExe
        engine_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $engineExe).Hash.ToLowerInvariant()
        manifest_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $versionRoot "DESKTOP-MANIFEST.json")).Hash.ToLowerInvariant()
        security_products_modified = $false
        existing_provider_must_remain_active = $true
    }

    New-Item -ItemType Directory -Force -Path $startMenuDirectory | Out-Null
    Assert-RegularDirectory $startMenuDirectory
    $shell = New-Object -ComObject WScript.Shell
    $pendingShortcuts = @(
        @{ Temporary = (Join-Path $rollbackRoot "new-desktop-shortcut.lnk"); Destination = $desktopShortcut },
        @{ Temporary = (Join-Path $rollbackRoot "new-start-menu-shortcut.lnk"); Destination = $startMenuShortcut }
    )
    foreach ($record in $pendingShortcuts) {
        $shortcut = $shell.CreateShortcut([string]$record.Temporary)
        $shortcut.TargetPath = $desktopExe
        $shortcut.WorkingDirectory = Split-Path -Parent $desktopExe
        $shortcut.Description = "ZSEC Antivirus Community desktop"
        $shortcut.IconLocation = "$desktopExe,0"
        $shortcut.Save()
        Assert-RegularFile ([string]$record.Temporary)
    }

    Write-JsonAtomic -Path $currentPath -Value $installed
    foreach ($record in $pendingShortcuts) {
        $destination = [string]$record.Destination
        Remove-RegularFileIfPresent $destination
        Move-Item -LiteralPath ([string]$record.Temporary) -Destination $destination -ErrorAction Stop
        Assert-RegularFile $destination
    }

    $result = [ordered]@{
        schema = "zsec.antivirus.windows-desktop-install-result.v1"
        installed = $true
        version = [string]$manifest.version
        destination = $versionRoot
        desktop_executable = $desktopExe
        desktop_sha256 = $installed.desktop_sha256
        engine_executable = $engineExe
        engine_sha256 = $installed.engine_sha256
        shortcuts = @($desktopShortcut, $startMenuShortcut)
        signed = ((Get-AuthenticodeSignature -FilePath $desktopExe).Status -eq "Valid")
        security_products_modified = $false
        existing_provider_must_remain_active = $true
    }
    $result | ConvertTo-Json -Depth 8
    if ($Open) {
        Start-Process -FilePath $desktopExe -WorkingDirectory (Split-Path -Parent $desktopExe)
    }
    if ($null -ne $rollbackRoot -and (Test-Path -LiteralPath $rollbackRoot)) {
        Assert-RegularDirectory $rollbackRoot
        Remove-Item -LiteralPath $rollbackRoot -Recurse -Force -ErrorAction Stop
    }
}
catch {
    $installationError = $_
    try {
        if ($null -ne $rollbackRoot -and (Test-Path -LiteralPath $rollbackRoot)) {
            Assert-RegularDirectory $rollbackRoot
            if ($null -ne $currentBackup -and (Test-Path -LiteralPath $currentBackup -PathType Leaf)) {
                Remove-RegularFileIfPresent $currentPath
                Copy-Item -LiteralPath $currentBackup -Destination $currentPath -ErrorAction Stop
            }
            else {
                Remove-RegularFileIfPresent $currentPath
            }
            foreach ($restore in @(
                @{ Backup = $desktopShortcutBackup; Destination = $desktopShortcut },
                @{ Backup = $startMenuShortcutBackup; Destination = $startMenuShortcut }
            )) {
                $backup = [string]$restore.Backup
                $destination = [string]$restore.Destination
                Remove-RegularFileIfPresent $destination
                if (-not [string]::IsNullOrWhiteSpace($backup) -and (Test-Path -LiteralPath $backup -PathType Leaf)) {
                    Copy-Item -LiteralPath $backup -Destination $destination -ErrorAction Stop
                }
            }
            Remove-Item -LiteralPath $rollbackRoot -Recurse -Force -ErrorAction Stop
        }
    }
    catch {
        throw "ZSEC Antivirus installation failed and activation rollback also failed: $($installationError.Exception.Message); rollback: $($_.Exception.Message)"
    }
    if ($createdVersion -and (Test-Path -LiteralPath $versionRoot) -and (Test-IsBelow $versionRoot $productRoot)) {
        Remove-Item -LiteralPath $versionRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    throw $installationError
}
