#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "TalkToAI\ZSEC Antivirus")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$currentPath = Join-Path ([IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')) "current.json"
$reasons = New-Object Collections.Generic.List[string]
$installation = $null
if (-not (Test-Path -LiteralPath $currentPath -PathType Leaf)) {
    $reasons.Add("installation record is absent")
}
else {
    try {
        $installation = Get-Content -LiteralPath $currentPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($installation.schema -ne "zsec.antivirus.windows-desktop-installation.v1") {
            throw "unsupported installation schema"
        }
    }
    catch {
        $reasons.Add("installation record is invalid: $($_.Exception.Message)")
    }
}

$desktop = $null
$engine = $null
$desktopHash = $null
$engineHash = $null
$signature = "Unavailable"
$running = $false
if ($null -ne $installation) {
    $desktop = [string]$installation.desktop_executable
    $engine = [string]$installation.engine_executable
    foreach ($entry in @(
        @{ label = "desktop"; path = $desktop; expected = [string]$installation.desktop_sha256 },
        @{ label = "engine"; path = $engine; expected = [string]$installation.engine_sha256 }
    )) {
        if (-not (Test-Path -LiteralPath $entry.path -PathType Leaf)) {
            $reasons.Add("$($entry.label) executable is absent")
            continue
        }
        $item = Get-Item -LiteralPath $entry.path -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            $reasons.Add("$($entry.label) executable is a reparse point")
            continue
        }
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $entry.path).Hash.ToLowerInvariant()
        if ($actual -ne $entry.expected.ToLowerInvariant()) {
            $reasons.Add("$($entry.label) executable hash differs from the installation record")
        }
        if ($entry.label -eq "desktop") { $desktopHash = $actual } else { $engineHash = $actual }
    }
    if (Test-Path -LiteralPath $desktop -PathType Leaf) {
        $signature = [string](Get-AuthenticodeSignature -FilePath $desktop).Status
        $running = @(Get-CimInstance Win32_Process -Filter "Name = 'ZSEC Antivirus.exe'" -ErrorAction SilentlyContinue | Where-Object {
            $_.ExecutablePath -and ([IO.Path]::GetFullPath($_.ExecutablePath) -eq [IO.Path]::GetFullPath($desktop))
        }).Count -gt 0
    }
    if ($installation.security_products_modified -ne $false) {
        $reasons.Add("installation record does not preserve the security-products invariant")
    }
    if ($installation.existing_provider_must_remain_active -ne $true) {
        $reasons.Add("installation record does not require the existing provider")
    }
}

$result = [ordered]@{
    schema = "zsec.antivirus.windows-desktop-status.v1"
    installed = ($null -ne $installation)
    healthy_installation = (($null -ne $installation) -and $reasons.Count -eq 0)
    version = if ($null -ne $installation) { [string]$installation.version } else { $null }
    desktop_executable = $desktop
    desktop_sha256 = $desktopHash
    engine_executable = $engine
    engine_sha256 = $engineHash
    authenticode = $signature
    running = $running
    primary_antivirus = $false
    real_time_protection = $false
    pre_access_enforcement = $false
    existing_provider_must_remain_active = $true
    security_products_modified = $false
    reasons = @($reasons)
}
$result | ConvertTo-Json -Depth 8
if ($result.healthy_installation) { exit 0 } else { exit 2 }
