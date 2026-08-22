#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ProductRoot = (Join-Path $env:LOCALAPPDATA "TalkToAI\ZSEC Browser"),
    [int]$TimeoutSeconds = 20,
    [string]$ReportPath = "",
    [switch]$LeaveClosed
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-KeyValueFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $values = @{}
    $stream = New-Object IO.FileStream(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    )
    $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::UTF8, $true)
    try {
        $lines = $reader.ReadToEnd() -split "`r?`n"
    }
    finally {
        $reader.Dispose()
        $stream.Dispose()
    }
    foreach ($line in $lines) {
        $separator = $line.IndexOf('=')
        if ($separator -gt 0) {
            $values[$line.Substring(0, $separator)] = $line.Substring($separator + 1)
        }
    }
    return $values
}

function Close-ExactBrowser {
    param([Parameter(Mandatory = $true)][string]$ExpectedPath)
    $processes = Get-Process -Name "ZSEC Browser" -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -eq $ExpectedPath }
    foreach ($process in @($processes)) {
        [void]$process.CloseMainWindow()
    }
    if ($processes) {
        $processes | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
    }
    $remaining = Get-Process -Name "ZSEC Browser" -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -eq $ExpectedPath }
    if ($remaining) {
        throw "The exact ZSEC Browser test process did not close cleanly."
    }
}

function Invoke-BrowserEvidenceTest {
    param(
        [Parameter(Mandatory = $true)][string]$ApplicationPath,
        [Parameter(Mandatory = $true)][string]$EvidencePath,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][scriptblock]$Accept
    )
    $startedAt = [DateTimeOffset]::UtcNow
    Start-Process -FilePath $ApplicationPath -ArgumentList $Destination | Out-Null
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 250
        if (Test-Path -LiteralPath $EvidencePath -PathType Leaf) {
            $evidence = Get-KeyValueFile -Path $EvidencePath
            $evidenceTime = [DateTimeOffset]::MinValue
            if ([DateTimeOffset]::TryParse($evidence['checked_at'], [ref]$evidenceTime)) {
                if ($evidenceTime -ge $startedAt -and (& $Accept $evidence)) {
                    return $evidence
                }
            }
        }
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "Timed out waiting for ZSEC Browser runtime evidence for $Destination"
}

$root = [IO.Path]::GetFullPath($ProductRoot)
$statePath = Join-Path $root "install-state.json"
if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    throw "The ZSEC Browser installation marker is absent."
}
$state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
if (
    $state.schema -ne "zsec.browser.desktop-preview-installation.v2" -or
    $state.product -ne "ZSEC Browser Desktop Preview"
) {
    throw "The installed product identity is invalid."
}
$applicationPath = [IO.Path]::GetFullPath([string]$state.launcher.path)
$evidencePath = [IO.Path]::GetFullPath([string]$state.runtime_evidence_path)
$expectedHash = ([string]$state.launcher.sha256).ToLowerInvariant()
if (
    -not (Test-Path -LiteralPath $applicationPath -PathType Leaf) -or
    (Get-FileHash -Algorithm SHA256 -LiteralPath $applicationPath).Hash.ToLowerInvariant() -ne $expectedHash
) {
    throw "The installed ZSEC Browser executable failed its identity check."
}

Close-ExactBrowser -ExpectedPath $applicationPath
$trackingEvidence = Invoke-BrowserEvidenceTest `
    -ApplicationPath $applicationPath `
    -EvidencePath $evidencePath `
    -Destination "https://talktoai.org/zero-browser/?utm_source=zsec_runtime_acceptance" `
    -Accept { param($evidence) [int]$evidence['tracking_cleanup_count'] -ge 1 -and $evidence['last_navigation_https'] -eq 'true' }
Close-ExactBrowser -ExpectedPath $applicationPath

$blockingEvidence = Invoke-BrowserEvidenceTest `
    -ApplicationPath $applicationPath `
    -EvidencePath $evidencePath `
    -Destination "https://doubleclick.net/" `
    -Accept { param($evidence) [int]$evidence['blocked_request_count'] -ge 1 }
Close-ExactBrowser -ExpectedPath $applicationPath

if (-not $LeaveClosed) {
    Start-Process -FilePath ([string]$state.shortcuts[0]) | Out-Null
}

$result = [ordered]@{
    schema = "zsec.browser.desktop-preview-runtime-acceptance.v1"
    product = "ZSEC Browser Desktop Preview"
    version = [string]$state.version
    passed = $true
    tested_at = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    executable_sha256_verified = $true
    tests = [ordered]@{
        tracking_parameter_cleanup = [ordered]@{
            passed = $true
            count = [int]$trackingEvidence['tracking_cleanup_count']
            final_navigation_https = $trackingEvidence['last_navigation_https'] -eq 'true'
        }
        reviewed_tracker_domain_block = [ordered]@{
            passed = $true
            blocked_request_count = [int]$blockingEvidence['blocked_request_count']
            test_domain = "doubleclick.net"
        }
    }
    browser_reopened = (-not [bool]$LeaveClosed)
}
if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
    $normalizedReportPath = [IO.Path]::GetFullPath($ReportPath)
    New-Item -ItemType Directory -Path (Split-Path -Parent $normalizedReportPath) -Force | Out-Null
    [IO.File]::WriteAllText(
        $normalizedReportPath,
        (($result | ConvertTo-Json -Depth 8) + [Environment]::NewLine),
        (New-Object Text.UTF8Encoding($false))
    )
}
$result | ConvertTo-Json -Depth 8
