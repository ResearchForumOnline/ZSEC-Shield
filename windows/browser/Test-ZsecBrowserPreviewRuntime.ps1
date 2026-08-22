#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ProductRoot = (Join-Path $env:LOCALAPPDATA "TalkToAI\ZSEC Browser"),
    [int]$TimeoutSeconds = 30,
    [string]$ReportPath = "",
    [switch]$LeaveClosed
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-KeyValueFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $values = @{}
    $stream = $null
    $openDeadline = [DateTimeOffset]::UtcNow.AddSeconds(2)
    do {
        try {
            $stream = New-Object IO.FileStream(
                $Path,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
            )
            break
        }
        catch [IO.IOException] {
            if ([DateTimeOffset]::UtcNow -ge $openDeadline) {
                throw
            }
            Start-Sleep -Milliseconds 50
        }
    } while ($null -eq $stream)
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
        [string[]]$AdditionalArguments = @(),
        [Parameter(Mandatory = $true)][scriptblock]$Accept
    )
    $startedAt = [DateTimeOffset]::UtcNow
    $arguments = @($Destination) + $AdditionalArguments
    Start-Process -FilePath $ApplicationPath -ArgumentList $arguments | Out-Null
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
    $state.product -ne "ZSEC Browser"
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

$dnrEvidence = Invoke-BrowserEvidenceTest `
    -ApplicationPath $applicationPath `
    -EvidencePath $evidencePath `
    -Destination "https://talktoai.org/zero-browser/runtime-check/index.html" `
    -Accept {
        param($evidence)
        $evidence['dnr_runtime_test_status'] -eq 'passed' -and
        $evidence['browser_shields_extension'] -eq 'enabled' -and
        $evidence['browser_shields_expected_id'] -eq 'ddjbjhnlhapggenanpmcidieimaomiif' -and
        $evidence['browser_shields_installed_id'] -eq 'ddjbjhnlhapggenanpmcidieimaomiif' -and
        $evidence['tracking_prevention_effective'] -eq 'balanced'
    }
Close-ExactBrowser -ExpectedPath $applicationPath

$nativePolicyEvidence = Invoke-BrowserEvidenceTest `
    -ApplicationPath $applicationPath `
    -EvidencePath $evidencePath `
    -Destination "https://newtab.zsec.local/native-request-probe.html" `
    -Accept {
        param($evidence)
        $evidence['native_request_filter_source_kinds'] -eq 'all' -and
        $evidence['native_reviewed_tracker_blocking'] -eq 'enabled' -and
        $evidence['native_tracker_policy_self_test_status'] -eq 'passed' -and
        $evidence['native_subresource_runtime_probe_status'] -eq 'passed' -and
        [int]$evidence['blocked_request_count'] -ge 1
    }
Close-ExactBrowser -ExpectedPath $applicationPath

$youtubeEvidence = Invoke-BrowserEvidenceTest `
    -ApplicationPath $applicationPath `
    -EvidencePath $evidencePath `
    -Destination "https://www.youtube.com/" `
    -Accept {
        param($evidence)
        $evidence['youtube_native_protection_enabled'] -eq 'true' -and
        $evidence['youtube_protection_hook_status'] -eq 'loaded' -and
        ([string]$evidence['youtube_protection_script_sha256']) -match '^[0-9a-f]{64}$' -and
        [int]$evidence['youtube_ad_intervention_count'] -ge 0
    }
Close-ExactBrowser -ExpectedPath $applicationPath

$newTabEvidence = Invoke-BrowserEvidenceTest `
    -ApplicationPath $applicationPath `
    -EvidencePath $evidencePath `
    -Destination "https://talktoai.org/zero-browser/" `
    -AdditionalArguments @("--zsec-runtime-test=new-tab") `
    -Accept {
        param($evidence)
        [int]$evidence['tab_count'] -eq 2 -and
        [int]$evidence['ready_tab_count'] -eq 2 -and
        [int]$evidence['tab_creation_failure_count'] -eq 0 -and
        $evidence['last_tab_action'] -eq 'new_tab_ready' -and
        $evidence['last_new_tab_command_source'] -eq 'runtime_acceptance'
    }
Close-ExactBrowser -ExpectedPath $applicationPath

if (-not $LeaveClosed) {
    Start-Process -FilePath ([string]$state.shortcuts[0]) | Out-Null
}

$result = [ordered]@{
    schema = "zsec.browser.desktop-preview-runtime-acceptance.v2"
    product = "ZSEC Browser"
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
        browser_shields_dnr = [ordered]@{
            passed = $true
            fixture = "https://talktoai.org/zero-browser/runtime-check/index.html"
            expected_extension_id = [string]$dnrEvidence['browser_shields_expected_id']
            installed_extension_id = [string]$dnrEvidence['browser_shields_installed_id']
            manifest_sha256 = [string]$dnrEvidence['browser_shields_manifest_sha256']
            dnr_runtime_test_status = [string]$dnrEvidence['dnr_runtime_test_status']
            tracking_prevention_effective = [string]$dnrEvidence['tracking_prevention_effective']
        }
        native_all_subresource_policy = [ordered]@{
            passed = $true
            source_kinds = [string]$nativePolicyEvidence['native_request_filter_source_kinds']
            tracker_policy_self_test_status = [string]$nativePolicyEvidence['native_tracker_policy_self_test_status']
            subresource_runtime_probe_status = [string]$nativePolicyEvidence['native_subresource_runtime_probe_status']
            reviewed_tracker_blocks = [int]$nativePolicyEvidence['native_tracker_block_count']
        }
        youtube_native_protection = [ordered]@{
            passed = $true
            exact_site = "https://www.youtube.com/"
            hook_status = [string]$youtubeEvidence['youtube_protection_hook_status']
            script_sha256 = [string]$youtubeEvidence['youtube_protection_script_sha256']
            ad_interventions_observed = [int]$youtubeEvidence['youtube_ad_intervention_count']
            no_ad_served_is_not_a_failure = $true
        }
        new_tab = [ordered]@{
            passed = $true
            tab_count = [int]$newTabEvidence['tab_count']
            ready_tab_count = [int]$newTabEvidence['ready_tab_count']
            tab_creation_failure_count = [int]$newTabEvidence['tab_creation_failure_count']
            last_tab_action = [string]$newTabEvidence['last_tab_action']
            command_source = [string]$newTabEvidence['last_new_tab_command_source']
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
