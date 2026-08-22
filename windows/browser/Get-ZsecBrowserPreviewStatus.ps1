#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ProductRoot = (Join-Path $env:LOCALAPPDATA "TalkToAI\ZSEC Browser")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ShortcutState {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedTarget
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [ordered]@{ path = $Path; present = $false; target_verified = $false }
    }
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($Path)
    return [ordered]@{
        path = $Path
        present = $true
        target = [string]$shortcut.TargetPath
        target_verified = (
            [System.IO.Path]::GetFullPath([string]$shortcut.TargetPath) -eq
            [System.IO.Path]::GetFullPath($ExpectedTarget)
        )
    }
}

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
            $key = $line.Substring(0, $separator)
            $value = $line.Substring($separator + 1)
            $values[$key] = $value
        }
    }
    return $values
}

$checkedAt = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
$root = [System.IO.Path]::GetFullPath($ProductRoot)
$statePath = Join-Path $root "install-state.json"
if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    [ordered]@{
        schema = "zsec.browser.desktop-preview-status.v2"
        product = "ZSEC Browser"
        checked_at = $checkedAt
        installed = $false
        healthy = $false
        reasons = @("installation marker is absent")
    } | ConvertTo-Json -Depth 6
    exit 2
}

$state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
$reasons = @()
if (
    $state.schema -ne "zsec.browser.desktop-preview-installation.v2" -or
    $state.product -ne "ZSEC Browser" -or
    $state.architecture -ne "windows-x64-webview2-shell" -or
    $state.standalone_chromium_fork -ne $false -or
    $state.signed_zsec_binary -ne $false
) {
    $reasons += "installation identity or architecture boundary is invalid"
}

$fileStates = @()
$filesVerified = $true
$versionRoot = Split-Path -Parent ([string]$state.launcher.path)
foreach ($entry in @($state.app_files)) {
    $path = Join-Path $versionRoot ([string]$entry.path).Replace('/', '\')
    $verified = $false
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
        $verified = $hash -eq ([string]$entry.sha256).ToLowerInvariant()
    }
    if (-not $verified) {
        $filesVerified = $false
        $reasons += "application file is absent or changed: $($entry.path)"
    }
    $fileStates += [ordered]@{ path = [string]$entry.path; hash_verified = $verified }
}

$engineVerified = $false
$engineVersion = $null
if (Test-Path -LiteralPath ([string]$state.engine.path) -PathType Leaf) {
    $signature = Get-AuthenticodeSignature -LiteralPath ([string]$state.engine.path)
    $engineVersion = (Get-Item -LiteralPath ([string]$state.engine.path)).VersionInfo.FileVersion
    $engineVerified = (
        $signature.Status -eq [System.Management.Automation.SignatureStatus]::Valid -and
        $null -ne $signature.SignerCertificate -and
        $signature.SignerCertificate.Subject -match 'Microsoft Corporation' -and
        ([Version]$engineVersion).Major -ge 120
    )
}
if (-not $engineVerified) {
    $reasons += "Microsoft-signed Evergreen WebView2 Chromium runtime is absent or untrusted"
}

$policyVerified = $false
if (Test-Path -LiteralPath ([string]$state.policy.provenance_path) -PathType Leaf) {
    $policy = Get-Content -LiteralPath ([string]$state.policy.provenance_path) -Raw -Encoding UTF8 | ConvertFrom-Json
    $policyVerified = (
        $policy.schema -eq "zsec.browser.desktop-policy.v1" -and
        $policy.source_extension.name -eq "ZSEC Browser Shields" -and
        [string]$policy.source_extension.version -eq [string]$state.policy.source_version -and
        [int]$policy.outputs.tracker_domain_count -eq [int]$state.policy.tracker_domain_count -and
        [int]$policy.outputs.tracking_parameter_count -eq [int]$state.policy.tracking_parameter_count
    )
}
if (-not $policyVerified) {
    $reasons += "compiled ZSEC Browser policy is absent or invalid"
}

$shortcutStates = @()
foreach ($shortcutPath in @($state.shortcuts)) {
    $shortcutState = Get-ShortcutState -Path ([string]$shortcutPath) -ExpectedTarget ([string]$state.launcher.path)
    $shortcutStates += $shortcutState
    if (-not $shortcutState.target_verified) {
        $reasons += "shortcut is absent or points outside the installed application: $shortcutPath"
    }
}

$runtimeEvidence = [ordered]@{
    present = $false
    valid = $false
}
if (Test-Path -LiteralPath ([string]$state.runtime_evidence_path) -PathType Leaf) {
    $evidence = Get-KeyValueFile -Path ([string]$state.runtime_evidence_path)
    $evidenceValid = (
        $evidence['schema'] -eq 'zsec.browser.runtime.v1' -and
        $evidence['product'] -eq 'ZSEC Browser' -and
        $evidence['version'] -eq [string]$state.version -and
        $evidence['profile_root'] -eq [string]$state.profile_root -and
        $evidence['host_objects_allowed'] -eq 'false' -and
        $evidence['web_messages_enabled'] -eq 'false' -and
        $evidence['password_autosave_enabled'] -eq 'false' -and
        $evidence['general_autofill_enabled'] -eq 'false' -and
        $evidence['permissions_default'] -eq 'deny' -and
        $evidence['native_request_filter_source_kinds'] -eq 'all' -and
        $evidence['native_tracker_policy_self_test_status'] -eq 'passed' -and
        [int]$evidence['tracker_domain_count'] -eq [int]$state.policy.tracker_domain_count
    )
    $runtimeEvidence = [ordered]@{
        present = $true
        valid = $evidenceValid
        engine = $evidence['engine']
        engine_version = $evidence['engine_version']
        profile_root = $evidence['profile_root']
        blocked_request_count = $evidence['blocked_request_count']
        native_tracker_block_count = $evidence['native_tracker_block_count']
        native_subresource_runtime_probe_status = $evidence['native_subresource_runtime_probe_status']
        youtube_protection_hook_status = $evidence['youtube_protection_hook_status']
        youtube_ad_intervention_count = $evidence['youtube_ad_intervention_count']
        tracking_cleanup_count = $evidence['tracking_cleanup_count']
        last_navigation_https = $evidence['last_navigation_https']
        elevated = $evidence['elevated']
        process_id = $evidence['process_id']
        checked_at = $evidence['checked_at']
    }
    if (-not $evidenceValid) {
        $reasons += "runtime initialization evidence is invalid"
    }
}
else {
    $reasons += "runtime initialization evidence is absent; open ZSEC Browser once"
}

$running = @()
$runtimeProcesses = @()
$prohibitedFlagsAbsent = $true
try {
    $expectedExecutable = [System.IO.Path]::GetFullPath([string]$state.launcher.path)
    $processes = Get-CimInstance Win32_Process -Filter "Name = 'ZSEC Browser.exe'" -ErrorAction Stop
    foreach ($process in @($processes)) {
        $processPath = [string]$process.ExecutablePath
        if (
            -not [string]::IsNullOrWhiteSpace($processPath) -and
            [System.IO.Path]::GetFullPath($processPath) -eq $expectedExecutable
        ) {
            $running += [ordered]@{
                process_id = [int]$process.ProcessId
                executable_path_verified = $true
            }
        }
    }
    $profilePattern = '*' + ([string]$state.profile_root).Replace('[', '[[]') + '*'
    $forbiddenFlags = @(
        '--no-sandbox',
        '--disable-web-security',
        '--ignore-certificate-errors',
        '--allow-running-insecure-content',
        '--disable-site-isolation-trials',
        '--remote-debugging-port'
    )
    foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name = 'msedgewebview2.exe'" -ErrorAction Stop)) {
        $commandLine = [string]$process.CommandLine
        if ($commandLine -notlike $profilePattern) {
            continue
        }
        $matchedFlags = @($forbiddenFlags | Where-Object { $commandLine -like "*$_*" })
        if ($matchedFlags.Count -gt 0) {
            $prohibitedFlagsAbsent = $false
            $reasons += "a ZSEC WebView2 process contains a prohibited security flag"
        }
        $processType = 'browser'
        if ($commandLine -match '--type=([^\s"]+)') {
            $processType = $Matches[1]
        }
        $runtimeProcesses += [ordered]@{
            process_id = [int]$process.ProcessId
            parent_process_id = [int]$process.ParentProcessId
            process_type = $processType
            prohibited_flags_absent = $matchedFlags.Count -eq 0
        }
    }
}
catch {
    $reasons += "could not inspect the ZSEC Browser process boundary"
}

$healthy = $reasons.Count -eq 0
[ordered]@{
    schema = "zsec.browser.desktop-preview-status.v2"
    product = "ZSEC Browser"
    checked_at = $checkedAt
    installed = $true
    healthy = $healthy
    architecture = "windows-x64-webview2-shell"
    standalone_chromium_fork = $false
    signed_zsec_binary = $false
    reasons = $reasons
    application = [ordered]@{
        path = [string]$state.launcher.path
        version = [string]$state.version
        all_hashes_verified = $filesVerified
        files = $fileStates
    }
    engine = [ordered]@{
        product = "Microsoft Edge WebView2 Runtime"
        distribution = "Evergreen"
        path = [string]$state.engine.path
        version = $engineVersion
        signature_verified = $engineVerified
    }
    policy = [ordered]@{
        source = [string]$state.policy.source_name
        source_version = [string]$state.policy.source_version
        tracker_domain_count = [int]$state.policy.tracker_domain_count
        tracking_parameter_count = [int]$state.policy.tracking_parameter_count
        identity_verified = $policyVerified
    }
    runtime_evidence = $runtimeEvidence
    shortcuts = $shortcutStates
    running = $running
    running_instance_verified = $running.Count -gt 0
    runtime_process_boundary = [ordered]@{
        process_count = $runtimeProcesses.Count
        processes = $runtimeProcesses
        prohibited_security_flags_absent = $prohibitedFlagsAbsent
        sandbox_attestation_complete = $false
    }
    default_browser_changed = $false
    system_security_products_modified = $false
} | ConvertTo-Json -Depth 10
exit $(if ($healthy) { 0 } else { 2 })
