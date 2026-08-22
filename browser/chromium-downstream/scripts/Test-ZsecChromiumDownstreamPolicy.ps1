[CmdletBinding()]
param(
    [string]$LockPath,
    [string]$SeriesPath,
    [string]$PatchRoot,
    [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$packageRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($LockPath)) {
    $LockPath = Join-Path $packageRoot 'upstream.lock.json'
}
if ([string]::IsNullOrWhiteSpace($SeriesPath)) {
    $SeriesPath = Join-Path $packageRoot 'patches\series.json'
}
if ([string]::IsNullOrWhiteSpace($PatchRoot)) {
    $PatchRoot = Join-Path $packageRoot 'patches'
}

Import-Module (Join-Path $PSScriptRoot 'ZsecChromiumDownstream.psm1') -Force
$result = Test-ZsecChromiumDownstreamPolicy -LockPath $LockPath -SeriesPath $SeriesPath -PatchRoot $PatchRoot
if ($Json) {
    $result | ConvertTo-Json -Depth 32
}
else {
    $state = if ([bool]$result.passed) { 'PASS' } else { 'FAIL' }
    "ZSEC Chromium downstream source policy: $state"
    foreach ($check in @($result.checks)) {
        $mark = if ([bool]$check.passed) { 'PASS' } else { 'FAIL' }
        "[$mark] $($check.id): actual=$($check.actual); expected=$($check.expected)"
    }
    'This validates a source lock and patch inventory only; it is not a Chromium build or maintained-fork attestation.'
}
exit $(if ([bool]$result.passed) { 0 } else { 2 })
