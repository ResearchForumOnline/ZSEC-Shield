[CmdletBinding()]
param(
    [string]$LockPath,
    [string]$CandidatePath,
    [switch]$CheckUpstream,
    [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$packageRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($LockPath)) {
    $LockPath = Join-Path $packageRoot 'upstream.lock.json'
}
if (-not [string]::IsNullOrWhiteSpace($CandidatePath) -and $CheckUpstream) {
    throw 'Choose either -CandidatePath or -CheckUpstream, not both.'
}

Import-Module (Join-Path $PSScriptRoot 'ZsecChromiumDownstream.psm1') -Force
$lock = Read-ZsecDownstreamJson -Path $LockPath
if (-not [string]::IsNullOrWhiteSpace($CandidatePath)) {
    $candidate = Read-ZsecDownstreamJson -Path $CandidatePath
}
elseif ($CheckUpstream) {
    $candidate = Get-ZsecChromiumStableCandidate -Lock $lock
}
else {
    $candidate = [pscustomobject]@{
        channel                       = [string]$lock.channel
        platform                      = [string]$lock.platform
        version                       = [string]$lock.version
        milestone                     = [int]$lock.milestone
        chromium_main_branch_position = [int64]$lock.chromium_main_branch_position
        hashes                         = [pscustomobject]@{ chromium = [string]$lock.chromium_commit }
    }
}

$plan = New-ZsecChromiumUpdatePlan -Lock $lock -Candidate $candidate
if ($Json) {
    $plan | ConvertTo-Json -Depth 16
}
else {
    "ZSEC Chromium update plan: $($plan.status)"
    "Locked: $($plan.current.version) $($plan.current.commit)"
    "Candidate: $($plan.candidate.version) $($plan.candidate.commit)"
    foreach ($reason in @($plan.reasons)) { "Reason: $reason" }
    foreach ($action in @($plan.actions)) { "Review action: $action" }
    'No source lock, checkout, patch, build, installation, or live product was changed.'
}

if ([string]$plan.status -like 'refused_*') { exit 2 }
exit 0
