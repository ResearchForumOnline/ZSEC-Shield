[CmdletBinding()]
param(
    [string]$RequirementsPath,
    [string]$LockPath,
    [string]$SeriesPath,
    [string]$PatchRoot,
    [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$packageRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($RequirementsPath)) {
    $RequirementsPath = Join-Path $packageRoot 'toolchain.requirements.json'
}
if ([string]::IsNullOrWhiteSpace($LockPath)) {
    $LockPath = Join-Path $packageRoot 'upstream.lock.json'
}
if ([string]::IsNullOrWhiteSpace($SeriesPath)) {
    $SeriesPath = Join-Path $packageRoot 'patches\series.json'
}
if ([string]::IsNullOrWhiteSpace($PatchRoot)) {
    $PatchRoot = Join-Path $packageRoot 'patches'
}

Import-Module (Join-Path $PSScriptRoot 'ZsecChromiumBootstrap.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ZsecChromiumDownstream.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ZsecChromiumCheckout.psm1') -Force

$requirements = Get-ZsecChromiumRequirements -Path $RequirementsPath
$lock = Read-ZsecDownstreamJson -Path $LockPath
$series = Read-ZsecDownstreamJson -Path $SeriesPath
$hostAudit = Invoke-ZsecChromiumAudit -RequirementsPath $RequirementsPath
$downstreamPolicy = Test-ZsecChromiumDownstreamPolicy `
    -LockPath $LockPath -SeriesPath $SeriesPath -PatchRoot $PatchRoot
$depotProbe = Get-ZsecGitRepositoryProbe -RepositoryPath ([string]$requirements.depot_tools.root)
$depotAttestation = Test-ZsecGitRepositoryAttestation -Probe $depotProbe `
    -ExpectedOrigin ([string]$lock.depot_tools_remote) `
    -ExpectedCommit ([string]$lock.depot_tools_commit) -Identity 'depot_tools'
$targetExists = Test-Path -LiteralPath ([string]$requirements.checkout.target)
$plan = New-ZsecChromiumCheckoutPlan -Requirements $requirements -Lock $lock -Series $series `
    -PatchRoot $PatchRoot -HostAuditPassed ([bool]$hostAudit.passed) `
    -DownstreamPolicyPassed ([bool]$downstreamPolicy.passed) `
    -DepotToolsAttestationPassed ([bool]$depotAttestation.passed) `
    -TargetExists $targetExists

$result = [pscustomobject]@{
    schema_version          = 1
    product                 = 'ZSEC Chromium Locked Checkout Preflight'
    passed                  = [bool]$plan.execution_permitted
    manual_review_required  = $true
    host_audit              = $hostAudit
    downstream_policy       = $downstreamPolicy
    depot_tools_attestation = $depotAttestation
    checkout_plan           = $plan
}

if ($Json) {
    $result | ConvertTo-Json -Depth 40
}
else {
    $state = if ([bool]$result.passed) { 'PASS (explicit confirmation still required)' } else { 'FAIL (no checkout permitted)' }
    "ZSEC Chromium locked checkout preflight: $state"
    "Host audit: $($hostAudit.passed)"
    "Downstream source/patch policy: $($downstreamPolicy.passed)"
    "depot_tools exact origin/HEAD/clean attestation: $($depotAttestation.passed)"
    "Locked Chromium: $($lock.version) $($lock.chromium_commit)"
    "Patch count: $(@($series.series).Count)"
    "Checkout target exists: $targetExists"
    'This command is read-only. It did not fetch, check out, patch, build, install, or publish Chromium.'
}

exit $(if ([bool]$result.passed) { 0 } else { 2 })
