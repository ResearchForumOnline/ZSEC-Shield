[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$packageRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $packageRoot 'scripts\ZsecChromiumBootstrap.psm1') -Force
Import-Module (Join-Path $packageRoot 'scripts\ZsecChromiumDownstream.psm1') -Force
Import-Module (Join-Path $packageRoot 'scripts\ZsecChromiumCheckout.psm1') -Force

$script:testsRun = 0
function Assert-True {
    param([Parameter(Mandatory)][bool]$Condition, [Parameter(Mandatory)][string]$Message)
    $script:testsRun++
    if (-not $Condition) { throw "ASSERT TRUE FAILED: $Message" }
}
function Assert-False {
    param([Parameter(Mandatory)][bool]$Condition, [Parameter(Mandatory)][string]$Message)
    Assert-True -Condition (-not $Condition) -Message $Message
}
function Assert-Equal {
    param([AllowNull()][object]$Expected, [AllowNull()][object]$Actual, [Parameter(Mandatory)][string]$Message)
    $script:testsRun++
    if ([string]$Expected -cne [string]$Actual) {
        throw "ASSERT EQUAL FAILED: $Message (expected='$Expected', actual='$Actual')"
    }
}
function Get-Check {
    param([Parameter(Mandatory)][object]$Result, [Parameter(Mandatory)][string]$Id)
    $matches = @($Result.checks | Where-Object { [string]$_.id -ceq $Id })
    if ($matches.Count -ne 1) { throw "Expected one check '$Id', found $($matches.Count)." }
    return $matches[0]
}
function Invoke-TestGit {
    param([Parameter(Mandatory)][string]$Repository, [Parameter(Mandatory)][string[]]$Arguments)
    $output = @(& git.exe -C $Repository @Arguments 2>&1 | ForEach-Object { [string]$_ })
    if ($LASTEXITCODE -ne 0) {
        throw "Test Git failed: git -C $Repository $($Arguments -join ' ')`n$($output -join "`n")"
    }
    return @($output)
}

$requirementsPath = Join-Path $packageRoot 'toolchain.requirements.json'
$lockPath = Join-Path $packageRoot 'upstream.lock.json'
$seriesPath = Join-Path $packageRoot 'patches\series.json'
$patchRoot = Join-Path $packageRoot 'patches'
$requirements = Get-ZsecChromiumRequirements -Path $requirementsPath
$lock = Read-ZsecDownstreamJson -Path $lockPath
$series = Read-ZsecDownstreamJson -Path $seriesPath

Assert-Equal -Expected '0' -Actual $requirements.depot_tools.required_environment.DEPOT_TOOLS_UPDATE `
    -Message 'Pinned depot_tools must be prevented from self-updating.'
Assert-Equal -Expected 'FETCH_LOCKED_CHROMIUM' -Actual $requirements.safety.fetch_confirmation `
    -Message 'The mutation token must describe a locked, not moving, checkout.'
Assert-Equal -Expected '--nohooks' -Actual $requirements.checkout.fetch_arguments[0] `
    -Message 'Initial moving fetch must not run hooks before the source is pinned.'
Assert-Equal -Expected '--git-cache' -Actual $requirements.checkout.fetch_arguments[1] `
    -Message 'The full-history shared cache must remain explicit.'

$tempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$tempRoot = Join-Path $tempParent ("zsec-chromium-checkout-tests-{0}" -f [guid]::NewGuid().ToString('N'))
$tempRootFull = [IO.Path]::GetFullPath($tempRoot)
if (-not $tempRootFull.StartsWith($tempParent + '\', [StringComparison]::OrdinalIgnoreCase) -or
    -not ([IO.Path]::GetFileName($tempRootFull)).StartsWith('zsec-chromium-checkout-tests-', [StringComparison]::Ordinal)) {
    throw "Refused unsafe test directory: $tempRootFull"
}

try {
    $repo = Join-Path $tempRootFull 'depot_tools'
    $null = New-Item -ItemType Directory -Path $repo
    [void](Invoke-TestGit -Repository $repo -Arguments @('init'))
    [void](Invoke-TestGit -Repository $repo -Arguments @('config', 'user.name', 'ZSEC Test'))
    [void](Invoke-TestGit -Repository $repo -Arguments @('config', 'user.email', 'test@example.invalid'))
    Set-Content -LiteralPath (Join-Path $repo 'fetch.bat') -Value '@echo fetch' -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $repo 'gclient.bat') -Value '@echo gclient' -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $repo 'vpython3.bat') -Value '@echo vpython' -Encoding ASCII
    [void](Invoke-TestGit -Repository $repo -Arguments @('add', '--', 'fetch.bat', 'gclient.bat', 'vpython3.bat'))
    [void](Invoke-TestGit -Repository $repo -Arguments @('commit', '-m', 'Pinned depot tools fixture'))
    [void](Invoke-TestGit -Repository $repo -Arguments @(
        'remote', 'add', 'origin', 'https://chromium.googlesource.com/chromium/tools/depot_tools.git'
    ))
    $headOutput = @(Invoke-TestGit -Repository $repo -Arguments @('rev-parse', 'HEAD'))
    $head = [string]$headOutput[0]

    $probe = Get-ZsecGitRepositoryProbe -RepositoryPath $repo
    $attestation = Test-ZsecGitRepositoryAttestation -Probe $probe `
        -ExpectedOrigin 'https://chromium.googlesource.com/chromium/tools/depot_tools.git' `
        -ExpectedCommit $head -Identity 'depot_tools'
    Assert-True -Condition ([bool]$attestation.passed) `
        -Message 'An exact official-origin, exact-HEAD, clean Git fixture should pass.'
    Assert-Equal -Expected 0 -Actual @($probe.dirty_paths).Count `
        -Message 'The clean fixture should report no dirty paths.'

    Add-Content -LiteralPath (Join-Path $repo 'fetch.bat') -Value '@echo tamper' -Encoding ASCII
    $attestation = Test-ZsecGitRepositoryAttestation `
        -Probe (Get-ZsecGitRepositoryProbe -RepositoryPath $repo) `
        -ExpectedOrigin 'https://chromium.googlesource.com/chromium/tools/depot_tools.git' `
        -ExpectedCommit $head -Identity 'depot_tools'
    Assert-False -Condition ([bool]$attestation.passed) `
        -Message 'A modified tracked entrypoint must fail the clean-tree gate.'
    Assert-False -Condition ([bool](Get-Check -Result $attestation -Id 'depot_tools.clean').passed) `
        -Message 'Tracked entrypoint tampering must fail the explicit clean check.'
    [void](Invoke-TestGit -Repository $repo -Arguments @('restore', '--worktree', '--staged', '.'))

    Set-Content -LiteralPath (Join-Path $repo 'untracked-tool.bat') -Value '@echo untracked' -Encoding ASCII
    $attestation = Test-ZsecGitRepositoryAttestation `
        -Probe (Get-ZsecGitRepositoryProbe -RepositoryPath $repo) `
        -ExpectedOrigin 'https://chromium.googlesource.com/chromium/tools/depot_tools.git' `
        -ExpectedCommit $head -Identity 'depot_tools'
    Assert-False -Condition ([bool]$attestation.passed) `
        -Message 'An untracked tool file must fail the clean-tree gate.'
    Remove-Item -LiteralPath (Join-Path $repo 'untracked-tool.bat') -Force

    [void](Invoke-TestGit -Repository $repo -Arguments @(
        'remote', 'set-url', 'origin', 'https://example.invalid/depot_tools.git'
    ))
    $attestation = Test-ZsecGitRepositoryAttestation `
        -Probe (Get-ZsecGitRepositoryProbe -RepositoryPath $repo) `
        -ExpectedOrigin 'https://chromium.googlesource.com/chromium/tools/depot_tools.git' `
        -ExpectedCommit $head -Identity 'depot_tools'
    Assert-False -Condition ([bool](Get-Check -Result $attestation -Id 'depot_tools.origin').passed) `
        -Message 'A lookalike depot_tools origin must fail closed.'
    [void](Invoke-TestGit -Repository $repo -Arguments @(
        'remote', 'set-url', 'origin', 'https://chromium.googlesource.com/chromium/tools/depot_tools.git'
    ))

    [void](Invoke-TestGit -Repository $repo -Arguments @(
        'remote', 'set-url', '--add', 'origin', 'https://example.invalid/second.git'
    ))
    $attestation = Test-ZsecGitRepositoryAttestation `
        -Probe (Get-ZsecGitRepositoryProbe -RepositoryPath $repo) `
        -ExpectedOrigin 'https://chromium.googlesource.com/chromium/tools/depot_tools.git' `
        -ExpectedCommit $head -Identity 'depot_tools'
    Assert-False -Condition ([bool](Get-Check -Result $attestation -Id 'depot_tools.origin').passed) `
        -Message 'Multiple effective origin URLs must fail closed.'
    [void](Invoke-TestGit -Repository $repo -Arguments @(
        'remote', 'set-url', '--delete', 'origin', 'https://example.invalid/second.git'
    ))

    $attestation = Test-ZsecGitRepositoryAttestation `
        -Probe (Get-ZsecGitRepositoryProbe -RepositoryPath $repo) `
        -ExpectedOrigin 'https://chromium.googlesource.com/chromium/tools/depot_tools.git' `
        -ExpectedCommit 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' -Identity 'depot_tools'
    Assert-False -Condition ([bool](Get-Check -Result $attestation -Id 'depot_tools.head').passed) `
        -Message 'A different reviewed depot_tools commit must fail closed.'

    $badBoundaryProbe = [pscustomobject]@{
        path = $repo; present = $true; reparse_point = $true
        git_metadata_present = $true; git_metadata_reparse = $false; git_executable = 'git.exe'
        top_level = $repo; origin_urls = @('https://chromium.googlesource.com/chromium/tools/depot_tools.git')
        is_work_tree = $true; origin = 'https://chromium.googlesource.com/chromium/tools/depot_tools.git'
        head = $head; dirty_paths = @(); command_errors = @()
    }
    $attestation = Test-ZsecGitRepositoryAttestation -Probe $badBoundaryProbe `
        -ExpectedOrigin 'https://chromium.googlesource.com/chromium/tools/depot_tools.git' `
        -ExpectedCommit $head -Identity 'depot_tools'
    Assert-False -Condition ([bool](Get-Check -Result $attestation -Id 'depot_tools.boundary').passed) `
        -Message 'A reparse-point repository root must fail closed.'
    $badBoundaryProbe.reparse_point = $false
    $badBoundaryProbe.git_metadata_reparse = $true
    $attestation = Test-ZsecGitRepositoryAttestation -Probe $badBoundaryProbe `
        -ExpectedOrigin 'https://chromium.googlesource.com/chromium/tools/depot_tools.git' `
        -ExpectedCommit $head -Identity 'depot_tools'
    Assert-False -Condition ([bool](Get-Check -Result $attestation -Id 'depot_tools.boundary').passed) `
        -Message 'A reparse-point Git metadata boundary must fail closed.'
}
finally {
    if (Test-Path -LiteralPath $tempRootFull) {
        Remove-Item -LiteralPath $tempRootFull -Recurse -Force
    }
}

$plan = New-ZsecChromiumCheckoutPlan -Requirements $requirements -Lock $lock -Series $series `
    -PatchRoot $patchRoot -HostAuditPassed $true -DownstreamPolicyPassed $true `
    -DepotToolsAttestationPassed $true -TargetExists $false
Assert-True -Condition ([bool]$plan.execution_permitted) `
    -Message 'All validated prerequisites should produce an executable locked plan.'
Assert-True -Condition ([bool]$plan.manual_review_required) `
    -Message 'A valid plan must still require explicit human review and confirmation.'
Assert-Equal -Expected ([string]$lock.chromium_commit) -Actual $plan.chromium.commit `
    -Message 'The plan must retain the exact Chromium commit.'
Assert-Equal -Expected ([string]$lock.depot_tools_commit) -Actual $plan.depot_tools.commit `
    -Message 'The plan must retain the exact depot_tools commit.'
Assert-Equal -Expected '--nohooks' -Actual $plan.commands.fetch.arguments[0] `
    -Message 'Fetch must suppress hooks until the exact source revision is selected.'
Assert-Equal -Expected '--git-cache' -Actual $plan.commands.fetch.arguments[1] `
    -Message 'Fetch must retain the reviewed git-cache mode.'
Assert-Equal -Expected 'chromium' -Actual $plan.commands.fetch.arguments[2] `
    -Message 'Fetch configuration must be Chromium.'
Assert-Equal -Expected 'sync' -Actual $plan.commands.sync.arguments[0] `
    -Message 'The dependency action must be an explicit gclient sync.'
Assert-Equal -Expected '--revision' -Actual $plan.commands.sync.arguments[1] `
    -Message 'The dependency sync must select an exact revision.'
Assert-Equal -Expected ("src@{0}" -f [string]$lock.chromium_commit) -Actual $plan.commands.sync.arguments[2] `
    -Message 'The dependency sync must use src@the exact locked commit.'
Assert-True -Condition ([IO.Path]::IsPathRooted([string]$plan.commands.fetch.executable)) `
    -Message 'fetch.bat must be invoked by an absolute pinned path.'
Assert-True -Condition ([IO.Path]::IsPathRooted([string]$plan.commands.sync.executable)) `
    -Message 'gclient.bat must be invoked by an absolute pinned path.'
Assert-Equal -Expected '0' -Actual $plan.environment.DEPOT_TOOLS_UPDATE `
    -Message 'The exact plan must disable depot_tools self-update.'
Assert-Equal -Expected 0 -Actual $plan.patch_count `
    -Message 'The current plan must truthfully contain no downstream patches.'

$refused = New-ZsecChromiumCheckoutPlan -Requirements $requirements -Lock $lock -Series $series `
    -PatchRoot $patchRoot -HostAuditPassed $false -DownstreamPolicyPassed $true `
    -DepotToolsAttestationPassed $true -TargetExists $false
Assert-False -Condition ([bool]$refused.execution_permitted) `
    -Message 'An unsupported host must never receive execution permission.'
$refused = New-ZsecChromiumCheckoutPlan -Requirements $requirements -Lock $lock -Series $series `
    -PatchRoot $patchRoot -HostAuditPassed $true -DownstreamPolicyPassed $true `
    -DepotToolsAttestationPassed $false -TargetExists $false
Assert-False -Condition ([bool]$refused.execution_permitted) `
    -Message 'Failed depot_tools attestation must never receive execution permission.'
$refused = New-ZsecChromiumCheckoutPlan -Requirements $requirements -Lock $lock -Series $series `
    -PatchRoot $patchRoot -HostAuditPassed $true -DownstreamPolicyPassed $true `
    -DepotToolsAttestationPassed $true -TargetExists $true
Assert-False -Condition ([bool]$refused.execution_permitted) `
    -Message 'An existing target must never be overwritten or silently resumed.'
$wrongPaths = $requirements | ConvertTo-Json -Depth 32 | ConvertFrom-Json
$wrongPaths.checkout.target = 'D:\src\zsec-chromium'
$refused = New-ZsecChromiumCheckoutPlan -Requirements $wrongPaths -Lock $lock -Series $series `
    -PatchRoot $patchRoot -HostAuditPassed $true -DownstreamPolicyPassed $true `
    -DepotToolsAttestationPassed $true -TargetExists $false
Assert-False -Condition ([bool](Get-Check -Result $refused -Id 'plan.paths').passed) `
    -Message 'A requirements edit cannot redirect the reviewed checkout outside C:\src.'

$bootstrapText = Get-Content -LiteralPath (Join-Path $packageRoot 'scripts\Invoke-ZsecChromiumBootstrap.ps1') -Raw
$policyIndex = $bootstrapText.IndexOf('$downstreamPolicy = Test-ZsecChromiumDownstreamPolicy', [StringComparison]::Ordinal)
$depotIndex = $bootstrapText.IndexOf('$depotAttestation = Test-ZsecGitRepositoryAttestation', [StringComparison]::Ordinal)
$planIndex = $bootstrapText.IndexOf('$plan = New-ZsecChromiumCheckoutPlan', [StringComparison]::Ordinal)
$permissionIndex = $bootstrapText.IndexOf('if (-not [bool]$plan.execution_permitted)', [StringComparison]::Ordinal)
$mutationIndex = $bootstrapText.IndexOf('$null = New-Item', [StringComparison]::Ordinal)
Assert-True -Condition ($policyIndex -ge 0 -and $depotIndex -gt $policyIndex -and
    $planIndex -gt $depotIndex -and $permissionIndex -gt $planIndex -and $mutationIndex -gt $permissionIndex) `
    -Message 'Policy, depot attestation, plan and permission refusal must all precede mutation.'
Assert-True -Condition ($bootstrapText -match '\$env:DEPOT_TOOLS_UPDATE =') `
    -Message 'The executor must freeze depot_tools before invoking fetch or gclient.'
Assert-True -Condition ($bootstrapText -match 'Test-ZsecGitRepositoryAttestation') `
    -Message 'The executor must attest Chromium after locked dependency sync.'

$forbiddenSecurityMutations = @(
    'Add-MpPreference', 'Set-MpPreference', 'Remove-MpPreference', 'Stop-Service',
    'Set-Service', 'SecurityCenter2', 'Malwarebytes'
)
foreach ($token in $forbiddenSecurityMutations) {
    Assert-False -Condition ($bootstrapText -match [regex]::Escape($token)) `
        -Message "Locked checkout executor must not contain security-provider mutation token: $token"
}

"PASS: $script:testsRun assertions"
exit 0
