[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$RequirementsPath,
    [string]$LockPath,
    [string]$SeriesPath,
    [string]$PatchRoot,
    [switch]$FetchChromium,
    [string]$Confirmation,
    [switch]$JsonAudit
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

function Invoke-ZsecRequiredPlanCommand {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Command)

    $executable = [string]$Command.executable
    $arguments = @($Command.arguments | ForEach-Object { [string]$_ })
    $workingDirectory = [string]$Command.working_dir
    if (-not (Test-Path -LiteralPath $workingDirectory -PathType Container)) {
        throw "Plan phase '$($Command.phase)' refused: working directory is absent: $workingDirectory"
    }
    Push-Location -LiteralPath $workingDirectory
    try {
        & $executable @arguments
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            throw "Plan phase '$($Command.phase)' failed with exit code $exitCode. Partial state was preserved for review."
        }
    }
    finally {
        Pop-Location
    }
}

function Get-ZsecRequiredGitValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RepositoryPath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Label
    )

    $git = @(Get-Command -Name 'git.exe' -CommandType Application -ErrorAction Stop)
    $output = @(& $git[0].Path -C $RepositoryPath @Arguments 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -or $output.Count -ne 1 -or [string]::IsNullOrWhiteSpace($output[0])) {
        throw "Could not read exact $Label from $RepositoryPath (exit=$exitCode, lines=$($output.Count))."
    }
    return [string]$output[0]
}

$requirements = Get-ZsecChromiumRequirements -Path $RequirementsPath
$lock = Read-ZsecDownstreamJson -Path $LockPath
$series = Read-ZsecDownstreamJson -Path $SeriesPath
$lockInputSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $LockPath).Hash.ToLowerInvariant()
$seriesInputSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $SeriesPath).Hash.ToLowerInvariant()
$audit = Invoke-ZsecChromiumAudit -RequirementsPath $RequirementsPath
$downstreamPolicy = Test-ZsecChromiumDownstreamPolicy `
    -LockPath $LockPath -SeriesPath $SeriesPath -PatchRoot $PatchRoot
$depotProbe = Get-ZsecGitRepositoryProbe -RepositoryPath ([string]$requirements.depot_tools.root)
$depotAttestation = Test-ZsecGitRepositoryAttestation -Probe $depotProbe `
    -ExpectedOrigin ([string]$lock.depot_tools_remote) `
    -ExpectedCommit ([string]$lock.depot_tools_commit) -Identity 'depot_tools'
$targetExists = Test-Path -LiteralPath ([string]$requirements.checkout.target)
$plan = New-ZsecChromiumCheckoutPlan -Requirements $requirements -Lock $lock -Series $series `
    -PatchRoot $PatchRoot -HostAuditPassed ([bool]$audit.passed) `
    -DownstreamPolicyPassed ([bool]$downstreamPolicy.passed) `
    -DepotToolsAttestationPassed ([bool]$depotAttestation.passed) `
    -TargetExists $targetExists

$preflight = [pscustomobject]@{
    schema_version          = 1
    product                 = 'ZSEC Chromium Locked Checkout Preflight'
    passed                  = [bool]$plan.execution_permitted
    manual_review_required  = $true
    host_audit              = $audit
    downstream_policy       = $downstreamPolicy
    depot_tools_attestation = $depotAttestation
    checkout_plan           = $plan
}

if ($JsonAudit) {
    $preflight | ConvertTo-Json -Depth 40
}
else {
    Format-ZsecChromiumAudit -Audit $audit
    "Downstream source/patch policy: $($downstreamPolicy.passed)"
    "depot_tools exact origin/HEAD/clean attestation: $($depotAttestation.passed)"
    "Locked source plan permitted: $($plan.execution_permitted)"
}

if (-not [bool]$plan.execution_permitted) {
    [Console]::Error.WriteLine('Bootstrap refused: host, source policy, depot_tools attestation, or target-boundary checks failed. No directory was created and Chromium was not fetched.')
    exit 2
}

if (-not $FetchChromium) {
    'Audit-only mode complete. The exact locked checkout plan passed; no files were fetched or changed.'
    exit 0
}

$requiredConfirmation = [string]$requirements.safety.fetch_confirmation
if ([string]$Confirmation -cne $requiredConfirmation) {
    [Console]::Error.WriteLine("Fetch refused: pass -Confirmation $requiredConfirmation together with -FetchChromium.")
    exit 3
}
if ([bool]$requirements.branding.allow_chrome_branding) {
    [Console]::Error.WriteLine('Fetch refused: Chrome branding must remain disabled in the pinned manifest.')
    exit 4
}

$targetPath = [string]$plan.checkout.root
$sourcePath = [string]$plan.checkout.source
$gitCachePath = [string]$plan.environment.GIT_CACHE_PATH
$description = "execute the reviewed locked Chromium $($plan.chromium.version) checkout plan at $($plan.chromium.commit)"
if (-not $PSCmdlet.ShouldProcess($targetPath, $description)) {
    'WhatIf/confirmation stopped the locked checkout. No checkout was created.'
    exit 0
}

# Mutation begins only after host, downstream-policy, exact depot_tools, target,
# explicit-token and ShouldProcess gates have all passed.
$null = New-Item -ItemType Directory -Path $targetPath -ErrorAction Stop
$null = New-Item -ItemType Directory -Path $gitCachePath -Force -ErrorAction Stop
$env:GIT_CACHE_PATH = [string]$plan.environment.GIT_CACHE_PATH
$env:DEPOT_TOOLS_WIN_TOOLCHAIN = [string]$plan.environment.DEPOT_TOOLS_WIN_TOOLCHAIN
$env:DEPOT_TOOLS_UPDATE = [string]$plan.environment.DEPOT_TOOLS_UPDATE

Invoke-ZsecRequiredPlanCommand -Command $plan.commands.fetch

$gclientMarker = Join-Path $targetPath '.gclient'
$sourceMarker = Join-Path $sourcePath 'chrome\BUILD.gn'
if (-not (Test-Path -LiteralPath $gclientMarker -PathType Leaf) -or
    -not (Test-Path -LiteralPath $sourceMarker -PathType Leaf)) {
    throw 'Fetch returned success but required Chromium checkout markers are missing. Partial state was preserved for review.'
}

$sourceProbe = Get-ZsecGitRepositoryProbe -RepositoryPath $sourcePath
$sourceBoundaryPass = [bool]$sourceProbe.present -and -not [bool]$sourceProbe.reparse_point -and
    [bool]$sourceProbe.is_work_tree -and @($sourceProbe.command_errors).Count -eq 0 -and
    [string]$sourceProbe.origin -ceq [string]$lock.chromium_remote -and
    @($sourceProbe.dirty_paths).Count -eq 0
if (-not $sourceBoundaryPass) {
    throw 'Fetched Chromium source failed the official-origin, Git-boundary, or clean-tree check. Partial state was preserved.'
}

Invoke-ZsecRequiredPlanCommand -Command $plan.commands.verify_commit
Invoke-ZsecRequiredPlanCommand -Command $plan.commands.checkout
Invoke-ZsecRequiredPlanCommand -Command $plan.commands.sync

$baseAttestation = Test-ZsecGitRepositoryAttestation `
    -Probe (Get-ZsecGitRepositoryProbe -RepositoryPath $sourcePath) `
    -ExpectedOrigin ([string]$lock.chromium_remote) `
    -ExpectedCommit ([string]$lock.chromium_commit) -Identity 'chromium_base'
if (-not [bool]$baseAttestation.passed) {
    throw 'Chromium failed exact origin/HEAD/clean attestation after locked dependency sync. Partial state was preserved.'
}

$depotAttestationAfterSync = Test-ZsecGitRepositoryAttestation `
    -Probe (Get-ZsecGitRepositoryProbe -RepositoryPath ([string]$requirements.depot_tools.root)) `
    -ExpectedOrigin ([string]$lock.depot_tools_remote) `
    -ExpectedCommit ([string]$lock.depot_tools_commit) -Identity 'depot_tools_after_sync'
if (-not [bool]$depotAttestationAfterSync.passed) {
    throw 'depot_tools changed during fetch or dependency sync. Partial state was preserved and no patch was applied.'
}
$currentLockSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $LockPath).Hash.ToLowerInvariant()
$currentSeriesSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $SeriesPath).Hash.ToLowerInvariant()
$prePatchPolicy = Test-ZsecChromiumDownstreamPolicy `
    -LockPath $LockPath -SeriesPath $SeriesPath -PatchRoot $PatchRoot
if ($currentLockSha256 -cne $lockInputSha256 -or
    $currentSeriesSha256 -cne $seriesInputSha256 -or
    -not [bool]$prePatchPolicy.passed -or
    [string]$prePatchPolicy.lock.chromium_commit -cne [string]$lock.chromium_commit -or
    [int]$prePatchPolicy.patch_series.count -ne @($series.series).Count) {
    throw 'The reviewed lock, patch inventory, or patch content changed during checkout. No patch was applied.'
}

foreach ($patchCommand in @($plan.commands.patches)) {
    $patchPath = [string]$patchCommand.arguments[@($patchCommand.arguments).Count - 1]
    $actualPatchSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $patchPath).Hash.ToLowerInvariant()
    if ($actualPatchSha256 -cne [string]$patchCommand.patch_sha256) {
        throw "Patch '$($patchCommand.patch_id)' changed after review. It was not applied."
    }
    Invoke-ZsecRequiredPlanCommand -Command $patchCommand
}

$finalProbe = Get-ZsecGitRepositoryProbe -RepositoryPath $sourcePath
$finalPass = [bool]$finalProbe.present -and -not [bool]$finalProbe.reparse_point -and
    [bool]$finalProbe.is_work_tree -and @($finalProbe.command_errors).Count -eq 0 -and
    [string]$finalProbe.origin -ceq [string]$lock.chromium_remote -and
    @($finalProbe.dirty_paths).Count -eq 0
if (-not $finalPass) {
    throw 'The final patched Chromium checkout is not a clean official-origin Git tree. Partial state was preserved.'
}

$finalHead = Get-ZsecRequiredGitValue -RepositoryPath $sourcePath `
    -Arguments @('rev-parse', '--verify', 'HEAD') -Label 'final HEAD'
$finalTree = Get-ZsecRequiredGitValue -RepositoryPath $sourcePath `
    -Arguments @('rev-parse', '--verify', 'HEAD^{tree}') -Label 'final tree'
$receipt = [ordered]@{
    schema_version = 1
    product = 'ZSEC Chromium Locked Checkout Receipt'
    created_at_utc = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    chromium = [ordered]@{
        version = [string]$lock.version
        remote = [string]$lock.chromium_remote
        base_commit = [string]$lock.chromium_commit
        final_head = $finalHead
        final_tree = $finalTree
    }
    depot_tools = [ordered]@{
        remote = [string]$lock.depot_tools_remote
        commit = [string]$lock.depot_tools_commit
    }
    patches = @($series.series | ForEach-Object {
        [ordered]@{ order = [int]$_.order; id = [string]$_.id; sha256 = [string]$_.sha256 }
    })
    environment = [ordered]@{
        DEPOT_TOOLS_WIN_TOOLCHAIN = '0'
        DEPOT_TOOLS_UPDATE = '0'
        chrome_branding = $false
    }
    build_performed = $false
    signing_performed = $false
    installation_performed = $false
}
$receiptPath = [string]$plan.checkout.receipt_path
$temporaryReceipt = $receiptPath + '.tmp-' + [guid]::NewGuid().ToString('N')
try {
    [IO.File]::WriteAllText(
        $temporaryReceipt,
        (($receipt | ConvertTo-Json -Depth 12) + [Environment]::NewLine),
        (New-Object Text.UTF8Encoding($false))
    )
    Move-Item -LiteralPath $temporaryReceipt -Destination $receiptPath -ErrorAction Stop
}
finally {
    if (Test-Path -LiteralPath $temporaryReceipt) {
        Remove-Item -LiteralPath $temporaryReceipt -Force
    }
}

'Exact locked Chromium checkout completed. No build, antivirus change, Chrome branding, signing, installation, update, or deployment was performed.'
"Receipt: $receiptPath"
"Next reviewed target: autoninja -C out\ZsecDev $($requirements.checkout.initial_build_target)"
exit 0
