[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$packageRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$modulePath = Join-Path $packageRoot 'scripts\ZsecChromiumDownstream.psm1'
$lockPath = Join-Path $packageRoot 'upstream.lock.json'
$seriesPath = Join-Path $packageRoot 'patches\series.json'
$patchRoot = Join-Path $packageRoot 'patches'
Import-Module $modulePath -Force

$script:testsRun = 0

function Assert-True {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )
    $script:testsRun++
    if (-not $Condition) {
        throw "ASSERT TRUE FAILED: $Message"
    }
}

function Assert-False {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )
    Assert-True -Condition (-not $Condition) -Message $Message
}

function Assert-Equal {
    param(
        [AllowNull()][object]$Expected,
        [AllowNull()][object]$Actual,
        [Parameter(Mandatory)][string]$Message
    )
    $script:testsRun++
    if ([string]$Expected -cne [string]$Actual) {
        throw "ASSERT EQUAL FAILED: $Message (expected='$Expected', actual='$Actual')"
    }
}

function Get-Check {
    param(
        [Parameter(Mandatory)][object]$Result,
        [Parameter(Mandatory)][string]$Id
    )
    $matches = @($Result.checks | Where-Object { [string]$_.id -ceq $Id })
    if ($matches.Count -ne 1) {
        throw "Expected exactly one policy check named '$Id', found $($matches.Count)."
    }
    return $matches[0]
}

function Copy-JsonObject {
    param([Parameter(Mandatory)][object]$InputObject)
    return $InputObject | ConvertTo-Json -Depth 32 | ConvertFrom-Json
}

function New-Candidate {
    param(
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][int]$Milestone,
        [Parameter(Mandatory)][int64]$BranchPosition,
        [Parameter(Mandatory)][string]$Commit
    )
    [pscustomobject]@{
        channel                       = 'Stable'
        platform                      = 'Windows'
        version                       = $Version
        milestone                     = $Milestone
        chromium_main_branch_position = $BranchPosition
        hashes                         = [pscustomobject]@{ chromium = $Commit }
    }
}

$lock = Read-ZsecDownstreamJson -Path $lockPath
$baseline = Test-ZsecChromiumDownstreamPolicy `
    -LockPath $lockPath -SeriesPath $seriesPath -PatchRoot $patchRoot
Assert-True -Condition ([bool]$baseline.passed) `
    -Message 'The checked-in source lock and patch inventory must pass policy.'
Assert-Equal -Expected 0 -Actual $baseline.patch_series.count `
    -Message 'The first downstream slice must disclose an empty patch series.'

$current = New-Candidate -Version ([string]$lock.version) -Milestone ([int]$lock.milestone) `
    -BranchPosition ([int64]$lock.chromium_main_branch_position) -Commit ([string]$lock.chromium_commit)
$plan = New-ZsecChromiumUpdatePlan -Lock $lock -Candidate $current
Assert-Equal -Expected 'current' -Actual $plan.status -Message 'The locked candidate should report current.'
Assert-False -Condition ([bool]$plan.safe_to_update_lock) `
    -Message 'Even a valid candidate must never authorize an automatic lock write.'
Assert-True -Condition ([bool]$plan.manual_review_required) `
    -Message 'Every source-lock decision must require manual review.'

$newerCommit = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
$newer = New-Candidate -Version '152.0.8000.1' -Milestone 152 `
    -BranchPosition 1700000 -Commit $newerCommit
$plan = New-ZsecChromiumUpdatePlan -Lock $lock -Candidate $newer
Assert-Equal -Expected 'update_available' -Actual $plan.status `
    -Message 'A valid newer Windows Stable release should produce a review plan.'
Assert-False -Condition ([bool]$plan.safe_to_update_lock) `
    -Message 'An available update must still be review-only.'
Assert-True -Condition (@($plan.actions).Count -ge 5) `
    -Message 'The update plan must retain patch, build, test, and review actions.'

$older = New-Candidate -Version '150.0.7900.1' -Milestone 150 `
    -BranchPosition 1600000 -Commit 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
$plan = New-ZsecChromiumUpdatePlan -Lock $lock -Candidate $older
Assert-Equal -Expected 'refused_downgrade' -Actual $plan.status `
    -Message 'A downgrade candidate must fail closed.'

$changedSameVersion = New-Candidate -Version ([string]$lock.version) -Milestone ([int]$lock.milestone) `
    -BranchPosition ([int64]$lock.chromium_main_branch_position) `
    -Commit 'cccccccccccccccccccccccccccccccccccccccc'
$plan = New-ZsecChromiumUpdatePlan -Lock $lock -Candidate $changedSameVersion
Assert-Equal -Expected 'refused_same_version_commit_change' -Actual $plan.status `
    -Message 'A changed commit for the same release version must fail closed.'

$invalid = New-Candidate -Version '152.0.8000.1' -Milestone 152 `
    -BranchPosition 1700000 -Commit 'not-a-commit'
$plan = New-ZsecChromiumUpdatePlan -Lock $lock -Candidate $invalid
Assert-Equal -Expected 'refused_invalid_candidate' -Actual $plan.status `
    -Message 'Malformed candidate identity must fail closed.'

$tempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$tempRoot = Join-Path $tempParent ("zsec-chromium-downstream-tests-{0}" -f [guid]::NewGuid().ToString('N'))
$tempRootFull = [IO.Path]::GetFullPath($tempRoot)
if (-not $tempRootFull.StartsWith($tempParent + '\', [StringComparison]::OrdinalIgnoreCase) -or
    -not ([IO.Path]::GetFileName($tempRootFull)).StartsWith('zsec-chromium-downstream-tests-', [StringComparison]::Ordinal)) {
    throw "Refused unsafe test directory: $tempRootFull"
}

try {
    $null = New-Item -ItemType Directory -Path $tempRootFull
    $testLockPath = Join-Path $tempRootFull 'upstream.lock.json'
    $testSeriesPath = Join-Path $tempRootFull 'series.json'
    $testPatchPath = Join-Path $tempRootFull '0001-test.patch'
    Copy-Item -LiteralPath $lockPath -Destination $testLockPath

    $patchText = @'
From dddddddddddddddddddddddddddddddddddddddd Mon Sep 17 00:00:00 2001
From: ZSEC Test <test@example.invalid>
Date: Fri, 22 Aug 2026 00:00:00 +0000
Subject: [PATCH] Exercise downstream policy

---
 chrome/test.cc | 1 +
 1 file changed, 1 insertion(+)

diff --git a/chrome/test.cc b/chrome/test.cc
index 1111111..2222222 100644
--- a/chrome/test.cc
+++ b/chrome/test.cc
@@ -1 +1,2 @@
 existing();
+reviewable_change();
--{{SP}}
2.50.0
'@
    $patchText = $patchText.Replace('--{{SP}}', '-- ')
    Set-Content -LiteralPath $testPatchPath -Value $patchText -Encoding UTF8 -NoNewline
    $patchHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $testPatchPath).Hash.ToLowerInvariant()
    $testSeries = Read-ZsecDownstreamJson -Path $seriesPath
    $testSeries.series = @([pscustomobject]@{
        order         = 1
        id            = 'test-reviewable-change'
        path          = '0001-test.patch'
        sha256        = $patchHash
        purpose       = 'Exercise the policy validator without changing Chromium source.'
        upstream_area = 'chrome/test'
    })
    $testSeries | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $testSeriesPath -Encoding UTF8

    $result = Test-ZsecChromiumDownstreamPolicy `
        -LockPath $testLockPath -SeriesPath $testSeriesPath -PatchRoot $tempRootFull
    Assert-True -Condition ([bool]$result.passed) `
        -Message 'A bounded, hashed text format-patch should pass.'

    Add-Content -LiteralPath $testPatchPath -Value "`n+post_hash_tamper();" -Encoding UTF8
    $result = Test-ZsecChromiumDownstreamPolicy `
        -LockPath $testLockPath -SeriesPath $testSeriesPath -PatchRoot $tempRootFull
    Assert-False -Condition ([bool](Get-Check -Result $result -Id 'patches.entry.1.file').passed) `
        -Message 'Patch content changed after review must fail its hash gate.'

    $unsafePatch = $patchText.Replace('+reviewable_change();', '+command_line.AppendSwitch("--no-sandbox");')
    Set-Content -LiteralPath $testPatchPath -Value $unsafePatch -Encoding UTF8 -NoNewline
    $testSeries = Read-ZsecDownstreamJson -Path $testSeriesPath
    $testSeries.series[0].sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $testPatchPath).Hash.ToLowerInvariant()
    $testSeries | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $testSeriesPath -Encoding UTF8
    $result = Test-ZsecChromiumDownstreamPolicy `
        -LockPath $testLockPath -SeriesPath $testSeriesPath -PatchRoot $tempRootFull
    Assert-False -Condition ([bool](Get-Check -Result $result -Id 'patches.entry.1.security_additions').passed) `
        -Message 'A newly added sandbox-disabling flag must fail closed.'

    $testSeries = Read-ZsecDownstreamJson -Path $testSeriesPath
    $testSeries.series[0].path = '../escape.patch'
    $testSeries | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $testSeriesPath -Encoding UTF8
    $result = Test-ZsecChromiumDownstreamPolicy `
        -LockPath $testLockPath -SeriesPath $testSeriesPath -PatchRoot $tempRootFull
    Assert-False -Condition ([bool](Get-Check -Result $result -Id 'patches.entry.1.path').passed) `
        -Message 'A path-escaping patch entry must fail closed.'

    $testLock = Read-ZsecDownstreamJson -Path $testLockPath
    $testLock.chromium_remote = 'https://example.invalid/chromium.git'
    $testLock | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $testLockPath -Encoding UTF8
    $result = Test-ZsecChromiumDownstreamPolicy `
        -LockPath $testLockPath -SeriesPath $seriesPath -PatchRoot $patchRoot
    Assert-False -Condition ([bool](Get-Check -Result $result -Id 'lock.official_sources').passed) `
        -Message 'An unapproved Chromium source origin must fail closed.'
}
finally {
    if (Test-Path -LiteralPath $tempRootFull) {
        Remove-Item -LiteralPath $tempRootFull -Recurse -Force
    }
}

$scriptText = (Get-ChildItem -LiteralPath (Join-Path $packageRoot 'scripts') -File |
    ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
$mutationTokens = @(
    'git checkout',
    'git fetch',
    'git am',
    'gclient sync',
    'Invoke-WebRequest',
    'Add-MpPreference',
    'Set-MpPreference',
    'Stop-Service',
    'SecurityCenter2'
)
foreach ($token in $mutationTokens) {
    Assert-False -Condition ($scriptText -match [regex]::Escape($token)) `
        -Message "Downstream policy/update-plan scripts must not contain mutation token: $token"
}

"PASS: $script:testsRun assertions"
exit 0
