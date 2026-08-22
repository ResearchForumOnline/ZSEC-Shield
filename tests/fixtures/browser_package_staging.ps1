#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BuildScript,
    [Parameter(Mandatory = $true)][string]$ValidPackage,
    [Parameter(Mandatory = $true)][string]$PartialPackage,
    [Parameter(Mandatory = $true)][string]$CacheRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$tokens = $null
$parseErrors = $null
$scriptText = Get-Content -LiteralPath $BuildScript -Raw -Encoding UTF8
$scriptAst = [Management.Automation.Language.Parser]::ParseInput(
    $scriptText,
    [ref]$tokens,
    [ref]$parseErrors
)
if (@($parseErrors).Count -ne 0) {
    throw "The browser build script could not be parsed."
}
foreach ($functionName in @(
        "Remove-OwnedPackageExtraction",
        "Expand-PinnedPackageToFreshStaging"
    )) {
    $definition = $scriptAst.Find(
        {
            param($Node)
            $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $Node.Name -eq $functionName
        },
        $true
    )
    if ($null -eq $definition) {
        throw "Required browser-build helper is absent: $functionName"
    }
    . ([scriptblock]::Create($definition.Extent.Text))
}

New-Item -ItemType Directory -Path $CacheRoot -ErrorAction Stop | Out-Null
$legacy = Join-Path $CacheRoot "extracted"
$legacyCore = Join-Path $legacy "lib\net462\Microsoft.Web.WebView2.Core.dll"
New-Item -ItemType Directory -Path (Split-Path -Parent $legacyCore) -Force | Out-Null
[IO.File]::WriteAllText($legacyCore, "poisoned legacy cache")
[IO.File]::WriteAllText((Join-Path $legacy "poison.txt"), "must remain untouched")

$firstStage = Expand-PinnedPackageToFreshStaging `
    -PackagePath $ValidPackage `
    -CacheRoot $CacheRoot
if ([string]::Equals(
        $firstStage,
        $legacy,
        [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "The legacy extracted cache was selected as fresh staging."
}
$firstCore = Join-Path $firstStage "lib\net462\Microsoft.Web.WebView2.Core.dll"
if (-not (Test-Path -LiteralPath $firstCore -PathType Leaf) -or
    [IO.File]::ReadAllText($firstCore) -ne "verified package core") {
    throw "Fresh staging did not supply the verified package content."
}
if (Test-Path -LiteralPath (Join-Path $firstStage "poison.txt")) {
    throw "Fresh staging consumed a file from the poisoned legacy cache."
}
Remove-OwnedPackageExtraction `
    -Path $firstStage `
    -CacheRoot $CacheRoot `
    -PackagePath $ValidPackage
if (Test-Path -LiteralPath $firstStage) {
    throw "Successful fresh staging was not removed."
}

$partialFailed = $false
$partialStage = $null
try {
    $partialStage = Expand-PinnedPackageToFreshStaging `
        -PackagePath $PartialPackage `
        -CacheRoot $CacheRoot
}
catch {
    $partialFailed = $true
}
if (-not $partialFailed -or $null -ne $partialStage) {
    if ($null -ne $partialStage) {
        Remove-OwnedPackageExtraction `
            -Path $partialStage `
            -CacheRoot $CacheRoot `
            -PackagePath $PartialPackage
    }
    throw "The deliberately partial package did not fail extraction."
}
$remainingStages = @(
    Get-ChildItem -LiteralPath $CacheRoot -Directory -Force |
        Where-Object { $_.Name -match '^extract-[0-9a-f]{32}$' }
)
if ($remainingStages.Count -ne 0) {
    throw "A failed partial extraction left reusable staging behind."
}

$secondStage = Expand-PinnedPackageToFreshStaging `
    -PackagePath $ValidPackage `
    -CacheRoot $CacheRoot
try {
    if ([string]::Equals(
            $firstStage,
            $secondStage,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "A later extraction reused a previous staging path."
    }
    $unexpected = Join-Path $secondStage "unexpected.txt"
    [IO.File]::WriteAllText($unexpected, "not described by the verified package")
    $cleanupFailedClosed = $false
    try {
        Remove-OwnedPackageExtraction `
            -Path $secondStage `
            -CacheRoot $CacheRoot `
            -PackagePath $ValidPackage
    }
    catch {
        $cleanupFailedClosed = $true
    }
    if (-not $cleanupFailedClosed -or
        -not (Test-Path -LiteralPath $unexpected -PathType Leaf)) {
        throw "Cleanup did not fail closed on an unexpected nested object."
    }
    [IO.File]::Delete($unexpected)
    Remove-OwnedPackageExtraction `
        -Path $secondStage `
        -CacheRoot $CacheRoot `
        -PackagePath $ValidPackage
}
finally {
    if (Test-Path -LiteralPath $secondStage) {
        throw "The second owned staging path was not removed."
    }
}

$legacyPreserved = (
    (Test-Path -LiteralPath $legacyCore -PathType Leaf) -and
    [IO.File]::ReadAllText($legacyCore) -eq "poisoned legacy cache" -and
    [IO.File]::ReadAllText((Join-Path $legacy "poison.txt")) -eq "must remain untouched"
)
if (-not $legacyPreserved) {
    throw "The poisoned legacy cache was read from or modified by staging cleanup."
}

$nestedWebViewCache = Join-Path $CacheRoot "nested-webview"
$nestedCompilerCache = Join-Path $CacheRoot "nested-compiler"
New-Item -ItemType Directory -Path $nestedWebViewCache -ErrorAction Stop | Out-Null
New-Item -ItemType Directory -Path $nestedCompilerCache -ErrorAction Stop | Out-Null

$webViewStage = $null
$compilerStage = $null
$nestedSuccessReached = $false
try {
    $webViewStage = Expand-PinnedPackageToFreshStaging `
        -PackagePath $ValidPackage `
        -CacheRoot $nestedWebViewCache
    try {
        $compilerStage = Expand-PinnedPackageToFreshStaging `
            -PackagePath $ValidPackage `
            -CacheRoot $nestedCompilerCache
        $nestedSuccessReached = $true
    }
    finally {
        if ($null -ne $compilerStage) {
            Remove-OwnedPackageExtraction `
                -Path $compilerStage `
                -CacheRoot $nestedCompilerCache `
                -PackagePath $ValidPackage
        }
    }
}
finally {
    if ($null -ne $webViewStage) {
        Remove-OwnedPackageExtraction `
            -Path $webViewStage `
            -CacheRoot $nestedWebViewCache `
            -PackagePath $ValidPackage
    }
}
if (-not $nestedSuccessReached) {
    throw "The nested package success path did not run."
}

$webViewStage = $null
$compilerStage = $null
$buildFailureCaught = $false
try {
    try {
        $webViewStage = Expand-PinnedPackageToFreshStaging `
            -PackagePath $ValidPackage `
            -CacheRoot $nestedWebViewCache
        try {
            $compilerStage = Expand-PinnedPackageToFreshStaging `
                -PackagePath $ValidPackage `
                -CacheRoot $nestedCompilerCache
            throw "deliberate nested build failure"
        }
        finally {
            if ($null -ne $compilerStage) {
                Remove-OwnedPackageExtraction `
                    -Path $compilerStage `
                    -CacheRoot $nestedCompilerCache `
                    -PackagePath $ValidPackage
            }
        }
    }
    finally {
        if ($null -ne $webViewStage) {
            Remove-OwnedPackageExtraction `
                -Path $webViewStage `
                -CacheRoot $nestedWebViewCache `
                -PackagePath $ValidPackage
        }
    }
}
catch {
    if ($_.Exception.Message -eq "deliberate nested build failure") {
        $buildFailureCaught = $true
    }
    else {
        throw
    }
}
if (-not $buildFailureCaught) {
    throw "The deliberate nested build failure did not propagate."
}

$webViewStage = $null
$compilerStage = $null
$compilerFailureCaught = $false
try {
    try {
        $webViewStage = Expand-PinnedPackageToFreshStaging `
            -PackagePath $ValidPackage `
            -CacheRoot $nestedWebViewCache
        try {
            $compilerStage = Expand-PinnedPackageToFreshStaging `
                -PackagePath $PartialPackage `
                -CacheRoot $nestedCompilerCache
        }
        finally {
            if ($null -ne $compilerStage) {
                Remove-OwnedPackageExtraction `
                    -Path $compilerStage `
                    -CacheRoot $nestedCompilerCache `
                    -PackagePath $PartialPackage
            }
        }
    }
    finally {
        if ($null -ne $webViewStage) {
            Remove-OwnedPackageExtraction `
                -Path $webViewStage `
                -CacheRoot $nestedWebViewCache `
                -PackagePath $ValidPackage
        }
    }
}
catch {
    $compilerFailureCaught = $true
}
if (-not $compilerFailureCaught) {
    throw "The deliberate compiler-package extraction failure did not propagate."
}
$nestedStagesRemaining = @(
    Get-ChildItem -LiteralPath @($nestedWebViewCache, $nestedCompilerCache) `
        -Directory `
        -Force |
        Where-Object { $_.Name -match '^extract-[0-9a-f]{32}$' }
)
if ($nestedStagesRemaining.Count -ne 0) {
    throw "A nested compiler or WebView staging path remained after cleanup."
}

[ordered]@{
    schema = "zsec.tests.browser-package-staging.v1"
    legacy_cache_ignored = $true
    legacy_cache_preserved = $legacyPreserved
    fresh_stage_used = $true
    partial_stage_not_reused = $true
    unexpected_nested_object_failed_closed = $true
    nested_success_cleanup_verified = $nestedSuccessReached
    nested_build_failure_cleanup_verified = $buildFailureCaught
    compiler_extraction_failure_cleanup_verified = $compilerFailureCaught
} | ConvertTo-Json -Depth 3
