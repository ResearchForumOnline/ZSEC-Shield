[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$RequirementsPath,

    [switch]$FetchChromium,

    [string]$Confirmation,

    [switch]$JsonAudit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RequirementsPath)) {
    $RequirementsPath = Join-Path $PSScriptRoot '..\toolchain.requirements.json'
}

Import-Module (Join-Path $PSScriptRoot 'ZsecChromiumBootstrap.psm1') -Force

$requirements = Get-ZsecChromiumRequirements -Path $RequirementsPath
$audit = Invoke-ZsecChromiumAudit -RequirementsPath $RequirementsPath

if ($JsonAudit) {
    $audit | ConvertTo-Json -Depth 32
}
else {
    Format-ZsecChromiumAudit -Audit $audit
}

if (-not [bool]$audit.passed) {
    [Console]::Error.WriteLine('Bootstrap refused: one or more pinned host/toolchain checks failed. No directory was created and Chromium was not fetched.')
    exit 2
}

if (-not $FetchChromium) {
    'Audit-only mode complete. No files were fetched or changed.'
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

$depotRoot = ConvertTo-ZsecNormalizedPath -Path ([string]$requirements.depot_tools.root)
$fetchPath = ConvertTo-ZsecNormalizedPath -Path (Join-Path $depotRoot 'fetch.bat')
$targetPath = ConvertTo-ZsecNormalizedPath -Path ([string]$requirements.checkout.target)
$gitCachePath = ConvertTo-ZsecNormalizedPath -Path ([string]$requirements.checkout.git_cache)

if (-not (Test-Path -LiteralPath $fetchPath -PathType Leaf)) {
    [Console]::Error.WriteLine("Fetch refused: pinned fetch tool is missing: $fetchPath")
    exit 5
}
if ($targetPath -match '\s' -or $gitCachePath -match '\s') {
    [Console]::Error.WriteLine('Fetch refused: checkout and cache paths must not contain whitespace.')
    exit 6
}
if (Test-Path -LiteralPath $targetPath) {
    [Console]::Error.WriteLine("Fetch refused: target already exists. This wrapper never overwrites or deletes it: $targetPath")
    exit 7
}

$fetchArguments = @($requirements.checkout.fetch_arguments | ForEach-Object { [string]$_ })
$fetchArguments += [string]$requirements.checkout.fetch_configuration

if (-not $PSCmdlet.ShouldProcess(
        $targetPath,
        "Create checkout directory and execute $fetchPath $($fetchArguments -join ' ')"
    )) {
    'WhatIf/confirmation stopped the fetch. No checkout was created.'
    exit 0
}

# Mutation begins only after every audit and explicit-confirmation gate above.
$null = New-Item -ItemType Directory -Path $targetPath -ErrorAction Stop
$null = New-Item -ItemType Directory -Path $gitCachePath -Force -ErrorAction Stop
$env:GIT_CACHE_PATH = $gitCachePath

Push-Location -LiteralPath $targetPath
try {
    & $fetchPath @fetchArguments
    if ($LASTEXITCODE -ne 0) {
        throw "fetch.bat failed with exit code $LASTEXITCODE. The partial checkout was preserved for review; nothing was deleted."
    }
}
finally {
    Pop-Location
}

$gclientMarker = Join-Path $targetPath '.gclient'
$sourceMarker = Join-Path $targetPath 'src\chrome\BUILD.gn'
if (-not (Test-Path -LiteralPath $gclientMarker -PathType Leaf) -or
    -not (Test-Path -LiteralPath $sourceMarker -PathType Leaf)) {
    [Console]::Error.WriteLine('Fetch returned success but required Chromium checkout markers are missing. Treat the checkout as incomplete.')
    exit 8
}

'Chromium source checkout completed. No build, antivirus change, Chrome branding, signing, installation, or deployment was performed.'
"Next reviewed target: autoninja -C out\ZsecDev $($requirements.checkout.initial_build_target)"
exit 0
