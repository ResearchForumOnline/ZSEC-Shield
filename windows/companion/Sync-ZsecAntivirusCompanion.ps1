#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CliPath,
    [string]$StateDirectory = (Join-Path $env:LOCALAPPDATA "ZSEC\Shield"),
    [string]$ToolsRoot,
    [switch]$PlanOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Resolve the sibling tools directory after parameter binding. Windows
# PowerShell 5.1 may otherwise observe an empty $PSScriptRoot while evaluating
# the default expression for a script launched with -File.
if (-not $PSBoundParameters.ContainsKey("ToolsRoot")) {
    $ToolsRoot = $PSScriptRoot
}

function Get-NormalizedPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains('"')) {
        throw "A required path is empty or contains an invalid quote character."
    }
    return [IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Assert-RegularFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Expected a regular non-reparse file: $Path"
    }
}

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    Assert-RegularFile $Path
    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Invoke-JsonScript {
    param(
        [Parameter(Mandatory = $true)][string]$Script,
        [Parameter(Mandatory = $true)][object[]]$Arguments,
        [switch]$AllowNonzeroJson
    )
    Assert-RegularFile $Script
    $output = & $script:WindowsPowerShell -NoLogo -NoProfile -NonInteractive `
        -ExecutionPolicy RemoteSigned -File $Script @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -and -not $AllowNonzeroJson) {
        $detail = (($output -join " ") -replace "[\r\n]+", " ").Trim()
        throw "Companion command failed with exit code $exitCode`: $Script; $detail"
    }
    try {
        $payload = ($output -join [Environment]::NewLine) | ConvertFrom-Json
    }
    catch {
        throw "Companion command returned invalid JSON: $Script"
    }
    return $payload
}

function Invoke-CompanionInstall {
    param(
        [Parameter(Mandatory = $true)][string]$Script,
        [Parameter(Mandatory = $true)][string]$Cli,
        [Parameter(Mandatory = $true)][string]$State,
        [string[]]$Roots = @(),
        [bool]$Quarantine = $false,
        [bool]$UseDefaults = $false
    )
    Assert-RegularFile $Script
    if ($UseDefaults) {
        $output = & $Script `
            -CliPath $Cli `
            -StateDirectory $State `
            -EnableQuarantine:$Quarantine `
            -StartNow `
            -Confirm:$false
    }
    else {
        $output = & $Script `
            -CliPath $Cli `
            -StateDirectory $State `
            -ProtectedRoot $Roots `
            -EnableQuarantine:$Quarantine `
            -StartNow `
            -Confirm:$false
    }
    try {
        $payload = ($output -join [Environment]::NewLine) | ConvertFrom-Json
    }
    catch {
        throw "Companion install returned invalid JSON: $Script"
    }
    if (
        $payload.schema -ne "zsec.antivirus.windows-companion-install-result.v1" -or
        $payload.installed -ne $true -or
        $payload.started -ne $true -or
        $payload.existing_protection_must_remain_active -ne $true
    ) {
        throw "Companion install did not return a verified activation result: $Script"
    }
    return $payload
}

function Wait-CompanionActivation {
    param(
        [Parameter(Mandatory = $true)][string]$StatusScript,
        [Parameter(Mandatory = $true)][string]$State
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
    $lastStatus = $null
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        try {
            $lastStatus = Invoke-JsonScript -Script $StatusScript -Arguments @(
                "-StateDirectory", $State
            ) -AllowNonzeroJson
            $integrityReady = (
                $lastStatus.integrity.cli_hash_verified -eq $true -and
                $lastStatus.integrity.runtime_hash_verified -eq $true -and
                $lastStatus.integrity.launcher_hash_verified -eq $true
            )
            $runtimeReady = (
                $lastStatus.supervisor.registration_verified -eq $true -and
                $lastStatus.health.schema_valid -eq $true -and
                $lastStatus.health.fresh -eq $true -and
                $lastStatus.health.process_verified -eq $true -and
                $lastStatus.existing_primary_protection.aggregate_good -eq $true
            )
            if (
                $lastStatus.schema -eq "zsec.antivirus.windows-companion-status.v1" -and
                $lastStatus.decision -eq "healthy_companion" -and
                $lastStatus.healthy -eq $true -and
                $integrityReady -and
                $runtimeReady
            ) {
                return [ordered]@{
                    activation_verified = $true
                    healthy = $true
                    decision = "healthy_companion"
                    operational_state = "healthy"
                    status = $lastStatus
                }
            }
            $reasons = @($lastStatus.reasons)
            if (
                $lastStatus.schema -eq "zsec.antivirus.windows-companion-status.v1" -and
                $lastStatus.installed -eq $true -and
                $lastStatus.decision -eq "degraded" -and
                $lastStatus.healthy -eq $false -and
                $reasons.Count -eq 1 -and
                $reasons[0] -eq "watch session reports baselining" -and
                $lastStatus.health.last_record.operational_state -eq "baselining" -and
                $integrityReady -and
                $runtimeReady
            ) {
                return [ordered]@{
                    activation_verified = $true
                    healthy = $false
                    decision = "initializing"
                    operational_state = "baselining"
                    status = $lastStatus
                }
            }
        }
        catch {
            $lastStatus = $null
        }
        Start-Sleep -Milliseconds 500
    }
    $reason = if ($null -eq $lastStatus) {
        "no valid status was returned"
    }
    else {
        "decision=$($lastStatus.decision); reasons=$(@($lastStatus.reasons) -join '; ')"
    }
    throw "The automatic companion did not produce verified activation within 30 seconds: $reason"
}

function Get-RollbackInstaller {
    param(
        [Parameter(Mandatory = $true)][string]$PreviousCli,
        [Parameter(Mandatory = $true)][string]$Fallback
    )
    $engineRoot = Split-Path -Parent (Get-NormalizedPath $PreviousCli)
    $versionRoot = Split-Path -Parent $engineRoot
    $candidate = Join-Path $versionRoot "Tools\Install-ZsecAntivirusCompanion.ps1"
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        Assert-RegularFile $candidate
        return $candidate
    }
    return $Fallback
}

function Move-PartialCompanionAside {
    param(
        [Parameter(Mandatory = $true)][string]$State,
        [Parameter(Mandatory = $true)]$PreviousInstallation
    )
    $root = Join-Path $State "companion"
    $marker = Join-Path $root "installation.json"
    if (-not (Test-Path -LiteralPath $root -PathType Container) -or
        (Test-Path -LiteralPath $marker -PathType Leaf)) {
        return $null
    }
    $rootItem = Get-Item -LiteralPath $root -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Partial companion root is a reparse point; refusing recovery move."
    }
    $allowed = @{}
    foreach ($path in @($PreviousInstallation.generated_files)) {
        $allowed[[IO.Path]::GetFileName([string]$path).ToLowerInvariant()] = $true
    }
    foreach ($item in @(Get-ChildItem -LiteralPath $root -Force)) {
        if ($item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            -not $allowed.ContainsKey($item.Name.ToLowerInvariant())) {
            throw "Partial companion root contains an unexpected recovery item: $($item.Name)"
        }
    }
    $recovery = Join-Path $State ("companion.rollback-recovery-" + [Guid]::NewGuid().ToString("N"))
    Move-Item -LiteralPath $root -Destination $recovery -ErrorAction Stop
    return $recovery
}

function Get-MigratedProtectedRoots {
    param(
        [Parameter(Mandatory = $true)]$PreviousInstallation,
        [Parameter(Mandatory = $true)][string]$State
    )
    $volatileTemp = (Get-NormalizedPath ([IO.Path]::GetTempPath())).ToLowerInvariant()
    $values = New-Object Collections.Generic.List[string]
    $seen = @{}
    foreach ($candidate in @(
        @($PreviousInstallation.protected_roots) +
        @(
            ([Environment]::GetFolderPath("Desktop")),
            (Join-Path $env:USERPROFILE "Downloads"),
            ([Environment]::GetFolderPath("MyDocuments"))
        )
    )) {
        if ([string]::IsNullOrWhiteSpace([string]$candidate)) { continue }
        $normalized = Get-NormalizedPath ([string]$candidate)
        if ($normalized.ToLowerInvariant() -eq $volatileTemp) { continue }
        if (-not (Test-Path -LiteralPath $normalized -PathType Container)) { continue }
        $item = Get-Item -LiteralPath $normalized -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        $key = $normalized.ToLowerInvariant()
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $values.Add($normalized)
        }
    }
    if ($values.Count -lt 1) {
        throw "No safe nonvolatile protected root is available for companion migration."
    }
    return @($values)
}

$cli = Get-NormalizedPath $CliPath
$state = Get-NormalizedPath $StateDirectory
$tools = Get-NormalizedPath $ToolsRoot
$script:WindowsPowerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
$installScript = Join-Path $tools "Install-ZsecAntivirusCompanion.ps1"
$uninstallScript = Join-Path $tools "Uninstall-ZsecAntivirusCompanion.ps1"
$statusScript = Join-Path $tools "Get-ZsecAntivirusCompanionStatus.ps1"
foreach ($path in @($cli, $script:WindowsPowerShell, $installScript, $uninstallScript, $statusScript)) {
    Assert-RegularFile $path
}

$installationPath = Join-Path $state "companion\installation.json"
$configPath = Join-Path $state "companion\config.json"
$previousInstallation = $null
$previousConfig = $null
$migratedRoots = @()
if (Test-Path -LiteralPath $installationPath -PathType Leaf) {
    $previousInstallation = Read-JsonFile $installationPath
    $previousConfig = Read-JsonFile $configPath
    if (
        $previousInstallation.schema -ne "zsec.antivirus.windows-companion-installation.v1" -or
        $previousInstallation.product -ne "ZSEC Antivirus" -or
        $previousConfig.schema -ne "zsec.antivirus.windows-companion.v1" -or
        $previousConfig.product -ne "ZSEC Antivirus"
    ) {
        throw "The existing companion does not have a supported trusted installation contract."
    }
    $migratedRoots = Get-MigratedProtectedRoots `
        -PreviousInstallation $previousInstallation `
        -State $state
}

$mode = if ($null -eq $previousInstallation) {
    "fresh_install"
}
elseif ((Get-NormalizedPath ([string]$previousInstallation.cli_path)) -eq $cli) {
    "verify_existing"
}
else {
    "upgrade"
}
$plan = [ordered]@{
    schema = "zsec.antivirus.windows-companion-sync-plan.v1"
    product = "ZSEC Antivirus"
    mode = $mode
    cli_path = $cli
    state_directory = $state
    existing_provider_must_remain_active = $true
    automatic_provider_changes = $false
    rollback_available = ($null -ne $previousInstallation)
    legacy_temp_root_retired = $(if ($null -eq $previousInstallation) { $false } else {
        @($previousInstallation.protected_roots | Where-Object {
            (Get-NormalizedPath ([string]$_)).ToLowerInvariant() -eq
                (Get-NormalizedPath ([IO.Path]::GetTempPath())).ToLowerInvariant()
        }).Count -gt 0
    })
    plan_only = [bool]$PlanOnly
}
if ($PlanOnly) {
    $plan | ConvertTo-Json -Depth 8
    return
}

if ($mode -eq "verify_existing") {
    $activation = Wait-CompanionActivation -StatusScript $statusScript -State $state
    [ordered]@{
        schema = "zsec.antivirus.windows-companion-sync-result.v1"
        product = "ZSEC Antivirus"
        mode = $mode
        changed = $false
        activation_verified = $true
        healthy = $activation.healthy
        decision = $activation.decision
        operational_state = $activation.operational_state
        rollback_performed = $false
        existing_provider_must_remain_active = $true
    } | ConvertTo-Json -Depth 8
    return
}

$removedPrevious = $false
try {
    if ($null -ne $previousInstallation) {
        $null = Invoke-JsonScript -Script $uninstallScript -Arguments @(
            "-StateDirectory", $state
        )
        $removedPrevious = $true
    }
    if ($null -ne $previousInstallation) {
        $roots = @($migratedRoots)
        if ($roots.Count -lt 1) {
            throw "The previous companion has no protected roots to migrate."
        }
        $null = Invoke-CompanionInstall `
            -Script $installScript `
            -Cli $cli `
            -State $state `
            -Roots $roots `
            -Quarantine ($previousConfig.quarantine_enabled -eq $true)
    }
    else {
        $null = Invoke-CompanionInstall `
            -Script $installScript `
            -Cli $cli `
            -State $state `
            -UseDefaults $true
    }
    $activation = Wait-CompanionActivation -StatusScript $statusScript -State $state
    [ordered]@{
        schema = "zsec.antivirus.windows-companion-sync-result.v1"
        product = "ZSEC Antivirus"
        mode = $mode
        changed = $true
        activation_verified = $true
        healthy = $activation.healthy
        decision = $activation.decision
        operational_state = $activation.operational_state
        rollback_performed = $false
        existing_provider_must_remain_active = $true
    } | ConvertTo-Json -Depth 8
}
catch {
    $syncError = $_
    if ($null -ne $previousInstallation) {
        try {
            try {
                $null = Invoke-JsonScript -Script $uninstallScript -Arguments @(
                    "-StateDirectory", $state
                )
            }
            catch {
                $null = Move-PartialCompanionAside `
                    -State $state `
                    -PreviousInstallation $previousInstallation
            }
            $null = Move-PartialCompanionAside `
                -State $state `
                -PreviousInstallation $previousInstallation
            $rollbackInstaller = Get-RollbackInstaller `
                -PreviousCli ([string]$previousInstallation.cli_path) `
                -Fallback $installScript
            $null = Invoke-CompanionInstall `
                -Script $rollbackInstaller `
                -Cli ([string]$previousInstallation.cli_path) `
                -State $state `
                -Roots @($previousInstallation.protected_roots) `
                -Quarantine ($previousConfig.quarantine_enabled -eq $true)
            $null = Wait-CompanionActivation -StatusScript $statusScript -State $state
        }
        catch {
            throw (
                "Automatic companion sync failed and rollback also failed: " +
                "$($syncError.Exception.Message); rollback: $($_.Exception.Message)"
            )
        }
        throw "Automatic companion sync failed; the prior healthy companion was restored: $($syncError.Exception.Message)"
    }
    throw $syncError
}
