#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$PackageRoot,
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "TalkToAI\ZSEC Antivirus"),
    [switch]$Open,
    [switch]$PlanOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Windows PowerShell 5.1 can evaluate a script parameter's default expression
# before $PSScriptRoot is populated. Resolve the sibling package root only
# after parameter binding so the documented no-argument -File path is stable
# in both Windows PowerShell 5.1 and PowerShell 7.
if (-not $PSBoundParameters.ContainsKey("PackageRoot")) {
    $PackageRoot = $PSScriptRoot
}

function Get-NormalizedPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains('"')) {
        throw "A required path is empty or contains an invalid quote character."
    }
    return [IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Test-IsBelow {
    param([string]$Candidate, [string]$Parent)
    $child = Get-NormalizedPath $Candidate
    $root = Get-NormalizedPath $Parent
    return $child.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)
}

$DesktopRunKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$DesktopRunValueName = "ZSEC Antivirus Desktop"

function Get-ProcessIdentityRecord {
    param([Parameter(Mandatory = $true)][int]$ProcessId)
    try {
        $candidate = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction Stop
        if ($null -eq $candidate) { return $null }
        return [pscustomobject]@{
            ProcessId = [int]$candidate.ProcessId
            ExecutablePath = Get-NormalizedPath ([string]$candidate.ExecutablePath)
            Source = "cim"
        }
    }
    catch {
        try {
            $candidate = Get-Process -Id $ProcessId -ErrorAction Stop
            return [pscustomobject]@{
                ProcessId = [int]$candidate.Id
                ExecutablePath = Get-NormalizedPath ([string]$candidate.Path)
                Source = "process"
            }
        }
        catch [Microsoft.PowerShell.Commands.ProcessCommandException] {
            return $null
        }
        catch {
            throw "Cannot verify ZSEC Antivirus process $ProcessId through CIM or Get-Process: $($_.Exception.Message)"
        }
    }
}

function Get-ZsecDesktopProcessRecords {
    try {
        return @(Get-CimInstance Win32_Process -Filter "Name = 'ZSEC Antivirus.exe'" -ErrorAction Stop |
            ForEach-Object {
                [pscustomobject]@{
                    ProcessId = [int]$_.ProcessId
                    ExecutablePath = Get-NormalizedPath ([string]$_.ExecutablePath)
                    Source = "cim"
                }
            })
    }
    catch {
        try {
            return @(Get-Process -Name "ZSEC Antivirus" -ErrorAction SilentlyContinue |
                ForEach-Object {
                    [pscustomobject]@{
                        ProcessId = [int]$_.Id
                        ExecutablePath = Get-NormalizedPath ([string]$_.Path)
                        Source = "process"
                    }
                })
        }
        catch {
            throw "Cannot enumerate ZSEC Antivirus processes through CIM or Get-Process: $($_.Exception.Message)"
        }
    }
}

function Get-OwnedDesktopStartupRegistration {
    param(
        [Parameter(Mandatory = $true)][string]$ApplicationRoot,
        [Parameter(Mandatory = $true)][string]$CurrentDesktopExecutable
    )
    $ownedRoot = Get-NormalizedPath $ApplicationRoot
    $currentExecutable = Get-NormalizedPath $CurrentDesktopExecutable
    $key = Get-Item -LiteralPath $DesktopRunKeyPath -ErrorAction SilentlyContinue
    if ($null -eq $key) {
        return [ordered]@{ present = $false; owned = $false; current = $false; value = $null }
    }
    try {
        $kind = $key.GetValueKind($DesktopRunValueName)
        $value = $key.GetValue(
            $DesktopRunValueName,
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
    }
    catch [System.ArgumentException] {
        return [ordered]@{ present = $false; owned = $false; current = $false; value = $null }
    }
    if ($kind -ne [Microsoft.Win32.RegistryValueKind]::String -or $value -isnot [string]) {
        return [ordered]@{ present = $true; owned = $false; current = $false; value = $null }
    }
    $match = [regex]::Match([string]$value, '^"([^"\r\n]+)" --startup$')
    if (-not $match.Success) {
        return [ordered]@{ present = $true; owned = $false; current = $false; value = [string]$value }
    }
    try {
        $candidate = Get-NormalizedPath $match.Groups[1].Value
        Assert-RegularFile $candidate
        if (-not (Test-IsBelow -Candidate $candidate -Parent $ownedRoot)) {
            throw "outside owned root"
        }
        $relative = $candidate.Substring($ownedRoot.Length + 1).Split('\')
        $layoutOwned = (
            $relative.Count -eq 3 -and
            -not [string]::IsNullOrWhiteSpace($relative[0]) -and
            $relative[1] -eq "App" -and
            $relative[2] -eq "ZSEC Antivirus.exe"
        )
        if (-not $layoutOwned) { throw "unexpected layout" }
        return [ordered]@{
            present = $true
            owned = $true
            current = [String]::Equals(
                $candidate,
                $currentExecutable,
                [StringComparison]::OrdinalIgnoreCase
            )
            value = [string]$value
        }
    }
    catch {
        return [ordered]@{ present = $true; owned = $false; current = $false; value = [string]$value }
    }
}

function Set-OwnedDesktopStartupToCurrent {
    param(
        [Parameter(Mandatory = $true)][string]$ApplicationRoot,
        [Parameter(Mandatory = $true)][string]$CurrentDesktopExecutable
    )
    $before = Get-OwnedDesktopStartupRegistration `
        -ApplicationRoot $ApplicationRoot `
        -CurrentDesktopExecutable $CurrentDesktopExecutable
    $currentCommand = '"' + (Get-NormalizedPath $CurrentDesktopExecutable) + '" --startup'
    if (-not $before.present) {
        return [ordered]@{ state = "absent"; changed = $false; previous_value = $null }
    }
    if (-not $before.owned) {
        return [ordered]@{ state = "unowned_preserved"; changed = $false; previous_value = $null }
    }
    if ($before.current) {
        return [ordered]@{ state = "current"; changed = $false; previous_value = [string]$before.value }
    }
    try {
        Set-ItemProperty -LiteralPath $DesktopRunKeyPath -Name $DesktopRunValueName `
            -Value $currentCommand -ErrorAction Stop
        $after = Get-OwnedDesktopStartupRegistration `
            -ApplicationRoot $ApplicationRoot `
            -CurrentDesktopExecutable $CurrentDesktopExecutable
        if (-not $after.present -or -not $after.owned -or -not $after.current -or
            [string]$after.value -ne $currentCommand) {
            throw "The owned ZSEC Antivirus desktop startup migration failed read-back verification."
        }
    }
    catch {
        $migrationError = $_
        try {
            Restore-OwnedDesktopStartupRegistration -PreviousValue ([string]$before.value)
        }
        catch {
            throw (
                "The owned desktop startup migration failed and its registry rollback also failed: " +
                $migrationError.Exception.Message + " / " + $_.Exception.Message
            )
        }
        throw $migrationError
    }
    return [ordered]@{
        state = "migrated"
        changed = $true
        previous_value = [string]$before.value
    }
}

function Restore-OwnedDesktopStartupRegistration {
    param([Parameter(Mandatory = $true)][string]$PreviousValue)
    Set-ItemProperty -LiteralPath $DesktopRunKeyPath -Name $DesktopRunValueName `
        -Value $PreviousValue -ErrorAction Stop
    $key = Get-Item -LiteralPath $DesktopRunKeyPath -ErrorAction Stop
    $actual = $key.GetValue(
        $DesktopRunValueName,
        $null,
        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
    )
    if ($key.GetValueKind($DesktopRunValueName) -ne
            [Microsoft.Win32.RegistryValueKind]::String -or
        [string]$actual -ne $PreviousValue) {
        throw "The prior ZSEC Antivirus desktop startup value failed rollback verification."
    }
}

function Invoke-ObsoleteDesktopHandoff {
    param(
        [Parameter(Mandatory = $true)][string]$ApplicationRoot,
        [Parameter(Mandatory = $true)][string]$CurrentDesktopExecutable,
        [int]$GracefulWaitMilliseconds = 8000
    )
    $ownedRoot = Get-NormalizedPath $ApplicationRoot
    $currentExecutable = Get-NormalizedPath $CurrentDesktopExecutable
    $verified = @()
    $inspectionErrors = 0
    foreach ($candidate in @(Get-ZsecDesktopProcessRecords)) {
        try {
            $candidatePath = Get-NormalizedPath ([string]$candidate.ExecutablePath)
            if (
                (Test-IsBelow -Candidate $candidatePath -Parent $ownedRoot) -and
                -not [String]::Equals($candidatePath, $currentExecutable, [StringComparison]::OrdinalIgnoreCase)
            ) {
                $verified += [pscustomobject]@{
                    ProcessId = [int]$candidate.ProcessId
                    ExecutablePath = $candidatePath
                }
            }
        }
        catch { $inspectionErrors++ }
    }

    $closeRequested = 0
    foreach ($candidate in $verified) {
        try {
            $live = Get-ProcessIdentityRecord -ProcessId $candidate.ProcessId
            if ($null -eq $live) { continue }
            $livePath = [string]$live.ExecutablePath
            if (-not [String]::Equals($livePath, $candidate.ExecutablePath, [StringComparison]::OrdinalIgnoreCase)) {
                continue
            }
            $process = Get-Process -Id $candidate.ProcessId -ErrorAction Stop
            $closeRequested++
            [void]$process.CloseMainWindow()
        }
        catch { $inspectionErrors++ }
    }

    $deadline = [DateTime]::UtcNow.AddMilliseconds([Math]::Max(0, $GracefulWaitMilliseconds))
    do {
        $remaining = @($verified | Where-Object {
            $candidate = $_
            try {
                $live = Get-ProcessIdentityRecord -ProcessId $candidate.ProcessId
                if ($null -eq $live) { return $false }
                $livePath = [string]$live.ExecutablePath
                return [String]::Equals($livePath, $candidate.ExecutablePath, [StringComparison]::OrdinalIgnoreCase)
            }
            catch { throw }
        })
        if ($remaining.Count -eq 0 -or [DateTime]::UtcNow -ge $deadline) { break }
        Start-Sleep -Milliseconds 200
    } while ($true)
    $gracefullyClosed = [Math]::Max(0, $verified.Count - $remaining.Count)

    $forced = @()
    foreach ($candidate in $remaining) {
        try {
            # Re-resolve both PID and executable immediately before force. This
            # prevents a recycled PID or an outside process from being stopped.
            $live = Get-ProcessIdentityRecord -ProcessId $candidate.ProcessId
            if ($null -eq $live) { continue }
            $livePath = [string]$live.ExecutablePath
            if (
                [String]::Equals($livePath, $candidate.ExecutablePath, [StringComparison]::OrdinalIgnoreCase) -and
                (Test-IsBelow -Candidate $livePath -Parent $ownedRoot) -and
                -not [String]::Equals($livePath, $currentExecutable, [StringComparison]::OrdinalIgnoreCase)
            ) {
                Stop-Process -Id $candidate.ProcessId -Force -ErrorAction Stop
                $forced += [int]$candidate.ProcessId
            }
        }
        catch { $inspectionErrors++ }
    }
    if ($forced.Count -gt 0) { Start-Sleep -Milliseconds 500 }

    $stillRunning = 0
    foreach ($candidate in $verified) {
        try {
            $live = Get-ProcessIdentityRecord -ProcessId $candidate.ProcessId
            if ($null -ne $live) {
                $livePath = [string]$live.ExecutablePath
                if ([String]::Equals($livePath, $candidate.ExecutablePath, [StringComparison]::OrdinalIgnoreCase)) {
                    $stillRunning++
                }
            }
        }
        catch { throw }
    }
    if ($stillRunning -gt 0) {
        throw "$stillRunning verified obsolete ZSEC Antivirus process(es) remain running after handoff."
    }
    return [ordered]@{
        owned_candidates = [int]$verified.Count
        graceful_close_requested = [int]$closeRequested
        closed_during_grace_period = [int]$gracefullyClosed
        graceful_wait_milliseconds = [int]$GracefulWaitMilliseconds
        forced_process_ids = @($forced)
        forced_termination = $forced.Count -gt 0
        still_running = [int]$stillRunning
        inspection_errors = [int]$inspectionErrors
        profiles_preserved = $true
        security_products_modified = $false
    }
}

function Assert-RegularDirectory {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Expected a regular non-reparse directory: $Path"
    }
}

function Assert-RegularFile {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Expected a regular non-reparse file: $Path"
    }
}

function Remove-RegularFileIfPresent {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        Assert-RegularFile $Path
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    }
}

function Assert-DesktopShortcut {
    param(
        [Parameter(Mandatory = $true)]$Shell,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedTarget,
        [Parameter(Mandatory = $true)][string]$ExpectedWorkingDirectory
    )
    Assert-RegularFile $Path
    $shortcut = $Shell.CreateShortcut($Path)
    $actualTarget = Get-NormalizedPath ([string]$shortcut.TargetPath)
    $actualWorkingDirectory = Get-NormalizedPath ([string]$shortcut.WorkingDirectory)
    if (-not [String]::Equals(
            $actualTarget,
            (Get-NormalizedPath $ExpectedTarget),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [String]::Equals(
            $actualWorkingDirectory,
            (Get-NormalizedPath $ExpectedWorkingDirectory),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "ZSEC Antivirus shortcut target or working directory failed read-back verification: $Path"
    }
}

function Write-JsonAtomic {
    param([string]$Path, $Value)
    $temporary = "$Path.tmp-$([Guid]::NewGuid().ToString('N'))"
    $encoding = New-Object Text.UTF8Encoding($false)
    try {
        [IO.File]::WriteAllText(
            $temporary,
            (($Value | ConvertTo-Json -Depth 8) + [Environment]::NewLine),
            $encoding
        )
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Test-ManifestFiles {
    param([string]$Root, $Manifest)
    Assert-RegularDirectory $Root
    $seen = @{}
    foreach ($record in @($Manifest.files)) {
        if ($record.type -ne "file" -or [string]::IsNullOrWhiteSpace([string]$record.path)) {
            throw "The desktop manifest contains an unsupported record."
        }
        $relative = ([string]$record.path).Replace('/', '\')
        if ([IO.Path]::IsPathRooted($relative) -or $relative.Split('\') -contains '..') {
            throw "The desktop manifest contains an unsafe path: $relative"
        }
        $candidate = Get-NormalizedPath (Join-Path $Root $relative)
        if (-not (Test-IsBelow -Candidate $candidate -Parent $Root)) {
            throw "The desktop manifest path escapes the package root: $relative"
        }
        $key = $candidate.ToLowerInvariant()
        if ($seen.ContainsKey($key)) {
            throw "The desktop manifest contains a duplicate path: $relative"
        }
        $seen[$key] = $true
        Assert-RegularFile $candidate
        $file = Get-Item -LiteralPath $candidate
        if ([int64]$file.Length -ne [int64]$record.size) {
            throw "Size verification failed for $relative"
        }
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $candidate).Hash.ToLowerInvariant()
        if ($hash -ne ([string]$record.sha256).ToLowerInvariant()) {
            throw "SHA-256 verification failed for $relative"
        }
    }
}

$package = Get-NormalizedPath $PackageRoot
$productRoot = Get-NormalizedPath $InstallRoot
Assert-RegularDirectory $package
$manifestPath = Join-Path $package "DESKTOP-MANIFEST.json"
Assert-RegularFile $manifestPath
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (
    $manifest.schema -ne "zsec.antivirus.windows-desktop-distribution.v1" -or
    $manifest.product -ne "ZSEC Antivirus" -or
    [string]::IsNullOrWhiteSpace([string]$manifest.version)
) {
    throw "The desktop package manifest is not a supported ZSEC Antivirus distribution."
}
if (
    $manifest.runtime_policy.primary_antivirus -ne $false -or
    $manifest.runtime_policy.pre_access_enforcement -ne $false -or
    $manifest.runtime_policy.existing_provider_must_remain_active -ne $true -or
    $manifest.runtime_policy.automatic_provider_removal -ne $false
) {
    throw "The desktop package violates the coexistence policy."
}
Test-ManifestFiles -Root $package -Manifest $manifest

$versionRoot = Get-NormalizedPath (Join-Path (Join-Path $productRoot "App") ([string]$manifest.version))
$desktopExe = Join-Path $versionRoot "App\ZSEC Antivirus.exe"
$engineExe = Join-Path $versionRoot "Engine\zsec-shield.exe"
$companionSync = Join-Path $versionRoot "Tools\Sync-ZsecAntivirusCompanion.ps1"
$companionUninstall = Join-Path $versionRoot "Tools\Uninstall-ZsecAntivirusCompanion.ps1"
$currentPath = Join-Path $productRoot "current.json"
$desktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "ZSEC Antivirus.lnk"
$startMenuDirectory = Join-Path ([Environment]::GetFolderPath("Programs")) "ZSEC"
$startMenuShortcut = Join-Path $startMenuDirectory "ZSEC Antivirus.lnk"
$plan = [ordered]@{
    schema = "zsec.antivirus.windows-desktop-install-plan.v1"
    version = [string]$manifest.version
    source = $package
    destination = $versionRoot
    desktop_executable = $desktopExe
    engine_executable = $engineExe
    desktop_shortcut = $desktopShortcut
    start_menu_shortcut = $startMenuShortcut
    existing_provider_must_remain_active = $true
    security_products_modified = $false
    automatic_companion_lifecycle = $true
    plan_only = [bool]$PlanOnly
}
if ($PlanOnly) {
    $plan | ConvertTo-Json -Depth 8
    return
}
if (Test-Path -LiteralPath $versionRoot) {
    throw "This version is already installed; the installer never overwrites it: $versionRoot"
}

$createdVersion = $false
$rollbackRoot = $null
$currentBackup = $null
$desktopShortcutBackup = $null
$startMenuShortcutBackup = $null
$previousEngineForRollback = $null
$companionSynchronized = $false
$desktopStartupMigration = $null
try {
    if (Test-Path -LiteralPath $productRoot) {
        Assert-RegularDirectory $productRoot
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $versionRoot) | Out-Null
    Copy-Item -LiteralPath $package -Destination $versionRoot -Recurse -ErrorAction Stop
    $createdVersion = $true
    Assert-RegularDirectory $versionRoot
    Test-ManifestFiles -Root $versionRoot -Manifest $manifest
    Assert-RegularFile $desktopExe
    Assert-RegularFile $engineExe
    Assert-RegularFile $companionSync
    Assert-RegularFile $companionUninstall

    New-Item -ItemType Directory -Force -Path $productRoot | Out-Null
    $rollbackRoot = Get-NormalizedPath (Join-Path $productRoot (".install-transaction-" + [Guid]::NewGuid().ToString("N")))
    if (-not (Test-IsBelow -Candidate $rollbackRoot -Parent $productRoot)) {
        throw "The installer transaction directory escaped the owned product root."
    }
    New-Item -ItemType Directory -Path $rollbackRoot -ErrorAction Stop | Out-Null
    Assert-RegularDirectory $rollbackRoot
    $currentBackup = Join-Path $rollbackRoot "current.json"
    $desktopShortcutBackup = Join-Path $rollbackRoot "desktop-shortcut.lnk"
    $startMenuShortcutBackup = Join-Path $rollbackRoot "start-menu-shortcut.lnk"
    if (Test-Path -LiteralPath $currentPath) {
        Assert-RegularFile $currentPath
        Copy-Item -LiteralPath $currentPath -Destination $currentBackup -ErrorAction Stop
        $previousDesktop = Get-Content -LiteralPath $currentBackup -Raw -Encoding UTF8 |
            ConvertFrom-Json
        if (
            $previousDesktop.schema -ne "zsec.antivirus.windows-desktop-installation.v1" -or
            [string]::IsNullOrWhiteSpace([string]$previousDesktop.engine_executable)
        ) {
            throw "The previous desktop activation record is invalid."
        }
        $previousEngineForRollback = Get-NormalizedPath ([string]$previousDesktop.engine_executable)
        Assert-RegularFile $previousEngineForRollback
    }
    if (Test-Path -LiteralPath $desktopShortcut) {
        Assert-RegularFile $desktopShortcut
        Copy-Item -LiteralPath $desktopShortcut -Destination $desktopShortcutBackup -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $startMenuShortcut) {
        Assert-RegularFile $startMenuShortcut
        Copy-Item -LiteralPath $startMenuShortcut -Destination $startMenuShortcutBackup -ErrorAction Stop
    }

    $installed = [ordered]@{
        schema = "zsec.antivirus.windows-desktop-installation.v1"
        product = "ZSEC Antivirus"
        version = [string]$manifest.version
        installed_at = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        version_root = $versionRoot
        desktop_executable = $desktopExe
        desktop_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $desktopExe).Hash.ToLowerInvariant()
        engine_executable = $engineExe
        engine_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $engineExe).Hash.ToLowerInvariant()
        manifest_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $versionRoot "DESKTOP-MANIFEST.json")).Hash.ToLowerInvariant()
        security_products_modified = $false
        existing_provider_must_remain_active = $true
        automatic_companion_lifecycle = $true
    }

    New-Item -ItemType Directory -Force -Path $startMenuDirectory | Out-Null
    Assert-RegularDirectory $startMenuDirectory
    $shell = New-Object -ComObject WScript.Shell
    $pendingShortcuts = @(
        @{ Temporary = (Join-Path $rollbackRoot "new-desktop-shortcut.lnk"); Destination = $desktopShortcut },
        @{ Temporary = (Join-Path $rollbackRoot "new-start-menu-shortcut.lnk"); Destination = $startMenuShortcut }
    )
    foreach ($record in $pendingShortcuts) {
        $shortcut = $shell.CreateShortcut([string]$record.Temporary)
        $shortcut.TargetPath = $desktopExe
        $shortcut.WorkingDirectory = Split-Path -Parent $desktopExe
        $shortcut.Description = "ZSEC Antivirus Community desktop"
        $shortcut.IconLocation = "$desktopExe,0"
        $shortcut.Save()
        Assert-RegularFile ([string]$record.Temporary)
    }

    Write-JsonAtomic -Path $currentPath -Value $installed
    foreach ($record in $pendingShortcuts) {
        $destination = [string]$record.Destination
        Remove-RegularFileIfPresent $destination
        Move-Item -LiteralPath ([string]$record.Temporary) -Destination $destination -ErrorAction Stop
        Assert-DesktopShortcut `
            -Shell $shell `
            -Path $destination `
            -ExpectedTarget $desktopExe `
            -ExpectedWorkingDirectory (Split-Path -Parent $desktopExe)
    }

    $desktopStartupMigration = Set-OwnedDesktopStartupToCurrent `
        -ApplicationRoot (Join-Path $productRoot "App") `
        -CurrentDesktopExecutable $desktopExe

    $companionOutput = & $companionSync -CliPath $engineExe
    try {
        $companionResult = ($companionOutput -join [Environment]::NewLine) | ConvertFrom-Json
    }
    catch {
        throw "The automatic companion lifecycle command returned invalid JSON."
    }
    if (
        $companionResult.schema -ne "zsec.antivirus.windows-companion-sync-result.v1" -or
        $companionResult.activation_verified -ne $true -or
        $companionResult.decision -notin @("healthy_companion", "initializing") -or
        $companionResult.existing_provider_must_remain_active -ne $true
    ) {
        throw "The automatic companion did not pass post-install health verification."
    }
    $companionSynchronized = $true

    $obsoleteWindows = Invoke-ObsoleteDesktopHandoff `
        -ApplicationRoot (Join-Path $productRoot "App") `
        -CurrentDesktopExecutable $desktopExe

    $result = [ordered]@{
        schema = "zsec.antivirus.windows-desktop-install-result.v1"
        installed = $true
        version = [string]$manifest.version
        destination = $versionRoot
        desktop_executable = $desktopExe
        desktop_sha256 = $installed.desktop_sha256
        engine_executable = $engineExe
        engine_sha256 = $installed.engine_sha256
        shortcuts = @($desktopShortcut, $startMenuShortcut)
        signed = ((Get-AuthenticodeSignature -FilePath $desktopExe).Status -eq "Valid")
        security_products_modified = $false
        existing_provider_must_remain_active = $true
        automatic_companion_lifecycle = $true
        companion_mode = [string]$companionResult.mode
        companion_activation_verified = $true
        companion_healthy = [bool]$companionResult.healthy
        companion_decision = [string]$companionResult.decision
        obsolete_windows = $obsoleteWindows
        desktop_startup = [ordered]@{
            state = [string]$desktopStartupMigration.state
            changed = [bool]$desktopStartupMigration.changed
            read_back_verified = $true
        }
        profiles_preserved = $true
    }
    $result | ConvertTo-Json -Depth 8
    if ($Open) {
        Start-Process -FilePath $desktopExe -WorkingDirectory (Split-Path -Parent $desktopExe)
    }
    if ($null -ne $rollbackRoot -and (Test-Path -LiteralPath $rollbackRoot)) {
        Assert-RegularDirectory $rollbackRoot
        Remove-Item -LiteralPath $rollbackRoot -Recurse -Force -ErrorAction Stop
    }
}
catch {
    $installationError = $_
    try {
        if ($null -ne $desktopStartupMigration -and $desktopStartupMigration.changed -eq $true) {
            Restore-OwnedDesktopStartupRegistration `
                -PreviousValue ([string]$desktopStartupMigration.previous_value)
        }
        if ($companionSynchronized) {
            if (-not [string]::IsNullOrWhiteSpace($previousEngineForRollback)) {
                $companionRollbackOutput = & $companionSync -CliPath $previousEngineForRollback
                $companionRollback = ($companionRollbackOutput -join [Environment]::NewLine) |
                    ConvertFrom-Json
                if (
                    $companionRollback.schema -ne
                        "zsec.antivirus.windows-companion-sync-result.v1" -or
                    $companionRollback.activation_verified -ne $true
                ) {
                    throw "The prior automatic companion failed rollback verification."
                }
            }
            else {
                $companionRemovalOutput = & $companionUninstall -Confirm:$false
                $companionRemoval = ($companionRemovalOutput -join [Environment]::NewLine) |
                    ConvertFrom-Json
                if (
                    $companionRemoval.schema -ne
                        "zsec.antivirus.windows-companion-uninstall-result.v1" -or
                    $companionRemoval.removed -ne $true
                ) {
                    throw "The fresh automatic companion failed rollback verification."
                }
            }
        }
        if ($null -ne $rollbackRoot -and (Test-Path -LiteralPath $rollbackRoot)) {
            Assert-RegularDirectory $rollbackRoot
            if ($null -ne $currentBackup -and (Test-Path -LiteralPath $currentBackup -PathType Leaf)) {
                Remove-RegularFileIfPresent $currentPath
                Copy-Item -LiteralPath $currentBackup -Destination $currentPath -ErrorAction Stop
            }
            else {
                Remove-RegularFileIfPresent $currentPath
            }
            foreach ($restore in @(
                @{ Backup = $desktopShortcutBackup; Destination = $desktopShortcut },
                @{ Backup = $startMenuShortcutBackup; Destination = $startMenuShortcut }
            )) {
                $backup = [string]$restore.Backup
                $destination = [string]$restore.Destination
                Remove-RegularFileIfPresent $destination
                if (-not [string]::IsNullOrWhiteSpace($backup) -and (Test-Path -LiteralPath $backup -PathType Leaf)) {
                    Copy-Item -LiteralPath $backup -Destination $destination -ErrorAction Stop
                }
            }
            Remove-Item -LiteralPath $rollbackRoot -Recurse -Force -ErrorAction Stop
        }
    }
    catch {
        throw "ZSEC Antivirus installation failed and activation rollback also failed: $($installationError.Exception.Message); rollback: $($_.Exception.Message)"
    }
    if ($createdVersion -and (Test-Path -LiteralPath $versionRoot) -and (Test-IsBelow $versionRoot $productRoot)) {
        Remove-Item -LiteralPath $versionRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    throw $installationError
}
