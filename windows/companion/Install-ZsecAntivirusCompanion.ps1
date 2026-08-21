#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
param(
    [string]$CliPath = "",
    [string]$ProtectedRoot = (Join-Path $env:USERPROFILE "Downloads"),
    [string]$StateDirectory = (Join-Path $env:LOCALAPPDATA "ZSEC\Shield"),
    [switch]$EnableQuarantine,
    [switch]$StartNow,
    [switch]$PlanOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProductName = "ZSEC Antivirus"
$TaskDescription = (
    "ZSEC Antivirus per-user companion v1. Foreground post-change monitoring only; " +
    "not primary antivirus or pre-access enforcement. Existing protection stays active."
)

function Get-NormalizedPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains('"')) {
        throw "A required path is empty or contains an invalid quote character."
    }
    return [System.IO.Path]::GetFullPath($Path)
}

function Test-IsPathBelow {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$Parent
    )
    $normalizedCandidate = (Get-NormalizedPath $Candidate).TrimEnd('\')
    $normalizedParent = (Get-NormalizedPath $Parent).TrimEnd('\')
    return $normalizedCandidate.StartsWith(
        $normalizedParent + '\',
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Assert-RegularNonReparseFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Expected a regular, non-reparse file: $Path"
    }
}

function Assert-RegularNonReparseDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Expected a regular, non-reparse directory: $Path"
    }
}

function Write-Utf8JsonAtomic {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )
    $temporary = "$Path.tmp-$([Guid]::NewGuid().ToString('N'))"
    $encoding = New-Object System.Text.UTF8Encoding($false)
    try {
        [System.IO.File]::WriteAllText(
            $temporary,
            (($Value | ConvertTo-Json -Depth 10) + [Environment]::NewLine),
            $encoding
        )
        Move-Item -LiteralPath $temporary -Destination $Path -ErrorAction Stop
    }
    finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [System.IO.File]::OpenRead($Path)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $algorithm.ComputeHash($stream)
        return ([System.BitConverter]::ToString($digest)).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
        $stream.Dispose()
    }
}

if ($PSVersionTable.PSEdition -eq "Core" -and -not $IsWindows) {
    throw "ZSEC Antivirus companion installation is supported only on Windows."
}

Import-Module ScheduledTasks -ErrorAction Stop
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $identity.User) {
    throw "Could not resolve the current Windows user SID."
}
$ownerSid = $identity.User.Value
$ownerName = $identity.Name
$taskName = "ZSEC Antivirus Companion - $ownerSid"
$taskPath = "\"

if ([string]::IsNullOrWhiteSpace($CliPath)) {
    $command = Get-Command "zero-security.exe" -CommandType Application -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        $command = Get-Command "zsec-shield.exe" -CommandType Application -ErrorAction SilentlyContinue
    }
    if ($null -eq $command) {
        throw "Cannot find zero-security.exe or zsec-shield.exe; pass -CliPath explicitly."
    }
    $CliPath = $command.Source
}

$cli = Get-NormalizedPath $CliPath
$protected = Get-NormalizedPath $ProtectedRoot
$state = Get-NormalizedPath $StateDirectory
Assert-RegularNonReparseFile $cli
Assert-RegularNonReparseDirectory $protected
if ((Get-NormalizedPath $protected).TrimEnd('\') -eq (Get-NormalizedPath $state).TrimEnd('\')) {
    throw "The protected root cannot be the ZSEC state directory."
}
if (Test-IsPathBelow -Candidate $protected -Parent $state) {
    throw "The protected root cannot be located below the excluded ZSEC state directory."
}

$installRoot = Join-Path $state "companion"
$configPath = Join-Path $installRoot "config.json"
$installationPath = Join-Path $installRoot "installation.json"
$launcherPath = Join-Path $installRoot "Start-ZsecAntivirusCompanion.ps1"
$healthPath = Join-Path $installRoot "health.json"
$eventLogPath = Join-Path $installRoot "events.ndjson"
$stdoutPath = Join-Path $installRoot "last.stdout.log"
$stderrPath = Join-Path $installRoot "last.stderr.log"
$sourceLauncher = Join-Path $PSScriptRoot "Start-ZsecAntivirusCompanion.ps1"
Assert-RegularNonReparseFile $sourceLauncher

$powerShellExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
Assert-RegularNonReparseFile $powerShellExe
$taskArguments = (
    '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy RemoteSigned ' +
    "-File `"$launcherPath`" -ConfigPath `"$configPath`""
)
$cliHash = Get-Sha256 $cli
$launcherHash = Get-Sha256 $sourceLauncher
$runtimeOutput = & $cli "runtime-identity" "--json" 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "The ZSEC Antivirus CLI could not report its read-only runtime identity."
}
try {
    $runtimeIdentity = ($runtimeOutput -join [Environment]::NewLine) | ConvertFrom-Json
}
catch {
    throw "The ZSEC Antivirus CLI returned an invalid runtime identity."
}
if (
    $runtimeIdentity.schema -ne "zsec.antivirus.runtime-identity.v1" -or
    $runtimeIdentity.product -ne $ProductName -or
    $runtimeIdentity.engine -ne "ZSEC Shield" -or
    $runtimeIdentity.read_only -ne $true
) {
    throw "The ZSEC Antivirus CLI returned an untrusted runtime identity."
}
$runtimeExecutable = Get-NormalizedPath ([string]$runtimeIdentity.runtime_executable)
Assert-RegularNonReparseFile $runtimeExecutable
$runtimeHash = Get-Sha256 $runtimeExecutable
if ($runtimeHash -ne ([string]$runtimeIdentity.runtime_sha256).ToLowerInvariant()) {
    throw "The ZSEC Antivirus runtime identity failed its SHA-256 check."
}

$existingTask = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
if ($null -ne $existingTask) {
    throw (
        "A Scheduled Task already exists at $taskPath$taskName. " +
        "This installer never overwrites a task; review or uninstall it first."
    )
}

$plan = [ordered]@{
    schema = "zsec.antivirus.windows-companion-plan.v1"
    product = $ProductName
    owner_sid = $ownerSid
    owner_name = $ownerName
    task_name = $taskName
    task_path = $taskPath
    trigger = "current-user-logon"
    principal = "InteractiveToken / LeastPrivilege"
    task_action_execute = $powerShellExe
    task_action_arguments = $taskArguments
    cli_path = $cli
    cli_sha256 = $cliHash
    runtime_executable = $runtimeExecutable
    runtime_sha256 = $runtimeHash
    protected_roots = @($protected)
    state_directory = $state
    install_root = $installRoot
    quarantine_enabled = [bool]$EnableQuarantine
    settings = [ordered]@{
        multiple_instances = "IgnoreNew"
        priority = 8
        restart_count = 3
        restart_interval_seconds = 60
        start_when_available = $true
        execution_time_limit = "unlimited"
    }
    resource_bounds = [ordered]@{
        serial_scanner = $true
        event_queue_size = 2048
        max_file_bytes = 67108864
        chunk_bytes = 1048576
        event_log_max_bytes = 4194304
        event_log_backups = 3
        process_priority = "BelowNormal"
    }
    health = [ordered]@{
        heartbeat_seconds = 30
        health_file = $healthPath
        stale_after_seconds = 105
    }
    policy = [ordered]@{
        primary_antivirus = $false
        real_time_protection = $false
        pre_access_enforcement = $false
        windows_security_registration = $false
        existing_protection_must_remain_active = $true
        automatic_provider_changes = $false
        primary_provider_uninstall_allowed = $false
        cutover_allowed = $false
    }
    plan_only = [bool]$PlanOnly
}

if ($PlanOnly) {
    $plan | ConvertTo-Json -Depth 10
    return
}
if (-not $PSCmdlet.ShouldProcess("$taskPath$taskName", "Install per-user companion")) {
    $plan | ConvertTo-Json -Depth 10
    return
}

$installRootPreexisted = Test-Path -LiteralPath $installRoot
if ($installRootPreexisted) {
    Assert-RegularNonReparseDirectory $installRoot
    if ($null -ne (Get-ChildItem -LiteralPath $installRoot -Force | Select-Object -First 1)) {
        throw "The companion install directory already exists and is not empty: $installRoot"
    }
}

$registeredByThisRun = $false
try {
    if (-not $installRootPreexisted) {
        New-Item -ItemType Directory -Path $installRoot -Force:$false | Out-Null
    }
    Copy-Item -LiteralPath $sourceLauncher -Destination $launcherPath -ErrorAction Stop
    Assert-RegularNonReparseFile $launcherPath
    $copiedLauncherHash = Get-Sha256 $launcherPath
    if ($copiedLauncherHash -ne $launcherHash) {
        throw "The installed companion launcher failed its SHA-256 copy check."
    }

    $installedAt = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $config = [ordered]@{
        schema = "zsec.antivirus.windows-companion.v1"
        product = $ProductName
        engine = "ZSEC Shield"
        owner_sid = $ownerSid
        task_name = $taskName
        cli_path = $cli
        cli_sha256 = $cliHash
        runtime_executable = $runtimeExecutable
        runtime_sha256 = $runtimeHash
        state_directory = $state
        protected_roots = @($protected)
        backend = "auto"
        debounce_seconds = 0.75
        poll_seconds = 1.0
        reconcile_seconds = 300.0
        heartbeat_seconds = 30.0
        event_queue_size = 2048
        max_file_bytes = 67108864
        chunk_bytes = 1048576
        health_file = $healthPath
        event_log = $eventLogPath
        event_log_max_bytes = 4194304
        event_log_backups = 3
        stdout_file = $stdoutPath
        stderr_file = $stderrPath
        quarantine_enabled = [bool]$EnableQuarantine
        installed_at = $installedAt
        policy = $plan.policy
    }
    $installation = [ordered]@{
        schema = "zsec.antivirus.windows-companion-installation.v1"
        product = $ProductName
        installed_at = $installedAt
        owner_sid = $ownerSid
        owner_name = $ownerName
        task_name = $taskName
        task_path = $taskPath
        task_description = $TaskDescription
        task_action_execute = $powerShellExe
        task_action_arguments = $taskArguments
        cli_path = $cli
        cli_sha256 = $cliHash
        runtime_executable = $runtimeExecutable
        runtime_sha256 = $runtimeHash
        launcher_path = $launcherPath
        launcher_sha256 = $launcherHash
        config_path = $configPath
        install_root = $installRoot
        install_root_preexisted = [bool]$installRootPreexisted
        state_directory = $state
        protected_roots = @($protected)
        generated_files = @(
            $configPath,
            $installationPath,
            $launcherPath,
            $healthPath,
            $eventLogPath,
            $stdoutPath,
            $stderrPath
        )
        policy = $plan.policy
    }
    Write-Utf8JsonAtomic -Path $configPath -Value $config
    Write-Utf8JsonAtomic -Path $installationPath -Value $installation

    $action = New-ScheduledTaskAction `
        -Execute $powerShellExe `
        -Argument $taskArguments `
        -WorkingDirectory $installRoot
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $ownerName
    $principal = New-ScheduledTaskPrincipal `
        -UserId $ownerName `
        -LogonType Interactive `
        -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet `
        -MultipleInstances IgnoreNew `
        -Priority 8 `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries
    $definition = New-ScheduledTask `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description $TaskDescription
    Register-ScheduledTask `
        -TaskName $taskName `
        -TaskPath $taskPath `
        -InputObject $definition | Out-Null
    $registeredByThisRun = $true

    $registered = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop
    if ($registered.Description -ne $TaskDescription) {
        throw "Scheduled Task description verification failed."
    }
    if (@($registered.Actions).Count -ne 1) {
        throw "Scheduled Task action-count verification failed."
    }
    if (
        $registered.Actions[0].Execute -ne $powerShellExe -or
        $registered.Actions[0].Arguments -ne $taskArguments
    ) {
        throw "Scheduled Task action read-back verification failed."
    }
    if ($registered.Principal.UserId -ne $ownerName) {
        throw "Scheduled Task principal read-back verification failed."
    }
    if ($registered.Settings.MultipleInstances.ToString() -ne "IgnoreNew") {
        throw "Scheduled Task single-instance setting verification failed."
    }

    if ($StartNow) {
        Start-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop
    }

    [ordered]@{
        schema = "zsec.antivirus.windows-companion-install-result.v1"
        product = $ProductName
        installed = $true
        started = [bool]$StartNow
        task_name = $taskName
        task_path = $taskPath
        config_path = $configPath
        health_command = (
            "powershell.exe -NoProfile -File `"" +
            (Join-Path $PSScriptRoot "Get-ZsecAntivirusCompanionStatus.ps1") + "`""
        )
        existing_protection_must_remain_active = $true
    } | ConvertTo-Json -Depth 6
}
catch {
    if ($registeredByThisRun) {
        Unregister-ScheduledTask `
            -TaskName $taskName `
            -TaskPath $taskPath `
            -Confirm:$false `
            -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $installRoot) {
        if ($installRootPreexisted) {
            foreach ($path in @($configPath, $installationPath, $launcherPath)) {
                if (Test-Path -LiteralPath $path -PathType Leaf) {
                    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
                }
            }
        }
        else {
            Remove-Item -LiteralPath $installRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    throw
}
