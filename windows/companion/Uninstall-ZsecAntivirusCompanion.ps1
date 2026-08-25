#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
param(
    [string]$StateDirectory = (Join-Path $env:LOCALAPPDATA "ZSEC\Shield"),
    [switch]$PlanOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$RunKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$RunValueName = "ZSEC Antivirus Companion"

function Get-NormalizedPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [System.IO.Path]::GetFullPath($Path)
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

function Assert-RegularNonReparseFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Expected a regular, non-reparse file: $Path"
    }
}

function Test-OwnedSupervisorMutexPresent {
    param([Parameter(Mandatory = $true)][string]$OwnerSid)
    $mutexName = "Local\ZSEC-Antivirus-Companion-$OwnerSid"
    try {
        $mutex = [System.Threading.Mutex]::OpenExisting($mutexName)
    }
    catch [System.Threading.WaitHandleCannotBeOpenedException] {
        return $false
    }
    try {
        return $true
    }
    finally {
        $mutex.Dispose()
    }
}

function Get-LatestSupervisorLifecycleRecord {
    param([Parameter(Mandatory = $true)][string]$Path)
    Assert-RegularNonReparseFile $Path
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.Length -lt 1 -or $item.Length -gt 1048576) {
        throw "Supervisor lifecycle evidence size is invalid; refusing process termination."
    }
    $lines = [System.IO.File]::ReadAllLines($Path)
    $latest = $null
    for ($index = $lines.Count - 1; $index -ge 0; $index--) {
        if (-not [string]::IsNullOrWhiteSpace($lines[$index])) {
            $latest = $lines[$index]
            break
        }
    }
    if ($null -eq $latest -or $latest.Length -gt 4096) {
        throw "Supervisor lifecycle evidence has no bounded latest record."
    }
    try {
        $record = $latest | ConvertFrom-Json
    }
    catch {
        throw "Supervisor lifecycle evidence is invalid; refusing process termination."
    }
    $expectedFields = @(
        "schema", "event", "generated_at", "supervisor_process_id",
        "watcher_process_id", "exit_code", "lifetime_milliseconds",
        "rapid_failure_count", "restart_scheduled", "restart_delay_seconds", "reason"
    )
    $actualFields = @($record.PSObject.Properties.Name | Sort-Object)
    $wantedFields = @($expectedFields | Sort-Object)
    $allowedReasons = @{
        supervisor_started = "supervisor_lock_acquired"
        watcher_started = "watcher_process_started"
        watcher_exited = @(
            "watcher_exit_restart_scheduled",
            "watcher_exit_rapid_failure_limit"
        )
    }
    if (
        @(Compare-Object -ReferenceObject $wantedFields -DifferenceObject $actualFields).Count -ne 0 -or
        $record.schema -ne "zsec.antivirus.supervisor-event.v1" -or
        $record.event -notin @("supervisor_started", "watcher_started", "watcher_exited") -or
        $record.reason -notin @($allowedReasons[[string]$record.event]) -or
        ($record.supervisor_process_id -isnot [int] -and
            $record.supervisor_process_id -isnot [long]) -or
        $record.supervisor_process_id -lt 1 -or
        $record.supervisor_process_id -gt [int]::MaxValue
    ) {
        throw "Supervisor lifecycle identity is invalid; refusing process termination."
    }
    try {
        $generatedAt = ([DateTimeOffset]$record.generated_at).ToUniversalTime()
    }
    catch {
        throw "Supervisor lifecycle timestamp is invalid; refusing process termination."
    }
    return [ordered]@{
        process_id = [int]$record.supervisor_process_id
        generated_at = $generatedAt
    }
}

function Get-OwnedHkcuSupervisorProcess {
    param(
        [Parameter(Mandatory = $true)]$Installation,
        [Parameter(Mandatory = $true)][string]$LifecyclePath,
        [Parameter(Mandatory = $true)][string]$ExpectedCommandLine
    )
    $ownerSid = [string]$Installation.owner_sid
    if (-not (Test-OwnedSupervisorMutexPresent -OwnerSid $ownerSid)) {
        return $null
    }
    if (-not (Test-Path -LiteralPath $LifecyclePath -PathType Leaf)) {
        throw "Owned supervisor mutex is active but lifecycle identity is absent; refusing removal."
    }
    $lifecycle = Get-LatestSupervisorLifecycleRecord -Path $LifecyclePath
    $candidate = Get-CimInstance `
        -ClassName Win32_Process `
        -Filter "ProcessId = $($lifecycle.process_id)" `
        -ErrorAction Stop
    if ($null -eq $candidate) {
        if (Test-OwnedSupervisorMutexPresent -OwnerSid $ownerSid) {
            throw "Owned supervisor mutex is active but its recorded PID is absent; refusing removal."
        }
        return $null
    }
    $owner = Invoke-CimMethod -InputObject $candidate -MethodName GetOwnerSid -ErrorAction Stop
    $expectedExecutable = Get-NormalizedPath ([string]$Installation.task_action_execute)
    $unquotedCommandLine = "$expectedExecutable $($Installation.task_action_arguments)"
    # Win32_Process can retain Start-Process's single trailing separator. Remove
    # trailing whitespace only; the executable and every argument remain exact.
    $observedCommandLine = ([string]$candidate.CommandLine).TrimEnd()
    try {
        $createdAt = ([DateTimeOffset]$candidate.CreationDate).ToUniversalTime()
    }
    catch {
        throw "Supervisor process creation time is invalid; refusing process termination."
    }
    if (
        $owner.ReturnValue -ne 0 -or
        [string]$owner.Sid -ne $ownerSid -or
        [int]$candidate.ProcessId -ne [int]$lifecycle.process_id -or
        (Get-NormalizedPath ([string]$candidate.ExecutablePath)) -ne $expectedExecutable -or
        $observedCommandLine -notin @($ExpectedCommandLine, $unquotedCommandLine) -or
        $createdAt -gt $lifecycle.generated_at.AddSeconds(5)
    ) {
        throw "Supervisor PID does not match the exact owned HKCU runtime; refusing process termination."
    }
    return $candidate
}

function Stop-OwnedHkcuSupervisorProcess {
    param(
        [Parameter(Mandatory = $true)]$Installation,
        [Parameter(Mandatory = $true)][string]$LifecyclePath,
        [Parameter(Mandatory = $true)][string]$ExpectedCommandLine
    )
    $candidate = Get-OwnedHkcuSupervisorProcess `
        -Installation $Installation `
        -LifecyclePath $LifecyclePath `
        -ExpectedCommandLine $ExpectedCommandLine
    if ($null -eq $candidate) {
        return $false
    }
    Stop-Process -Id ([int]$candidate.ProcessId) -Force -ErrorAction Stop
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(10)
    do {
        Start-Sleep -Milliseconds 100
        $remaining = Get-CimInstance `
            -ClassName Win32_Process `
            -Filter "ProcessId = $([int]$candidate.ProcessId)" `
            -ErrorAction Stop
    } while ($null -ne $remaining -and [DateTimeOffset]::UtcNow -lt $deadline)
    if ($null -ne $remaining) {
        throw "Owned HKCU supervisor did not stop; refusing state deletion."
    }
    return $true
}

function Get-RunRegistration {
    if (-not (Test-Path -LiteralPath $RunKeyPath -PathType Container)) {
        return [ordered]@{ present = $false; value_data = $null }
    }
    $key = Get-Item -LiteralPath $RunKeyPath -ErrorAction Stop
    if ($key.GetValueNames() -notcontains $RunValueName) {
        return [ordered]@{ present = $false; value_data = $null }
    }
    return [ordered]@{
        present = $true
        value_data = [string]$key.GetValue(
            $RunValueName,
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
    }
}

function Stop-OwnedHeartbeatProcess {
    param(
        [Parameter(Mandatory = $true)]$Installation,
        [Parameter(Mandatory = $true)][string]$HealthPath
    )
    if (-not (Test-Path -LiteralPath $HealthPath -PathType Leaf)) {
        return $false
    }
    $health = Get-Content -LiteralPath $HealthPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (
        $health.schema -ne "zsec.antivirus.companion-health.v1" -or
        $health.product -ne "ZSEC Antivirus" -or
        (Get-NormalizedPath ([string]$health.runtime_executable)) -ne
            (Get-NormalizedPath ([string]$Installation.runtime_executable)) -or
        ([string]$health.runtime_sha256).ToLowerInvariant() -ne
            ([string]$Installation.runtime_sha256).ToLowerInvariant()
    ) {
        throw "Heartbeat identity does not match this installation; refusing process termination."
    }
    $process = Get-Process -Id ([int]$health.process_id) -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        return $false
    }
    # ConvertFrom-Json returns a string in Windows PowerShell and a DateTime in
    # PowerShell 7. Cast either representation directly so process ownership
    # validation cannot become locale-dependent.
    $updatedAt = ([DateTimeOffset]$health.updated_at).ToUniversalTime()
    $maximumAge = [double]$health.heartbeat_seconds * 3.0 + 15.0
    $age = ([DateTimeOffset]::UtcNow - $updatedAt).TotalSeconds
    if ($age -lt -5.0 -or $age -gt $maximumAge) {
        throw "Heartbeat is stale or from the future; refusing process termination."
    }
    if (
        (Get-NormalizedPath $process.Path) -ne
        (Get-NormalizedPath ([string]$Installation.runtime_executable))
    ) {
        throw "Heartbeat PID does not match the owned runtime; refusing process termination."
    }
    Stop-Process -Id $process.Id -Force -ErrorAction Stop
    $process.WaitForExit(10000) | Out-Null
    if ($null -ne (Get-Process -Id $process.Id -ErrorAction SilentlyContinue)) {
        throw "Owned companion process did not stop; refusing state deletion."
    }
    return $true
}

function Remove-OwnedCompanionDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(10)
    do {
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            return
        }
        catch [IO.IOException] {
            if ([DateTimeOffset]::UtcNow -ge $deadline) { throw }
        }
        catch [UnauthorizedAccessException] {
            if ([DateTimeOffset]::UtcNow -ge $deadline) { throw }
        }
        Start-Sleep -Milliseconds 250
    } while ($true)
}

if ($PSVersionTable.PSEdition -eq "Core" -and -not $IsWindows) {
    throw "ZSEC Antivirus companion uninstall is supported only on Windows."
}
$state = Get-NormalizedPath $StateDirectory
$installRoot = Join-Path $state "companion"
$installationPath = Join-Path $installRoot "installation.json"
if (-not (Test-Path -LiteralPath $installationPath -PathType Leaf)) {
    [ordered]@{
        schema = "zsec.antivirus.windows-companion-uninstall-result.v1"
        product = "ZSEC Antivirus"
        removed = $false
        decision = "not_installed"
        preserved_state_directory = $state
    } | ConvertTo-Json -Depth 5
    return
}

$installation = Get-Content -LiteralPath $installationPath -Raw -Encoding UTF8 |
    ConvertFrom-Json
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$expectedPowerShell = Get-NormalizedPath (
    Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
)
$expectedLauncher = Get-NormalizedPath (Join-Path $installRoot "Start-ZsecAntivirusCompanion.ps1")
$expectedConfig = Get-NormalizedPath (Join-Path $installRoot "config.json")
$expectedTaskArguments = (
    '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy RemoteSigned ' +
    "-File `"$expectedLauncher`" -ConfigPath `"$expectedConfig`""
)
if (
    $installation.schema -ne "zsec.antivirus.windows-companion-installation.v1" -or
    $installation.product -ne "ZSEC Antivirus" -or
    $installation.supervisor_kind -notin @("scheduled_task", "hkcu_run") -or
    $installation.supervisor.kind -ne $installation.supervisor_kind -or
    $null -eq $identity.User -or
    $installation.owner_sid -ne $identity.User.Value -or
    (Get-NormalizedPath $installation.install_root) -ne (Get-NormalizedPath $installRoot) -or
    (Get-NormalizedPath $installation.state_directory) -ne $state -or
    (Get-NormalizedPath ([string]$installation.task_action_execute)) -ne $expectedPowerShell -or
    [string]$installation.task_action_arguments -ne $expectedTaskArguments -or
    (Get-NormalizedPath ([string]$installation.launcher_path)) -ne $expectedLauncher -or
    (Get-NormalizedPath ([string]$installation.config_path)) -ne $expectedConfig
) {
    throw "Installation ownership/path verification failed; refusing to remove anything."
}
Assert-RegularNonReparseFile $expectedPowerShell
Assert-RegularNonReparseFile $expectedLauncher
Assert-RegularNonReparseFile $expectedConfig
if (
    (Get-Sha256 $expectedLauncher) -ne
        ([string]$installation.launcher_sha256).ToLowerInvariant()
) {
    throw "Installed companion launcher hash verification failed; refusing removal."
}
$installItem = Get-Item -LiteralPath $installRoot -Force -ErrorAction Stop
if (
    -not $installItem.PSIsContainer -or
    (($installItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
) {
    throw "Companion install root is not a regular, non-reparse directory."
}

$supervisorKind = [string]$installation.supervisor_kind
$task = $null
$runRegistration = [ordered]@{ present = $false; value_data = $null }
$expectedRunData = "`"$expectedPowerShell`" $expectedTaskArguments"
if ($supervisorKind -eq "scheduled_task") {
    Import-Module ScheduledTasks -ErrorAction Stop
    $task = Get-ScheduledTask `
        -TaskName $installation.task_name `
        -TaskPath $installation.task_path `
        -ErrorAction SilentlyContinue
    if ($null -ne $task) {
        $ownedTask = (
            @($task.Actions).Count -eq 1 -and
            $task.Actions[0].Execute -eq $installation.task_action_execute -and
            $task.Actions[0].Arguments -eq $installation.task_action_arguments -and
            $task.Description -eq $installation.task_description
        )
        if (-not $ownedTask) {
            throw "Scheduled Task no longer matches the owned installation; refusing removal."
        }
    }
}
else {
    if (
        $installation.supervisor.registry_path -ne $RunKeyPath -or
        $installation.supervisor.value_name -ne $RunValueName -or
        $installation.supervisor.value_data -ne $expectedRunData
    ) {
        throw "HKCU Run metadata is outside the exact owned boundary; refusing removal."
    }
    $runRegistration = Get-RunRegistration
    if ($runRegistration.present -and $runRegistration.value_data -ne $expectedRunData) {
        throw "HKCU Run value data changed; refusing registry or state removal."
    }
}

$plan = [ordered]@{
    schema = "zsec.antivirus.windows-companion-uninstall-plan.v1"
    product = "ZSEC Antivirus"
    supervisor_kind = $supervisorKind
    supervisor = $(
        if ($supervisorKind -eq "scheduled_task") {
            [ordered]@{
                task_name = $installation.task_name
                task_path = $installation.task_path
                present = $null -ne $task
            }
        }
        else {
            [ordered]@{
                registry_path = $RunKeyPath
                value_name = $RunValueName
                present = $runRegistration.present
                value_data_verified = (
                    $runRegistration.present -and
                    $runRegistration.value_data -eq $expectedRunData
                )
            }
        }
    )
    remove_only = $installRoot
    preserve = @(
        $state,
        (Join-Path $state "feed"),
        (Join-Path $state "quarantine"),
        "Microsoft Defender",
        "Malwarebytes",
        "Windows Security registration"
    )
    plan_only = [bool]$PlanOnly
}
if ($PlanOnly) {
    $plan | ConvertTo-Json -Depth 6
    return
}
if (-not $PSCmdlet.ShouldProcess($supervisorKind, "Uninstall per-user companion")) {
    $plan | ConvertTo-Json -Depth 6
    return
}

if ($null -ne $task) {
    Stop-ScheduledTask `
        -TaskName $installation.task_name `
        -TaskPath $installation.task_path `
        -ErrorAction SilentlyContinue
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 250
        $currentTask = Get-ScheduledTask `
            -TaskName $installation.task_name `
            -TaskPath $installation.task_path `
            -ErrorAction SilentlyContinue
    } while (
        $null -ne $currentTask -and
        $currentTask.State.ToString() -eq "Running" -and
        [DateTimeOffset]::UtcNow -lt $deadline
    )
    if ($null -ne $currentTask -and $currentTask.State.ToString() -eq "Running") {
        throw "Scheduled Task did not stop; refusing to unregister or delete evidence."
    }
    Unregister-ScheduledTask `
        -TaskName $installation.task_name `
        -TaskPath $installation.task_path `
        -Confirm:$false `
        -ErrorAction Stop
}
$runRemoved = $false
$ownedSupervisorStopped = $false
if ($supervisorKind -eq "hkcu_run") {
    $supervisorEventLogPath = Join-Path $installRoot "supervisor-events.ndjson"
    # Validate the live supervisor before changing registration. A stale or
    # ambiguous lifecycle PID must preserve the registry value and all state.
    $null = Get-OwnedHkcuSupervisorProcess `
        -Installation $installation `
        -LifecyclePath $supervisorEventLogPath `
        -ExpectedCommandLine $expectedRunData
    if ($runRegistration.present) {
        $runAtRemoval = Get-RunRegistration
        if (-not $runAtRemoval.present -or $runAtRemoval.value_data -ne $expectedRunData) {
            throw "HKCU Run value changed after validation; refusing registry or state removal."
        }
        Remove-ItemProperty `
            -LiteralPath $RunKeyPath `
            -Name $RunValueName `
            -ErrorAction Stop
        $runRemoved = $true
    }
    # Revalidate the exact PID after removing its autostart authority, then
    # stop the supervisor before terminating the heartbeat child it can restart.
    $ownedSupervisorStopped = Stop-OwnedHkcuSupervisorProcess `
        -Installation $installation `
        -LifecyclePath $supervisorEventLogPath `
        -ExpectedCommandLine $expectedRunData
}
$healthPath = Join-Path $installRoot "health.json"
$ownedProcessStopped = Stop-OwnedHeartbeatProcess `
    -Installation $installation `
    -HealthPath $healthPath
Remove-OwnedCompanionDirectory -Path $installRoot
if ([bool]$installation.install_root_preexisted) {
    New-Item -ItemType Directory -Path $installRoot -Force:$false | Out-Null
}

[ordered]@{
    schema = "zsec.antivirus.windows-companion-uninstall-result.v1"
    product = "ZSEC Antivirus"
    removed = $true
    supervisor_kind = $supervisorKind
    task_removed = $null -ne $task
    hkcu_run_removed = $runRemoved
    owned_supervisor_stopped = $ownedSupervisorStopped
    owned_process_stopped = $ownedProcessStopped
    generated_companion_files_removed = $true
    preserved_state_directory = $state
    preserved_feed = (Join-Path $state "feed")
    preserved_quarantine = (Join-Path $state "quarantine")
    existing_protection_unchanged = $true
} | ConvertTo-Json -Depth 6
