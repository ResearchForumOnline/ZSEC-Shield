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
    $updatedAt = [DateTimeOffset]::Parse([string]$health.updated_at).ToUniversalTime()
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

if ($PSVersionTable.PSEdition -eq "Core" -and -not $IsWindows) {
    throw "ZSEC Antivirus companion uninstall is supported only on Windows."
}
Import-Module ScheduledTasks -ErrorAction Stop
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
if (
    $installation.schema -ne "zsec.antivirus.windows-companion-installation.v1" -or
    $installation.product -ne "ZSEC Antivirus" -or
    $installation.supervisor_kind -notin @("scheduled_task", "hkcu_run") -or
    $installation.supervisor.kind -ne $installation.supervisor_kind -or
    $null -eq $identity.User -or
    $installation.owner_sid -ne $identity.User.Value -or
    (Get-NormalizedPath $installation.install_root) -ne (Get-NormalizedPath $installRoot) -or
    (Get-NormalizedPath $installation.state_directory) -ne $state
) {
    throw "Installation ownership/path verification failed; refusing to remove anything."
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
$expectedRunData = "`"$($installation.task_action_execute)`" $($installation.task_action_arguments)"
if ($supervisorKind -eq "scheduled_task") {
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
$healthPath = Join-Path $installRoot "health.json"
$ownedProcessStopped = Stop-OwnedHeartbeatProcess `
    -Installation $installation `
    -HealthPath $healthPath
$runRemoved = $false
if ($supervisorKind -eq "hkcu_run" -and $runRegistration.present) {
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

Remove-Item -LiteralPath $installRoot -Recurse -Force -ErrorAction Stop
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
    owned_process_stopped = $ownedProcessStopped
    generated_companion_files_removed = $true
    preserved_state_directory = $state
    preserved_feed = (Join-Path $state "feed")
    preserved_quarantine = (Join-Path $state "quarantine")
    existing_protection_unchanged = $true
} | ConvertTo-Json -Depth 6
