#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
param(
    [string]$StateDirectory = (Join-Path $env:LOCALAPPDATA "ZSEC\Shield"),
    [switch]$PlanOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-NormalizedPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [System.IO.Path]::GetFullPath($Path)
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

$plan = [ordered]@{
    schema = "zsec.antivirus.windows-companion-uninstall-plan.v1"
    product = "ZSEC Antivirus"
    task_name = $installation.task_name
    task_path = $installation.task_path
    task_present = $null -ne $task
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
if (-not $PSCmdlet.ShouldProcess("$($installation.task_path)$($installation.task_name)", "Uninstall per-user companion")) {
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

Remove-Item -LiteralPath $installRoot -Recurse -Force -ErrorAction Stop
if ([bool]$installation.install_root_preexisted) {
    New-Item -ItemType Directory -Path $installRoot -Force:$false | Out-Null
}

[ordered]@{
    schema = "zsec.antivirus.windows-companion-uninstall-result.v1"
    product = "ZSEC Antivirus"
    removed = $true
    task_removed = $null -ne $task
    generated_companion_files_removed = $true
    preserved_state_directory = $state
    preserved_feed = (Join-Path $state "feed")
    preserved_quarantine = (Join-Path $state "quarantine")
    existing_protection_unchanged = $true
} | ConvertTo-Json -Depth 6
