#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$LauncherScript,
    [Parameter(Mandatory = $true)][string]$StatusScript,
    [Parameter(Mandatory = $true)][string]$TemporaryDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Import-NamedFunction {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $ScriptPath,
        [ref]$tokens,
        [ref]$errors
    )
    if ($errors.Count -ne 0) {
        throw "Could not parse $ScriptPath."
    }
    $function = $ast.FindAll(
        {
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $Name
        },
        $true
    ) | Select-Object -First 1
    if ($null -eq $function) {
        throw "Function $Name was not found in $ScriptPath."
    }
    $definition = $function.Extent.Text -replace (
        "^function\s+" + [regex]::Escape($Name)
    ), ("function global:" + $Name)
    Invoke-Expression $definition
}

foreach ($name in @(
        "Get-NormalizedPath",
        "Test-IsPathBelow",
        "Assert-RegularNonReparseFile",
        "Write-SupervisorLifecycleEvent"
    )) {
    Import-NamedFunction -ScriptPath $LauncherScript -Name $name
}
foreach ($name in @(
        "ConvertTo-SupervisorLifecycleRecord",
        "Get-SupervisorLifecycleEvidence"
    )) {
    Import-NamedFunction -ScriptPath $StatusScript -Name $name
}

$state = [IO.Path]::GetFullPath($TemporaryDirectory)
New-Item -ItemType Directory -Path $state -Force | Out-Null
$supervisorEventLog = Join-Path $state "supervisor-events.ndjson"
$config = [pscustomobject]@{
    supervisor_event_log_max_bytes = 900
    supervisor_event_log_backups = 2
}

Write-SupervisorLifecycleEvent `
    -Event "supervisor_started" `
    -Reason "supervisor_lock_acquired"
for ($index = 1; $index -le 12; $index++) {
    Write-SupervisorLifecycleEvent `
        -Event "watcher_exited" `
        -Reason "watcher_exit_restart_scheduled" `
        -WatcherProcessId (1000 + $index) `
        -ExitCode 2 `
        -LifetimeMilliseconds (100 + $index) `
        -RapidFailureCount ([Math]::Min($index, 4)) `
        -RestartScheduled $true `
        -RestartDelaySeconds 2
}
Write-SupervisorLifecycleEvent `
    -Event "watcher_started" `
    -Reason "watcher_process_started" `
    -WatcherProcessId 2000

$files = @(Get-ChildItem -LiteralPath $state -File | Sort-Object Name)
$records = @()
foreach ($file in $files) {
    foreach ($line in @(Get-Content -LiteralPath $file.FullName -Encoding UTF8)) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            $records += $line | ConvertFrom-Json
        }
    }
}
$allowedFields = @(
    "schema", "event", "generated_at", "supervisor_process_id",
    "watcher_process_id", "exit_code", "lifetime_milliseconds",
    "rapid_failure_count", "restart_scheduled", "restart_delay_seconds", "reason"
) | Sort-Object
$fieldsExact = $true
foreach ($record in $records) {
    $actual = @($record.PSObject.Properties.Name | Sort-Object)
    if (@(Compare-Object -ReferenceObject $allowedFields -DifferenceObject $actual).Count -ne 0) {
        $fieldsExact = $false
    }
}
$evidence = Get-SupervisorLifecycleEvidence `
    -Path $supervisorEventLog `
    -MaximumBytes 900 `
    -BackupCount 2

[ordered]@{
    schema = "zsec.tests.supervisor-lifecycle-evidence.v1"
    rotated_files = $files.Count
    bounded_files = @($files | Where-Object { $_.Length -gt 4996 }).Count -eq 0
    records_present = $records.Count -gt 0
    fields_exact = $fieldsExact
    latest_event = $evidence.latest_event.event
    latest_exit_reason = $evidence.latest_exit.reason
    evidence_valid = $evidence.valid
} | ConvertTo-Json -Depth 5
