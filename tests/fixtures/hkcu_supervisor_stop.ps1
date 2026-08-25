#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$UninstallerScript,
    [Parameter(Mandatory = $true)][string]$TemporaryDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $UninstallerScript,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw "Uninstaller parsing failed: $($parseErrors -join '; ')"
}
$functionNames = @(
    "Get-NormalizedPath",
    "Assert-RegularNonReparseFile",
    "Get-LatestSupervisorLifecycleRecord",
    "Get-OwnedHkcuSupervisorProcess",
    "Stop-OwnedHkcuSupervisorProcess"
)
foreach ($functionName in $functionNames) {
    $definition = @(
        $ast.FindAll(
            {
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -eq $functionName
            },
            $true
        )
    )
    if ($definition.Count -ne 1) {
        throw "Expected one definition for $functionName."
    }
    Invoke-Expression $definition[0].Extent.Text
}

# The live-process fixture exercises PID/SID/executable/command-line/creation-time
# validation. Its disposable child intentionally does not contend with the real
# per-user companion mutex, so this one dependency is replaced with an exact stub.
function Test-OwnedSupervisorMutexPresent {
    param([Parameter(Mandatory = $true)][string]$OwnerSid)
    return -not [string]::IsNullOrWhiteSpace($OwnerSid)
}

$worker = Join-Path $TemporaryDirectory "owned-supervisor-worker.ps1"
$config = Join-Path $TemporaryDirectory "config.json"
$lifecycle = Join-Path $TemporaryDirectory "supervisor-events.ndjson"
$workerSource = @'
param([Parameter(Mandatory = $true)][string]$ConfigPath)
while ($true) { Start-Sleep -Seconds 1 }
'@
[System.IO.File]::WriteAllText($worker, $workerSource, (New-Object Text.UTF8Encoding($false)))
[System.IO.File]::WriteAllText($config, "{}", (New-Object Text.UTF8Encoding($false)))

$ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$powerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
$arguments = (
    '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ' +
    "-File `"$worker`" -ConfigPath `"$config`""
)
$expectedCommandLine = "`"$powerShell`" $arguments"
$installation = [pscustomobject]@{
    owner_sid = $ownerSid
    task_action_execute = $powerShell
    task_action_arguments = $arguments
}
$process = $null
$mismatchRejected = $false
$pidReuseRejected = $false
try {
    $process = Start-Process `
        -FilePath $powerShell `
        -ArgumentList $arguments `
        -WindowStyle Hidden `
        -PassThru
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(10)
    do {
        Start-Sleep -Milliseconds 100
        $candidate = Get-CimInstance `
            -ClassName Win32_Process `
            -Filter "ProcessId = $($process.Id)" `
            -ErrorAction Stop
    } while ($null -eq $candidate -and [DateTimeOffset]::UtcNow -lt $deadline)
    if ($null -eq $candidate) {
        throw "Disposable supervisor did not become observable."
    }

    $record = [ordered]@{
        schema = "zsec.antivirus.supervisor-event.v1"
        event = "watcher_started"
        generated_at = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        supervisor_process_id = [int]$process.Id
        watcher_process_id = 1
        exit_code = $null
        lifetime_milliseconds = $null
        rapid_failure_count = 0
        restart_scheduled = $false
        restart_delay_seconds = $null
        reason = "watcher_process_started"
    }
    [System.IO.File]::WriteAllText(
        $lifecycle,
        (($record | ConvertTo-Json -Compress) + [Environment]::NewLine),
        (New-Object Text.UTF8Encoding($false))
    )
    try {
        $owned = Get-OwnedHkcuSupervisorProcess `
            -Installation $installation `
            -LifecyclePath $lifecycle `
            -ExpectedCommandLine $expectedCommandLine
    }
    catch {
        $observedOwner = Invoke-CimMethod `
            -InputObject $candidate `
            -MethodName GetOwnerSid `
            -ErrorAction Stop
        throw (
            "Exact fixture identity failed. " +
            "exe='$($candidate.ExecutablePath)' command='$($candidate.CommandLine)' " +
            "owner='$($observedOwner.Sid)' created='$($candidate.CreationDate)': " +
            $_.Exception.Message
        )
    }
    if ([int]$owned.ProcessId -ne [int]$process.Id) {
        throw "Exact owned supervisor was not resolved."
    }

    try {
        $mismatchedInstallation = [pscustomobject]@{
            owner_sid = $ownerSid
            task_action_execute = $powerShell
            task_action_arguments = ($arguments + " --not-owned")
        }
        $null = Get-OwnedHkcuSupervisorProcess `
            -Installation $mismatchedInstallation `
            -LifecyclePath $lifecycle `
            -ExpectedCommandLine ($expectedCommandLine + " --not-owned")
    }
    catch {
        $mismatchRejected = $true
    }
    if (-not $mismatchRejected -or $process.HasExited) {
        throw "Command-line mismatch was not rejected without termination."
    }

    $record.generated_at = "2000-01-01T00:00:00Z"
    [System.IO.File]::WriteAllText(
        $lifecycle,
        (($record | ConvertTo-Json -Compress) + [Environment]::NewLine),
        (New-Object Text.UTF8Encoding($false))
    )
    try {
        $null = Get-OwnedHkcuSupervisorProcess `
            -Installation $installation `
            -LifecyclePath $lifecycle `
            -ExpectedCommandLine $expectedCommandLine
    }
    catch {
        $pidReuseRejected = $true
    }
    if (-not $pidReuseRejected -or $process.HasExited) {
        throw "PID-reuse timestamp mismatch was not rejected without termination."
    }

    $record.generated_at = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    [System.IO.File]::WriteAllText(
        $lifecycle,
        (($record | ConvertTo-Json -Compress) + [Environment]::NewLine),
        (New-Object Text.UTF8Encoding($false))
    )
    $stopped = Stop-OwnedHkcuSupervisorProcess `
        -Installation $installation `
        -LifecyclePath $lifecycle `
        -ExpectedCommandLine $expectedCommandLine
    if (-not $stopped) {
        throw "Exact owned supervisor was not stopped."
    }
    $process.Refresh()
    if (-not $process.HasExited) {
        throw "Exact owned supervisor remained alive after stop."
    }

    [ordered]@{
        schema = "zsec.tests.hkcu-supervisor-stop.v1"
        exact_identity_resolved = $true
        command_line_mismatch_rejected = $mismatchRejected
        pid_reuse_rejected = $pidReuseRejected
        exact_process_stopped = $true
    } | ConvertTo-Json -Compress
}
finally {
    if ($null -ne $process) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }
}
