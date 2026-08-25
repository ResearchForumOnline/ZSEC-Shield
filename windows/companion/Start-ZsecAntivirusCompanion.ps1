#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ConfigPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-NormalizedPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains('"')) {
        throw "A configured path is empty or contains an invalid quote character."
    }
    return [System.IO.Path]::GetFullPath($Path)
}

function Test-IsPathBelow {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$Parent
    )
    $pathSeparators = [char[]]@(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $normalizedCandidate = (Get-NormalizedPath $Candidate).TrimEnd($pathSeparators)
    $normalizedParent = (Get-NormalizedPath $Parent).TrimEnd($pathSeparators)
    return $normalizedCandidate.StartsWith(
        $normalizedParent + [IO.Path]::DirectorySeparatorChar,
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Assert-ExactFields {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Context
    )
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    if (@(Compare-Object -ReferenceObject $wanted -DifferenceObject $actual).Count -ne 0) {
        throw "$Context fields are invalid."
    }
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

function Quote-NativeArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value.Contains('"')) {
        throw "A native process argument contains an invalid quote character."
    }
    return '"' + $Value + '"'
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
    throw "ZSEC Antivirus companion launch is supported only on Windows."
}

$configFile = Get-NormalizedPath $ConfigPath
Assert-RegularNonReparseFile $configFile
$config = Get-Content -LiteralPath $configFile -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-ExactFields -Value $config -Context "Companion config" -Expected @(
    "schema", "product", "engine", "owner_sid", "task_name", "cli_path", "cli_sha256",
    "runtime_executable", "runtime_sha256",
    "state_directory", "protected_roots", "backend", "debounce_seconds", "poll_seconds",
    "reconcile_seconds", "full_rescan_seconds", "heartbeat_seconds", "event_queue_size", "max_file_bytes",
    "intelligence_update_url", "intelligence_check_seconds",
    "chunk_bytes", "health_file", "event_log", "event_log_max_bytes", "event_log_backups",
    "supervisor_event_log", "supervisor_event_log_max_bytes", "supervisor_event_log_backups",
    "stdout_file", "stderr_file", "quarantine_enabled", "installed_at", "policy"
)
if (
    $config.schema -ne "zsec.antivirus.windows-companion.v1" -or
    $config.product -ne "ZSEC Antivirus" -or
    $config.engine -ne "ZSEC Shield"
) {
    throw "Companion config identity is invalid."
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $identity.User -or $config.owner_sid -ne $identity.User.Value) {
    throw "Companion config belongs to a different Windows user."
}

$cli = Get-NormalizedPath ([string]$config.cli_path)
$runtimeExecutable = Get-NormalizedPath ([string]$config.runtime_executable)
$state = Get-NormalizedPath ([string]$config.state_directory)
$health = Get-NormalizedPath ([string]$config.health_file)
$eventLog = Get-NormalizedPath ([string]$config.event_log)
$supervisorEventLog = Get-NormalizedPath ([string]$config.supervisor_event_log)
$stdout = Get-NormalizedPath ([string]$config.stdout_file)
$stderr = Get-NormalizedPath ([string]$config.stderr_file)
Assert-RegularNonReparseFile $cli
Assert-RegularNonReparseFile $runtimeExecutable
if (Test-Path -LiteralPath $state) {
    Assert-RegularNonReparseDirectory $state
}
foreach ($evidencePath in @(
        $configFile, $health, $eventLog, $supervisorEventLog, $stdout, $stderr
    )) {
    if (-not (Test-IsPathBelow -Candidate $evidencePath -Parent $state)) {
        throw "All companion control/evidence files must stay below the excluded state directory."
    }
}
$actualCliHash = Get-Sha256 $cli
if ($actualCliHash -ne ([string]$config.cli_sha256).ToLowerInvariant()) {
    throw "The configured ZSEC Antivirus executable hash changed; reinstall after review."
}
$actualRuntimeHash = Get-Sha256 $runtimeExecutable
if ($actualRuntimeHash -ne ([string]$config.runtime_sha256).ToLowerInvariant()) {
    throw "The configured ZSEC Antivirus runtime hash changed; reinstall after review."
}

$roots = @($config.protected_roots)
if ($roots.Count -lt 1 -or $roots.Count -gt 8) {
    throw "Companion config must contain between one and eight protected roots."
}
$normalizedRoots = @()
foreach ($root in $roots) {
    $normalizedRoot = Get-NormalizedPath ([string]$root)
    Assert-RegularNonReparseDirectory $normalizedRoot
    if (
        $normalizedRoot.TrimEnd('\') -eq $state.TrimEnd('\') -or
        (Test-IsPathBelow -Candidate $normalizedRoot -Parent $state)
    ) {
        throw "A protected root overlaps the excluded state directory."
    }
    $normalizedRoots += $normalizedRoot
}

if ($config.backend -notin @("auto", "native", "polling")) {
    throw "Companion backend is invalid."
}
if ($config.event_queue_size -lt 16 -or $config.event_queue_size -gt 65536) {
    throw "Companion event queue bound is invalid."
}
if ($config.max_file_bytes -lt 1 -or $config.max_file_bytes -gt 268435456) {
    throw "Companion maximum file size is invalid."
}
if ($config.chunk_bytes -lt 4096 -or $config.chunk_bytes -gt 4194304) {
    throw "Companion chunk size is invalid."
}
if ($config.event_log_max_bytes -lt 65536 -or $config.event_log_max_bytes -gt 67108864) {
    throw "Companion event-log bound is invalid."
}
if ($config.event_log_backups -lt 1 -or $config.event_log_backups -gt 10) {
    throw "Companion event-log backup count is invalid."
}
if (
    $config.supervisor_event_log_max_bytes -lt 16384 -or
    $config.supervisor_event_log_max_bytes -gt 1048576
) {
    throw "Companion supervisor event-log bound is invalid."
}
if (
    $config.supervisor_event_log_backups -lt 1 -or
    $config.supervisor_event_log_backups -gt 5
) {
    throw "Companion supervisor event-log backup count is invalid."
}
if ($config.heartbeat_seconds -lt 5 -or $config.heartbeat_seconds -gt 300) {
    throw "Companion heartbeat interval is invalid."
}
if ($config.reconcile_seconds -lt 30 -or $config.reconcile_seconds -gt 3600) {
    throw "Companion reconciliation interval is invalid."
}
if (
    $config.full_rescan_seconds -lt $config.reconcile_seconds -or
    $config.full_rescan_seconds -gt 604800
) {
    throw "Companion cache-independent full-rescan interval is invalid."
}
if (
    [string]$config.intelligence_update_url -ne
    "https://talktoai.org/zsec/intelligence/v1/feed.json"
) {
    throw "Companion intelligence update URL is invalid."
}
if ($config.intelligence_check_seconds -lt 300 -or $config.intelligence_check_seconds -gt 21600) {
    throw "Companion intelligence check interval is invalid."
}

$arguments = @(
    "--state-dir", (Quote-NativeArgument $state),
    "watch"
)
foreach ($root in $normalizedRoots) {
    $arguments += (Quote-NativeArgument $root)
}
$arguments += @(
    "--backend", [string]$config.backend,
    "--debounce-seconds", [string]$config.debounce_seconds,
    "--poll-seconds", [string]$config.poll_seconds,
    "--reconcile-seconds", [string]$config.reconcile_seconds,
    "--full-rescan-seconds", [string]$config.full_rescan_seconds,
    "--heartbeat-seconds", [string]$config.heartbeat_seconds,
    "--event-queue-size", [string]$config.event_queue_size,
    "--max-file-bytes", [string]$config.max_file_bytes,
    "--chunk-bytes", [string]$config.chunk_bytes,
    "--health-file", (Quote-NativeArgument $health),
    "--event-log", (Quote-NativeArgument $eventLog),
    "--event-log-max-bytes", [string]$config.event_log_max_bytes,
    "--event-log-backups", [string]$config.event_log_backups,
    "--quiet"
)
if ([bool]$config.quarantine_enabled) {
    $arguments += "--quarantine"
}
$argumentLine = $arguments -join " "

$mutexName = "Local\ZSEC-Antivirus-Companion-" + ([string]$config.owner_sid)
$createdNew = $false
$supervisorMutex = New-Object System.Threading.Mutex($true, $mutexName, ([ref]$createdNew))
if (-not $createdNew) {
    $supervisorMutex.Dispose()
    # A verified per-user supervisor already owns this companion identity.
    # A duplicate HKCU Run, Scheduled Task, or recovery launch exits without
    # starting a second watcher or touching its evidence files.
    exit 0
}

try {
    foreach ($outputPath in @($stdout, $stderr)) {
        if (Test-Path -LiteralPath $outputPath -PathType Leaf) {
            Assert-RegularNonReparseFile $outputPath
            Remove-Item -LiteralPath $outputPath -Force
        }
    }

    function Write-SupervisorLifecycleEvent {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("supervisor_started", "watcher_started", "watcher_exited")]
        [string]$Event,
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            "supervisor_lock_acquired",
            "watcher_process_started",
            "watcher_exit_restart_scheduled",
            "watcher_exit_rapid_failure_limit"
        )]
        [string]$Reason,
        [Nullable[int]]$WatcherProcessId = $null,
        [Nullable[int]]$ExitCode = $null,
        [Nullable[long]]$LifetimeMilliseconds = $null,
        [int]$RapidFailureCount = 0,
        [bool]$RestartScheduled = $false,
        [Nullable[int]]$RestartDelaySeconds = $null
    )
    $record = [ordered]@{
        schema = "zsec.antivirus.supervisor-event.v1"
        event = $Event
        generated_at = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        supervisor_process_id = [int]$PID
        watcher_process_id = $WatcherProcessId
        exit_code = $ExitCode
        lifetime_milliseconds = $LifetimeMilliseconds
        rapid_failure_count = $RapidFailureCount
        restart_scheduled = $RestartScheduled
        restart_delay_seconds = $RestartDelaySeconds
        reason = $Reason
    }
    $line = $record | ConvertTo-Json -Compress
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $lineBytes = $utf8.GetByteCount($line + [Environment]::NewLine)
    if ($lineBytes -gt 4096) {
        throw "Supervisor lifecycle evidence exceeded its per-record bound."
    }
    if (Test-Path -LiteralPath $supervisorEventLog -PathType Leaf) {
        Assert-RegularNonReparseFile $supervisorEventLog
        $length = (Get-Item -LiteralPath $supervisorEventLog -Force).Length
        if ($length + $lineBytes -gt [long]$config.supervisor_event_log_max_bytes) {
            for ($index = [int]$config.supervisor_event_log_backups; $index -ge 1; $index--) {
                $source = if ($index -eq 1) {
                    $supervisorEventLog
                }
                else {
                    "$supervisorEventLog.$($index - 1)"
                }
                $destination = "$supervisorEventLog.$index"
                foreach ($path in @($source, $destination)) {
                    if (-not (Test-IsPathBelow -Candidate $path -Parent $state)) {
                        throw "Supervisor lifecycle rotation escaped the excluded state directory."
                    }
                }
                if (Test-Path -LiteralPath $destination) {
                    Assert-RegularNonReparseFile $destination
                    Remove-Item -LiteralPath $destination -Force
                }
                if (Test-Path -LiteralPath $source -PathType Leaf) {
                    Assert-RegularNonReparseFile $source
                    Move-Item -LiteralPath $source -Destination $destination
                }
            }
        }
    }
    [System.IO.File]::AppendAllText(
        $supervisorEventLog,
        $line + [Environment]::NewLine,
        $utf8
    )
    }

    function Invoke-IntelligenceCheck {
    try {
        $output = & $cli `
            "--state-dir" $state `
            "update-intelligence" `
            "--url" ([string]$config.intelligence_update_url) `
            "--json" 2>$null
        if ([string]::IsNullOrWhiteSpace(($output -join ""))) {
            return "error"
        }
        $result = ($output -join [Environment]::NewLine) | ConvertFrom-Json
        if ($result.schema -ne "zsec.shield.automatic-update-status.v1") {
            return "error"
        }
        return [string]$result.state
    }
    catch {
        # Network or verification failure is recorded by the CLI and never
        # removes the last-known-good catalog. Monitoring continues.
        return "error"
    }
    }

    function Get-OptionalProperty {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
    }

    function Invoke-DefenderSecurityIntelligenceMaintenance {
    try {
        # Defender remains the Windows real-time provider. This bounded maintenance
        # path reads its own health signal and requests a signature refresh only
        # when Defender is active and reports stale or missing signature material.
        # It never changes preferences, exclusions, provider selection, Security
        # Center registration, or installed security products.
        $status = Get-MpComputerStatus -ErrorAction Stop
        $active = (
            [bool]$status.AMServiceEnabled -and
            [bool]$status.AntivirusEnabled -and
            [bool]$status.RealTimeProtectionEnabled
        )
        if (-not $active) { return "provider_not_active" }

        $outOfDate = Get-OptionalProperty -InputObject $status -Name "DefenderSignaturesOutOfDate"
        $version = [string](Get-OptionalProperty -InputObject $status -Name "AntivirusSignatureVersion")
        $updated = Get-OptionalProperty -InputObject $status -Name "AntivirusSignatureLastUpdated"
        $missingMaterial = [string]::IsNullOrWhiteSpace($version) -or $null -eq $updated
        if ($outOfDate -eq $true -or $missingMaterial) {
            Update-MpSignature -ErrorAction Stop | Out-Null
            return "refresh_requested"
        }
        return "current"
    }
    catch {
        # Defender and Windows Update keep their normal servicing authority. A
        # failed maintenance request never stops ZSEC post-change monitoring.
        return "unavailable"
    }
    }

    Write-SupervisorLifecycleEvent `
        -Event "supervisor_started" `
        -Reason "supervisor_lock_acquired"

    $rapidFailures = 0
    $maximumRapidFailures = 5
    while ($true) {
        $startedAt = [DateTimeOffset]::UtcNow
        $process = Start-Process `
            -FilePath $cli `
            -ArgumentList $argumentLine `
            -WorkingDirectory (Split-Path -Parent $cli) `
            -WindowStyle Hidden `
            -RedirectStandardOutput $stdout `
            -RedirectStandardError $stderr `
            -PassThru
        try {
            $process.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
        }
        catch {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            throw "Could not apply BelowNormal priority to the companion process."
        }
        Write-SupervisorLifecycleEvent `
            -Event "watcher_started" `
            -Reason "watcher_process_started" `
            -WatcherProcessId $process.Id `
            -RapidFailureCount $rapidFailures
        # Bring local monitoring online before any network-backed maintenance.
        $null = Invoke-DefenderSecurityIntelligenceMaintenance
        $null = Invoke-IntelligenceCheck
        while (-not $process.HasExited) {
            $null = $process.WaitForExit([int]([double]$config.intelligence_check_seconds * 1000.0))
            if (-not $process.HasExited) {
                # The CLI persists a randomized next-check time, so hourly supervision
                # results in one fleet-spread check per day rather than synchronized load.
                $null = Invoke-DefenderSecurityIntelligenceMaintenance
                $null = Invoke-IntelligenceCheck
            }
        }

        $lifetimeSeconds = ([DateTimeOffset]::UtcNow - $startedAt).TotalSeconds
        $lifetimeMilliseconds = [Math]::Max(0, [long][Math]::Round($lifetimeSeconds * 1000.0))
        if ($lifetimeSeconds -ge 300.0) { $rapidFailures = 0 }
        else { $rapidFailures++ }
        if ($rapidFailures -ge $maximumRapidFailures) {
            Write-SupervisorLifecycleEvent `
                -Event "watcher_exited" `
                -Reason "watcher_exit_rapid_failure_limit" `
                -WatcherProcessId $process.Id `
                -ExitCode $process.ExitCode `
                -LifetimeMilliseconds $lifetimeMilliseconds `
                -RapidFailureCount $rapidFailures
            # Fail visibly after a bounded crash loop. Status retains the stale
            # heartbeat/process evidence instead of claiming monitoring is active.
            exit $process.ExitCode
        }
        $restartDelaySeconds = [Math]::Min(60, [Math]::Pow(2, $rapidFailures))
        Write-SupervisorLifecycleEvent `
            -Event "watcher_exited" `
            -Reason "watcher_exit_restart_scheduled" `
            -WatcherProcessId $process.Id `
            -ExitCode $process.ExitCode `
            -LifetimeMilliseconds $lifetimeMilliseconds `
            -RapidFailureCount $rapidFailures `
            -RestartScheduled $true `
            -RestartDelaySeconds ([int]$restartDelaySeconds)
        Start-Sleep -Seconds ([int]$restartDelaySeconds)
    }
}
finally {
    try { $supervisorMutex.ReleaseMutex() }
    catch [System.ApplicationException] { }
    $supervisorMutex.Dispose()
}
