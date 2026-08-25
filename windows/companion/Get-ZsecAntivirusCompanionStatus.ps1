#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$StateDirectory = (Join-Path $env:LOCALAPPDATA "ZSEC\Shield")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$RunKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$RunValueName = "ZSEC Antivirus Companion"

function Get-NormalizedPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [System.IO.Path]::GetFullPath($Path)
}

function Write-StatusAndExit {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][int]$Code
    )
    $Value | ConvertTo-Json -Depth 10
    exit $Code
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

function Get-OptionalProperty {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function ConvertTo-SupervisorLifecycleRecord {
    param([Parameter(Mandatory = $true)]$Value)
    $expected = @(
        "schema", "event", "generated_at", "supervisor_process_id",
        "watcher_process_id", "exit_code", "lifetime_milliseconds",
        "rapid_failure_count", "restart_scheduled", "restart_delay_seconds", "reason"
    )
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    if (@(Compare-Object -ReferenceObject ($expected | Sort-Object) -DifferenceObject $actual).Count -ne 0) {
        return $null
    }
    if ($Value.schema -ne "zsec.antivirus.supervisor-event.v1") {
        return $null
    }
    $allowedReasons = @{
        supervisor_started = "supervisor_lock_acquired"
        watcher_started = "watcher_process_started"
        watcher_exited = @(
            "watcher_exit_restart_scheduled",
            "watcher_exit_rapid_failure_limit"
        )
    }
    if (-not $allowedReasons.ContainsKey([string]$Value.event)) {
        return $null
    }
    if (@($allowedReasons[[string]$Value.event]) -notcontains [string]$Value.reason) {
        return $null
    }
    try {
        $generatedAt = ([DateTimeOffset]$Value.generated_at).ToUniversalTime()
    }
    catch {
        return $null
    }
    if (
        $Value.supervisor_process_id -isnot [int] -or
        $Value.supervisor_process_id -lt 1 -or
        $Value.rapid_failure_count -isnot [int] -or
        $Value.rapid_failure_count -lt 0 -or
        $Value.rapid_failure_count -gt 5 -or
        $Value.restart_scheduled -isnot [bool]
    ) {
        return $null
    }
    foreach ($field in @(
            "watcher_process_id", "exit_code", "lifetime_milliseconds", "restart_delay_seconds"
        )) {
        $propertyValue = $Value.$field
        if (
            $null -ne $propertyValue -and
            $propertyValue -isnot [int] -and
            $propertyValue -isnot [long]
        ) {
            return $null
        }
    }
    if (
        ($null -ne $Value.watcher_process_id -and $Value.watcher_process_id -lt 1) -or
        ($null -ne $Value.lifetime_milliseconds -and $Value.lifetime_milliseconds -lt 0) -or
        ($null -ne $Value.restart_delay_seconds -and (
            $Value.restart_delay_seconds -lt 1 -or $Value.restart_delay_seconds -gt 60
        ))
    ) {
        return $null
    }
    if (
        ($Value.event -eq "supervisor_started" -and (
            $null -ne $Value.watcher_process_id -or
            $null -ne $Value.exit_code -or
            $null -ne $Value.lifetime_milliseconds -or
            $Value.rapid_failure_count -ne 0 -or
            $Value.restart_scheduled -ne $false -or
            $null -ne $Value.restart_delay_seconds
        )) -or
        ($Value.event -ne "supervisor_started" -and $null -eq $Value.watcher_process_id) -or
        ($Value.event -eq "watcher_started" -and (
            $null -ne $Value.exit_code -or
            $null -ne $Value.lifetime_milliseconds -or
            $Value.restart_scheduled -ne $false -or
            $null -ne $Value.restart_delay_seconds
        )) -or
        ($Value.event -eq "watcher_exited" -and (
            $null -eq $Value.exit_code -or $null -eq $Value.lifetime_milliseconds
        )) -or
        ($Value.reason -eq "watcher_exit_restart_scheduled" -and (
            $Value.restart_scheduled -ne $true -or
            $null -eq $Value.restart_delay_seconds -or
            $Value.rapid_failure_count -ge 5
        )) -or
        ($Value.reason -eq "watcher_exit_rapid_failure_limit" -and (
            $Value.restart_scheduled -ne $false -or
            $null -ne $Value.restart_delay_seconds -or
            $Value.rapid_failure_count -ne 5
        ))
    ) {
        return $null
    }
    return [ordered]@{
        schema = [string]$Value.schema
        event = [string]$Value.event
        generated_at = $generatedAt.ToString("yyyy-MM-ddTHH:mm:ssZ")
        supervisor_process_id = [int]$Value.supervisor_process_id
        watcher_process_id = $Value.watcher_process_id
        exit_code = $Value.exit_code
        lifetime_milliseconds = $Value.lifetime_milliseconds
        rapid_failure_count = [int]$Value.rapid_failure_count
        restart_scheduled = [bool]$Value.restart_scheduled
        restart_delay_seconds = $Value.restart_delay_seconds
        reason = [string]$Value.reason
    }
}

function Get-SupervisorLifecycleEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][long]$MaximumBytes,
        [Parameter(Mandatory = $true)][int]$BackupCount
    )
    $paths = @()
    for ($index = $BackupCount; $index -ge 1; $index--) {
        $paths += "$Path.$index"
    }
    $paths += $Path
    $availablePaths = @($paths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
    if ($availablePaths.Count -eq 0) {
        return [ordered]@{
            available = $false
            valid = $true
            within_bound = $true
            latest_event = $null
            latest_exit = $null
        }
    }
    $latestEvent = $null
    $latestExit = $null
    $invalidRecords = 0
    $withinBound = $true
    foreach ($evidencePath in $availablePaths) {
        $item = Get-Item -LiteralPath $evidencePath -Force -ErrorAction Stop
        if (
            $item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            $item.Length -gt $MaximumBytes + 4096
        ) {
            $withinBound = $false
            continue
        }
        foreach ($line in @(Get-Content -LiteralPath $evidencePath -Encoding UTF8)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try {
                $parsed = $line | ConvertFrom-Json
                $record = ConvertTo-SupervisorLifecycleRecord -Value $parsed
            }
            catch {
                $record = $null
            }
            if ($null -eq $record) {
                $invalidRecords++
                continue
            }
            $latestEvent = $record
            if ($record.event -eq "watcher_exited") {
                $latestExit = $record
            }
        }
    }
    return [ordered]@{
        available = $true
        valid = ($invalidRecords -eq 0 -and $withinBound -and $null -ne $latestEvent)
        within_bound = $withinBound
        latest_event = $latestEvent
        latest_exit = $latestExit
    }
}

function ConvertTo-UtcEvidenceTimestamp {
    param($Value)
    if ($null -eq $Value) {
        return $null
    }
    try {
        return ([DateTimeOffset]$Value).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    catch {
        return $null
    }
}

function ConvertTo-OptionalEvidenceString {
    param($Value)
    if ($null -eq $Value) {
        return $null
    }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }
    return $text
}

function ConvertTo-DefenderAgeEvidence {
    param($Value)
    if ($null -eq $Value -or $Value -is [bool]) {
        return $null
    }
    [long]$parsed = 0
    $text = [string]$Value
    if (-not [long]::TryParse(
            $text,
            [Globalization.NumberStyles]::Integer,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$parsed
        )) {
        return $null
    }
    if ($parsed -lt 0 -or $parsed -gt [int]::MaxValue) {
        return $null
    }
    return [int]$parsed
}

function Set-DefenderAgeAndFeatureEvidence {
    param(
        [Parameter(Mandatory = $true)]$Defender,
        [Parameter(Mandatory = $true)]$Status
    )
    $Defender.signatures.antivirus_age_days = ConvertTo-DefenderAgeEvidence (
        Get-OptionalProperty -InputObject $Status -Name "AntivirusSignatureAge"
    )
    $Defender.scans.quick_scan_age_days = ConvertTo-DefenderAgeEvidence (
        Get-OptionalProperty -InputObject $Status -Name "QuickScanAge"
    )
    $Defender.scans.quick_scan_end = ConvertTo-UtcEvidenceTimestamp (
        Get-OptionalProperty -InputObject $Status -Name "QuickScanEndTime"
    )
    $Defender.scans.full_scan_age_days = ConvertTo-DefenderAgeEvidence (
        Get-OptionalProperty -InputObject $Status -Name "FullScanAge"
    )
    $Defender.scans.full_scan_end = ConvertTo-UtcEvidenceTimestamp (
        Get-OptionalProperty -InputObject $Status -Name "FullScanEndTime"
    )
    $Defender.confirmed_active = (
        $Defender.antivirus_enabled -and
        $Defender.real_time_protection_enabled -and
        $Defender.service_enabled
    )
    $Defender.baseline_features_confirmed = (
        $Defender.confirmed_active -and
        $Defender.behavior_monitor_enabled -and
        $Defender.ioav_protection_enabled -and
        $Defender.on_access_protection_enabled -and
        $Defender.network_inspection_enabled
    )
}

function Get-SecurityServiceEvidence {
    $values = @()
    foreach ($serviceName in @(
            "WinDefend",
            "WdNisSvc",
            "MDCoreSvc",
            "wscsvc",
            "SecurityHealthService"
        )) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        $values += [ordered]@{
            name = $serviceName
            available = ($null -ne $service)
            status = $(if ($null -eq $service) { "unavailable" } else { $service.Status.ToString() })
        }
    }
    return @($values)
}

function Get-WscAntivirusEvidence {
    $source = @'
using System;
using System.Runtime.InteropServices;
public static class ZsecWscHealth {
    [DllImport("wscapi.dll")]
    public static extern int WscGetSecurityProviderHealth(uint providers, out int health);
}
'@
    if ($null -eq ("ZsecWscHealth" -as [type])) {
        Add-Type -TypeDefinition $source -ErrorAction Stop
    }
    $healthValue = 2
    $hresult = [ZsecWscHealth]::WscGetSecurityProviderHealth(0x4, [ref]$healthValue)
    $healthNames = @("GOOD", "NOTMONITORED", "POOR", "SNOOZE")
    $healthName = if ($healthValue -ge 0 -and $healthValue -lt $healthNames.Count) {
        $healthNames[$healthValue]
    }
    else {
        "UNKNOWN_$healthValue"
    }
    $registrations = @()
    $registrationInventoryComplete = $true
    $registrationInventoryError = $null
    try {
        $products = Get-CimInstance `
            -Namespace "root/SecurityCenter2" `
            -ClassName "AntivirusProduct" `
            -ErrorAction Stop
        foreach ($product in @($products)) {
            $registrations += [ordered]@{
                display_name = [string]$product.displayName
                product_state_raw = [int]$product.productState
                product_state_interpreted = $false
                instance_guid = [string]$product.instanceGuid
            }
        }
    }
    catch {
        $registrations = @()
        $registrationInventoryComplete = $false
        $registrationInventoryError = $_.Exception.Message
    }
    $defender = [ordered]@{
        available = $false
        source = "Get-MpComputerStatus"
        antivirus_enabled = $null
        real_time_protection_enabled = $null
        antispyware_enabled = $null
        service_enabled = $null
        behavior_monitor_enabled = $null
        ioav_protection_enabled = $null
        on_access_protection_enabled = $null
        network_inspection_enabled = $null
        network_protection = [ordered]@{
            state = "unavailable"
            raw_value = $null
            source = "Get-MpPreference.EnableNetworkProtection"
            note = "Defender Network Protection posture could not be read."
        }
        tamper_protection = "unknown"
        reboot_required = $null
        signatures = [ordered]@{
            engine_version = $null
            product_version = $null
            antivirus_version = $null
            antivirus_last_updated = $null
            antivirus_age_days = $null
            defender_reports_out_of_date = $null
        }
        scans = [ordered]@{
            quick_scan_age_days = $null
            quick_scan_end = $null
            full_scan_age_days = $null
            full_scan_end = $null
        }
        confirmed_active = $false
        baseline_features_confirmed = $false
        signatures_current = $false
        update_recommended = $false
        note = "Defender is not inferred active from WSC registration."
    }
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $defender.available = $true
        $defender.antivirus_enabled = [bool]$mp.AntivirusEnabled
        $defender.real_time_protection_enabled = [bool]$mp.RealTimeProtectionEnabled
        $defender.antispyware_enabled = [bool]$mp.AntispywareEnabled
        $defender.service_enabled = [bool]$mp.AMServiceEnabled
        $defender.behavior_monitor_enabled = [bool]$mp.BehaviorMonitorEnabled
        $defender.ioav_protection_enabled = [bool]$mp.IoavProtectionEnabled
        $defender.on_access_protection_enabled = [bool]$mp.OnAccessProtectionEnabled
        $defender.network_inspection_enabled = [bool]$mp.NISEnabled
        $tamperProtected = Get-OptionalProperty -InputObject $mp -Name "IsTamperProtected"
        if ($null -ne $tamperProtected) {
            $defender.tamper_protection = $(if ([bool]$tamperProtected) { "enabled" } else { "disabled" })
        }
        $rebootRequired = Get-OptionalProperty -InputObject $mp -Name "RebootRequired"
        if ($null -ne $rebootRequired) {
            $defender.reboot_required = [bool]$rebootRequired
        }
        $defender.signatures.engine_version = ConvertTo-OptionalEvidenceString (
            Get-OptionalProperty -InputObject $mp -Name "AMEngineVersion"
        )
        $defender.signatures.product_version = ConvertTo-OptionalEvidenceString (
            Get-OptionalProperty -InputObject $mp -Name "AMProductVersion"
        )
        $defender.signatures.antivirus_version = ConvertTo-OptionalEvidenceString (
            Get-OptionalProperty -InputObject $mp -Name "AntivirusSignatureVersion"
        )
        $defender.signatures.antivirus_last_updated = ConvertTo-UtcEvidenceTimestamp (
            Get-OptionalProperty -InputObject $mp -Name "AntivirusSignatureLastUpdated"
        )
        $signaturesOutOfDate = Get-OptionalProperty `
            -InputObject $mp `
            -Name "DefenderSignaturesOutOfDate"
        if ($null -ne $signaturesOutOfDate) {
            $defender.signatures.defender_reports_out_of_date = [bool]$signaturesOutOfDate
            $signatureMaterialPresent = (
                -not [string]::IsNullOrWhiteSpace($defender.signatures.antivirus_version) -and
                -not [string]::IsNullOrWhiteSpace(
                    $defender.signatures.antivirus_last_updated
                )
            )
            $defender.signatures_current = (
                -not [bool]$signaturesOutOfDate -and $signatureMaterialPresent
            )
            $defender.update_recommended = (
                [bool]$signaturesOutOfDate -or -not $signatureMaterialPresent
            )
        }
        Set-DefenderAgeAndFeatureEvidence `
            -Defender $defender `
            -Status $mp
        try {
            $preference = Get-MpPreference -ErrorAction Stop
            $rawNetworkProtection = Get-OptionalProperty `
                -InputObject $preference `
                -Name "EnableNetworkProtection"
            if ($null -ne $rawNetworkProtection) {
                $rawNetworkProtection = [int]$rawNetworkProtection
                $defender.network_protection.raw_value = $rawNetworkProtection
                switch ($rawNetworkProtection) {
                    1 {
                        $defender.network_protection.state = "active"
                        $defender.network_protection.note = (
                            "Microsoft Defender Network Protection is in block mode."
                        )
                    }
                    2 {
                        $defender.network_protection.state = "audit"
                        $defender.network_protection.note = (
                            "Microsoft Defender Network Protection is in audit mode."
                        )
                    }
                    0 {
                        $defender.network_protection.state = "disabled"
                        $defender.network_protection.note = (
                            "Microsoft Defender Network Protection is disabled."
                        )
                    }
                    default {
                        $defender.network_protection.state = "unavailable"
                        $defender.network_protection.note = (
                            "Microsoft Defender returned an unknown Network Protection value."
                        )
                    }
                }
            }
        }
        catch {
            # This posture is independent evidence only. It never changes the
            # companion health decision and ZSEC never mutates the preference.
            $defender.network_protection.state = "unavailable"
            $defender.network_protection.raw_value = $null
            $defender.network_protection.note = (
                "Defender Network Protection posture could not be read; no setting was changed."
            )
        }
        $defender.note = $(if ($defender.confirmed_active) {
                "Defender active state is confirmed by Get-MpComputerStatus."
            }
            else {
                "Defender is installed but not confirmed as the active real-time antivirus."
            })
    }
    catch {
        $defender.note = (
            "Microsoft Defender status evidence could not be completed; " +
            "no Defender-active inference made."
        )
    }
    return [ordered]@{
        method = "WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_ANTIVIRUS)"
        hresult = $hresult
        aggregate_health = $healthName
        aggregate_good = ($hresult -eq 0 -and $healthValue -eq 0)
        registered_products = $registrations
        registration_inventory_complete = $registrationInventoryComplete
        registration_inventory_error = $registrationInventoryError
        registration_note = (
            "SecurityCenter2 productState values are retained as raw evidence and are not decoded."
        )
        security_services = @(Get-SecurityServiceEvidence)
        defender = $defender
        existing_primary_protection_present_and_active = (
            $hresult -eq 0 -and $healthValue -eq 0
        )
    }
}

if ($PSVersionTable.PSEdition -eq "Core" -and -not $IsWindows) {
    throw "ZSEC Antivirus companion status is supported only on Windows."
}
Import-Module ScheduledTasks -ErrorAction Stop
$state = Get-NormalizedPath $StateDirectory
$installRoot = Join-Path $state "companion"
$installationPath = Join-Path $installRoot "installation.json"
$configPath = Join-Path $installRoot "config.json"
$healthPath = Join-Path $installRoot "health.json"
$base = [ordered]@{
    schema = "zsec.antivirus.windows-companion-status.v1"
    product = "ZSEC Antivirus"
    checked_at = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    primary_antivirus = $false
    real_time_protection = $false
    pre_access_enforcement = $false
    windows_security_registration = $false
    existing_protection_must_remain_active = $true
    primary_provider_uninstall_allowed = $false
    cutover_allowed = $false
}
$existingProtectionError = $null
try {
    $existingProtection = Get-WscAntivirusEvidence
}
catch {
    $existingProtectionError = $_.Exception.Message
    $existingProtection = [ordered]@{
        method = "WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_ANTIVIRUS)"
        aggregate_health = "UNKNOWN"
        aggregate_good = $false
        registered_products = @()
        existing_primary_protection_present_and_active = $false
        error = $existingProtectionError
    }
}
$base.existing_primary_protection = $existingProtection
if (-not (Test-Path -LiteralPath $installationPath -PathType Leaf)) {
    $base.installed = $false
    $base.healthy = $false
    $base.decision = "not_installed"
    $base.reasons = @("installation marker is absent")
    Write-StatusAndExit -Value $base -Code 2
}

$reasons = @()
if ($null -ne $existingProtectionError) {
    $reasons += "cannot prove existing antivirus aggregate health: $existingProtectionError"
}
elseif (-not $existingProtection.aggregate_good) {
    $reasons += "Windows Security Center antivirus aggregate health is not GOOD"
}
try {
    $installation = Get-Content -LiteralPath $installationPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    $config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (
        $installation.schema -ne "zsec.antivirus.windows-companion-installation.v1" -or
        $installation.product -ne "ZSEC Antivirus" -or
        $config.schema -ne "zsec.antivirus.windows-companion.v1" -or
        $installation.supervisor_kind -notin @("scheduled_task", "hkcu_run") -or
        $installation.supervisor.kind -ne $installation.supervisor_kind
    ) {
        throw "installation/config schema is invalid"
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (
        $null -eq $identity.User -or
        $installation.owner_sid -ne $identity.User.Value -or
        $config.owner_sid -ne $identity.User.Value
    ) {
        throw "installation belongs to a different Windows user"
    }
    $lifecycleConfigNames = @(
        "supervisor_event_log",
        "supervisor_event_log_max_bytes",
        "supervisor_event_log_backups"
    )
    $lifecycleConfigPresent = @(
        $lifecycleConfigNames | Where-Object { $null -ne $config.PSObject.Properties[$_] }
    )
    if ($lifecycleConfigPresent.Count -eq 0) {
        # A previous signed companion can be inspected and restored during an
        # upgrade rollback. Its launcher/config pair predates lifecycle evidence.
        $supervisorLifecycleEvidence = [ordered]@{
            available = $false
            valid = $true
            within_bound = $true
            latest_event = $null
            latest_exit = $null
        }
    }
    elseif ($lifecycleConfigPresent.Count -ne $lifecycleConfigNames.Count) {
        throw "supervisor lifecycle evidence configuration is incomplete"
    }
    else {
        $supervisorEventLogPath = Get-NormalizedPath ([string]$config.supervisor_event_log)
        if (
            $supervisorEventLogPath -ne
            (Get-NormalizedPath (Join-Path $installRoot "supervisor-events.ndjson")) -or
            $config.supervisor_event_log_max_bytes -lt 16384 -or
            $config.supervisor_event_log_max_bytes -gt 1048576 -or
            $config.supervisor_event_log_backups -lt 1 -or
            $config.supervisor_event_log_backups -gt 5
        ) {
            throw "supervisor lifecycle evidence configuration is invalid"
        }
        $supervisorLifecycleEvidence = Get-SupervisorLifecycleEvidence `
            -Path $supervisorEventLogPath `
            -MaximumBytes ([long]$config.supervisor_event_log_max_bytes) `
            -BackupCount ([int]$config.supervisor_event_log_backups)
    }
}
catch {
    $base.installed = $true
    $base.healthy = $false
    $base.decision = "degraded"
    $base.reasons = @("cannot validate installation metadata: $($_.Exception.Message)")
    Write-StatusAndExit -Value $base -Code 2
}

$supervisorKind = [string]$installation.supervisor_kind
$supervisorRegistrationVerified = $false
$supervisorState = "unknown"
$supervisorDetails = $null
$task = $null
$taskInfo = $null
$taskActionVerified = $false
$taskSingleInstance = $false
if ($supervisorKind -eq "scheduled_task") {
    $task = Get-ScheduledTask `
        -TaskName $installation.task_name `
        -TaskPath $installation.task_path `
        -ErrorAction SilentlyContinue
    if ($null -eq $task) {
        $supervisorState = "absent"
        $reasons += "owned Scheduled Task is absent"
    }
    else {
        $taskInfo = Get-ScheduledTaskInfo `
            -TaskName $installation.task_name `
            -TaskPath $installation.task_path `
            -ErrorAction SilentlyContinue
        $taskActionVerified = (
            @($task.Actions).Count -eq 1 -and
            $task.Actions[0].Execute -eq $installation.task_action_execute -and
            $task.Actions[0].Arguments -eq $installation.task_action_arguments -and
            $task.Description -eq $installation.task_description
        )
        $taskSingleInstance = $task.Settings.MultipleInstances.ToString() -eq "IgnoreNew"
        $supervisorState = $task.State.ToString()
        $supervisorRegistrationVerified = $taskActionVerified -and $taskSingleInstance
        if (-not $taskActionVerified) {
            $reasons += "Scheduled Task ownership/action verification failed"
        }
        if (-not $taskSingleInstance) {
            $reasons += "Scheduled Task single-instance policy is not IgnoreNew"
        }
        if ($supervisorState -ne "Running") {
            $reasons += "Scheduled Task is not running"
        }
    }
    $supervisorDetails = [ordered]@{
        task_name = $installation.task_name
        task_path = $installation.task_path
        action_verified = $taskActionVerified
        single_instance_verified = $taskSingleInstance
        last_task_result = $(if ($null -eq $taskInfo) { $null } else { $taskInfo.LastTaskResult })
    }
}
else {
    $expectedRunData = (
        "`"$($installation.task_action_execute)`" " +
        [string]$installation.task_action_arguments
    )
    $metadataVerified = (
        $installation.supervisor.registry_path -eq $RunKeyPath -and
        $installation.supervisor.value_name -eq $RunValueName -and
        $installation.supervisor.value_data -eq $expectedRunData
    )
    $runRegistration = Get-RunRegistration
    $runValueVerified = (
        $runRegistration.present -and
        $runRegistration.value_data -eq $expectedRunData
    )
    $supervisorRegistrationVerified = $metadataVerified -and $runValueVerified
    if (-not $metadataVerified) {
        $supervisorState = "invalid_metadata"
        $reasons += "HKCU Run supervisor metadata is outside the exact owned boundary"
    }
    elseif (-not $runRegistration.present) {
        $supervisorState = "absent"
        $reasons += "owned HKCU Run value is absent"
    }
    elseif (-not $runValueVerified) {
        $supervisorState = "mismatch"
        $reasons += "HKCU Run value data no longer matches the exact owned command"
    }
    else {
        $supervisorState = "registered_for_logon"
    }
    $supervisorDetails = [ordered]@{
        registry_path = $RunKeyPath
        value_name = $RunValueName
        value_present = $runRegistration.present
        value_data_verified = $runValueVerified
        metadata_verified = $metadataVerified
    }
}

$cliHashVerified = $false
$runtimeHashVerified = $false
$launcherHashVerified = $false
try {
    $cliHashVerified = (
        (Get-Sha256 ([string]$installation.cli_path)) -eq
        ([string]$installation.cli_sha256).ToLowerInvariant()
    )
}
catch {
    $cliHashVerified = $false
}
try {
    $runtimeHashVerified = (
        (Get-Sha256 ([string]$installation.runtime_executable)) -eq
        ([string]$installation.runtime_sha256).ToLowerInvariant()
    )
}
catch {
    $runtimeHashVerified = $false
}
try {
    $launcherHashVerified = (
        (Get-Sha256 ([string]$installation.launcher_path)) -eq
        ([string]$installation.launcher_sha256).ToLowerInvariant()
    )
}
catch {
    $launcherHashVerified = $false
}
if (-not $cliHashVerified) {
    $reasons += "configured CLI executable is missing or changed"
}
if (-not $runtimeHashVerified) {
    $reasons += "configured CLI runtime is missing or changed"
}
if (-not $launcherHashVerified) {
    $reasons += "installed companion launcher is missing or changed"
}

$health = $null
$healthFresh = $false
$healthSchemaValid = $false
$processVerified = $false
if (-not (Test-Path -LiteralPath $healthPath -PathType Leaf)) {
    $reasons += "health heartbeat is absent"
}
else {
    try {
        $health = Get-Content -LiteralPath $healthPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $healthSchemaValid = (
            $health.schema -eq "zsec.antivirus.companion-health.v1" -and
            $health.product -eq "ZSEC Antivirus" -and
            (Get-NormalizedPath ([string]$health.runtime_executable)) -eq
                (Get-NormalizedPath ([string]$installation.runtime_executable)) -and
            ([string]$health.runtime_sha256).ToLowerInvariant() -eq
                ([string]$installation.runtime_sha256).ToLowerInvariant() -and
            $health.policy.primary_antivirus -eq $false -and
            $health.policy.real_time_protection -eq $false -and
            $health.policy.pre_access_enforcement -eq $false
        )
        if (-not $healthSchemaValid) {
            $reasons += "health schema or non-primary policy is invalid"
        }
        # Windows PowerShell leaves JSON timestamps as strings, while PowerShell 7
        # materializes ISO-8601 values as DateTime. A direct DateTimeOffset cast
        # preserves the instant in both runtimes without a locale-sensitive
        # DateTime -> display string -> Parse round trip.
        $updatedAt = ([DateTimeOffset]$health.updated_at).ToUniversalTime()
        $maximumAge = [double]$health.heartbeat_seconds * 3.0 + 15.0
        $age = ([DateTimeOffset]::UtcNow - $updatedAt).TotalSeconds
        $healthFresh = $age -ge -5.0 -and $age -le $maximumAge
        if (-not $healthFresh) {
            $reasons += "health heartbeat is stale or from the future"
        }
        if ($health.operational_state -ne "healthy") {
            $reasons += "watch session reports $($health.operational_state)"
        }
        $process = Get-Process -Id ([int]$health.process_id) -ErrorAction SilentlyContinue
        if ($null -ne $process) {
            try {
                $processVerified = (
                    (Get-NormalizedPath $process.Path) -eq
                    (Get-NormalizedPath ([string]$installation.runtime_executable))
                )
            }
            catch {
                $processVerified = $false
            }
        }
        if (-not $processVerified) {
            $reasons += "heartbeat process is absent or does not match the configured CLI runtime"
        }
    }
    catch {
        $reasons += "cannot validate health heartbeat: $($_.Exception.Message)"
    }
}

$healthy = $reasons.Count -eq 0
$metadataInventoryInProgress = (
    -not $healthy -and
    $reasons.Count -eq 1 -and
    $reasons[0] -eq "watch session reports inventorying_metadata" -and
    $supervisorRegistrationVerified -and
    $cliHashVerified -and
    $runtimeHashVerified -and
    $launcherHashVerified -and
    $healthSchemaValid -and
    $healthFresh -and
    $processVerified -and
    $base.existing_primary_protection.aggregate_good -eq $true
)
$base.installed = $true
$base.healthy = $healthy
$base.decision = $(
    if ($healthy) { "healthy_companion" }
    elseif ($metadataInventoryInProgress) { "metadata_inventory_in_progress" }
    else { "degraded" }
)
if ($metadataInventoryInProgress) {
    $base.reasons = [object[]]@(
        "initial protected-folder metadata inventory is in progress"
    )
}
else {
    $base.reasons = $reasons
}
$base.supervisor = [ordered]@{
    kind = $supervisorKind
    registration_verified = $supervisorRegistrationVerified
    state = $supervisorState
    details = $supervisorDetails
    lifecycle = $supervisorLifecycleEvidence
}
$base.integrity = [ordered]@{
    cli_hash_verified = $cliHashVerified
    runtime_hash_verified = $runtimeHashVerified
    launcher_hash_verified = $launcherHashVerified
}
$base.health = [ordered]@{
    path = $healthPath
    schema_valid = $healthSchemaValid
    fresh = $healthFresh
    process_verified = $processVerified
    last_record = $health
}
Write-StatusAndExit -Value $base -Code $(if ($healthy) { 0 } else { 2 })
