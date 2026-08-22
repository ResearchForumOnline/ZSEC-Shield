#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("UpdateSignatures", "QuickScan", "FullScan")]
    [string]$Action
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

function ConvertTo-OptionalEvidenceBoolean {
    param($Value)
    if ($null -eq $Value) {
        return $null
    }
    return [bool]$Value
}

function Get-DefenderEvidence {
    $status = Get-MpComputerStatus -ErrorAction Stop
    return [ordered]@{
        source = "Get-MpComputerStatus"
        antivirus_enabled = [bool]$status.AntivirusEnabled
        real_time_protection_enabled = [bool]$status.RealTimeProtectionEnabled
        service_enabled = [bool]$status.AMServiceEnabled
        behavior_monitor_enabled = [bool]$status.BehaviorMonitorEnabled
        ioav_protection_enabled = [bool]$status.IoavProtectionEnabled
        on_access_protection_enabled = [bool]$status.OnAccessProtectionEnabled
        signature_version = ConvertTo-OptionalEvidenceString (
            Get-OptionalProperty -InputObject $status -Name "AntivirusSignatureVersion"
        )
        signature_last_updated = ConvertTo-UtcEvidenceTimestamp (
            Get-OptionalProperty -InputObject $status -Name "AntivirusSignatureLastUpdated"
        )
        signatures_out_of_date = ConvertTo-OptionalEvidenceBoolean (
            Get-OptionalProperty -InputObject $status -Name "DefenderSignaturesOutOfDate"
        )
        quick_scan_end = ConvertTo-UtcEvidenceTimestamp (
            Get-OptionalProperty -InputObject $status -Name "QuickScanEndTime"
        )
        full_scan_end = ConvertTo-UtcEvidenceTimestamp (
            Get-OptionalProperty -InputObject $status -Name "FullScanEndTime"
        )
    }
}

if ($PSVersionTable.PSEdition -eq "Core" -and -not $IsWindows) {
    throw "Windows protection actions are supported only on Windows."
}

$startedAt = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
$result = [ordered]@{
    schema = "zsec.antivirus.windows-protection-action.v1"
    product = "ZSEC Antivirus"
    provider = "Microsoft Defender Antivirus"
    action = $Action
    started_at = $startedAt
    completed_at = $null
    outcome = "failed"
    provider_configuration_changed = $false
    exclusions_changed = $false
    security_center_registration_changed = $false
    existing_provider_removed = $false
    evidence = $null
    error = $null
}

try {
    # These are the only permitted operations. They ask Defender to refresh its
    # signatures or scan; they never select a provider, change preferences,
    # create exclusions, alter Security Center registration, or remove software.
    switch ($Action) {
        "UpdateSignatures" {
            Update-MpSignature -ErrorAction Stop | Out-Null
        }
        "QuickScan" {
            Start-MpScan -ScanType QuickScan -ErrorAction Stop
        }
        "FullScan" {
            Start-MpScan -ScanType FullScan -ErrorAction Stop
        }
    }
    $result.evidence = Get-DefenderEvidence
    $result.outcome = "completed"
}
catch {
    $message = [string]$_.Exception.Message
    if ($message.Length -gt 1000) {
        $message = $message.Substring(0, 1000)
    }
    $result.error = $message
}
finally {
    $result.completed_at = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
}

$result | ConvertTo-Json -Depth 8
if ($result.outcome -eq "completed") {
    exit 0
}
exit 2
