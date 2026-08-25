#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$StatusScript
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$tokens = $null
$parseErrors = $null
$scriptText = Get-Content -LiteralPath $StatusScript -Raw -Encoding UTF8
$scriptAst = [Management.Automation.Language.Parser]::ParseInput(
    $scriptText,
    [ref]$tokens,
    [ref]$parseErrors
)
if (@($parseErrors).Count -ne 0) {
    throw "The status script could not be parsed."
}

foreach ($functionName in @(
        "Get-OptionalProperty",
        "ConvertTo-UtcEvidenceTimestamp",
        "ConvertTo-OptionalEvidenceInt64",
        "ConvertTo-BoundedEvidenceString",
        "Get-DefenderThreatStatusName",
        "Get-DefenderExecutionStatusName",
        "Get-DefenderDetectionSourceName",
        "Get-DefenderSeverityName",
        "ConvertTo-DefenderProtectionHistoryEvidence"
    )) {
    $definition = $scriptAst.Find(
        {
            param($Node)
            $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $Node.Name -eq $functionName
        },
        $true
    )
    if ($null -eq $definition) {
        throw "Required status helper is absent: $functionName"
    }
    . ([scriptblock]::Create($definition.Extent.Text))
}

$referenceTime = [DateTimeOffset]::Parse("2026-08-25T12:00:00Z")
$detections = @(
    [pscustomobject]@{
        ThreatID = [long]1001
        DetectionSourceTypeID = 3
        InitialDetectionTime = [DateTimeOffset]::Parse("2026-08-24T09:00:00Z")
        LastThreatStatusChangeTime = [DateTimeOffset]::Parse("2026-08-24T09:05:00Z")
        RemediationTime = $null
        ThreatStatusID = 1
        CurrentThreatExecutionStatusID = 3
        ActionSuccess = $false
        Resources = @("file:_C:\private\secret-sample.exe")
        ProcessName = "C:\private\secret-process.exe"
        DomainUser = "PRIVATE-DOMAIN\private-user"
    },
    [pscustomobject]@{
        ThreatID = [long]1002
        DetectionSourceTypeID = 4
        InitialDetectionTime = [DateTimeOffset]::Parse("2026-08-23T10:00:00Z")
        LastThreatStatusChangeTime = [DateTimeOffset]::Parse("2026-08-23T10:01:00Z")
        RemediationTime = [DateTimeOffset]::Parse("2026-08-23T10:01:00Z")
        ThreatStatusID = 102
        CurrentThreatExecutionStatusID = 4
        ActionSuccess = $false
    }
)
for ($index = 0; $index -lt 22; $index++) {
    $detections += [pscustomobject]@{
        ThreatID = [long](2000 + $index)
        DetectionSourceTypeID = 2
        InitialDetectionTime = [DateTimeOffset]::Parse("2026-01-01T00:00:00Z").AddDays($index)
        LastThreatStatusChangeTime = [DateTimeOffset]::Parse("2026-01-01T00:01:00Z").AddDays($index)
        RemediationTime = [DateTimeOffset]::Parse("2026-01-01T00:01:00Z").AddDays($index)
        ThreatStatusID = 2
        CurrentThreatExecutionStatusID = 4
        ActionSuccess = $true
    }
}

$longThreatName = "Trojan$([char]0):Win32/" + ("X" * 240)
$descriptors = @{
    "1001" = [ordered]@{
        threat_name = $longThreatName
        severity_id = 4
        category_id = 8
    }
    "1002" = [ordered]@{
        threat_name = "PUA:Win32/Test"
        severity_id = 2
        category_id = 27
    }
}
$evidence = ConvertTo-DefenderProtectionHistoryEvidence `
    -Detections $detections `
    -ThreatDescriptors $descriptors `
    -ReferenceTime $referenceTime `
    -ThreatDescriptorsAvailable $true
$json = $evidence | ConvertTo-Json -Depth 8
foreach ($secret in @("private", "secret-sample", "secret-process", "PRIVATE-DOMAIN")) {
    if ($json -match [regex]::Escape($secret)) {
        throw "Protection history leaked a deliberately excluded private marker: $secret"
    }
}
if ($evidence.records[0].threat_name.Length -ne 200) {
    throw "Threat names must be control-free and bounded to 200 characters."
}
if ($evidence.records[0].threat_name.IndexOf([char]0) -ge 0) {
    throw "Threat names must not retain control characters."
}

[ordered]@{
    schema = "zsec.tests.defender-protection-history-evidence.v1"
    total_detection_records = $evidence.total_detection_records
    returned_records = $evidence.returned_records
    recent_30_days_count = $evidence.recent_30_days_count
    attention_required_count = $evidence.attention_required_count
    remediation_failed_count = $evidence.remediation_failed_count
    first_status = $evidence.records[0].status
    first_source = $evidence.records[0].source
    first_severity = $evidence.records[0].severity
    first_name_length = $evidence.records[0].threat_name.Length
    local_only = $evidence.privacy.local_only
    resource_paths_included = $evidence.privacy.resource_paths_included
    cloud_upload_performed = $evidence.privacy.cloud_upload_performed
} | ConvertTo-Json -Depth 4
