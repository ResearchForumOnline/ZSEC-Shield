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
        "ConvertTo-DefenderAgeEvidence",
        "Set-DefenderAgeAndFeatureEvidence"
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

function Assert-Equal {
    param($Expected, $Actual, [Parameter(Mandatory = $true)][string]$Label)
    if ($Expected -ne $Actual) {
        throw "$Label expected '$Expected' but received '$Actual'."
    }
}

foreach ($invalidValue in @(
        $null,
        [uint32]::MaxValue,
        -1,
        "not-a-number",
        ([long][int]::MaxValue + 1),
        [double]::PositiveInfinity,
        $true
    )) {
    $normalized = ConvertTo-DefenderAgeEvidence $invalidValue
    if ($null -ne $normalized) {
        throw "Invalid scan-age evidence was not mapped to null: '$invalidValue'."
    }
}

foreach ($validValue in @(0, 7, "14", [int]::MaxValue)) {
    Assert-Equal `
        -Expected ([int]$validValue) `
        -Actual (ConvertTo-DefenderAgeEvidence $validValue) `
        -Label "valid scan age $validValue"
}

$status = [pscustomobject]@{
    AntivirusEnabled = $true
    RealTimeProtectionEnabled = $true
    AntispywareEnabled = $true
    AMServiceEnabled = $true
    BehaviorMonitorEnabled = $true
    IoavProtectionEnabled = $true
    OnAccessProtectionEnabled = $true
    NISEnabled = $true
    IsTamperProtected = $true
    RebootRequired = $false
    AMEngineVersion = "1.1.26080.1"
    AMProductVersion = "4.18.26070.1004"
    AntivirusSignatureVersion = "1.435.1.0"
    AntivirusSignatureLastUpdated = [DateTimeOffset]::Parse("2026-08-22T12:00:00Z")
    AntivirusSignatureAge = [uint32]::MaxValue
    DefenderSignaturesOutOfDate = $false
    QuickScanAge = [uint32]3
    QuickScanEndTime = [DateTimeOffset]::Parse("2026-08-22T11:00:00Z")
    FullScanAge = [uint32]::MaxValue
    FullScanEndTime = $null
}
$evidence = [ordered]@{
    antivirus_enabled = $true
    real_time_protection_enabled = $true
    service_enabled = $true
    behavior_monitor_enabled = $true
    ioav_protection_enabled = $true
    on_access_protection_enabled = $true
    network_inspection_enabled = $true
    confirmed_active = $false
    baseline_features_confirmed = $false
    signatures = [ordered]@{
        antivirus_age_days = $null
    }
    scans = [ordered]@{
        quick_scan_age_days = $null
        quick_scan_end = $null
        full_scan_age_days = $null
        full_scan_end = $null
    }
}
Set-DefenderAgeAndFeatureEvidence -Defender $evidence -Status $status
Assert-Equal -Expected $true -Actual $evidence.confirmed_active -Label "active evidence"
Assert-Equal `
    -Expected $true `
    -Actual $evidence.baseline_features_confirmed `
    -Label "baseline evidence"
Assert-Equal -Expected 3 -Actual $evidence.scans.quick_scan_age_days -Label "quick age"
if ($null -ne $evidence.scans.full_scan_age_days) {
    throw "The no-full-scan sentinel must remain absent evidence."
}
if ($null -ne $evidence.signatures.antivirus_age_days) {
    throw "The invalid signature-age sentinel must remain absent evidence."
}

[ordered]@{
    schema = "zsec.tests.defender-scan-age-evidence.v1"
    sentinel_maps_to_null = ($null -eq $evidence.scans.full_scan_age_days)
    signature_sentinel_maps_to_null = ($null -eq $evidence.signatures.antivirus_age_days)
    normal_age_days = $evidence.scans.quick_scan_age_days
    confirmed_active = $evidence.confirmed_active
    baseline_features_confirmed = $evidence.baseline_features_confirmed
} | ConvertTo-Json -Depth 4
