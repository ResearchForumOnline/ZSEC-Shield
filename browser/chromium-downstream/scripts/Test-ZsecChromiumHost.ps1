[CmdletBinding()]
param(
    [string]$RequirementsPath,

    [switch]$Json,

    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RequirementsPath)) {
    $RequirementsPath = Join-Path $PSScriptRoot '..\toolchain.requirements.json'
}

Import-Module (Join-Path $PSScriptRoot 'ZsecChromiumBootstrap.psm1') -Force

try {
    $audit = Invoke-ZsecChromiumAudit -RequirementsPath $RequirementsPath
}
catch {
    $audit = [pscustomobject]@{
        schema_version = 1
        audited_at_utc = [DateTime]::UtcNow.ToString('o')
        passed         = $false
        fatal_error    = $_.Exception.Message
        checks         = @()
    }
}

$serialized = $audit | ConvertTo-Json -Depth 32
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $outputDirectory = Split-Path -Parent $OutputPath
    if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and
        -not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
        throw "Output directory does not exist: $outputDirectory"
    }
    Set-Content -LiteralPath $OutputPath -Value $serialized -Encoding UTF8 -NoNewline
}

if ($Json) {
    $serialized
}
elseif ($audit.PSObject.Properties.Name -contains 'fatal_error') {
    "ZSEC Chromium downstream host audit: FAIL (no fetch permitted)"
    "Fatal audit error: $($audit.fatal_error)"
}
else {
    Format-ZsecChromiumAudit -Audit $audit
}

if ([bool]$audit.passed) {
    exit 0
}
exit 2
