[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$packageRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$requirementsPath = Join-Path $packageRoot 'toolchain.requirements.json'
$modulePath = Join-Path $packageRoot 'scripts\ZsecChromiumBootstrap.psm1'
Import-Module $modulePath -Force

$script:testsRun = 0

function Assert-True {
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,

        [Parameter(Mandatory)]
        [string]$Message
    )
    $script:testsRun++
    if (-not $Condition) {
        throw "ASSERT TRUE FAILED: $Message"
    }
}

function Assert-False {
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,

        [Parameter(Mandatory)]
        [string]$Message
    )
    Assert-True -Condition (-not $Condition) -Message $Message
}

function Copy-Probe {
    param([Parameter(Mandatory)][object]$Probe)
    return $Probe | ConvertTo-Json -Depth 16 | ConvertFrom-Json
}

function New-SupportedProbe {
    [pscustomobject]@{
        os = [pscustomobject]@{
            platform     = 'Windows'
            caption      = 'Microsoft Windows 11 Pro'
            version      = '10.0.26100'
            build_number = 26100
            architecture = '64-bit'
            product_type = 1
        }
        memory = [pscustomobject]@{
            total_bytes = [int64]34359738368
        }
        disk = [pscustomobject]@{
            drive      = 'C:'
            filesystem = 'NTFS'
            free_bytes = [int64]536870912000
        }
        visual_studio = [pscustomobject]@{
            present           = $true
            version           = '18.8.2.0'
            installation_path = 'C:\Program Files\Microsoft Visual Studio\18\BuildTools'
            has_cpp_x64       = $true
            has_atlmfc        = $true
            vswhere_path      = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
        }
        sdk = [pscustomobject]@{
            present      = $true
            version      = '10.0.28000.0'
            include_path = 'C:\Program Files (x86)\Windows Kits\10\Include\10.0.28000.0'
            lib_path     = 'C:\Program Files (x86)\Windows Kits\10\Lib\10.0.28000.0'
        }
        debugging_tools = [pscustomobject]@{
            present  = $true
            version  = '10.0.28000.2270'
            cdb_path = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'
        }
        depot_tools = [pscustomobject]@{
            root                  = 'C:\src\depot_tools'
            present               = $true
            missing_files         = @()
            first_path_entry      = 'C:\src\depot_tools'
            first_python3         = 'C:\src\depot_tools\python3.bat'
            first_gclient         = 'C:\src\depot_tools\gclient.bat'
            toolchain_environment = '0'
        }
        checkout = [pscustomobject]@{
            root           = 'C:\src'
            target         = 'C:\src\zsec-chromium'
            git_cache      = 'C:\src\zsec-git-cache'
            root_exists    = $true
            contains_space = $false
        }
    }
}

function Get-Check {
    param(
        [Parameter(Mandatory)][object]$Audit,
        [Parameter(Mandatory)][string]$Id
    )
    return @($Audit.checks | Where-Object { $_.id -eq $Id })[0]
}

$requirements = Get-ZsecChromiumRequirements -Path $requirementsPath
Assert-False -Condition ([bool]$requirements.branding.allow_chrome_branding) `
    -Message 'Manifest must disable Chrome branding.'
Assert-False -Condition ([bool]$requirements.safety.may_modify_antivirus) `
    -Message 'Manifest must prohibit antivirus mutation.'
Assert-True -Condition ([string]$requirements.safety.default_mode -eq 'audit-only') `
    -Message 'Default mode must remain audit-only.'

$good = New-SupportedProbe
$audit = Test-ZsecChromiumProbe -Probe $good -Requirements $requirements
Assert-True -Condition ([bool]$audit.passed) -Message 'Supported Windows 11 probe should pass.'

$server = Copy-Probe $good
$server.os.caption = 'Microsoft Windows Server 2022 Standard'
$server.os.product_type = 3
$server.os.build_number = 20348
$audit = Test-ZsecChromiumProbe -Probe $server -Requirements $requirements
Assert-True -Condition ([bool]$audit.passed) -Message 'Supported Windows Server probe should pass.'

$win10 = Copy-Probe $good
$win10.os.caption = 'Microsoft Windows 10 Pro'
$win10.os.product_type = 1
$win10.os.build_number = 19045
$audit = Test-ZsecChromiumProbe -Probe $win10 -Requirements $requirements
Assert-False -Condition ([bool]$audit.passed) -Message 'Windows 10 must fail closed.'
Assert-False -Condition ([bool](Get-Check -Audit $audit -Id 'host.os').passed) -Message 'Windows 10 must fail host.os.'

$vs2022 = Copy-Probe $good
$vs2022.visual_studio.version = '17.14.0.0'
$audit = Test-ZsecChromiumProbe -Probe $vs2022 -Requirements $requirements
Assert-False -Condition ([bool](Get-Check -Audit $audit -Id 'visual_studio.version').passed) `
    -Message 'Visual Studio 2022 must fail the current toolchain version gate.'

$noMfc = Copy-Probe $good
$noMfc.visual_studio.has_atlmfc = $false
$audit = Test-ZsecChromiumProbe -Probe $noMfc -Requirements $requirements
Assert-False -Condition ([bool](Get-Check -Audit $audit -Id 'visual_studio.atlmfc').passed) `
    -Message 'Missing ATL/MFC must fail closed.'

$oldSdk = Copy-Probe $good
$oldSdk.sdk.version = '10.0.26100.0'
$audit = Test-ZsecChromiumProbe -Probe $oldSdk -Requirements $requirements
Assert-False -Condition ([bool](Get-Check -Audit $audit -Id 'windows_sdk').passed) `
    -Message 'SDK 26100 must fail the pinned SDK gate.'

$oldDebugger = Copy-Probe $good
$oldDebugger.debugging_tools.version = '10.0.26100.1000'
$audit = Test-ZsecChromiumProbe -Probe $oldDebugger -Requirements $requirements
Assert-False -Condition ([bool](Get-Check -Audit $audit -Id 'debugging_tools').passed) `
    -Message 'Old Debugging Tools must fail closed.'

$wrongPath = Copy-Probe $good
$wrongPath.depot_tools.first_path_entry = 'C:\Program Files\Git\cmd'
$wrongPath.depot_tools.first_python3 = 'C:\Users\User\AppData\Local\Microsoft\WindowsApps\python3.exe'
$audit = Test-ZsecChromiumProbe -Probe $wrongPath -Requirements $requirements
Assert-False -Condition ([bool](Get-Check -Audit $audit -Id 'depot_tools.path_first').passed) `
    -Message 'depot_tools not first on PATH must fail closed.'
Assert-False -Condition ([bool](Get-Check -Audit $audit -Id 'depot_tools.python3').passed) `
    -Message 'WindowsApps Python must fail closed.'

$lowDisk = Copy-Probe $good
$lowDisk.disk.free_bytes = [int64]107374182400
$audit = Test-ZsecChromiumProbe -Probe $lowDisk -Requirements $requirements
Assert-False -Condition ([bool](Get-Check -Audit $audit -Id 'resources.disk').passed) `
    -Message 'Less than 250 GiB free must fail closed.'

$lowMemory = Copy-Probe $good
$lowMemory.memory.total_bytes = [int64]8589934592
$audit = Test-ZsecChromiumProbe -Probe $lowMemory -Requirements $requirements
Assert-False -Condition ([bool](Get-Check -Audit $audit -Id 'resources.memory').passed) `
    -Message 'Less than 16 GiB RAM must fail closed.'

$spacePath = Copy-Probe $good
$spacePath.checkout.target = 'C:\src\ZSEC Chromium'
$spacePath.checkout.contains_space = $true
$audit = Test-ZsecChromiumProbe -Probe $spacePath -Requirements $requirements
Assert-False -Condition ([bool](Get-Check -Audit $audit -Id 'checkout.paths').passed) `
    -Message 'Whitespace in checkout paths must fail closed.'

$scripts = Get-ChildItem -LiteralPath (Join-Path $packageRoot 'scripts') -File |
    Where-Object { $_.Extension -in @('.ps1', '.psm1', '.cmd') }
$scriptText = ($scripts | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
$forbiddenCommands = @(
    'Add-MpPreference',
    'Set-MpPreference',
    'Remove-MpPreference',
    'Stop-Service',
    'Set-Service',
    'Unregister-ScheduledTask',
    'SecurityCenter2',
    'Win32_Product',
    'Malwarebytes'
)
foreach ($forbidden in $forbiddenCommands) {
    Assert-False -Condition ($scriptText -match [regex]::Escape($forbidden)) `
        -Message "Bootstrap scripts must not contain security-provider mutation token: $forbidden"
}

$bootstrapText = Get-Content -LiteralPath (Join-Path $packageRoot 'scripts\Invoke-ZsecChromiumBootstrap.ps1') -Raw
$auditIndex = $bootstrapText.IndexOf('$audit = Invoke-ZsecChromiumAudit', [StringComparison]::Ordinal)
$mutationIndex = $bootstrapText.IndexOf('$null = New-Item', [StringComparison]::Ordinal)
Assert-True -Condition ($auditIndex -ge 0 -and $mutationIndex -gt $auditIndex) `
    -Message 'Audit invocation must precede the first checkout/cache mutation.'
Assert-True -Condition ($bootstrapText -match 'if \(-not \[bool\]\$audit\.passed\)') `
    -Message 'Bootstrap must explicitly reject a failed audit.'

"PASS: $script:testsRun assertions"
exit 0
