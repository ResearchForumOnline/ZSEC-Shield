Set-StrictMode -Version Latest

function ConvertTo-ZsecVersion {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return [version]'0.0.0.0'
    }

    $parts = @([regex]::Matches([string]$Value, '\d+') | ForEach-Object {
        [int]$_.Value
    })
    if ($parts.Count -eq 0) {
        return [version]'0.0.0.0'
    }

    $normalized = @(0, 0, 0, 0)
    for ($index = 0; $index -lt [math]::Min(4, $parts.Count); $index++) {
        $normalized[$index] = $parts[$index]
    }

    return [version]::new(
        $normalized[0],
        $normalized[1],
        $normalized[2],
        $normalized[3]
    )
}

function ConvertTo-ZsecNormalizedPath {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    $candidate = $Path.Trim().Trim('"').Replace('/', '\')
    try {
        $candidate = [System.IO.Path]::GetFullPath($candidate)
    }
    catch {
        # Preserve the original value so the caller can report a failed check.
    }

    if ($candidate.Length -gt 3) {
        $candidate = $candidate.TrimEnd('\')
    }
    return $candidate
}

function Get-ZsecChromiumRequirements {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $requirements = Get-Content -LiteralPath $resolved -Raw -Encoding UTF8 |
        ConvertFrom-Json -ErrorAction Stop

    if ([int]$requirements.schema_version -ne 1) {
        throw "Unsupported requirements schema version: $($requirements.schema_version)"
    }
    if ([bool]$requirements.branding.allow_chrome_branding) {
        throw 'The requirements manifest must fail closed with Chrome branding disabled.'
    }
    if ([bool]$requirements.safety.may_modify_antivirus) {
        throw 'The requirements manifest must not authorize antivirus changes.'
    }
    if ([bool]$requirements.safety.may_fetch_when_audit_fails) {
        throw 'The requirements manifest must not authorize fetch after a failed audit.'
    }

    return $requirements
}

function New-ZsecAuditCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Id,

        [Parameter(Mandatory)]
        [bool]$Passed,

        [Parameter(Mandatory)]
        [string]$Expected,

        [AllowNull()]
        [object]$Actual,

        [Parameter(Mandatory)]
        [string]$Evidence
    )

    [pscustomobject]@{
        id       = $Id
        passed   = $Passed
        expected = $Expected
        actual   = if ($null -eq $Actual) { $null } else { [string]$Actual }
        evidence = $Evidence
    }
}

function Get-ZsecFirstCommandPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $results = @(Get-Command -Name $Name -All -ErrorAction SilentlyContinue)
    if ($results.Count -eq 0 -or
        -not ($results[0].PSObject.Properties.Name -contains 'Path')) {
        return ''
    }
    return ConvertTo-ZsecNormalizedPath -Path ([string]$results[0].Path)
}

function Get-ZsecVisualStudioProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Requirements
    )

    $probe = [ordered]@{
        present           = $false
        version           = '0.0.0.0'
        installation_path = ''
        has_cpp_x64       = $false
        has_atlmfc        = $false
        vswhere_path      = ''
    }

    $programFilesX86 = [Environment]::GetFolderPath('ProgramFilesX86')
    $vswhere = Join-Path $programFilesX86 'Microsoft Visual Studio\Installer\vswhere.exe'
    $probe.vswhere_path = $vswhere
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        return [pscustomobject]$probe
    }

    try {
        $raw = & $vswhere -latest -products '*' -version '[18.0,19.0)' -format json -utf8 2>$null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($raw -join "`n"))) {
            return [pscustomobject]$probe
        }

        $instances = @(($raw -join "`n") | ConvertFrom-Json)
        if ($instances.Count -eq 0) {
            return [pscustomobject]$probe
        }

        $instance = $instances[0]
        $probe.present = $true
        $probe.version = [string]$instance.installationVersion
        $probe.installation_path = ConvertTo-ZsecNormalizedPath -Path ([string]$instance.installationPath)

        $cppPath = @(& $vswhere -latest -products '*' -version '[18.0,19.0)' `
            -requires 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64' `
            -property installationPath 2>$null)
        $mfcPath = @(& $vswhere -latest -products '*' -version '[18.0,19.0)' `
            -requires 'Microsoft.VisualStudio.Component.VC.ATLMFC' `
            -property installationPath 2>$null)

        $probe.has_cpp_x64 = $cppPath.Count -gt 0 -and
            (ConvertTo-ZsecNormalizedPath -Path ([string]$cppPath[0])) -ieq $probe.installation_path
        $probe.has_atlmfc = $mfcPath.Count -gt 0 -and
            (ConvertTo-ZsecNormalizedPath -Path ([string]$mfcPath[0])) -ieq $probe.installation_path
    }
    catch {
        $probe.present = $false
        $probe.version = '0.0.0.0'
        $probe.installation_path = ''
        $probe.has_cpp_x64 = $false
        $probe.has_atlmfc = $false
    }

    return [pscustomobject]$probe
}

function Get-ZsecChromiumHostProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Requirements
    )

    $os = $null
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    }
    catch {
        $os = [pscustomobject]@{
            Caption                = ''
            Version                = '0.0.0.0'
            BuildNumber            = '0'
            OSArchitecture         = ''
            ProductType            = 0
            TotalVisibleMemorySize = 0
        }
    }

    $checkoutRoot = ConvertTo-ZsecNormalizedPath -Path ([string]$Requirements.checkout.root)
    $checkoutDrive = [System.IO.Path]::GetPathRoot($checkoutRoot).TrimEnd('\')
    $logicalDisk = $null
    try {
        $logicalDisk = Get-CimInstance -ClassName Win32_LogicalDisk `
            -Filter "DeviceID='$checkoutDrive'" -ErrorAction Stop
    }
    catch {
        $logicalDisk = [pscustomobject]@{
            FileSystem = ''
            FreeSpace  = 0
        }
    }

    $programFilesX86 = [Environment]::GetFolderPath('ProgramFilesX86')
    $sdkRoot = Join-Path $programFilesX86 'Windows Kits\10'
    $sdkVersion = [string]$Requirements.windows_sdk.version_directory
    $sdkIncludePath = Join-Path $sdkRoot "Include\$sdkVersion"
    $sdkLibPath = Join-Path $sdkRoot "Lib\$sdkVersion"
    $sdkPresent = (Test-Path -LiteralPath (Join-Path $sdkIncludePath 'um\Windows.h') -PathType Leaf) -and
        (Test-Path -LiteralPath (Join-Path $sdkLibPath 'um\x64') -PathType Container) -and
        (Test-Path -LiteralPath (Join-Path $sdkLibPath 'um\x86') -PathType Container)

    $cdbPath = Join-Path $sdkRoot 'Debuggers\x64\cdb.exe'
    $debuggerVersion = '0.0.0.0'
    if (Test-Path -LiteralPath $cdbPath -PathType Leaf) {
        try {
            $debuggerVersion = [string](Get-Item -LiteralPath $cdbPath -ErrorAction Stop).VersionInfo.FileVersion
        }
        catch {
            $debuggerVersion = '0.0.0.0'
        }
    }

    $depotRoot = ConvertTo-ZsecNormalizedPath -Path ([string]$Requirements.depot_tools.root)
    $pathEntries = @($env:Path -split ';' | ForEach-Object {
        ConvertTo-ZsecNormalizedPath -Path $_
    } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $firstPathEntry = if ($pathEntries.Count -gt 0) { $pathEntries[0] } else { '' }

    $requiredDepotFiles = @($Requirements.depot_tools.required_files)
    $missingDepotFiles = @($requiredDepotFiles | Where-Object {
        -not (Test-Path -LiteralPath (Join-Path $depotRoot ([string]$_)))
    })

    $targetPath = ConvertTo-ZsecNormalizedPath -Path ([string]$Requirements.checkout.target)
    $gitCachePath = ConvertTo-ZsecNormalizedPath -Path ([string]$Requirements.checkout.git_cache)

    [pscustomobject]@{
        os = [pscustomobject]@{
            platform      = 'Windows'
            caption       = [string]$os.Caption
            version       = [string]$os.Version
            build_number  = [int]$os.BuildNumber
            architecture  = [string]$os.OSArchitecture
            product_type  = [int]$os.ProductType
        }
        memory = [pscustomobject]@{
            total_bytes = [int64]$os.TotalVisibleMemorySize * 1024
        }
        disk = [pscustomobject]@{
            drive       = $checkoutDrive
            filesystem  = [string]$logicalDisk.FileSystem
            free_bytes  = [int64]$logicalDisk.FreeSpace
        }
        visual_studio = Get-ZsecVisualStudioProbe -Requirements $Requirements
        sdk = [pscustomobject]@{
            present      = $sdkPresent
            version      = $sdkVersion
            include_path = $sdkIncludePath
            lib_path     = $sdkLibPath
        }
        debugging_tools = [pscustomobject]@{
            present  = Test-Path -LiteralPath $cdbPath -PathType Leaf
            version  = $debuggerVersion
            cdb_path = $cdbPath
        }
        depot_tools = [pscustomobject]@{
            root                 = $depotRoot
            present              = Test-Path -LiteralPath $depotRoot -PathType Container
            missing_files        = $missingDepotFiles
            first_path_entry     = $firstPathEntry
            first_python3        = Get-ZsecFirstCommandPath -Name 'python3'
            first_gclient        = Get-ZsecFirstCommandPath -Name 'gclient'
            toolchain_environment = [string]$env:DEPOT_TOOLS_WIN_TOOLCHAIN
        }
        checkout = [pscustomobject]@{
            root           = $checkoutRoot
            target         = $targetPath
            git_cache      = $gitCachePath
            root_exists    = Test-Path -LiteralPath $checkoutRoot -PathType Container
            contains_space = ($checkoutRoot -match '\s') -or ($targetPath -match '\s') -or ($gitCachePath -match '\s')
        }
    }
}

function Test-ZsecChromiumProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Probe,

        [Parameter(Mandatory)]
        [object]$Requirements
    )

    $checks = [System.Collections.Generic.List[object]]::new()

    $isClient = [int]$Probe.os.product_type -eq 1
    $isServer = [int]$Probe.os.product_type -in @(2, 3)
    $hostBuildPass = ($isClient -and [int]$Probe.os.build_number -ge [int]$Requirements.host.client_minimum_build) -or
        ($isServer -and [int]$Probe.os.build_number -ge [int]$Requirements.host.server_minimum_build)
    $checks.Add((New-ZsecAuditCheck -Id 'host.os' -Passed $hostBuildPass `
        -Expected 'Windows 11 build 22000+ or Windows Server build 17763+' `
        -Actual "$($Probe.os.caption) build $($Probe.os.build_number), ProductType $($Probe.os.product_type)" `
        -Evidence 'Current Chromium requires VS 2026; Microsoft supports VS 2026 only on Windows 11 or supported Windows Server.'))

    $architecturePass = ([string]$Probe.os.architecture -match '64')
    $checks.Add((New-ZsecAuditCheck -Id 'host.architecture' -Passed $architecturePass `
        -Expected 'x64/64-bit Windows' -Actual $Probe.os.architecture `
        -Evidence 'The pinned downstream is a Windows x64 build.'))

    $memoryPass = [int64]$Probe.memory.total_bytes -ge [int64]$Requirements.resources.minimum_memory_bytes
    $checks.Add((New-ZsecAuditCheck -Id 'resources.memory' -Passed $memoryPass `
        -Expected ">=$($Requirements.resources.minimum_memory_bytes) bytes" `
        -Actual $Probe.memory.total_bytes -Evidence 'Pinned fail-closed minimum: 16 GiB RAM.'))

    $filesystemPass = -not [bool]$Requirements.checkout.require_ntfs -or ([string]$Probe.disk.filesystem -ieq 'NTFS')
    $checks.Add((New-ZsecAuditCheck -Id 'resources.filesystem' -Passed $filesystemPass `
        -Expected 'NTFS' -Actual $Probe.disk.filesystem `
        -Evidence 'Chromium requires NTFS because repository objects can exceed FAT32 limits.'))

    $diskPass = [int64]$Probe.disk.free_bytes -ge [int64]$Requirements.resources.minimum_free_disk_bytes
    $checks.Add((New-ZsecAuditCheck -Id 'resources.disk' -Passed $diskPass `
        -Expected ">=$($Requirements.resources.minimum_free_disk_bytes) free bytes" `
        -Actual $Probe.disk.free_bytes -Evidence 'Pinned operational reserve: 250 GiB free before checkout.'))

    $vsPresent = [bool]$Probe.visual_studio.present
    $checks.Add((New-ZsecAuditCheck -Id 'visual_studio.present' -Passed $vsPresent `
        -Expected 'Visual Studio/Build Tools 2026 detected by vswhere' `
        -Actual $Probe.visual_studio.installation_path -Evidence 'A local supported VS toolchain is required.'))

    $vsVersionPass = $vsPresent -and
        (ConvertTo-ZsecVersion $Probe.visual_studio.version) -ge (ConvertTo-ZsecVersion $Requirements.visual_studio.minimum_version)
    $checks.Add((New-ZsecAuditCheck -Id 'visual_studio.version' -Passed $vsVersionPass `
        -Expected ">=$($Requirements.visual_studio.minimum_version)" -Actual $Probe.visual_studio.version `
        -Evidence 'Current Chromium documents Visual Studio 2026 version 18.0 or newer.'))

    $checks.Add((New-ZsecAuditCheck -Id 'visual_studio.cpp_x64' -Passed ([bool]$Probe.visual_studio.has_cpp_x64) `
        -Expected 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64' `
        -Actual $Probe.visual_studio.has_cpp_x64 -Evidence 'Required native x64/x86 C++ component.'))
    $checks.Add((New-ZsecAuditCheck -Id 'visual_studio.atlmfc' -Passed ([bool]$Probe.visual_studio.has_atlmfc) `
        -Expected 'Microsoft.VisualStudio.Component.VC.ATLMFC' `
        -Actual $Probe.visual_studio.has_atlmfc -Evidence 'Current Chromium requires ATL/MFC support.'))

    $sdkVersionPass = [bool]$Probe.sdk.present -and
        ([string]$Probe.sdk.version -eq [string]$Requirements.windows_sdk.version_directory)
    $checks.Add((New-ZsecAuditCheck -Id 'windows_sdk' -Passed $sdkVersionPass `
        -Expected $Requirements.windows_sdk.version_directory -Actual $Probe.sdk.version `
        -Evidence "Require Windows.h plus x86/x64 UM libraries from SDK installer $($Requirements.windows_sdk.installer_release)."))

    $debuggerPass = [bool]$Probe.debugging_tools.present -and
        (ConvertTo-ZsecVersion $Probe.debugging_tools.version) -ge (ConvertTo-ZsecVersion $Requirements.debugging_tools.minimum_version)
    $checks.Add((New-ZsecAuditCheck -Id 'debugging_tools' -Passed $debuggerPass `
        -Expected ">=$($Requirements.debugging_tools.minimum_version)" -Actual $Probe.debugging_tools.version `
        -Evidence 'Chromium requires sufficiently new Debugging Tools for large-page PDBs.'))

    $requiredDepotRoot = ConvertTo-ZsecNormalizedPath -Path ([string]$Requirements.depot_tools.root)
    $depotPresent = [bool]$Probe.depot_tools.present -and @($Probe.depot_tools.missing_files).Count -eq 0 -and
        (ConvertTo-ZsecNormalizedPath -Path ([string]$Probe.depot_tools.root)) -ieq $requiredDepotRoot
    $checks.Add((New-ZsecAuditCheck -Id 'depot_tools.files' -Passed $depotPresent `
        -Expected "$requiredDepotRoot with .git, gclient.bat, python3.bat and fetch.bat" `
        -Actual "$($Probe.depot_tools.root); missing=$(@($Probe.depot_tools.missing_files) -join ',')" `
        -Evidence 'A real git clone is required; incomplete archive extraction is rejected.'))

    $pathFirstPass = (ConvertTo-ZsecNormalizedPath -Path ([string]$Probe.depot_tools.first_path_entry)) -ieq $requiredDepotRoot
    $checks.Add((New-ZsecAuditCheck -Id 'depot_tools.path_first' -Passed $pathFirstPass `
        -Expected $requiredDepotRoot -Actual $Probe.depot_tools.first_path_entry `
        -Evidence 'depot_tools must be the first effective PATH entry, ahead of Python and Git.'))

    $expectedPython = ConvertTo-ZsecNormalizedPath -Path (Join-Path $requiredDepotRoot 'python3.bat')
    $pythonPass = (ConvertTo-ZsecNormalizedPath -Path ([string]$Probe.depot_tools.first_python3)) -ieq $expectedPython
    $checks.Add((New-ZsecAuditCheck -Id 'depot_tools.python3' -Passed $pythonPass `
        -Expected $expectedPython -Actual $Probe.depot_tools.first_python3 `
        -Evidence 'WindowsApps or an independent Python resolving first is rejected.'))

    $expectedGclient = ConvertTo-ZsecNormalizedPath -Path (Join-Path $requiredDepotRoot 'gclient.bat')
    $gclientPass = (ConvertTo-ZsecNormalizedPath -Path ([string]$Probe.depot_tools.first_gclient)) -ieq $expectedGclient
    $checks.Add((New-ZsecAuditCheck -Id 'depot_tools.gclient' -Passed $gclientPass `
        -Expected $expectedGclient -Actual $Probe.depot_tools.first_gclient `
        -Evidence 'The wrapper will not use an unrelated gclient.'))

    $toolchainEnvironmentPass = [string]$Probe.depot_tools.toolchain_environment -eq
        [string]$Requirements.depot_tools.required_environment.DEPOT_TOOLS_WIN_TOOLCHAIN
    $checks.Add((New-ZsecAuditCheck -Id 'depot_tools.local_toolchain' -Passed $toolchainEnvironmentPass `
        -Expected 'DEPOT_TOOLS_WIN_TOOLCHAIN=0' -Actual $Probe.depot_tools.toolchain_environment `
        -Evidence 'External builders must select the locally installed Visual Studio toolchain.'))

    $requiredRoot = ConvertTo-ZsecNormalizedPath -Path ([string]$Requirements.checkout.root)
    $requiredTarget = ConvertTo-ZsecNormalizedPath -Path ([string]$Requirements.checkout.target)
    $requiredCache = ConvertTo-ZsecNormalizedPath -Path ([string]$Requirements.checkout.git_cache)
    $pathPass = [bool]$Probe.checkout.root_exists -and -not [bool]$Probe.checkout.contains_space -and
        (ConvertTo-ZsecNormalizedPath -Path ([string]$Probe.checkout.root)) -ieq $requiredRoot -and
        (ConvertTo-ZsecNormalizedPath -Path ([string]$Probe.checkout.target)) -ieq $requiredTarget -and
        (ConvertTo-ZsecNormalizedPath -Path ([string]$Probe.checkout.git_cache)) -ieq $requiredCache
    $checks.Add((New-ZsecAuditCheck -Id 'checkout.paths' -Passed $pathPass `
        -Expected "$requiredRoot; target=$requiredTarget; cache=$requiredCache; no spaces" `
        -Actual "$($Probe.checkout.root); target=$($Probe.checkout.target); cache=$($Probe.checkout.git_cache); spaces=$($Probe.checkout.contains_space)" `
        -Evidence 'Chromium requires a short checkout path without spaces.'))

    $passed = @($checks | Where-Object { -not $_.passed }).Count -eq 0
    [pscustomobject]@{
        schema_version = 1
        audited_at_utc = [DateTime]::UtcNow.ToString('o')
        passed         = $passed
        checks         = @($checks)
        probe          = $Probe
    }
}

function Invoke-ZsecChromiumAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RequirementsPath
    )

    $requirements = Get-ZsecChromiumRequirements -Path $RequirementsPath
    $probe = Get-ZsecChromiumHostProbe -Requirements $requirements
    return Test-ZsecChromiumProbe -Probe $probe -Requirements $requirements
}

function Format-ZsecChromiumAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Audit
    )

    $state = if ([bool]$Audit.passed) { 'PASS' } else { 'FAIL (no fetch permitted)' }
    "ZSEC Chromium downstream host audit: $state"
    @($Audit.checks) | Select-Object @{Name = 'Status'; Expression = {
        if ($_.passed) { 'PASS' } else { 'FAIL' }
    } }, id, expected, actual | Format-Table -AutoSize | Out-String -Width 240
}

Export-ModuleMember -Function @(
    'ConvertTo-ZsecVersion',
    'ConvertTo-ZsecNormalizedPath',
    'Get-ZsecChromiumRequirements',
    'Get-ZsecChromiumHostProbe',
    'Test-ZsecChromiumProbe',
    'Invoke-ZsecChromiumAudit',
    'Format-ZsecChromiumAudit'
)
