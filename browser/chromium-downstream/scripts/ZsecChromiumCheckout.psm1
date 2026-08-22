Set-StrictMode -Version Latest

function New-ZsecCheckoutCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][bool]$Passed,
        [Parameter(Mandatory)][string]$Expected,
        [AllowNull()][object]$Actual,
        [Parameter(Mandatory)][string]$Evidence
    )

    [pscustomobject]@{
        id       = $Id
        passed   = $Passed
        expected = $Expected
        actual   = if ($null -eq $Actual) { $null } else { [string]$Actual }
        evidence = $Evidence
    }
}

function Invoke-ZsecGitReadOnly {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RepositoryPath,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    $git = @(Get-Command -Name 'git.exe' -CommandType Application -ErrorAction SilentlyContinue)
    if ($git.Count -eq 0) {
        return [pscustomobject]@{
            passed     = $false
            executable = ''
            exit_code  = -1
            output     = @()
            error      = 'git.exe is not available on PATH.'
        }
    }

    $output = @()
    $exitCode = -1
    try {
        $allArguments = @('-C', $RepositoryPath) + @($Arguments)
        $output = @(& $git[0].Path @allArguments 2>&1 | ForEach-Object { [string]$_ })
        $exitCode = $LASTEXITCODE
    }
    catch {
        return [pscustomobject]@{
            passed     = $false
            executable = [string]$git[0].Path
            exit_code  = -1
            output     = @($output)
            error      = $_.Exception.Message
        }
    }

    [pscustomobject]@{
        passed     = $exitCode -eq 0
        executable = [string]$git[0].Path
        exit_code  = $exitCode
        output     = @($output)
        error      = if ($exitCode -eq 0) { '' } else { $output -join "`n" }
    }
}

function Get-ZsecGitRepositoryProbe {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RepositoryPath)

    $fullPath = [IO.Path]::GetFullPath($RepositoryPath).TrimEnd('\')
    $present = Test-Path -LiteralPath $fullPath -PathType Container
    $reparsePoint = $false
    if ($present) {
        $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
        $reparsePoint = ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    }

    $probe = [ordered]@{
        path              = $fullPath
        present           = $present
        reparse_point     = $reparsePoint
        git_metadata_present = $false
        git_metadata_reparse = $false
        git_executable    = ''
        is_work_tree      = $false
        top_level         = ''
        origin_urls       = @()
        origin            = ''
        head              = ''
        dirty_paths       = @()
        command_errors    = @()
    }
    if (-not $present -or $reparsePoint) {
        return [pscustomobject]$probe
    }

    $gitMetadataPath = Join-Path $fullPath '.git'
    if (Test-Path -LiteralPath $gitMetadataPath) {
        $gitMetadata = Get-Item -LiteralPath $gitMetadataPath -Force -ErrorAction Stop
        $probe.git_metadata_present = $true
        $probe.git_metadata_reparse = `
            ($gitMetadata.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    }

    $inside = Invoke-ZsecGitReadOnly -RepositoryPath $fullPath -Arguments @(
        'rev-parse', '--is-inside-work-tree'
    )
    $probe.git_executable = [string]$inside.executable
    if (-not [bool]$inside.passed) {
        $probe.command_errors = @([string]$inside.error)
        return [pscustomobject]$probe
    }
    $probe.is_work_tree = @($inside.output).Count -eq 1 -and [string]$inside.output[0] -ceq 'true'
    if (-not $probe.is_work_tree) {
        $probe.command_errors = @('The directory is not a Git working tree.')
        return [pscustomobject]$probe
    }

    $head = Invoke-ZsecGitReadOnly -RepositoryPath $fullPath -Arguments @(
        'rev-parse', '--verify', 'HEAD'
    )
    $topLevel = Invoke-ZsecGitReadOnly -RepositoryPath $fullPath -Arguments @(
        'rev-parse', '--show-toplevel'
    )
    $origin = Invoke-ZsecGitReadOnly -RepositoryPath $fullPath -Arguments @(
        'remote', 'get-url', '--all', 'origin'
    )
    $status = Invoke-ZsecGitReadOnly -RepositoryPath $fullPath -Arguments @(
        'status', '--porcelain=v1', '--untracked-files=all'
    )
    $errors = @(@($head, $topLevel, $origin, $status) | Where-Object { -not [bool]$_.passed } |
        ForEach-Object { [string]$_.error })

    if ([bool]$head.passed -and @($head.output).Count -eq 1) {
        $probe.head = [string]$head.output[0]
    }
    if ([bool]$topLevel.passed -and @($topLevel.output).Count -eq 1) {
        $probe.top_level = [IO.Path]::GetFullPath([string]$topLevel.output[0]).TrimEnd('\')
    }
    if ([bool]$origin.passed) {
        $probe.origin_urls = @($origin.output | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if (@($probe.origin_urls).Count -eq 1) {
            $probe.origin = [string]$probe.origin_urls[0]
        }
    }
    if ([bool]$status.passed) {
        $probe.dirty_paths = @($status.output | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    $probe.command_errors = @($errors | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    [pscustomobject]$probe
}

function Test-ZsecGitRepositoryAttestation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Probe,
        [Parameter(Mandatory)][string]$ExpectedOrigin,
        [Parameter(Mandatory)][string]$ExpectedCommit,
        [string]$Identity = 'repository'
    )

    $checks = [Collections.Generic.List[object]]::new()
    $safeBoundary = [bool]$Probe.present -and -not [bool]$Probe.reparse_point -and
        [bool]$Probe.git_metadata_present -and -not [bool]$Probe.git_metadata_reparse -and
        [bool]$Probe.is_work_tree -and @($Probe.command_errors).Count -eq 0 -and
        [string]$Probe.top_level -ieq [string]$Probe.path
    $checks.Add((New-ZsecCheckoutCheck -Id "$Identity.boundary" -Passed $safeBoundary `
        -Expected 'present regular Git working tree with successful read-only probes' `
        -Actual "present=$($Probe.present); reparse=$($Probe.reparse_point); git_metadata=$($Probe.git_metadata_present)/$($Probe.git_metadata_reparse); git=$($Probe.is_work_tree); top=$($Probe.top_level); errors=$(@($Probe.command_errors).Count)" `
        -Evidence 'Missing, reparse-point, non-Git, or unreadable tool repositories fail closed.'))

    $originPass = $safeBoundary -and @($Probe.origin_urls).Count -eq 1 -and
        [string]$Probe.origin -ceq $ExpectedOrigin
    $checks.Add((New-ZsecCheckoutCheck -Id "$Identity.origin" -Passed $originPass `
        -Expected "exactly one origin URL: $ExpectedOrigin" `
        -Actual (@($Probe.origin_urls) -join ' | ') `
        -Evidence 'A lookalike, forked, redirected, or unexpected source origin is not accepted.'))

    $headPass = $safeBoundary -and [string]$Probe.head -cmatch '^[0-9a-f]{40}$' -and
        [string]$Probe.head -ceq $ExpectedCommit
    $checks.Add((New-ZsecCheckoutCheck -Id "$Identity.head" -Passed $headPass `
        -Expected $ExpectedCommit -Actual $Probe.head `
        -Evidence 'A moving branch or different tool revision is not the reviewed toolchain.'))

    $cleanPass = $safeBoundary -and @($Probe.dirty_paths).Count -eq 0
    $checks.Add((New-ZsecCheckoutCheck -Id "$Identity.clean" -Passed $cleanPass `
        -Expected '0 modified or untracked paths' -Actual @($Probe.dirty_paths).Count `
        -Evidence 'Local tool/source modifications could alter checkout or build behavior.'))

    [pscustomobject]@{
        schema_version = 1
        identity       = $Identity
        passed         = @($checks | Where-Object { -not [bool]$_.passed }).Count -eq 0
        probe          = $Probe
        checks         = @($checks)
    }
}

function New-ZsecChromiumCheckoutPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Requirements,
        [Parameter(Mandatory)][object]$Lock,
        [Parameter(Mandatory)][object]$Series,
        [Parameter(Mandatory)][string]$PatchRoot,
        [Parameter(Mandatory)][bool]$HostAuditPassed,
        [Parameter(Mandatory)][bool]$DownstreamPolicyPassed,
        [Parameter(Mandatory)][bool]$DepotToolsAttestationPassed,
        [Parameter(Mandatory)][bool]$TargetExists
    )

    $checks = [Collections.Generic.List[object]]::new()
    $chromiumRemote = 'https://chromium.googlesource.com/chromium/src.git'
    $depotRemote = 'https://chromium.googlesource.com/chromium/tools/depot_tools.git'
    $commitPattern = '^[0-9a-f]{40}$'
    $identityPass = [string]$Lock.chromium_remote -ceq $chromiumRemote -and
        [string]$Lock.depot_tools_remote -ceq $depotRemote -and
        [string]$Lock.chromium_commit -cmatch $commitPattern -and
        [string]$Lock.depot_tools_commit -cmatch $commitPattern -and
        [string]$Series.base_commit -ceq [string]$Lock.chromium_commit
    $checks.Add((New-ZsecCheckoutCheck -Id 'plan.lock_identity' -Passed $identityPass `
        -Expected 'official Chromium/depot_tools origins, exact 40-hex commits, matching patch base' `
        -Actual "$($Lock.chromium_remote); chromium=$($Lock.chromium_commit); depot=$($Lock.depot_tools_commit); patch_base=$($Series.base_commit)" `
        -Evidence 'The execution plan is derived only from the reviewed downstream identities.'))

    $targetPath = [IO.Path]::GetFullPath([string]$Requirements.checkout.target).TrimEnd('\')
    $sourcePath = [IO.Path]::Combine($targetPath, 'src')
    $gitCachePath = [IO.Path]::GetFullPath([string]$Requirements.checkout.git_cache).TrimEnd('\')
    $depotRoot = [IO.Path]::GetFullPath([string]$Requirements.depot_tools.root).TrimEnd('\')
    $pathPass = $targetPath -ieq 'C:\src\zsec-chromium' -and
        $gitCachePath -ieq 'C:\src\zsec-git-cache' -and
        $depotRoot -ieq 'C:\src\depot_tools' -and
        $targetPath -notmatch '\s' -and $sourcePath -notmatch '\s' -and
        $gitCachePath -notmatch '\s' -and $depotRoot -notmatch '\s' -and -not $TargetExists
    $checks.Add((New-ZsecCheckoutCheck -Id 'plan.paths' -Passed $pathPass `
        -Expected 'exact C:\src tool/cache/checkout paths, no spaces, target absent' `
        -Actual "target=$targetPath; exists=$TargetExists; cache=$gitCachePath; depot=$depotRoot" `
        -Evidence 'The gate never merges into or overwrites an existing checkout.'))

    $configurationPass = [string]$Requirements.checkout.fetch_configuration -ceq 'chromium' -and
        @($Requirements.checkout.fetch_arguments).Count -eq 2 -and
        [string]$Requirements.checkout.fetch_arguments[0] -ceq '--nohooks' -and
        [string]$Requirements.checkout.fetch_arguments[1] -ceq '--git-cache' -and
        -not [bool]$Requirements.branding.allow_chrome_branding -and
        [string]$Requirements.branding.gn_requirement -ceq 'is_chrome_branded=false' -and
        [string]$Requirements.depot_tools.required_environment.DEPOT_TOOLS_WIN_TOOLCHAIN -ceq '0' -and
        [string]$Requirements.depot_tools.required_environment.DEPOT_TOOLS_UPDATE -ceq '0'
    $checks.Add((New-ZsecCheckoutCheck -Id 'plan.configuration' -Passed $configurationPass `
        -Expected 'full-history git-cache Chromium fetch, Chromium branding off, local toolchain, depot auto-update off' `
        -Actual "configuration=$($Requirements.checkout.fetch_configuration); args=$(@($Requirements.checkout.fetch_arguments) -join ','); gn=$($Requirements.branding.gn_requirement)" `
        -Evidence 'Tool auto-update and mutable fetch configuration would defeat the reviewed depot/source pins.'))

    $prerequisitePass = $HostAuditPassed -and $DownstreamPolicyPassed -and
        $DepotToolsAttestationPassed -and -not $TargetExists
    $checks.Add((New-ZsecCheckoutCheck -Id 'plan.prerequisites' -Passed $prerequisitePass `
        -Expected 'host, downstream policy and depot_tools attestation pass; target absent' `
        -Actual "host=$HostAuditPassed; policy=$DownstreamPolicyPassed; depot=$DepotToolsAttestationPassed; target_exists=$TargetExists" `
        -Evidence 'No command in the plan is authorized when any prerequisite fails.'))

    $patchCommands = @()
    foreach ($entry in @($Series.series)) {
        $patchPath = [IO.Path]::GetFullPath((Join-Path $PatchRoot ([string]$entry.path).Replace('/', '\')))
        $patchCommands += [pscustomobject]@{
            phase       = 'apply_patch'
            executable  = 'git.exe'
            arguments   = @('-C', $sourcePath, 'am', '--3way', '--keep-cr', $patchPath)
            working_dir = $sourcePath
            patch_id    = [string]$entry.id
            patch_sha256 = [string]$entry.sha256
        }
    }

    $commands = [ordered]@{
        fetch = [pscustomobject]@{
            phase       = 'fetch'
            executable  = Join-Path $depotRoot 'fetch.bat'
            arguments   = @('--nohooks', '--git-cache', 'chromium')
            working_dir = $targetPath
        }
        verify_commit = [pscustomobject]@{
            phase       = 'verify_locked_commit'
            executable  = 'git.exe'
            arguments   = @('-C', $sourcePath, 'cat-file', '-e', "$($Lock.chromium_commit)^{commit}")
            working_dir = $sourcePath
        }
        checkout = [pscustomobject]@{
            phase       = 'checkout_locked_commit'
            executable  = 'git.exe'
            arguments   = @('-C', $sourcePath, 'checkout', '--detach', [string]$Lock.chromium_commit)
            working_dir = $sourcePath
        }
        sync = [pscustomobject]@{
            phase       = 'sync_locked_dependencies'
            executable  = Join-Path $depotRoot 'gclient.bat'
            arguments   = @('sync', '--revision', "src@$($Lock.chromium_commit)")
            working_dir = $targetPath
        }
        patches = @($patchCommands)
    }

    [pscustomobject]@{
        schema_version       = 1
        product              = 'ZSEC Chromium Locked Checkout Plan'
        execution_permitted  = $identityPass -and $pathPass -and $configurationPass -and $prerequisitePass
        manual_review_required = $true
        mutates_when_executed = $true
        chromium             = [pscustomobject]@{
            version  = [string]$Lock.version
            commit   = [string]$Lock.chromium_commit
            remote   = [string]$Lock.chromium_remote
        }
        depot_tools          = [pscustomobject]@{
            commit = [string]$Lock.depot_tools_commit
            remote = [string]$Lock.depot_tools_remote
            root   = $depotRoot
        }
        environment          = [pscustomobject]@{
            GIT_CACHE_PATH                = $gitCachePath
            DEPOT_TOOLS_WIN_TOOLCHAIN     = '0'
            DEPOT_TOOLS_UPDATE            = '0'
        }
        checkout             = [pscustomobject]@{
            root         = $targetPath
            source       = $sourcePath
            receipt_path = [IO.Path]::Combine($targetPath, 'zsec-checkout-receipt.json')
        }
        patch_count          = @($Series.series).Count
        commands             = [pscustomobject]$commands
        checks               = @($checks)
    }
}

Export-ModuleMember -Function @(
    'Get-ZsecGitRepositoryProbe',
    'Test-ZsecGitRepositoryAttestation',
    'New-ZsecChromiumCheckoutPlan'
)
