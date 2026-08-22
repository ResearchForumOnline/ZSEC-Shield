Set-StrictMode -Version Latest

function New-ZsecDownstreamCheck {
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

function Read-ZsecDownstreamJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
        return Get-Content -LiteralPath $resolved -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    }
    throw "Refused unsafe or non-file JSON input: $resolved"
}

function Test-ZsecSha1 {
    param([AllowNull()][object]$Value)
    return [string]$Value -cmatch '^[0-9a-f]{40}$'
}

function Test-ZsecSha256 {
    param([AllowNull()][object]$Value)
    return [string]$Value -cmatch '^[0-9a-f]{64}$'
}

function Test-ZsecChromiumDownstreamPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LockPath,
        [Parameter(Mandatory)][string]$SeriesPath,
        [Parameter(Mandatory)][string]$PatchRoot
    )

    $checks = [Collections.Generic.List[object]]::new()
    try {
        $lock = Read-ZsecDownstreamJson -Path $LockPath
        $series = Read-ZsecDownstreamJson -Path $SeriesPath
        $patchRootFull = [IO.Path]::GetFullPath($PatchRoot).TrimEnd('\')
        $patchRootItem = Get-Item -LiteralPath $patchRootFull -Force -ErrorAction Stop
        if (-not $patchRootItem.PSIsContainer -or
            ($patchRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refused unsafe patch root: $patchRootFull"
        }
    }
    catch {
        $checks.Add((New-ZsecDownstreamCheck -Id 'inputs.readable' -Passed $false `
            -Expected 'regular non-reparse JSON files and patch directory' -Actual $_.Exception.Message `
            -Evidence 'Downstream inputs must be locally reviewable regular files.'))
        return [pscustomobject]@{
            schema_version = 1
            passed         = $false
            lock           = $null
            patch_series   = $null
            checks         = @($checks)
        }
    }

    $checks.Add((New-ZsecDownstreamCheck -Id 'inputs.readable' -Passed $true `
        -Expected 'regular non-reparse JSON files and patch directory' -Actual 'readable' `
        -Evidence 'Downstream inputs were read without following a reparse boundary.'))

    $checks.Add((New-ZsecDownstreamCheck -Id 'lock.schema' `
        -Passed ([int]$lock.schema_version -eq 1 -and
            [string]$lock.product -eq 'ZSEC Chromium Downstream Source Lock') `
        -Expected 'schema 1 ZSEC Chromium Downstream Source Lock' `
        -Actual "$($lock.schema_version) / $($lock.product)" `
        -Evidence 'Unknown lock schemas fail closed.'))

    $versionText = [string]$lock.version
    $versionValid = $versionText -cmatch '^\d+\.\d+\.\d+\.\d+$'
    $versionMilestone = -1
    if ($versionValid) {
        $versionMilestone = [int]($versionText.Split('.')[0])
    }
    $checks.Add((New-ZsecDownstreamCheck -Id 'lock.release_identity' `
        -Passed ($versionValid -and [int]$lock.milestone -eq $versionMilestone -and
            [int64]$lock.chromium_main_branch_position -gt 0 -and
            [string]$lock.channel -ceq 'Stable' -and [string]$lock.platform -ceq 'Windows') `
        -Expected 'Windows Stable four-part version with matching milestone and positive branch position' `
        -Actual "$($lock.platform) $($lock.channel) $versionText milestone=$($lock.milestone) position=$($lock.chromium_main_branch_position)" `
        -Evidence 'The lock represents one ChromiumDash Windows Stable release.'))

    $checks.Add((New-ZsecDownstreamCheck -Id 'lock.chromium_commit' `
        -Passed (Test-ZsecSha1 -Value $lock.chromium_commit) -Expected 'lowercase 40-hex Chromium commit' `
        -Actual $lock.chromium_commit -Evidence 'A moving branch name is not a reproducible source lock.'))
    $checks.Add((New-ZsecDownstreamCheck -Id 'lock.depot_tools_commit' `
        -Passed (Test-ZsecSha1 -Value $lock.depot_tools_commit) -Expected 'lowercase 40-hex depot_tools commit' `
        -Actual $lock.depot_tools_commit -Evidence 'The source tool entrypoint is locked separately from Chromium.'))

    $expectedChromiumRemote = 'https://chromium.googlesource.com/chromium/src.git'
    $expectedDepotRemote = 'https://chromium.googlesource.com/chromium/tools/depot_tools.git'
    $expectedReleaseUrl = 'https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows&num=1'
    $checks.Add((New-ZsecDownstreamCheck -Id 'lock.official_sources' `
        -Passed ([string]$lock.chromium_remote -ceq $expectedChromiumRemote -and
            [string]$lock.depot_tools_remote -ceq $expectedDepotRemote -and
            [string]$lock.release_source.url -ceq $expectedReleaseUrl) `
        -Expected 'exact HTTPS Chromium, depot_tools, and ChromiumDash sources' `
        -Actual "$($lock.chromium_remote) | $($lock.depot_tools_remote) | $($lock.release_source.url)" `
        -Evidence 'Lookalike or redirected source origins are not accepted by policy.'))

    $lockPolicyPass = -not [bool]$lock.release_policy.allow_automatic_lock_rewrite -and
        -not [bool]$lock.release_policy.allow_downgrade -and
        [bool]$lock.release_policy.require_manual_review -and
        [bool]$lock.release_policy.require_patch_revalidation -and
        [bool]$lock.release_policy.require_supported_host_build
    $checks.Add((New-ZsecDownstreamCheck -Id 'lock.release_policy' -Passed $lockPolicyPass `
        -Expected 'no auto rewrite/downgrade; manual review, patch revalidation, supported build required' `
        -Actual ($lock.release_policy | ConvertTo-Json -Compress) `
        -Evidence 'Discovering a newer upstream release never authorizes an automatic product update.'))

    $seriesItems = @($series.series)
    $maxPatchCount = [int]$series.policy.maximum_patch_count
    $maxPatchBytes = [int64]$series.policy.maximum_patch_bytes
    $requiredForbiddenFragments = @(
        '--no-sandbox',
        '--disable-web-security',
        '--ignore-certificate-errors',
        '--allow-running-insecure-content',
        '--disable-site-isolation-trials',
        'is_chrome_branded=true',
        'is_chrome_branded = true',
        'google_api_key',
        'google_default_client_id',
        'google_default_client_secret'
    )
    $declaredForbiddenFragments = @($series.policy.forbidden_added_line_fragments | ForEach-Object {
        ([string]$_).ToLowerInvariant()
    })
    $forbiddenPolicyPass = $declaredForbiddenFragments.Count -eq $requiredForbiddenFragments.Count
    foreach ($requiredFragment in $requiredForbiddenFragments) {
        if ($declaredForbiddenFragments -cnotcontains $requiredFragment) {
            $forbiddenPolicyPass = $false
        }
    }
    $seriesHeaderPass = [int]$series.schema_version -eq 1 -and
        [string]$series.product -eq 'ZSEC Chromium Downstream Patch Series' -and
        (Test-ZsecSha1 -Value $series.base_commit) -and
        [string]$series.base_commit -ceq [string]$lock.chromium_commit -and
        $maxPatchCount -gt 0 -and $maxPatchCount -le 256 -and
        $maxPatchBytes -gt 0 -and $maxPatchBytes -le 10485760 -and
        [bool]$series.policy.require_git_format_patch -and
        [string]$series.policy.allowed_extension -ceq '.patch' -and
        $forbiddenPolicyPass
    $checks.Add((New-ZsecDownstreamCheck -Id 'patches.policy' -Passed $seriesHeaderPass `
        -Expected 'schema 1, exact locked base, bounded text git-format patch policy' `
        -Actual "base=$($series.base_commit); count=$($seriesItems.Count); max=$maxPatchCount/$maxPatchBytes" `
        -Evidence 'A patch stack cannot silently drift to another Chromium base.'))

    $countPass = $seriesItems.Count -le $maxPatchCount
    $checks.Add((New-ZsecDownstreamCheck -Id 'patches.count' -Passed $countPass `
        -Expected "0..$maxPatchCount patches" -Actual $seriesItems.Count `
        -Evidence 'The initial downstream patch surface remains intentionally bounded.'))

    $seenPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $forbiddenFragments = @($declaredForbiddenFragments)
    $patchRootPrefix = $patchRootFull + [IO.Path]::DirectorySeparatorChar

    for ($index = 0; $index -lt $seriesItems.Count; $index++) {
        $entry = $seriesItems[$index]
        $entryId = "patches.entry.$($index + 1)"
        $relative = [string]$entry.path
        $metadataPass = [int]$entry.order -eq ($index + 1) -and
            -not [string]::IsNullOrWhiteSpace([string]$entry.id) -and
            -not [string]::IsNullOrWhiteSpace([string]$entry.purpose) -and
            -not [string]::IsNullOrWhiteSpace([string]$entry.upstream_area) -and
            (Test-ZsecSha256 -Value $entry.sha256)
        $checks.Add((New-ZsecDownstreamCheck -Id "$entryId.metadata" -Passed $metadataPass `
            -Expected 'ordered id/path/SHA-256/purpose/upstream_area metadata' `
            -Actual "order=$($entry.order); id=$($entry.id); path=$relative" `
            -Evidence 'Every downstream difference must have a stable review identity and purpose.'))

        $pathSyntaxPass = $relative -cmatch '^[A-Za-z0-9][A-Za-z0-9._/-]*\.patch$' -and
            -not $relative.Contains('..') -and -not [IO.Path]::IsPathRooted($relative) -and
            $seenPaths.Add($relative)
        $candidatePath = ''
        $insideRoot = $false
        if ($pathSyntaxPass) {
            $candidatePath = [IO.Path]::GetFullPath((Join-Path $patchRootFull $relative.Replace('/', '\')))
            $insideRoot = $candidatePath.StartsWith($patchRootPrefix, [StringComparison]::OrdinalIgnoreCase)
        }
        $checks.Add((New-ZsecDownstreamCheck -Id "$entryId.path" -Passed ($pathSyntaxPass -and $insideRoot) `
            -Expected 'unique relative .patch path contained by patch root' -Actual $relative `
            -Evidence 'Absolute, duplicate, or path-escaping patch entries fail closed.'))

        if (-not $pathSyntaxPass -or -not $insideRoot -or
            -not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
            $checks.Add((New-ZsecDownstreamCheck -Id "$entryId.file" -Passed $false `
                -Expected 'present regular patch file' -Actual $candidatePath `
                -Evidence 'A declared patch must exist inside the reviewed patch directory.'))
            continue
        }

        $patchFile = Get-Item -LiteralPath $candidatePath -Force
        $regularPass = ($patchFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and
            [int64]$patchFile.Length -gt 0 -and [int64]$patchFile.Length -le $maxPatchBytes
        $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $candidatePath).Hash.ToLowerInvariant()
        $hashPass = $actualHash -ceq [string]$entry.sha256
        $checks.Add((New-ZsecDownstreamCheck -Id "$entryId.file" -Passed ($regularPass -and $hashPass) `
            -Expected "regular file <=$maxPatchBytes bytes with locked SHA-256" `
            -Actual "bytes=$($patchFile.Length); sha256=$actualHash" `
            -Evidence 'Reparse, oversized, empty, or hash-mismatched patch content is rejected.'))

        $patchText = Get-Content -LiteralPath $candidatePath -Raw -Encoding UTF8
        $formatPass = $patchText -cmatch '(?m)\AFrom [0-9a-f]{40} ' -and
            $patchText -cmatch '(?m)^Subject: .+' -and
            $patchText -cmatch '(?m)^diff --git a/.+ b/.+' -and
            $patchText -cnotmatch '(?m)^GIT binary patch\s*$' -and
            $patchText -cnotmatch '(?m)^Binary files .+ differ\s*$'
        $checks.Add((New-ZsecDownstreamCheck -Id "$entryId.format" -Passed $formatPass `
            -Expected 'text git format-patch with subject and textual diff' -Actual $formatPass `
            -Evidence 'Opaque binary changes are outside the first reviewable downstream slice.'))

        $unsafeAddedLines = [Collections.Generic.List[string]]::new()
        foreach ($line in ($patchText -split "`r?`n")) {
            if (-not $line.StartsWith('+', [StringComparison]::Ordinal) -or
                $line.StartsWith('+++', [StringComparison]::Ordinal)) {
                continue
            }
            $lower = $line.ToLowerInvariant()
            foreach ($fragment in $forbiddenFragments) {
                if ($lower.Contains($fragment)) {
                    $unsafeAddedLines.Add($fragment)
                }
            }
        }
        $checks.Add((New-ZsecDownstreamCheck -Id "$entryId.security_additions" `
            -Passed ($unsafeAddedLines.Count -eq 0) -Expected 'no forbidden security/branding/API-key additions' `
            -Actual (@($unsafeAddedLines | Sort-Object -Unique) -join ',') `
            -Evidence 'The gate scans added lines only, so patches removing dangerous flags are not rejected.'))
    }

    $passed = @($checks | Where-Object { -not [bool]$_.passed }).Count -eq 0
    [pscustomobject]@{
        schema_version = 1
        passed         = $passed
        lock           = [pscustomobject]@{
            version                = $versionText
            milestone              = [int]$lock.milestone
            chromium_commit        = [string]$lock.chromium_commit
            depot_tools_commit     = [string]$lock.depot_tools_commit
            main_branch_position   = [int64]$lock.chromium_main_branch_position
        }
        patch_series   = [pscustomobject]@{
            base_commit = [string]$series.base_commit
            count       = $seriesItems.Count
        }
        checks         = @($checks)
    }
}

function Get-ZsecChromiumStableCandidate {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Lock)

    $expectedUrl = 'https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows&num=1'
    if ([string]$Lock.release_source.url -cne $expectedUrl) {
        throw 'The lock does not contain the exact approved ChromiumDash Windows Stable endpoint.'
    }
    $response = Invoke-RestMethod -Method Get -Uri $expectedUrl -TimeoutSec 30 `
        -Headers @{ Accept = 'application/json' }
    $items = @($response)
    if ($items.Count -ne 1) {
        throw "Expected exactly one ChromiumDash release, received $($items.Count)."
    }
    return $items[0]
}

function New-ZsecChromiumUpdatePlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Lock,
        [Parameter(Mandatory)][object]$Candidate
    )

    $candidateCommit = [string]$Candidate.hashes.chromium
    $candidateVersionText = [string]$Candidate.version
    $candidateVersionValid = $candidateVersionText -cmatch '^\d+\.\d+\.\d+\.\d+$'
    $candidateMilestone = [int]$Candidate.milestone
    $candidatePosition = [int64]$Candidate.chromium_main_branch_position
    if (-not $candidateVersionValid -or -not (Test-ZsecSha1 -Value $candidateCommit) -or
        $candidateMilestone -ne [int]($candidateVersionText.Split('.')[0]) -or
        $candidatePosition -le 0 -or [string]$Candidate.channel -cne 'Stable' -or
        [string]$Candidate.platform -cne 'Windows') {
        return [pscustomobject]@{
            schema_version         = 1
            status                 = 'refused_invalid_candidate'
            safe_to_update_lock    = $false
            manual_review_required = $true
            current                = [pscustomobject]@{ version = [string]$Lock.version; commit = [string]$Lock.chromium_commit }
            candidate              = [pscustomobject]@{ version = $candidateVersionText; commit = $candidateCommit }
            reasons                = @('ChromiumDash candidate identity or release metadata is invalid.')
            actions                = @()
        }
    }

    $currentVersion = [version][string]$Lock.version
    $candidateVersion = [version]$candidateVersionText
    $status = 'current'
    $reasons = [Collections.Generic.List[string]]::new()
    $actions = [Collections.Generic.List[string]]::new()

    if ($candidateVersion -lt $currentVersion -or $candidateMilestone -lt [int]$Lock.milestone -or
        $candidatePosition -lt [int64]$Lock.chromium_main_branch_position) {
        $status = 'refused_downgrade'
        $reasons.Add('The candidate is older than the locked release or branch position.')
    }
    elseif ($candidateVersion -eq $currentVersion -and $candidateCommit -cne [string]$Lock.chromium_commit) {
        $status = 'refused_same_version_commit_change'
        $reasons.Add('The same release version resolved to a different Chromium commit.')
    }
    elseif ($candidateVersion -gt $currentVersion -and $candidateCommit -ceq [string]$Lock.chromium_commit) {
        $status = 'refused_version_change_without_commit_change'
        $reasons.Add('A newer version unexpectedly resolved to the already locked commit.')
    }
    elseif ($candidateVersion -gt $currentVersion) {
        $status = 'update_available'
        $reasons.Add('A newer Windows Stable Chromium release was observed.')
        $actions.Add('Review Chromium release and security notes.')
        $actions.Add('Create a reviewed pull request changing upstream.lock.json; never rewrite it automatically.')
        $actions.Add('Rebase and re-hash every downstream patch against the proposed base commit.')
        $actions.Add('Build on a host that passes the pinned Windows toolchain audit.')
        $actions.Add('Run Chromium and ZSEC browser tests before any signed staged update.')
    }
    else {
        $reasons.Add('The locked Windows Stable Chromium version and commit match the observed candidate.')
    }

    [pscustomobject]@{
        schema_version         = 1
        status                 = $status
        safe_to_update_lock    = $false
        manual_review_required = $true
        current                = [pscustomobject]@{
            version              = [string]$Lock.version
            milestone            = [int]$Lock.milestone
            branch_position      = [int64]$Lock.chromium_main_branch_position
            commit               = [string]$Lock.chromium_commit
        }
        candidate              = [pscustomobject]@{
            version              = $candidateVersionText
            milestone            = $candidateMilestone
            branch_position      = $candidatePosition
            commit               = $candidateCommit
        }
        reasons                = @($reasons)
        actions                = @($actions)
    }
}

Export-ModuleMember -Function @(
    'Read-ZsecDownstreamJson',
    'Test-ZsecChromiumDownstreamPolicy',
    'Get-ZsecChromiumStableCandidate',
    'New-ZsecChromiumUpdatePlan'
)
