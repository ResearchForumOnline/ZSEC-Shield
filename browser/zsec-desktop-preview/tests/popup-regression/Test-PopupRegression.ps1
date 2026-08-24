#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ProductRoot = (Join-Path $env:LOCALAPPDATA "TalkToAI\ZSEC Browser"),
    [ValidateRange(5, 120)][int]$TimeoutSeconds = 30,
    [string]$ReportPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Read-KeyValueFile([string]$Path) {
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        $stream = $null
        $reader = $null
        try {
            $stream = [IO.File]::Open(
                $Path,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
            )
            $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::UTF8, $true)
            $result = @{}
            foreach ($line in ($reader.ReadToEnd() -split "`r?`n")) {
                $separator = $line.IndexOf('=')
                if ($separator -gt 0) {
                    $result[$line.Substring(0, $separator)] = $line.Substring($separator + 1)
                }
            }
            return $result
        }
        catch [IO.IOException] {
            if ($attempt -ge 39) { throw }
            Start-Sleep -Milliseconds 50
        }
        finally {
            if ($null -ne $reader) { $reader.Dispose() }
            elseif ($null -ne $stream) { $stream.Dispose() }
        }
    }
    throw "Runtime evidence could not be read."
}

function Invoke-Automation([string]$PipeName, [string]$Token, [string]$Command, [string]$Url = "") {
    $client = New-Object IO.Pipes.NamedPipeClientStream(".", $PipeName, [IO.Pipes.PipeDirection]::InOut)
    try {
        $client.Connect(3000)
        $writer = New-Object IO.StreamWriter($client, (New-Object Text.UTF8Encoding($false)), 1024, $true)
        $reader = New-Object IO.StreamReader($client, [Text.Encoding]::UTF8, $true, 1024, $true)
        try {
            $request = @{ Token = $Token; Command = $Command }
            if ($Url) { $request.Url = $Url }
            $writer.WriteLine(($request | ConvertTo-Json -Compress))
            $writer.Flush()
            return ($reader.ReadLine() | ConvertFrom-Json)
        }
        finally { $reader.Dispose(); $writer.Dispose() }
    }
    finally { $client.Dispose() }
}

function Wait-State([string]$PipeName, [string]$Token, [int]$ExpectedTabs, [int]$ExpectedActive) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $state = Invoke-Automation $PipeName $Token "get_state"
        if ($state.Ok -and $state.RuntimeReady -and
            $state.TabCount -eq $ExpectedTabs -and $state.ActiveTab -eq $ExpectedActive) { return $state }
        Start-Sleep -Milliseconds 100
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "Browser state did not stabilize at the expected tab and active-tab values."
}

function Wait-PopupEvidence([string]$EvidencePath, [int]$MinimumRequests) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Test-Path -LiteralPath $EvidencePath -PathType Leaf) {
            $evidence = Read-KeyValueFile $EvidencePath
            if ([int]$evidence.popup_request_count -ge $MinimumRequests) { return $evidence }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "Popup runtime evidence did not reach request count $MinimumRequests."
}

function Wait-CurrentProcessEvidence([string]$EvidencePath, [int]$ProcessId) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Test-Path -LiteralPath $EvidencePath -PathType Leaf) {
            $evidence = Read-KeyValueFile $EvidencePath
            if ($evidence.process_id -and [int]$evidence.process_id -eq $ProcessId) {
                return $evidence
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "Runtime evidence did not bind to the isolated browser process."
}

$statePath = Join-Path ([IO.Path]::GetFullPath($ProductRoot)) "install-state.json"
if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) { throw "Installation marker is absent." }
$install = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
$applicationPath = [IO.Path]::GetFullPath([string]$install.launcher.path)
$evidencePath = [IO.Path]::GetFullPath([string]$install.runtime_evidence_path)
if ((Get-FileHash -LiteralPath $applicationPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne ([string]$install.launcher.sha256).ToLowerInvariant()) {
    throw "Installed browser identity check failed."
}
if (Get-Process -Name "ZSEC Browser" -ErrorAction SilentlyContinue) {
    throw "Close ZSEC Browser before this isolated test; the harness will not terminate an existing user session."
}

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("zsec-popup-regression-" + [Guid]::NewGuid().ToString("N"))
[void](New-Item -ItemType Directory -Path $temporaryRoot)
$stderrPath = Join-Path $temporaryRoot "browser.stderr"
$stdoutPath = Join-Path $temporaryRoot "browser.stdout"
$browser = $null
try {
    $fixtureRelativePath = "new-tab/popup-regression.html"
    $fixturePath = Join-Path (Split-Path -Parent $applicationPath) $fixtureRelativePath.Replace('/', '\')
    if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf)) {
        throw "The installed packaged popup fixture is absent."
    }
    $fixtureInventory = @($install.app_files | Where-Object { $_.path -eq $fixtureRelativePath })
    if ($fixtureInventory.Count -ne 1 -or
        (Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne
            ([string]$fixtureInventory[0].sha256).ToLowerInvariant()) {
        throw "The installed packaged popup fixture failed its inventory hash check."
    }
    $baseUri = "https://newtab.zsec.local/popup-regression.html"
    $browser = Start-Process -FilePath $applicationPath -PassThru -RedirectStandardError $stderrPath -RedirectStandardOutput $stdoutPath -ArgumentList @($baseUri + "?case=idle", "--enable-local-automation")
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $stderr = if (Test-Path $stderrPath) { [string](Get-Content $stderrPath -Raw) } else { "" }
        if ($null -eq $stderr) { $stderr = "" }
        $pipeMatch = [regex]::Match($stderr, 'ZSEC_AUTOMATION_PIPE=([^\r\n]+)')
        $tokenMatch = [regex]::Match($stderr, 'ZSEC_AUTOMATION_TOKEN=([0-9a-f]{64})')
        if ($pipeMatch.Success -and $tokenMatch.Success) { break }
        if ($browser.HasExited) { throw "Browser exited before automation readiness." }
        Start-Sleep -Milliseconds 50
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    if (-not $pipeMatch.Success -or -not $tokenMatch.Success) { throw "Automation readiness timed out." }
    $pipeName = $pipeMatch.Groups[1].Value
    $token = $tokenMatch.Groups[1].Value
    $initial = Wait-State $pipeName $token 1 0
    $baselineEvidence = Wait-CurrentProcessEvidence $evidencePath $browser.Id
    $requestFloor = [int]$baselineEvidence.popup_request_count
    $results = @()

    foreach ($case in @('load', 'timer', 'synthetic-click', 'target-blank', 'storm', 'javascript-scheme', 'data-scheme', 'file-scheme')) {
        $beforeEvidence = Read-KeyValueFile $evidencePath
        $beforeRequests = [int]$beforeEvidence.popup_request_count
        $response = Invoke-Automation $pipeName $token "open_url" ($baseUri + "?case=" + $case)
        if (-not $response.Ok) { throw "Navigation command failed for ${case}: $($response.Error)" }
        Start-Sleep -Milliseconds 750
        $afterState = Wait-State $pipeName $token 1 0
        $afterEvidence = Read-KeyValueFile $evidencePath
        $afterRequests = [int]$afterEvidence.popup_request_count
        if ($afterRequests -lt $beforeRequests) {
            throw "Popup request evidence regressed during $case."
        }
        $results += [ordered]@{
            case = $case
            passed = ($afterState.TabCount -eq 1 -and $afterState.ActiveTab -eq 0 -and [int]$afterEvidence.popup_allowed_count -eq 0)
            popup_event_observed = $afterRequests -gt $beforeRequests
            popup_request_delta = $afterRequests - $beforeRequests
            tab_count = $afterState.TabCount
            active_tab = $afterState.ActiveTab
        }
        if (-not $results[-1].passed) { throw "Popup isolation failed for $case." }
    }

    # Invoke the named WebView button through Windows accessibility, not DOM script execution.
    $response = Invoke-Automation $pipeName $token "open_url" ($baseUri + "?case=direct-click")
    if (-not $response.Ok) { throw "Navigation command failed for direct-click: $($response.Error)" }
    Start-Sleep -Milliseconds 500
    $browser.Refresh()
    if ($browser.MainWindowHandle -eq [IntPtr]::Zero) {
        throw "The isolated browser window handle was unavailable."
    }
    $activateResponse = Invoke-Automation $pipeName $token "activate"
    if (-not $activateResponse.Ok) { throw "Browser activation command failed." }
    Add-Type -AssemblyName UIAutomationClient
    Add-Type -AssemblyName UIAutomationTypes
    $rootElement = [Windows.Automation.AutomationElement]::FromHandle($browser.MainWindowHandle)
    $nameCondition = New-Object Windows.Automation.PropertyCondition(
        [Windows.Automation.AutomationElement]::NameProperty,
        "Open direct-click popup"
    )
    $directButton = $rootElement.FindFirst(
        [Windows.Automation.TreeScope]::Descendants,
        $nameCondition
    )
    $beforeDirect = Read-KeyValueFile $evidencePath
    if ($null -ne $directButton) {
        $invokePattern = [Windows.Automation.InvokePattern]$directButton.GetCurrentPattern(
            [Windows.Automation.InvokePattern]::Pattern
        )
        $invokePattern.Invoke()
    }
    else {
        # Chromium can omit its accessibility subtree until assistive technology
        # is attached. The active page has already focused its autofocus button.
        Add-Type -AssemblyName System.Windows.Forms
        [Windows.Forms.SendKeys]::SendWait("{ENTER}")
    }
    $directEvidence = Wait-PopupEvidence $evidencePath ([int]$beforeDirect.popup_request_count + 1)
    $directState = Wait-State $pipeName $token 1 0
    $results += [ordered]@{
        case = 'direct-click'
        passed = ($directState.TabCount -eq 1 -and $directState.ActiveTab -eq 0 -and [int]$directEvidence.popup_allowed_count -eq 0)
        popup_event_observed = $true
        popup_request_delta = [int]$directEvidence.popup_request_count - [int]$beforeDirect.popup_request_count
        tab_count = $directState.TabCount
        active_tab = $directState.ActiveTab
    }
    if (-not $results[-1].passed) { throw "Popup isolation failed for direct-click." }

    $report = [ordered]@{
        schema = 'zsec.browser.popup-regression.v1'
        passed = @($results | Where-Object { -not $_.passed }).Count -eq 0
        tested_at = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        fixture_origin = "https://newtab.zsec.local"
        executable_sha256_verified = $true
        fixture_sha256_verified = $true
        runtime_evidence_process_id_verified = $true
        default_popup_permission = 'deny'
        cases = $results
        note = 'popup_event_observed may be false for unsafe schemes rejected by WebView2 before NewWindowRequested; no-tab and active-tab invariants remain authoritative.'
    }
    if ($ReportPath) {
        $normalized = [IO.Path]::GetFullPath($ReportPath)
        [void](New-Item -ItemType Directory -Force -Path (Split-Path -Parent $normalized))
        [IO.File]::WriteAllText($normalized, (($report | ConvertTo-Json -Depth 8) + [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))
    }
    $report | ConvertTo-Json -Depth 8
}
finally {
    if ($browser -and -not $browser.HasExited) {
        [void]$browser.CloseMainWindow()
        if (-not $browser.WaitForExit(5000)) {
            # This is the hash-verified PID created above, never a pre-existing
            # user session because that state is rejected before launch.
            Stop-Process -Id $browser.Id
            $browser.WaitForExit()
        }
    }
    if (Test-Path -LiteralPath $temporaryRoot) { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force }
}
