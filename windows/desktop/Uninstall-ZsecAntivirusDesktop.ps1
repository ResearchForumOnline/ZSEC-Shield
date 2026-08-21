#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "TalkToAI\ZSEC Antivirus"),
    [switch]$RemoveState
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$productRoot = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
$currentPath = Join-Path $productRoot "current.json"
if (-not (Test-Path -LiteralPath $currentPath -PathType Leaf)) {
    throw "The owned ZSEC Antivirus installation record is absent."
}
$installation = Get-Content -LiteralPath $currentPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($installation.schema -ne "zsec.antivirus.windows-desktop-installation.v1") {
    throw "The owned ZSEC Antivirus installation record is invalid."
}
$versionRoot = [IO.Path]::GetFullPath([string]$installation.version_root).TrimEnd('\')
if (-not $versionRoot.StartsWith($productRoot + '\App\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "The recorded version path is outside the owned application directory."
}
$desktopExe = [IO.Path]::GetFullPath([string]$installation.desktop_executable)
$running = @(Get-CimInstance Win32_Process -Filter "Name = 'ZSEC Antivirus.exe'" -ErrorAction SilentlyContinue | Where-Object {
    $_.ExecutablePath -and ([IO.Path]::GetFullPath($_.ExecutablePath) -eq $desktopExe)
})
if ($running.Count -gt 0) {
    throw "Close ZSEC Antivirus before uninstalling it."
}

$shortcuts = @(
    (Join-Path ([Environment]::GetFolderPath("Desktop")) "ZSEC Antivirus.lnk"),
    (Join-Path (Join-Path ([Environment]::GetFolderPath("Programs")) "ZSEC") "ZSEC Antivirus.lnk")
)
if ($PSCmdlet.ShouldProcess($versionRoot, "Remove the owned ZSEC Antivirus desktop installation")) {
    foreach ($shortcutPath in $shortcuts) {
        if (-not (Test-Path -LiteralPath $shortcutPath -PathType Leaf)) { continue }
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        if ([IO.Path]::GetFullPath([string]$shortcut.TargetPath) -eq $desktopExe) {
            Remove-Item -LiteralPath $shortcutPath -Force
        }
    }
    Remove-Item -LiteralPath $versionRoot -Recurse -Force
    Remove-Item -LiteralPath $currentPath -Force
}

$stateRemoved = $false
if ($RemoveState) {
    $state = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA "ZSEC\Shield")).TrimEnd('\')
    if ($state -ne (Join-Path ([IO.Path]::GetFullPath($env:LOCALAPPDATA).TrimEnd('\')) "ZSEC\Shield")) {
        throw "The resolved state path is not the expected owned ZSEC state directory."
    }
    if ((Test-Path -LiteralPath $state) -and $PSCmdlet.ShouldProcess($state, "Permanently remove scan reports, feed state, encryption root and quarantine recovery data")) {
        Remove-Item -LiteralPath $state -Recurse -Force
        $stateRemoved = $true
    }
}

[ordered]@{
    schema = "zsec.antivirus.windows-desktop-uninstall-result.v1"
    removed = $true
    version = [string]$installation.version
    state_removed = $stateRemoved
    state_preserved = (-not $stateRemoved)
    security_products_modified = $false
} | ConvertTo-Json -Depth 6
