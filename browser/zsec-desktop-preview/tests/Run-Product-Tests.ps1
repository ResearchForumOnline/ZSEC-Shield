#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$packageRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$stateSource = Join-Path $packageRoot "src\BrowserProductState.cs"
$policySource = Join-Path $packageRoot "src\BrowserProductPolicy.cs"
$vaultContractsSource = Join-Path $packageRoot "src\BrowserVaultUiContracts.cs"
$passwordVaultSource = Join-Path $packageRoot "src\BrowserPasswordVault.cs"
$credentialWorkflowSource = Join-Path $packageRoot "src\BrowserCredentialWorkflowPolicy.cs"
$credentialImportSource = Join-Path $packageRoot "src\BrowserCredentialImport.cs"
$loginAssistantSource = Join-Path $packageRoot "src\BrowserLoginAssistant.cs"
$themeSource = Join-Path $packageRoot "src\BrowserTheme.cs"
$testSource = Join-Path $PSScriptRoot "BrowserProductStateTests.cs"
$compiler = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$temporary = Join-Path ([IO.Path]::GetTempPath()) ("zsec-browser-product-tests-" + [guid]::NewGuid().ToString("N"))
$executable = Join-Path $temporary "BrowserProductStateTests.exe"

foreach ($path in @(
    $stateSource, $policySource, $vaultContractsSource, $passwordVaultSource,
    $credentialWorkflowSource, $credentialImportSource, $loginAssistantSource, $themeSource, $testSource, $compiler
)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required browser product test input is absent: $path"
    }
}

try {
    New-Item -ItemType Directory -Path $temporary -ErrorAction Stop | Out-Null
    & $compiler `
        /nologo `
        /target:exe `
        /optimize+ `
        /reference:System.dll `
        /reference:System.Core.dll `
        /reference:System.Drawing.dll `
        /reference:System.Security.dll `
        /reference:System.Web.dll `
        /reference:System.Web.Extensions.dll `
        "/out:$executable" `
        $stateSource `
        $policySource `
        $vaultContractsSource `
        $passwordVaultSource `
        $credentialWorkflowSource `
        $credentialImportSource `
        $loginAssistantSource `
        $themeSource `
        $testSource
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "The browser product state test harness did not compile."
    }
    & $executable
    if ($LASTEXITCODE -ne 0) {
        throw "The browser product state tests failed with exit code $LASTEXITCODE."
    }
}
finally {
    if (Test-Path -LiteralPath $temporary -PathType Container) {
        Remove-Item -LiteralPath $temporary -Recurse -Force
    }
}
