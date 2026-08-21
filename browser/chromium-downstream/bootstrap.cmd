@echo off
setlocal
set "ZSEC_BOOTSTRAP_DIR=%~dp0"
set "ZSEC_BOOTSTRAP_PS=%ZSEC_BOOTSTRAP_DIR%scripts\Invoke-ZsecChromiumBootstrap.ps1"

if not exist "%ZSEC_BOOTSTRAP_PS%" (
  echo ZSEC Chromium bootstrap script is missing: "%ZSEC_BOOTSTRAP_PS%" 1>&2
  exit /b 10
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy RemoteSigned -File "%ZSEC_BOOTSTRAP_PS%" %*
exit /b %ERRORLEVEL%
