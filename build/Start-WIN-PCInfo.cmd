@echo off
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -STA -File "%~dp0Start-WIN-PCInfo.ps1" %*
set "WINPCINFO_EXIT=%errorlevel%"
if not "%WINPCINFO_EXIT%"=="0" if "%~1"=="" (
  echo WIN-PCInfo did not complete. Review the reason above, verify the complete package and its signature, and retry under your existing policy.
  pause
)
exit /b %WINPCINFO_EXIT%
