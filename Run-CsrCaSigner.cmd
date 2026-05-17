@echo off
setlocal
start "" powershell.exe -NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File "%~dp0CsrCaSigner.ps1"
exit /b %ERRORLEVEL%
