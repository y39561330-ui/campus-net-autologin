@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Uninstall-CampusNetAutoLogin.ps1" %*
echo.
pause
