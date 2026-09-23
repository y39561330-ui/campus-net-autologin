@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-CampusNetAutoLogin.ps1" %*
echo.
pause
