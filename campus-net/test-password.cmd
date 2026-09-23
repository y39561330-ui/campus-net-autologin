@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Test-CampusNetPassword.ps1" %*
echo.
pause
