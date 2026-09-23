@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Fix-Proxy.ps1" %*
echo.
pause
