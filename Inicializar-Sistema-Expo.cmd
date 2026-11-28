@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Inicializador-Maestro.ps1" -ModoExposicion %*
echo.
pause
