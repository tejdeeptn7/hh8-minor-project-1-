@echo off
echo =========================================
echo   Windows Security Audit Tool
echo =========================================

cd /d %~dp0
powershell -ExecutionPolicy Bypass -File src\WindowsSecurityAudit.ps1

echo.
echo Audit finished. Press any key to exit.
pause > nul
