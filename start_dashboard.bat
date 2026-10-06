@echo off
title Enterprise Network Vulnerability Scanner - Live Dashboard
cd /d "%~dp0"
echo ================================================================================
echo   STARTING ENTERPRISE NETWORK VULNERABILITY SCANNER DASHBOARD
echo   Localhost URL: http://localhost:8765
echo ================================================================================
python dashboard.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] The dashboard server exited with error code %ERRORLEVEL%.
    echo Review the error diagnostic above.
    echo.
)
pause
