@echo off
title Master LurkSec Suite Console Launcher
color 0A

:: Self-elevate script to Administrator if not already elevated
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting Administrative Privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"

echo ===============================================================================
echo                MASTER LURKSEC SUITE COMMAND LAUNCHER [ADMIN]
echo ===============================================================================
echo Starting Master LurkSec Unified Security Server on Port 8000...
echo.

start "Master LurkSec Server [Port 8000]" /min cmd /c "cd /d %~dp0 && python lurksec.py"

echo Waiting 3 seconds for server initialization...
timeout /t 3 /nobreak > nul

echo.
echo Opening Master LurkSec Command Console...
start http://127.0.0.1:8000

echo ===============================================================================
echo SUCCESS: Master LurkSec Command Console is active at http://127.0.0.1:8000
echo ===============================================================================
pause
