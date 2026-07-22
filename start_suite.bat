@echo off
title Master LurkSec Suite Console Launcher
color 0A
echo ===============================================================================
echo                MASTER LURKSEC SUITE COMMAND LAUNCHER
echo ===============================================================================
echo Starting Master LurkSec Unified Security Server on Port 8000...
echo.

start "Master LurkSec Server [Port 8000]" /min cmd /c "cd /d %~dp0 && python lurksec.py serve --port 8000"

echo Waiting 2 seconds for server initialization...
timeout /t 2 /nobreak > nul

echo.
echo Opening Master LurkSec Command Console...
start http://localhost:8000

echo ===============================================================================
echo SUCCESS: Master LurkSec Command Console is active at http://localhost:8000!
echo ===============================================================================
pause
