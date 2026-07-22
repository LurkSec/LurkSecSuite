@echo off
title LurkSec Suite Shutdown
color 0C
echo ===============================================================================
echo                LURKSEC DEFENSIVE SUITE SHUTDOWN
echo ===============================================================================
echo Stopping all active LurkSec Python servers...

powershell -Command "Get-Process -Name python -ErrorAction SilentlyContinue | Stop-Process -Force"

echo.
echo All LurkSec servers terminated cleanly.
echo ===============================================================================
pause
