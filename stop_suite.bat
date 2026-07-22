@echo off
title Master LurkSec Suite Shutdown
color 0C
echo ===============================================================================
echo                MASTER LURKSEC SUITE SHUTDOWN
echo ===============================================================================
echo Stopping active LurkSec Python server...

powershell -Command "Get-Process -Name python -ErrorAction SilentlyContinue | Stop-Process -Force"

echo.
echo Master LurkSec server terminated cleanly.
echo ===============================================================================
pause
