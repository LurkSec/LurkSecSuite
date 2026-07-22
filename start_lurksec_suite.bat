@echo off
title LurkSec Defensive Suite Master Launcher
color 0A
echo ===============================================================================
echo                LURKSEC DEFENSIVE SUITE MASTER LAUNCHER
echo ===============================================================================
echo Starting 5 LurkSec Security Servers...
echo.

echo [1/5] Launching LurkSentinel (Network & Socket Inspector) on Port 8000...
start "LurkSentinel [Port 8000]" /min cmd /c "cd /d %~dp0netsentinel-security-suite && python netsentinel.py serve --port 8000"

echo [2/5] Launching LurkSIEM (Event Log Correlation Engine) on Port 8001...
start "LurkSIEM [Port 8001]" /min cmd /c "cd /d %~dp0lurksiem-security-engine && python lurksiem.py serve --port 8001"

echo [3/5] Launching LurkDecoy (Internal Honeypot Telemetry) on Port 8002...
start "LurkDecoy [Port 8002]" /min cmd /c "cd /d %~dp0lurkdecoy-security-engine && python lurkdecoy.py serve --port 8002"

echo [4/5] Launching LurkPacket (Live PCAP & Protocol Inspector) on Port 8003...
start "LurkPacket [Port 8003]" /min cmd /c "cd /d %~dp0lurkpacket-security-engine && python lurkpacket.py serve --port 8003"

echo [5/5] Launching LurkTrace (Windows Process & Syscall Auditor) on Port 8004...
start "LurkTrace [Port 8004]" /min cmd /c "cd /d %~dp0lurktrace-security-engine && python lurktrace.py serve --port 8004"

echo.
echo Waiting 3 seconds for all 5 security servers to initialize...
timeout /t 3 /nobreak > nul

echo.
echo Opening Web Consoles in your browser...
start http://localhost:8000
start http://localhost:8001
start http://localhost:8002
start http://localhost:8003
start http://localhost:8004

echo ===============================================================================
echo SUCCESS: All 5 LurkSec Security Consoles are active!
echo - LurkSentinel: http://localhost:8000
echo - LurkSIEM:     http://localhost:8001
echo - LurkDecoy:    http://localhost:8002
echo - LurkPacket:   http://localhost:8003
echo - LurkTrace:    http://localhost:8004
echo ===============================================================================
pause
