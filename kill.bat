@echo off
@chcp 65001 >nul
setlocal
title PacketSentinel Emergency Kill Switch
echo ======================================================================
echo   PacketSentinel - Emergency Kill Switch Initiated
echo ======================================================================

:: 1. Touch file tripwire in app directories
echo STOP > "%~dp0KILL_SWITCH"
echo STOP > "%~dp0companion\KILL_SWITCH"

:: 2. Find and terminate any process listening on port 8765
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8765" ^| findstr "LISTENING"') do (
    echo [*] Terminating process on port 8765 (PID: %%a)...
    taskkill /F /PID %%a >nul 2>&1
)

:: 3. Terminate any running PacketSentinel python processes
powershell -Command "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*packetsentinel*' } | ForEach-Object { Write-Host ('[*] Stopping PID ' + $_.ProcessId); Stop-Process -Id $_.ProcessId -Force }" >nul 2>&1

:: 4. Clean up tripwire files
timeout /t 1 /nobreak >nul
if exist "%~dp0KILL_SWITCH" del "%~dp0KILL_SWITCH" >nul 2>&1
if exist "%~dp0companion\KILL_SWITCH" del "%~dp0companion\KILL_SWITCH" >nul 2>&1

echo.
echo [+] EMERGENCY KILL SWITCH COMPLETE:
echo     - All PacketSentinel processes terminated.
echo     - Volatile prompt memory released.
echo     - Background watchdog threads terminated.
echo ======================================================================
