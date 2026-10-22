@echo off
setlocal
title PacketSentinel - Windows Packet & Sketchy DNS Monitor
cd /d "%~dp0"

if exist "dist\PacketSentinel\PacketSentinel.exe" (
    "dist\PacketSentinel\PacketSentinel.exe" %*
    goto :end
)

where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [!] Python was not found in PATH and no prebuilt bundle exists.
    echo     Install Python 3.10+ or download the prebuilt PacketSentinel release bundle.
    pause
    exit /b 1
)

python run_packetsentinel.py %*

:end
if "%1"=="" pause
