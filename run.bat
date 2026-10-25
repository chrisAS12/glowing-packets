@echo off
@chcp 65001 >nul
setlocal enabledelayedexpansion
title PacketSentinel Desktop Launcher

:: -----------------------------------------------------------------------------
:: Python Auto-Detection (Finds conda, venv, or standard Windows Python)
:: -----------------------------------------------------------------------------
set "PYTHON_EXE="

:: 1. Check if 'python' in current PATH works
where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    set "PYTHON_EXE=python"
    goto :python_found
)

:: 2. Check Anaconda / Miniconda in UserProfile
if exist "%USERPROFILE%\anaconda3\python.exe" (
    set "PYTHON_EXE=%USERPROFILE%\anaconda3\python.exe"
    goto :python_found
)
if exist "%USERPROFILE%\miniconda3\python.exe" (
    set "PYTHON_EXE=%USERPROFILE%\miniconda3\python.exe"
    goto :python_found
)

:: 3. Check Windows Python Launcher (py)
where py >nul 2>nul
if %ERRORLEVEL% equ 0 (
    set "PYTHON_EXE=py"
    goto :python_found
)

:: 4. Check AppData Local Programs
for /d %%i in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
    if exist "%%i\python.exe" (
        set "PYTHON_EXE=%%i\python.exe"
        goto :python_found
    )
)

:: 5. Check Program Files
for /d %%i in ("%ProgramFiles%\Python3*") do (
    if exist "%%i\python.exe" (
        set "PYTHON_EXE=%%i\python.exe"
        goto :python_found
    )
)

:python_not_found
echo ======================================================================
echo   [!] Python Not Found in System PATH or Standard Directories
echo ======================================================================
echo   Could not find a working python.exe.
echo   Please ensure Anaconda or Python 3.10+ is installed.
echo   Checked: %USERPROFILE%\anaconda3\python.exe
echo ======================================================================
pause
exit /b 1

:python_found
:: Set companion on PYTHONPATH
set "PYTHONPATH=%~dp0companion;%PYTHONPATH%"

:: If arguments provided (e.g. run.bat --ui), execute directly
if not "%~1"=="" (
    "%PYTHON_EXE%" "%~dp0companion\run_packetsentinel.py" %*
    goto :eof
)

:menu
cls
echo ======================================================================
echo   PacketSentinel - Offline Micro-EDR ^& Pre-Model Privacy Airlock
echo ======================================================================
echo.
echo   [1] Launch Native Desktop App (--ui)
echo   [2] Start Live Packet Monitor (CLI)
echo   [3] Target Process Watchdog (--watch-process)
echo   [4] Run Security Audit ^& Verification (54 Tests)
echo   [5] EMERGENCY KILL SWITCH (Stop All Background Listeners)
echo   [6] Exit
echo.
echo   [Python detected: %PYTHON_EXE%]
echo ======================================================================
set /p choice="Select an option (1-6) [default: 1]: "

if "%choice%"=="" set choice=1
if "%choice%"=="1" goto launch_ui
if "%choice%"=="2" goto launch_monitor
if "%choice%"=="3" goto launch_watchdog
if "%choice%"=="4" goto run_audit
if "%choice%"=="5" goto kill_switch
if "%choice%"=="6" goto :eof
goto menu

:launch_ui
echo.
echo [*] Launching Native Desktop Security ^& Privacy Airlock...
"%PYTHON_EXE%" "%~dp0companion\run_packetsentinel.py" --ui
pause
goto menu

:launch_monitor
echo.
echo [*] Starting live packet capture...
"%PYTHON_EXE%" "%~dp0companion\run_packetsentinel.py"
pause
goto menu

:launch_watchdog
echo.
set /p proc="Enter process name or PID to watch (e.g. python or 1234): "
"%PYTHON_EXE%" "%~dp0companion\run_packetsentinel.py" --watch-process "%proc%"
pause
goto menu

:run_audit
echo.
echo [*] Running security and supply-chain audit...
"%PYTHON_EXE%" "%~dp0..\non-prod\audit_dependencies_and_code.py"
pause
goto menu

:kill_switch
call "%~dp0kill.bat"
pause
goto menu
