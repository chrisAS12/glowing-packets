@echo off
@chcp 65001 >nul
setlocal enabledelayedexpansion
title SentinelWire Desktop Launcher

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
echo   SentinelWire - Zero-Outbound Micro-EDR ^& Privacy Airlock
echo ======================================================================
echo.
echo   [1] Launch SentinelWire Desktop App (Recommended)
echo       - Includes Offline Voice AI, 5-Gate DLP Scrubber ^& Live Wire Guard
echo.
echo   [2] Emergency Kill Switch (Stop All Background Listeners)
echo   [3] Run Security ^& Dependency Audit (53 Tests)
echo   [4] Exit
echo.
echo   [Python detected: %PYTHON_EXE%]
echo ======================================================================
choice /c 1234 /t 3 /d 1 /m "Select option (1-4) [Auto-launching Option 1 in 3s]"
if errorlevel 4 goto :eof
if errorlevel 3 goto run_audit
if errorlevel 2 goto kill_switch
if errorlevel 1 goto launch_ui
goto menu

:launch_ui
echo.
echo [*] Launching SentinelWire Desktop Security ^& Privacy Airlock...
"%PYTHON_EXE%" "%~dp0companion\run_packetsentinel.py" --ui
goto :eof

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
