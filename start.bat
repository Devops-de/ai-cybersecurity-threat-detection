@echo off
title CyberSentinel AI - Threat Detection Platform
echo =================================================================
echo   CYBERSENTINEL AI: THREAT DETECTION & INCIDENT RESPONSE SOC
echo =================================================================
echo.
set "PATH=C:\Program Files\nodejs;%PATH%"
set "PYTHONPATH=%~dp0backend"

echo [*] Checking virtual environment...
if exist "%~dp0venv\Scripts\python.exe" (
    echo [+] Using virtual environment Python.
    "%~dp0venv\Scripts\python.exe" run_system.py
) else (
    echo [*] Running with default Python...
    python run_system.py
)
pause
