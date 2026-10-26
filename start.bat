@echo off
REM CyberAudit Monitor - one-click start for Windows.
REM First run: creates .venv, installs Flask, seeds the demo database. Later runs start immediately.
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (set "PY=py -3") else (set "PY=python")

if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    %PY% -m venv .venv
    if errorlevel 1 (
        echo.
        echo Python 3.10 or newer is required. Install it from https://www.python.org/downloads/
        echo and tick "Add python.exe to PATH" during installation, then run this file again.
        pause
        exit /b 1
    )
    echo Installing requirements...
    ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt
    if errorlevel 1 (
        echo Installing requirements failed. Check your internet connection and try again.
        pause
        exit /b 1
    )
)

start "" http://127.0.0.1:5000
".venv\Scripts\python.exe" run.py %*
pause
