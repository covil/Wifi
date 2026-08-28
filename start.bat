@echo off
REM wifiaudit launcher for Windows. Double-click, or run:  start.bat
REM On first run this creates a local .venv and installs wifiaudit, then opens
REM the interactive menu. (Live WiFi capture is not supported on Windows; use
REM the offline demo, or run on Linux for real captures.)
setlocal
set "HERE=%~dp0"
set "VENV=%HERE%.venv"
set "PY=%VENV%\Scripts\python.exe"

if not exist "%PY%" (
    echo First run: setting up wifiaudit ^(one-time^)...
    python -m venv "%VENV%" || ( echo error: could not create the virtualenv. Is Python 3.11+ installed? & exit /b 1 )
    "%PY%" -m pip install --upgrade pip >nul 2>&1
    echo   installing wifiaudit and its dependencies...
    "%PY%" -m pip install -e "%HERE%" || ( echo error: installation failed. & exit /b 1 )
    echo   setup complete.
    echo.
)

"%PY%" -m wifiaudit menu %*
