@echo off
setlocal
cd /d "%~dp0"
title Arenyxa v8.1.1 Source Launcher

set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS%" set "PS=powershell.exe"

"%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\launch.ps1"
set "ARENYXA_EXIT=%ERRORLEVEL%"

if not "%ARENYXA_EXIT%"=="0" (
    echo.
    echo [Arenyxa] Startup failed. Exit code: %ARENYXA_EXIT%
    echo [Arenyxa] The error above was kept on screen for troubleshooting.
    echo.
    pause
)

exit /b %ARENYXA_EXIT%
