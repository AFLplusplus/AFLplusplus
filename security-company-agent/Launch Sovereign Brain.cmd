@echo off
setlocal
cd /d "%~dp0"
if not exist "%~dp0.venv\Scripts\python.exe" (
    echo Sovereign Brain virtual environment not found at "%~dp0.venv".
    pause
    exit /b 1
)
"%~dp0.venv\Scripts\python.exe" "%~dp0launch_studio.py"
if errorlevel 1 pause
endlocal
