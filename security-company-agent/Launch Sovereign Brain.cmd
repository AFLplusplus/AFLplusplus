@echo off
cd /d "%~dp0"
"%~dp0.venv\Scripts\python.exe" "%~dp0launch_studio.py"
if errorlevel 1 pause
