@echo off
chcp 65001 >nul
set "ROOT=%~dp0.."
cd /d "%ROOT%"
python -m venv .venv
".venv\Scripts\python.exe" -m pip install -r "00_core\requirements.txt"
echo.
echo [OK] Python environment is ready.
echo Next: run 07_source_api_demo_windows.bat or 08_source_api_executable_demo_windows.bat
pause
