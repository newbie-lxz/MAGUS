@echo off
chcp 65001 >nul
set "FLOW=%~dp0"
for %%I in ("%~dp0..") do set "ROOT=%%~fI"
for %%I in ("%ROOT%\..\..") do set "WORKSPACE=%%~fI"
set "HYP_FILE=%WORKSPACE%\c\out\hypotheses.jsonl"
set "TARGET_FILE=%FLOW%targets.manual.json"

if not exist "%HYP_FILE%" (
  echo [ERROR] Cannot find C output:
  echo   %HYP_FILE%
  pause
  exit /b 1
)

"%ROOT%\.venv\Scripts\python.exe" "%ROOT%\00_core\gen_targets_from_hypotheses.py" --hypotheses "%HYP_FILE%" --out "%TARGET_FILE%"
echo.
echo [OK] Manual targets file generated:
echo   02_run_with_C\targets.manual.json
echo Edit repo_path, run_cmd/poc_cmd/test_cmd, and oracle fields if auto mode is not enough.
pause
