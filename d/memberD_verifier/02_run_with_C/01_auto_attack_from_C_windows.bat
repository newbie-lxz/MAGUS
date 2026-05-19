@echo off
chcp 65001 >nul
set "FLOW=%~dp0"
for %%I in ("%~dp0..") do set "ROOT=%%~fI"
for %%I in ("%ROOT%\..\..") do set "WORKSPACE=%%~fI"
set "HYP_FILE=%WORKSPACE%\c\out\hypotheses.jsonl"
set "OUT_DIR=%FLOW%output"
set "TARGET_FILE=%FLOW%targets.auto.json"

if not exist "%HYP_FILE%" (
  echo [ERROR] Cannot find C output:
  echo   %HYP_FILE%
  echo Run Stage C first so it writes c\out\hypotheses.jsonl.
  pause
  exit /b 1
)

"%ROOT%\.venv\Scripts\python.exe" "%ROOT%\00_core\gen_targets_from_hypotheses.py" --hypotheses "%HYP_FILE%" --out "%TARGET_FILE%" --auto-fill
"%ROOT%\.venv\Scripts\python.exe" "%ROOT%\00_core\verifier.py" --hypotheses "%HYP_FILE%" --targets "%TARGET_FILE%" --out-dir "%OUT_DIR%"
"%ROOT%\.venv\Scripts\python.exe" "%ROOT%\03_tools\validate_outputs.py" --out-dir "%OUT_DIR%"

echo.
echo [OK] C workflow finished.
echo Outputs:
echo   02_run_with_C\output\verification.jsonl
echo   02_run_with_C\output\verification.failed.jsonl
echo   02_run_with_C\output\verification.summary.md
pause
