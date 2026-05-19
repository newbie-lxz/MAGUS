@echo off
chcp 65001 >nul
set "FLOW=%~dp0"
for %%I in ("%~dp0..") do set "ROOT=%%~fI"
for %%I in ("%ROOT%\..\..") do set "WORKSPACE=%%~fI"
set "HYP_FILE=%WORKSPACE%\c\out\hypotheses.jsonl"
set "TARGET_FILE=%FLOW%targets.manual.json"
set "OUT_DIR=%FLOW%output_manual"

if not exist "%HYP_FILE%" (
  echo [ERROR] Cannot find C output: %HYP_FILE%
  pause
  exit /b 1
)

if not exist "%TARGET_FILE%" (
  echo [ERROR] Cannot find targets.manual.json. Run 02_generate_targets_from_C_windows.bat first.
  pause
  exit /b 1
)

"%ROOT%\.venv\Scripts\python.exe" "%ROOT%\00_core\verifier.py" --hypotheses "%HYP_FILE%" --targets "%TARGET_FILE%" --out-dir "%OUT_DIR%"
"%ROOT%\.venv\Scripts\python.exe" "%ROOT%\03_tools\validate_outputs.py" --out-dir "%OUT_DIR%"
pause
