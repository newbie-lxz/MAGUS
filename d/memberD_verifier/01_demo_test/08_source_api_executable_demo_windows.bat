@echo off
chcp 65001 >nul
set "DEMO=%~dp0"
set "ROOT=%~dp0.."
set "HYP_FILE=%DEMO%samples\hypotheses.source_api.executable.example.jsonl"
set "OUT_DIR=%DEMO%out_source_api_executable"
set "TARGET_FILE=%DEMO%targets.source_api.executable.auto.json"

"%ROOT%\.venv\Scripts\python.exe" "%ROOT%\00_core\gen_targets_from_hypotheses.py" --hypotheses "%HYP_FILE%" --out "%TARGET_FILE%" --auto-fill
"%ROOT%\.venv\Scripts\python.exe" "%ROOT%\00_core\verifier.py" --hypotheses "%HYP_FILE%" --targets "%TARGET_FILE%" --out-dir "%OUT_DIR%"
"%ROOT%\.venv\Scripts\python.exe" "%ROOT%\03_tools\validate_outputs.py" --out-dir "%OUT_DIR%"

echo.
echo [OK] Executable source/API payload demo finished.
echo Inspect 01_demo_test\out_source_api_executable\verification.jsonl
pause
