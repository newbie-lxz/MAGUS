#!/usr/bin/env bash
set -euo pipefail

DEMO="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DEMO/.." && pwd)"
WORKSPACE="$(cd "$ROOT/../.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
HYP_FILE="$DEMO/samples/hypotheses.source_api.executable.example.jsonl"
OUT_DIR="$DEMO/out_source_api_executable"
TARGET_FILE="$DEMO/targets.source_api.executable.auto.json"
REPORT_ROOT="$WORKSPACE/report"

if [[ ! -x "$PYTHON" ]]; then
  echo "[ERROR] Cannot find Python env: $PYTHON"
  echo "Run d/memberD_verifier/01_demo_test/01_setup_linux.sh first."
  exit 1
fi

"$PYTHON" "$ROOT/00_core/gen_targets_from_hypotheses.py" --hypotheses "$HYP_FILE" --out "$TARGET_FILE" --auto-fill
"$PYTHON" "$ROOT/00_core/verifier.py" --hypotheses "$HYP_FILE" --targets "$TARGET_FILE" --out-dir "$OUT_DIR"
"$PYTHON" "$ROOT/03_tools/validate_outputs.py" --out-dir "$OUT_DIR"
"$PYTHON" "$WORKSPACE/pipeline.py" report --d-output-dir "$OUT_DIR" --report-root "$REPORT_ROOT"

echo
echo "[OK] Executable source/API payload demo finished."
echo "Inspect 01_demo_test/out_source_api_executable/verification.jsonl"
echo "Inspect $REPORT_ROOT/repo_source_api_exec/verification.report.md"
