#!/usr/bin/env bash
set -euo pipefail

DEMO="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DEMO/.." && pwd)"
WORKSPACE="$(cd "$ROOT/../.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
HYP_FILE="$DEMO/samples/hypotheses.source_api.example.jsonl"
OUT_DIR="$DEMO/out_source_api"
TARGET_FILE="$DEMO/targets.source_api.auto.json"
REPORT_DIR="$WORKSPACE/report"
REPORT_CODE_DIR="$REPORT_DIR/code"

if [[ ! -x "$PYTHON" ]]; then
  echo "[ERROR] Cannot find Python env: $PYTHON"
  echo "Run d/memberD_verifier/01_demo_test/01_setup_linux.sh first."
  exit 1
fi

"$PYTHON" "$ROOT/00_core/gen_targets_from_hypotheses.py" --hypotheses "$HYP_FILE" --out "$TARGET_FILE" --auto-fill
"$PYTHON" "$ROOT/00_core/verifier.py" --hypotheses "$HYP_FILE" --targets "$TARGET_FILE" --out-dir "$OUT_DIR"
"$PYTHON" "$ROOT/03_tools/validate_outputs.py" --out-dir "$OUT_DIR"
"$PYTHON" "$REPORT_CODE_DIR/generate_report.py" --confirmed "$OUT_DIR/verification.jsonl" --failed "$OUT_DIR/verification.failed.jsonl" --out-dir "$REPORT_DIR"
"$PYTHON" "$REPORT_CODE_DIR/validate_report.py" --confirmed "$OUT_DIR/verification.jsonl" --report-dir "$REPORT_DIR"

echo
echo "[OK] Source/API misuse demo finished."
echo "Inspect 01_demo_test/out_source_api/verification.failed.jsonl"
echo "Inspect $REPORT_DIR/verification.report.md"
