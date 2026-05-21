#!/usr/bin/env bash
set -euo pipefail

FLOW="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$FLOW/.." && pwd)"
WORKSPACE="$(cd "$ROOT/../.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
C_OUT_DIR="$WORKSPACE/c/out"
TARGET_FILE="$FLOW/targets.manual.json"
OUT_DIR="$FLOW/output_manual"
REPORT_DIR="$WORKSPACE/report"
REPORT_CODE_DIR="$REPORT_DIR/code"

if [[ ! -d "$C_OUT_DIR" ]]; then
  echo "[ERROR] Cannot find C output directory: $C_OUT_DIR"
  exit 1
fi

if ! compgen -G "$C_OUT_DIR/*.jsonl" > /dev/null; then
  echo "[ERROR] No Stage C *.jsonl files found under: $C_OUT_DIR"
  exit 1
fi

if [[ ! -f "$TARGET_FILE" ]]; then
  echo "[ERROR] Cannot find targets.manual.json. Run 02_generate_targets_from_C_linux.sh first."
  exit 1
fi

if [[ ! -x "$PYTHON" ]]; then
  echo "[ERROR] Cannot find Python env: $PYTHON"
  echo "Run d/memberD_verifier/01_demo_test/01_setup_linux.sh first."
  exit 1
fi

"$PYTHON" "$ROOT/00_core/verifier.py" --hypotheses "$C_OUT_DIR" --targets "$TARGET_FILE" --out-dir "$OUT_DIR"
"$PYTHON" "$ROOT/03_tools/validate_outputs.py" --out-dir "$OUT_DIR"
"$PYTHON" "$REPORT_CODE_DIR/generate_report.py" --confirmed "$OUT_DIR/verification.jsonl" --failed "$OUT_DIR/verification.failed.jsonl" --out-dir "$REPORT_DIR"
"$PYTHON" "$REPORT_CODE_DIR/validate_report.py" --confirmed "$OUT_DIR/verification.jsonl" --report-dir "$REPORT_DIR"
echo "[OK] Manual target verification finished."
echo "[OK] Final report: $REPORT_DIR/verification.report.md"
